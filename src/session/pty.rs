use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use memchr::memmem;
use russh::client::Msg;
use russh::{ChannelMsg, ChannelReadHalf, ChannelWriteHalf};
use tokio::sync::{Mutex, MutexGuard, OwnedSemaphorePermit};
use tokio::time::timeout;

use crate::errors::{Result, SshError};
use crate::session::Session;

pub const DEFAULT_PTY_TERM: &str = "xterm-256color";
pub const DEFAULT_PTY_COLS: u32 = 200;
pub const DEFAULT_PTY_ROWS: u32 = 50;

/// PTY-backed shell where `cd` / `export` persist between calls.
/// Sentinel is appended after each command so we know when output ends.
///
/// Read and write halves are stored separately so `interrupt()` (writes a
/// Ctrl-C byte) can fire while a `run()` is mid-`wait()`. Previously the
/// shared `Mutex<Channel>` starved interrupt for the duration of the
/// in-flight command.
pub struct PtyState {
    read: Mutex<ChannelReadHalf>,
    write: ChannelWriteHalf<Msg>,
    pub session_id: String,
    /// Per-call sequence counter. Each `run()` rotates the sentinel token so
    /// a prior command output cannot forge an exit code for a subsequent call.
    seq: AtomicU64,
    /// Channel slot against `max_channels_per_host`, held for the lifetime
    /// of this PTY so long-lived shells count toward sshd MaxSessions.
    _permit: OwnedSemaphorePermit,
}

#[derive(Debug, Clone, Copy)]
pub struct PtyOpts {
    pub cols: u32,
    pub rows: u32,
    /// Soft cap on bytes captured per `run()`. Excess is dropped.
    pub max_capture: usize,
}

impl Default for PtyOpts {
    fn default() -> Self {
        Self {
            cols: DEFAULT_PTY_COLS,
            rows: DEFAULT_PTY_ROWS,
            max_capture: 256 * 1024,
        }
    }
}

impl PtyState {
    pub async fn open(session: &Session, opts: PtyOpts) -> Result<Self> {
        // Reuse a pre-warmed pool channel when one is parked (-1 RTT), and
        // hold its permit so the PTY counts against the channel quota.
        let (chan, permit, _) = session.take_or_open_channel().await?;
        // want_reply=false on request_pty saves another RTT; a rejected
        // pty-req surfaces as a failed shell/init drain right after, and
        // request_shell keeps want_reply=true as the actual failure detector.
        chan.request_pty(false, DEFAULT_PTY_TERM, opts.cols, opts.rows, 0, 0, &[])
            .await
            .map_err(SshError::from)?;
        chan.request_shell(true).await.map_err(SshError::from)?;

        let session_id = random_token("rdy")?;
        // `bind 'set enable-bracketed-paste off'` was a bashism that errored
        // under zsh/dash/fish. The portable `printf '\e[?2004l'` reset below
        // covers the same case across shells.
        //
        // The readiness marker is emitted via `printf '__%s__' <id>` so the
        // assembled `__<id>__` string never appears in the PTY echo of the
        // init block itself (the echo contains `'__%s__'` and `<id>`
        // separately). One occurrence therefore deterministically means the
        // shell has executed the whole init — no echo-counting heuristics,
        // no fixed settle delay.
        let init = format!(
            "stty -echo -onlcr 2>/dev/null\n\
             printf '\\e[?2004l'\n\
             export PS1='' PS2='' PROMPT_COMMAND=''\n\
             printf '__%s__\\n' {session_id}\n"
        );
        chan.data(init.as_bytes()).await.map_err(SshError::from)?;

        let (read, write) = chan.split();
        let pty = Self {
            read: Mutex::new(read),
            write,
            session_id: session_id.clone(),
            seq: AtomicU64::new(0),
            _permit: permit,
        };
        let init_marker = format!("__{session_id}__");
        pty.drain_until_marker(&init_marker, Duration::from_secs(15), opts.max_capture)
            .await?;
        Ok(pty)
    }

    /// Send a Ctrl-C (`\x03`) to the running foreground command on this PTY.
    /// Does not contend with `run()` because the write half is independent.
    pub async fn interrupt(&self) -> Result<()> {
        self.write
            .data(&b"\x03"[..])
            .await
            .map_err(SshError::from)?;
        Ok(())
    }

    /// Drain until the init readiness marker appears once. The marker is
    /// constructed so it cannot occur in the PTY echo of the init block (see
    /// `open`), so a single occurrence is definitive — the shell has run the
    /// whole init and any login banner has already flushed ahead of it.
    async fn drain_until_marker(
        &self,
        marker: &str,
        deadline: Duration,
        max_capture: usize,
    ) -> Result<()> {
        let start = Instant::now();
        let mut buf = Vec::with_capacity(4096);
        let finder = memmem::Finder::new(marker.as_bytes());
        let mut scan_from = 0usize;
        let mut read = self.read.lock().await;
        loop {
            let remaining = deadline.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                tracing::warn!(
                    marker = %marker,
                    bytes_received = buf.len(),
                    preview = %String::from_utf8_lossy(&buf[..buf.len().min(512)]),
                    "PTY init drain timed out"
                );
                return Err(SshError::Timeout(deadline.as_millis() as u64));
            }
            let res = timeout(remaining, read.wait()).await;
            match res {
                Ok(Some(ChannelMsg::Data { data })) => append_capped(&mut buf, &data, max_capture),
                Ok(Some(ChannelMsg::ExtendedData { data, .. })) => {
                    append_capped(&mut buf, &data, max_capture)
                }
                Ok(Some(ChannelMsg::Eof)) | Ok(Some(ChannelMsg::Close)) | Ok(None) => {
                    return Err(SshError::Other(
                        "PTY closed unexpectedly during init".into(),
                    ));
                }
                Ok(Some(_)) => {}
                Err(_) => continue,
            }
            let overlap = marker.len().saturating_sub(1);
            let scan_start = scan_from.saturating_sub(overlap);
            if finder.find(&buf[scan_start..]).is_some() {
                return Ok(());
            }
            scan_from = buf.len();
        }
    }

    /// Write `cmd` to the shell, append a sentinel echo of `$?`, read until sentinel observed.
    /// Returns `(output, exit_code)`.
    ///
    /// Locks the read half **before** issuing the write so two concurrent
    /// `run()` calls cannot interleave: payload A then payload B, then both
    /// race for `read.lock()` and the first lock-winner reads B's sentinel.
    /// The fresh per-call nonce in `token` also makes the sentinel
    /// unforgeable: a user command cannot pre-print the exact suffix because
    /// it doesn't know the random bytes.
    pub async fn run(
        &self,
        cmd: &str,
        deadline: Duration,
        max_capture: usize,
    ) -> Result<(String, i32)> {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let nonce = random_nonce()?;
        let token = format!("__DONE_{}_{}_{}__", self.session_id, seq, nonce);
        let payload = format!("{cmd}\nprintf '\\n%s:%s\\n' {token} \"$?\"\n");
        let read = self.read.lock().await;
        self.write
            .data(payload.as_bytes())
            .await
            .map_err(SshError::from)?;
        // The drain already located the terminating `\n<token>:<code>` — reuse
        // its position instead of re-scanning (and re-copying) the buffer.
        let (mut buf, pos) = self
            .drain_until_terminated(&token, deadline, max_capture, read)
            .await?;
        let code = parse_exit_code(&buf[pos + token.len() + 2..]);
        buf.truncate(pos);
        while matches!(buf.last(), Some(b'\n' | b'\r')) {
            buf.pop();
        }
        Ok((into_string_fast(buf), code))
    }

    /// Variant that requires the sentinel to be the LAST line and followed by `:` and a number.
    /// Avoids false-positive where the shell echoes the `printf` line containing the token.
    /// Returns the raw buffer plus the byte offset of the terminating
    /// `\n<token>:` pattern so the caller can slice without re-scanning.
    async fn drain_until_terminated(
        &self,
        token: &str,
        deadline: Duration,
        max_capture: usize,
        mut read: MutexGuard<'_, ChannelReadHalf>,
    ) -> Result<(Vec<u8>, usize)> {
        let pattern = format!("\n{token}:");
        let pattern_bytes = pattern.as_bytes();
        let finder = memmem::Finder::new(pattern_bytes);
        let start = Instant::now();
        let mut buf = Vec::with_capacity(4096);
        let mut scan_from = 0usize;
        let mut last_match: Option<usize> = None;
        loop {
            let remaining = deadline.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                return Err(SshError::Timeout(deadline.as_millis() as u64));
            }
            let res = timeout(remaining, read.wait()).await;
            match res {
                Ok(Some(ChannelMsg::Data { data })) => append_capped(&mut buf, &data, max_capture),
                Ok(Some(ChannelMsg::ExtendedData { data, .. })) => {
                    append_capped(&mut buf, &data, max_capture)
                }
                Ok(Some(ChannelMsg::Eof)) | Ok(Some(ChannelMsg::Close)) | Ok(None) => {
                    return Err(SshError::Other("PTY closed unexpectedly".into()));
                }
                Ok(Some(_)) => {}
                Err(_) => return Err(SshError::Timeout(deadline.as_millis() as u64)),
            }
            let overlap = pattern_bytes.len().saturating_sub(1);
            let scan_start = scan_from.saturating_sub(overlap);
            for pos in finder.find_iter(&buf[scan_start..]) {
                last_match = Some(scan_start + pos);
            }
            scan_from = buf.len();
            if let Some(pos) = last_match {
                let tail_start = pos + pattern_bytes.len();
                if let Some(nl_off) = memchr::memchr(b'\n', &buf[tail_start..]) {
                    let candidate = &buf[tail_start..tail_start + nl_off];
                    let candidate = strip_trailing_cr(candidate);
                    if !candidate.is_empty() && candidate.iter().all(|c| c.is_ascii_digit()) {
                        return Ok((buf, pos));
                    }
                }
            }
        }
    }
}

fn append_capped(buf: &mut Vec<u8>, data: &[u8], max: usize) {
    if buf.len() >= max {
        return;
    }
    let room = max - buf.len();
    if data.len() <= room {
        buf.extend_from_slice(data);
    } else {
        buf.extend_from_slice(&data[..room]);
    }
}

fn into_string_fast(bytes: Vec<u8>) -> String {
    match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    }
}

fn strip_trailing_cr(s: &[u8]) -> &[u8] {
    if let Some(last) = s.last() {
        if *last == b'\r' {
            return &s[..s.len() - 1];
        }
    }
    s
}

/// Parse the exit code from the bytes following `\n<token>:` — a digit run
/// terminated by `\n` or `\r` (PTY ONLCR emits CRLF).
fn parse_exit_code(tail: &[u8]) -> i32 {
    let end = tail
        .iter()
        .position(|&b| b == b'\n' || b == b'\r')
        .unwrap_or(tail.len());
    std::str::from_utf8(&tail[..end])
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(-1)
}

/// Random hex token. 64 bits of entropy is enough to make collision with user
/// output unrealistic. Fails the call rather than falling back to nanos: a
/// predictable sentinel breaks the spoof-resistance guarantee in
/// `PtyState::run`. The error propagates instead of panicking because the
/// release profile is `panic = "abort"`, where one bad call would take the
/// whole server down.
fn random_token(prefix: &str) -> Result<String> {
    Ok(format!("{prefix}{:016x}", random_u64()?))
}

/// Per-call nonce appended to the `__DONE_*` sentinel. Same hard-fail policy
/// as `random_token`: an attacker who learns nonces can spoof exit codes.
fn random_nonce() -> Result<String> {
    Ok(format!("{:016x}", random_u64()?))
}

fn random_u64() -> Result<u64> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes)
        .map_err(|e| SshError::Other(format!("system RNG unavailable: {e}")))?;
    Ok(u64::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirrors the slicing `run()` does after `drain_until_terminated`
    /// returns `(buf, pos)`: exit code from the tail, body truncated at pos.
    fn slice_like_run(raw: &[u8], token: &str, pos: usize) -> (String, i32) {
        let code = parse_exit_code(&raw[pos + token.len() + 2..]);
        let mut buf = raw[..pos].to_vec();
        while matches!(buf.last(), Some(b'\n' | b'\r')) {
            buf.pop();
        }
        (into_string_fast(buf), code)
    }

    #[test]
    fn parses_sentinel() {
        let raw = b"hello world\nsecond line\n__DONE_abc__:0\n";
        let pos = raw.len() - "\n__DONE_abc__:0\n".len();
        let (out, code) = slice_like_run(raw, "__DONE_abc__", pos);
        assert_eq!(out, "hello world\nsecond line");
        assert_eq!(code, 0);
    }

    #[test]
    fn parses_nonzero_exit() {
        let raw = b"boom\n__DONE_x__:42\n";
        let pos = raw.len() - "\n__DONE_x__:42\n".len();
        let (out, code) = slice_like_run(raw, "__DONE_x__", pos);
        assert_eq!(out, "boom");
        assert_eq!(code, 42);
    }

    #[test]
    fn handles_crlf_pty_output() {
        let raw = b"ok\r\n__DONE_x__:0\r\n";
        let pos = raw.len() - "\n__DONE_x__:0\r\n".len();
        let (out, code) = slice_like_run(raw, "__DONE_x__", pos);
        assert_eq!(code, 0);
        assert!(out.contains("ok"));
    }

    #[test]
    fn exit_code_garbage_is_minus_one() {
        assert_eq!(parse_exit_code(b"abc\n"), -1);
        assert_eq!(parse_exit_code(b""), -1);
        assert_eq!(parse_exit_code(b"7\r\n"), 7);
    }

    #[test]
    fn random_token_is_unique() {
        let a = random_token("x").expect("system RNG");
        let b = random_token("x").expect("system RNG");
        assert_ne!(a, b);
        assert!(a.starts_with("x"));
    }

    #[test]
    fn random_nonce_differs_per_call() {
        let a = random_nonce().expect("system RNG");
        let b = random_nonce().expect("system RNG");
        assert_ne!(a, b);
    }

    #[test]
    fn append_capped_drops_overflow() {
        let mut buf = Vec::new();
        append_capped(&mut buf, b"hello", 10);
        append_capped(&mut buf, b"world!!!", 10);
        assert_eq!(buf, b"helloworld");
    }
}
