use std::time::{Duration, Instant};

use memchr::memmem;
use russh::client::Msg;
use russh::{ChannelMsg, ChannelReadHalf, ChannelWriteHalf};
use tokio::sync::Mutex;
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
        let chan = session
            .handle
            .channel_open_session()
            .await
            .map_err(SshError::from)?;
        chan.request_pty(true, DEFAULT_PTY_TERM, opts.cols, opts.rows, 0, 0, &[])
            .await
            .map_err(SshError::from)?;
        chan.request_shell(true).await.map_err(SshError::from)?;

        let session_id = random_token("rdy");
        let init = format!(
            "stty -echo -onlcr 2>/dev/null\n\
             bind 'set enable-bracketed-paste off' 2>/dev/null\n\
             printf '\\e[?2004l'\n\
             export PS1='' PS2='' PROMPT_COMMAND=''\n\
             echo __INIT_{session_id}__\n"
        );
        chan.data(init.as_bytes()).await.map_err(SshError::from)?;

        let (read, write) = chan.split();
        let pty = Self {
            read: Mutex::new(read),
            write,
            session_id: session_id.clone(),
        };
        let init_marker = format!("__INIT_{session_id}__");
        let _ = pty
            .drain_until_two(&init_marker, Duration::from_secs(15), opts.max_capture)
            .await?;
        Ok(pty)
    }

    /// Send a Ctrl-C (`\x03`) to the running foreground command on this PTY.
    /// Does not contend with `run()` because the write half is independent.
    pub async fn interrupt(&self) -> Result<()> {
        self.write.data(&b"\x03"[..]).await.map_err(SshError::from)?;
        Ok(())
    }

    /// Drain until we see the sentinel **twice** — once is the shell echo of the line we sent,
    /// the second is the actual `echo` output. After the second we're certain the shell is
    /// ready and any login banner has flushed.
    async fn drain_until_two(
        &self,
        sentinel: &str,
        deadline: Duration,
        max_capture: usize,
    ) -> Result<String> {
        let start = Instant::now();
        let mut buf = Vec::with_capacity(4096);
        let finder = memmem::Finder::new(sentinel.as_bytes());
        let mut count = 0usize;
        let mut scan_from = 0usize;
        let mut read = self.read.lock().await;
        loop {
            let remaining = deadline.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                tracing::warn!(
                    sentinel = %sentinel,
                    bytes_received = buf.len(),
                    preview = %String::from_utf8_lossy(&buf[..buf.len().min(512)]),
                    "PTY init drain timed out"
                );
                return Err(SshError::Timeout(deadline.as_millis() as u64));
            }
            let res = timeout(remaining.min(Duration::from_millis(250)), read.wait()).await;
            match res {
                Ok(Some(ChannelMsg::Data { data })) => append_capped(&mut buf, &data, max_capture),
                Ok(Some(ChannelMsg::ExtendedData { data, .. })) => append_capped(&mut buf, &data, max_capture),
                Ok(Some(ChannelMsg::Eof)) | Ok(Some(ChannelMsg::Close)) | Ok(None) => {
                    return Err(SshError::Other("PTY closed unexpectedly during init".into()));
                }
                Ok(Some(_)) => {}
                Err(_) => {}
            }
            let overlap = sentinel.len().saturating_sub(1);
            let scan_start = scan_from.saturating_sub(overlap);
            for pos in finder.find_iter(&buf[scan_start..]) {
                count += 1;
                let end = scan_start + pos + sentinel.len();
                scan_from = scan_from.max(end);
                if count >= 2 {
                    return Ok(into_string_fast(buf));
                }
            }
            scan_from = buf.len();
            if count == 1 && start.elapsed() > Duration::from_millis(800) {
                return Ok(into_string_fast(buf));
            }
        }
    }

    /// Write `cmd` to the shell, append a sentinel echo of `$?`, read until sentinel observed.
    /// Returns `(output, exit_code)`.
    pub async fn run(
        &self,
        cmd: &str,
        deadline: Duration,
        max_capture: usize,
    ) -> Result<(String, i32)> {
        let token = format!("__DONE_{}__", self.session_id);
        let payload = format!("{cmd}\nprintf '\\n%s:%s\\n' {token} \"$?\"\n");
        self.write.data(payload.as_bytes()).await.map_err(SshError::from)?;
        let raw = self.drain_until_terminated(&token, deadline, max_capture).await?;
        let (output, code) = parse_sentinel(&raw, &token);
        Ok((output, code))
    }

    /// Variant that requires the sentinel to be the LAST line and followed by `:` and a number.
    /// Avoids false-positive where the shell echoes the `printf` line containing the token.
    async fn drain_until_terminated(
        &self,
        token: &str,
        deadline: Duration,
        max_capture: usize,
    ) -> Result<String> {
        let pattern = format!("\n{token}:");
        let pattern_bytes = pattern.as_bytes();
        let finder = memmem::Finder::new(pattern_bytes);
        let start = Instant::now();
        let mut buf = Vec::with_capacity(4096);
        let mut scan_from = 0usize;
        let mut last_match: Option<usize> = None;
        let mut read = self.read.lock().await;
        loop {
            let remaining = deadline.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                return Err(SshError::Timeout(deadline.as_millis() as u64));
            }
            let res = timeout(remaining, read.wait()).await;
            match res {
                Ok(Some(ChannelMsg::Data { data })) => append_capped(&mut buf, &data, max_capture),
                Ok(Some(ChannelMsg::ExtendedData { data, .. })) => append_capped(&mut buf, &data, max_capture),
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
                        return Ok(into_string_fast(buf));
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

/// Parse output that ends with `\n<token>:<n>\n[trailing]`. Returns body before token + exit code.
fn parse_sentinel(raw: &str, token: &str) -> (String, i32) {
    let needle = format!("\n{token}:");
    let idx = match raw.rfind(&needle) {
        Some(i) => i,
        None => return (raw.to_string(), -1),
    };
    let body = &raw[..idx];
    let rest = &raw[idx + needle.len()..];
    let exit_code: i32 = rest
        .split(['\n', '\r'])
        .next()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(-1);
    let cleaned = strip_trailing_newlines(body).to_string();
    (cleaned, exit_code)
}

fn strip_trailing_newlines(s: &str) -> &str {
    s.trim_end_matches(['\n', '\r'])
}

/// Random hex token. 64 bits of entropy is enough to make collision with user output unrealistic.
fn random_token(prefix: &str) -> String {
    let mut bytes = [0u8; 8];
    if getrandom::getrandom(&mut bytes).is_err() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        bytes = nanos.to_le_bytes();
    }
    format!("{prefix}{:016x}", u64::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sentinel() {
        let raw = "hello world\nsecond line\n__DONE_abc__:0\n";
        let (out, code) = parse_sentinel(raw, "__DONE_abc__");
        assert_eq!(out, "hello world\nsecond line");
        assert_eq!(code, 0);
    }

    #[test]
    fn parses_nonzero_exit() {
        let raw = "boom\n__DONE_x__:42\n";
        let (out, code) = parse_sentinel(raw, "__DONE_x__");
        assert_eq!(out, "boom");
        assert_eq!(code, 42);
    }

    #[test]
    fn handles_missing_sentinel() {
        let (out, code) = parse_sentinel("partial", "__DONE_x__");
        assert_eq!(out, "partial");
        assert_eq!(code, -1);
    }

    #[test]
    fn ignores_pty_echo_of_printf_line() {
        let raw = "user-cmd-output\nprintf '\\n%s:%s\\n' __DONE_x__ \"$?\"\nactual-stuff\n__DONE_x__:0\n";
        let (out, code) = parse_sentinel(raw, "__DONE_x__");
        assert_eq!(code, 0);
        assert!(out.ends_with("actual-stuff"), "got: {out:?}");
    }

    #[test]
    fn handles_crlf_pty_output() {
        let raw = "ok\r\n__DONE_x__:0\r\n";
        let (out, code) = parse_sentinel(raw, "__DONE_x__");
        assert_eq!(code, 0);
        assert!(out.contains("ok"));
    }

    #[test]
    fn random_token_is_unique() {
        let a = random_token("x");
        let b = random_token("x");
        assert_ne!(a, b);
        assert!(a.starts_with("x"));
    }

    #[test]
    fn append_capped_drops_overflow() {
        let mut buf = Vec::new();
        append_capped(&mut buf, b"hello", 10);
        append_capped(&mut buf, b"world!!!", 10);
        assert_eq!(buf, b"helloworld");
    }
}
