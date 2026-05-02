use std::time::{Duration, Instant};

use russh::{Channel, ChannelMsg};
use russh::client::Msg;
use tokio::sync::Mutex;
use tokio::time::timeout;

use crate::errors::{Result, SshError};
use crate::session::Session;

const PTY_TERM: &str = "xterm-256color";
const PTY_COLS: u32 = 200;
const PTY_ROWS: u32 = 50;

/// PTY-backed shell where `cd` / `export` persist between calls.
/// We trade JSON simplicity for shell statefulness — sentinel is appended after each command.
pub struct PtyState {
    pub channel: Mutex<Channel<Msg>>,
    pub session_id: String,
    pub last_used: Mutex<Instant>,
}

impl PtyState {
    pub async fn open(session: &Session) -> Result<Self> {
        let chan = session
            .handle
            .channel_open_session()
            .await
            .map_err(SshError::from)?;
        chan.request_pty(true, PTY_TERM, PTY_COLS, PTY_ROWS, 0, 0, &[])
            .await
            .map_err(SshError::from)?;
        chan.request_shell(true).await.map_err(SshError::from)?;

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let session_id = format!("rdy{nanos:x}");

        // Disable terminal echo so user commands aren't echoed back into the captured output.
        // Disable bracketed-paste escapes (readline emits \e[?2004h around input). Clear prompts.
        // Then emit the readiness sentinel.
        let init = format!(
            "stty -echo -onlcr 2>/dev/null\n\
             bind 'set enable-bracketed-paste off' 2>/dev/null\n\
             export PS1='' PS2='' PROMPT_COMMAND=''\n\
             echo __INIT_{session_id}__\n"
        );
        chan.data(init.as_bytes()).await.map_err(SshError::from)?;
        let pty = Self {
            channel: Mutex::new(chan),
            session_id: session_id.clone(),
            last_used: Mutex::new(Instant::now()),
        };
        let init_marker = format!("__INIT_{session_id}__");
        let _ = pty
            .drain_until_two(&init_marker, Duration::from_secs(15))
            .await?;
        Ok(pty)
    }

    /// Drain until we see the sentinel **twice** — once is the shell echo of the line we sent,
    /// the second is the actual `echo` output. After the second we're certain the shell is
    /// ready and any login banner has flushed.
    async fn drain_until_two(&self, sentinel: &str, deadline: Duration) -> Result<String> {
        let start = Instant::now();
        let mut buf = Vec::with_capacity(4096);
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
            let mut ch = self.channel.lock().await;
            let res = timeout(remaining.min(Duration::from_millis(250)), ch.wait()).await;
            match res {
                Ok(Some(ChannelMsg::Data { data })) => buf.extend_from_slice(&data),
                Ok(Some(ChannelMsg::ExtendedData { data, .. })) => buf.extend_from_slice(&data),
                Ok(Some(ChannelMsg::Eof)) | Ok(Some(ChannelMsg::Close)) | Ok(None) => {
                    return Err(SshError::Other("PTY closed unexpectedly during init".into()));
                }
                Ok(Some(_)) => {}
                Err(_) => {
                    // Inner timeout — fine, just loop and re-check overall deadline.
                }
            }
            drop(ch);
            let s = String::from_utf8_lossy(&buf);
            let count = s.matches(sentinel).count();
            tracing::trace!(count, bytes = buf.len(), "PTY init drain progress");
            if count >= 2 {
                return Ok(s.into_owned());
            }
            if count == 1 && start.elapsed() > Duration::from_millis(800) {
                return Ok(s.into_owned());
            }
        }
    }

    /// Write `cmd` to the shell, append a sentinel echo of `$?`, read until sentinel observed.
    /// Returns `(output, exit_code)`.
    pub async fn run(&self, cmd: &str, deadline: Duration) -> Result<(String, i32)> {
        let token = format!("__DONE_{}__", self.session_id);
        // We use a marker pattern that is unlikely to appear in user output. The shell will echo
        // the printf line back if its terminal echo is enabled — `parse_sentinel` finds the LAST
        // occurrence (the actual printed marker), so the echo is naturally discarded.
        let payload = format!("{cmd}\nprintf '\\n%s:%s\\n' {token} \"$?\"\n");
        {
            let ch = self.channel.lock().await;
            ch.data(payload.as_bytes()).await.map_err(SshError::from)?;
        }
        let raw = self.drain_until_terminated(&token, deadline).await?;
        *self.last_used.lock().await = Instant::now();
        let (output, code) = parse_sentinel(&raw, &token);
        Ok((output, code))
    }

    /// Variant that requires the sentinel to be the LAST line and followed by `:` and a number.
    /// Avoids the false-positive where the shell echoes the `printf` line containing the token.
    async fn drain_until_terminated(&self, token: &str, deadline: Duration) -> Result<String> {
        let pattern = format!("\n{token}:");
        let start = Instant::now();
        let mut buf = Vec::with_capacity(4096);
        loop {
            let remaining = deadline.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                return Err(SshError::Timeout(deadline.as_millis() as u64));
            }
            let mut ch = self.channel.lock().await;
            let res = timeout(remaining, ch.wait()).await;
            match res {
                Ok(Some(ChannelMsg::Data { data })) => buf.extend_from_slice(&data),
                Ok(Some(ChannelMsg::ExtendedData { data, .. })) => buf.extend_from_slice(&data),
                Ok(Some(ChannelMsg::Eof)) | Ok(Some(ChannelMsg::Close)) | Ok(None) => {
                    return Err(SshError::Other("PTY closed unexpectedly".into()));
                }
                Ok(Some(_)) => {}
                Err(_) => return Err(SshError::Timeout(deadline.as_millis() as u64)),
            }
            drop(ch);
            let s = String::from_utf8_lossy(&buf);
            if let Some(pos) = s.rfind(&pattern) {
                let tail_start = pos + pattern.len();
                if let Some(nl_off) = s[tail_start..].find('\n') {
                    let candidate = s[tail_start..tail_start + nl_off].trim_end_matches('\r');
                    if !candidate.is_empty() && candidate.chars().all(|c| c.is_ascii_digit()) {
                        return Ok(s.into_owned());
                    }
                }
            }
        }
    }

}

/// Parse output that ends with `\n<token>:<n>\n[trailing]`. Returns body before token + exit code.
fn parse_sentinel(raw: &str, token: &str) -> (String, i32) {
    // Find the LAST `\n<token>:` — earlier occurrences are PTY echoes of the printf command line.
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
        // Bash echoes the printf command (which contains the literal token), then runs it.
        // We must use the LAST occurrence as the real sentinel.
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
}
