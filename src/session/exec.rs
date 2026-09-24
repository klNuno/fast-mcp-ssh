use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use russh::ChannelMsg;
use tokio::sync::Notify;
use tokio::time::{Instant as TokioInstant, sleep_until};

use crate::errors::{Result, SshError};
use crate::session::{ChannelLease, ExecSlot, Session};

/// How long to wait for the server's `Close` once the command has exited and
/// its output ended. OpenSSH sends it right behind `Eof`; this only bounds a
/// server that never does.
const CLOSE_GRACE: Duration = Duration::from_millis(250);

/// How much of a stream's end is kept once its head has filled `max_capture`.
/// Covers half of any `truncate_bytes` up to 128 KiB, which is the share of
/// the display `head_tail` gives to the end.
const TAIL_KEEP: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct ExecResult {
    /// Start of stdout, up to `max_capture` bytes.
    pub stdout: String,
    /// End of stdout past `stdout`, at most `TAIL_KEEP` bytes. Empty unless
    /// capture was capped. Bytes between the two were never kept when
    /// `stdout_bytes > stdout.len() + stdout_tail.len()`.
    pub stdout_tail: String,
    pub stderr: String,
    pub stderr_tail: String,
    pub exit_code: i32,
    pub duration_ms: u128,
    /// Every byte the channel carried, kept or not.
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    pub timed_out: bool,
    /// True if capture stopped at `max_capture` before EOF.
    pub capture_capped: bool,
    /// True if the channel closed without delivering an `ExitStatus`. Caller
    /// should not conflate the resulting `exit_code = -1` with a process that
    /// genuinely exited with -1. Common cause: server-side abrupt hangup.
    pub connection_lost: bool,
    /// True if `interrupt` aborted this call before the remote process exited.
    pub interrupted: bool,
}

/// Run `cmd` over a fresh exec channel on the persistent SSH handle. `cmd` is passed verbatim
/// to the remote login shell (russh handles bash -c invocation server-side).
///
/// `max_capture` bounds the in-memory stdout/stderr buffer. Once exceeded, further data is
/// dropped (channel kept open until exit so the remote process isn't SIGPIPE-killed prematurely
/// on small overruns).
pub async fn exec(
    session: &Session,
    cmd: &str,
    deadline: Duration,
    max_capture: usize,
) -> Result<ExecResult> {
    // Grab a pre-opened channel from the per-session pool when one is
    // ready. Otherwise open a fresh session channel. Either way we hold
    // the matching semaphore permit until exec completes.
    let (channel, permit, from_pool) = session.take_or_open_channel().await?;
    exec_leased(
        ChannelLease {
            session,
            channel,
            permit,
            from_pool,
        },
        cmd,
        deadline,
        max_capture,
    )
    .await
}

/// `exec` on a channel `SessionPool::exec_channel` picked for this call.
pub async fn exec_on_slot(
    slot: ExecSlot,
    cmd: &str,
    deadline: Duration,
    max_capture: usize,
) -> Result<ExecResult> {
    let ExecSlot {
        session,
        channel,
        permit,
        from_pool,
    } = slot;
    exec_leased(
        ChannelLease {
            session: &session,
            channel,
            permit,
            from_pool,
        },
        cmd,
        deadline,
        max_capture,
    )
    .await
}

/// `exec` on a channel the caller already holds, typically one
/// `SessionPool::exec_channel` found on whichever of the host's connections
/// had a slot free. The lease's permit is held until the command finishes.
pub async fn exec_leased(
    lease: ChannelLease<'_>,
    cmd: &str,
    deadline: Duration,
    max_capture: usize,
) -> Result<ExecResult> {
    let ChannelLease {
        session,
        channel,
        permit: _permit,
        from_pool,
    } = lease;
    let first = exec_on_channel(session, channel, cmd, deadline, max_capture).await;
    // A parked channel can have been closed server-side while it waited in
    // the pool (sshd restart, channel timeout). That shows up as an instant
    // close with zero output and no ExitStatus — the exec request never ran.
    // Retry once on a fresh channel instead of failing the whole tool call.
    // Only when nothing was received: any data or exit status means the
    // command may have run, and re-running it would not be idempotent-safe.
    let retry = match &first {
        Ok(r) => {
            from_pool
                && r.connection_lost
                && r.stdout_bytes == 0
                && r.stderr_bytes == 0
                && !r.timed_out
                && !r.interrupted
        }
        Err(_) => from_pool,
    };
    if !retry {
        return first;
    }
    tracing::debug!("pooled channel was stale; retrying exec on a fresh channel");
    let channel = session.open_session_channel().await?;
    exec_on_channel(session, channel, cmd, deadline, max_capture).await
}

async fn exec_on_channel(
    session: &Session,
    mut channel: russh::Channel<russh::client::Msg>,
    cmd: &str,
    deadline: Duration,
    max_capture: usize,
) -> Result<ExecResult> {
    let start = Instant::now();
    // want_reply=false: do not wait for the SSH SUCCESS reply before
    // reading. Saves ~1 RTT per warm exec call. If the exec request fails
    // server-side we'll see Eof/Close immediately and the existing
    // `connection_lost` path takes over.
    channel.exec(false, cmd).await.map_err(SshError::from)?;

    // Bumping initial capacity from 4 KiB cuts 1-2 reallocs on typical
    // multi-KB exec output (e.g. `ls -laR`). 16 KiB is bounded by `max_capture`.
    let mut stdout = Capture::new(max_capture, 16 * 1024);
    let mut stderr = Capture::new(max_capture, 2 * 1024);
    let mut exit_code: Option<i32> = None;
    let mut timed_out = false;
    let mut interrupted = false;

    // Register cancel notify so `interrupt` can abort this call without
    // disconnecting the session.
    let cancel = Arc::new(Notify::new());
    let cancel_id = session.register_exec(Arc::clone(&cancel)).await;

    // Single Sleep registered for the whole exec; reused via Pin across
    // iterations to avoid the per-message timer-registration overhead of
    // wrapping `channel.wait()` in `tokio::time::timeout`.
    let sleep = sleep_until(TokioInstant::now() + deadline);
    tokio::pin!(sleep);

    let mut close_seen = false;
    // Set once the command has exited and its output ended: the loop then
    // only waits for the server's `Close`, bounded by `CLOSE_GRACE`.
    let mut closing = false;
    loop {
        tokio::select! {
            biased;
            _ = cancel.notified() => {
                interrupted = true;
                let _ = channel.close().await;
                break;
            }
            _ = &mut sleep => {
                if closing {
                    break;
                }
                timed_out = true;
                let _ = channel.close().await;
                break;
            }
            msg = channel.wait() => {
                match msg {
                    None => break,
                    Some(ChannelMsg::Data { ref data }) => stdout.push(data),
                    Some(ChannelMsg::ExtendedData { ref data, ext }) => {
                        if ext == 1 {
                            stderr.push(data);
                        } else {
                            stdout.push(data);
                        }
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        exit_code = Some(exit_status as i32);
                        if close_seen { break; }
                    }
                    Some(ChannelMsg::Close) => {
                        close_seen = true;
                        if exit_code.is_some() { break; }
                    }
                    Some(ChannelMsg::Eof) => {
                        // Not done yet: sshd still counts this channel against
                        // `MaxSessions` until it has sent `Close`, and the
                        // permit goes back when this returns. Releasing it at
                        // `Eof` let a burst open an 11th channel and sshd
                        // refused it ("no more sessions").
                        if exit_code.is_some() && !closing {
                            closing = true;
                            sleep.as_mut().reset(TokioInstant::now() + CLOSE_GRACE);
                        }
                    }
                    Some(_) => {}
                }
            }
        }
    }
    let connection_lost = close_seen && exit_code.is_none();

    let capture_capped = stdout.capped() || stderr.capped();
    let duration_ms = start.elapsed().as_millis();
    session.touch();
    session.deregister_exec(cancel_id).await;

    let final_exit = exit_code.unwrap_or(if interrupted {
        130 // 128 + SIGINT
    } else if timed_out {
        124
    } else {
        -1
    });

    let (stdout, stdout_tail, stdout_bytes) = stdout.finish();
    let (stderr, stderr_tail, stderr_bytes) = stderr.finish();
    Ok(ExecResult {
        stdout,
        stdout_tail,
        stderr,
        stderr_tail,
        exit_code: final_exit,
        duration_ms,
        stdout_bytes,
        stderr_bytes,
        timed_out,
        capture_capped,
        connection_lost,
        interrupted,
    })
}

/// One output stream: its first `max` bytes, a rolling window over its last
/// `TAIL_KEEP` bytes once the head is full, and a count of everything seen.
/// Memory stays bounded however much the command prints, and the end of the
/// output, where errors usually are, survives the cap.
struct Capture {
    head: Vec<u8>,
    tail: VecDeque<u8>,
    total: usize,
    max: usize,
}

impl Capture {
    fn new(max: usize, initial: usize) -> Self {
        Self {
            head: Vec::with_capacity(max.min(initial)),
            tail: VecDeque::new(),
            total: 0,
            max,
        }
    }

    fn push(&mut self, data: &[u8]) {
        self.total += data.len();
        let room = self.max.saturating_sub(self.head.len());
        let (to_head, rest) = data.split_at(data.len().min(room));
        self.head.extend_from_slice(to_head);
        if rest.is_empty() {
            return;
        }
        let keep = TAIL_KEEP.min(self.max.max(1));
        let rest = &rest[rest.len().saturating_sub(keep)..];
        let overflow = (self.tail.len() + rest.len()).saturating_sub(keep);
        self.tail.drain(..overflow);
        self.tail.extend(rest);
    }

    fn capped(&self) -> bool {
        self.total > self.head.len()
    }

    fn finish(self) -> (String, String, usize) {
        let mut tail = Vec::from(self.tail);
        // The window slides over bytes, so it can start inside a UTF-8
        // sequence. Drop the orphaned continuation bytes rather than print
        // a replacement character that is not in the output.
        let skip = tail
            .iter()
            .take(3)
            .take_while(|b| (**b & 0xC0) == 0x80)
            .count();
        tail.drain(..skip);
        (
            into_string_fast(self.head),
            into_string_fast(tail),
            self.total,
        )
    }
}

/// Avoid an extra alloc when bytes are already valid UTF-8 (the common case).
fn into_string_fast(bytes: Vec<u8>) -> String {
    match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_counts_past_the_cap_and_keeps_the_end() {
        let mut c = Capture::new(10, 4);
        c.push(b"0123456789abc");
        c.push(&[b'x'; 100_000]);
        c.push(b"END");
        assert!(c.capped());
        let (head, tail, total) = c.finish();
        assert_eq!(head, "0123456789");
        assert_eq!(total, 13 + 100_000 + 3);
        // The window is bounded by `max`, so here it holds the last 10 bytes.
        assert_eq!(tail, "xxxxxxxEND");
    }

    #[test]
    fn capture_under_the_cap_has_no_tail() {
        let mut c = Capture::new(100, 16);
        c.push(b"hello");
        assert!(!c.capped());
        let (head, tail, total) = c.finish();
        assert_eq!((head.as_str(), tail.as_str(), total), ("hello", "", 5));
    }

    #[test]
    fn capture_tail_drops_a_split_utf8_sequence() {
        let mut c = Capture::new(3, 4);
        c.push(b"abc");
        // 'é' is C3 A9; the 3-byte window over "xéyz" starts on A9.
        c.push("xéyz".as_bytes());
        let (_, tail, _) = c.finish();
        assert_eq!(tail, "yz");
    }
}
