use std::sync::Arc;
use std::time::{Duration, Instant};

use russh::ChannelMsg;
use tokio::sync::Notify;
use tokio::time::{Instant as TokioInstant, sleep_until};

use crate::errors::{Result, SshError};
use crate::session::Session;

#[derive(Debug, Clone)]
pub struct ExecResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration_ms: u128,
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
    let start = Instant::now();
    // Grab a pre-opened channel from the per-session pool when one is
    // ready. Otherwise open a fresh session channel. Either way we hold
    // the matching semaphore permit until exec completes.
    let (mut channel, _permit) = session.take_or_open_channel().await?;
    // want_reply=false: do not wait for the SSH SUCCESS reply before
    // reading. Saves ~1 RTT per warm exec call. If the exec request fails
    // server-side we'll see Eof/Close immediately and the existing
    // `connection_lost` path takes over.
    channel.exec(false, cmd).await.map_err(SshError::from)?;

    // Bumping initial capacity from 4 KiB cuts 1-2 reallocs on typical
    // multi-KB exec output (e.g. `ls -laR`). 16 KiB is bounded by `max_capture`.
    let stdout_cap = max_capture.min(16 * 1024);
    let stderr_cap = max_capture.min(2 * 1024);
    let mut stdout = Vec::with_capacity(stdout_cap);
    let mut stderr = Vec::with_capacity(stderr_cap);
    let mut exit_code: Option<i32> = None;
    let mut timed_out = false;
    let mut capture_capped = false;
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
    loop {
        tokio::select! {
            biased;
            _ = cancel.notified() => {
                interrupted = true;
                let _ = channel.close().await;
                break;
            }
            _ = &mut sleep => {
                timed_out = true;
                let _ = channel.close().await;
                break;
            }
            msg = channel.wait() => {
                match msg {
                    None => break,
                    Some(ChannelMsg::Data { ref data }) => append_capped(&mut stdout, data, max_capture, &mut capture_capped),
                    Some(ChannelMsg::ExtendedData { ref data, ext }) => {
                        if ext == 1 {
                            append_capped(&mut stderr, data, max_capture, &mut capture_capped);
                        } else {
                            append_capped(&mut stdout, data, max_capture, &mut capture_capped);
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
                        if exit_code.is_some() { break; }
                    }
                    Some(_) => {}
                }
            }
        }
    }
    let connection_lost = close_seen && exit_code.is_none();

    let stdout_bytes = stdout.len();
    let stderr_bytes = stderr.len();
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

    Ok(ExecResult {
        stdout: into_string_fast(stdout),
        stderr: into_string_fast(stderr),
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

fn append_capped(buf: &mut Vec<u8>, data: &[u8], max: usize, capped: &mut bool) {
    if buf.len() >= max {
        *capped = true;
        return;
    }
    let room = max - buf.len();
    if data.len() <= room {
        buf.extend_from_slice(data);
    } else {
        buf.extend_from_slice(&data[..room]);
        *capped = true;
    }
}

/// Avoid an extra alloc when bytes are already valid UTF-8 (the common case).
fn into_string_fast(bytes: Vec<u8>) -> String {
    match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    }
}
