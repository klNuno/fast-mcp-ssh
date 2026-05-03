use std::time::{Duration, Instant};

use russh::ChannelMsg;
use tokio::time::timeout;

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
    let _permit = session.acquire_channel().await?;
    let mut channel = session
        .handle
        .channel_open_session()
        .await
        .map_err(SshError::from)?;
    channel.exec(true, cmd).await.map_err(SshError::from)?;

    let mut stdout = Vec::with_capacity(4096);
    let mut stderr = Vec::with_capacity(1024);
    let mut exit_code: Option<i32> = None;
    let mut timed_out = false;
    let mut capture_capped = false;

    loop {
        let res = timeout(
            deadline.saturating_sub(start.elapsed()).max(Duration::from_millis(1)),
            channel.wait(),
        )
        .await;
        let msg = match res {
            Ok(Some(m)) => m,
            Ok(None) => break,
            Err(_) => {
                timed_out = true;
                let _ = channel.close().await;
                break;
            }
        };
        match msg {
            ChannelMsg::Data { ref data } => append_capped(&mut stdout, data, max_capture, &mut capture_capped),
            ChannelMsg::ExtendedData { ref data, ext } => {
                if ext == 1 {
                    append_capped(&mut stderr, data, max_capture, &mut capture_capped);
                } else {
                    append_capped(&mut stdout, data, max_capture, &mut capture_capped);
                }
            }
            ChannelMsg::ExitStatus { exit_status } => {
                exit_code = Some(exit_status as i32);
            }
            ChannelMsg::Close => break,
            ChannelMsg::Eof => {
                if exit_code.is_some() {
                    break;
                }
            }
            _ => {}
        }
    }

    let stdout_bytes = stdout.len();
    let stderr_bytes = stderr.len();
    let duration_ms = start.elapsed().as_millis();
    session.touch();

    Ok(ExecResult {
        stdout: into_string_fast(stdout),
        stderr: into_string_fast(stderr),
        exit_code: exit_code.unwrap_or(if timed_out { 124 } else { -1 }),
        duration_ms,
        stdout_bytes,
        stderr_bytes,
        timed_out,
        capture_capped,
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
