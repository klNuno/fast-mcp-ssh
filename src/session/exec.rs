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
}

/// Run `cmd` over a fresh exec channel on the persistent SSH handle. `cmd` is passed verbatim
/// to the remote login shell (russh handles bash -c invocation server-side).
pub async fn exec(session: &Session, cmd: &str, deadline: Duration) -> Result<ExecResult> {
    let start = Instant::now();
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
            ChannelMsg::Data { ref data } => stdout.extend_from_slice(data),
            ChannelMsg::ExtendedData { ref data, ext } => {
                if ext == 1 {
                    stderr.extend_from_slice(data);
                } else {
                    stdout.extend_from_slice(data);
                }
            }
            ChannelMsg::ExitStatus { exit_status } => {
                exit_code = Some(exit_status as i32);
            }
            ChannelMsg::Close => break,
            ChannelMsg::Eof => {
                // Eof can arrive before ExitStatus on some servers — keep draining.
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
    session.touch().await;

    Ok(ExecResult {
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        exit_code: exit_code.unwrap_or(if timed_out { 124 } else { -1 }),
        duration_ms,
        stdout_bytes,
        stderr_bytes,
        timed_out,
    })
}
