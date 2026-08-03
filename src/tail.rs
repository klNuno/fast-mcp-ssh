use std::time::Duration;

use crate::errors::Result;
use crate::session::{Session, exec::exec};
use crate::tools::shell_quote;

pub struct TailChunk {
    pub content: String,
    pub bytes: usize,
    pub exit_code: i32,
}

/// Read the last `lines` lines of `path`. If `follow=false` we just `tail -n`.
/// If `follow=true` we use `tail -F -n <lines>` capped at `max_wait`.
pub async fn tail(
    session: &Session,
    path: &str,
    lines: u32,
    follow: bool,
    max_wait: Duration,
    max_capture: usize,
) -> Result<TailChunk> {
    let path_q = shell_quote(path);
    let cmd = if follow {
        // Piping through `head -c` makes the call return as soon as the
        // capture cap is hit instead of sitting out the full `timeout` window
        // (and shipping bytes that would be dropped anyway): head exits at the
        // cap, tail dies on SIGPIPE, the pipeline completes immediately.
        // `2>&1` routes tail warnings (missing file, rotation) into the
        // captured output since the pipeline exit code is head's (0).
        format!(
            "timeout {sec} tail -n {lines} -F {path_q} 2>&1 | head -c {cap}",
            sec = max_wait.as_secs().max(1),
            cap = max_capture
        )
    } else {
        format!("tail -n {lines} {path_q}")
    };
    let res = exec(
        session,
        &cmd,
        max_wait + Duration::from_secs(if follow { 5 } else { 10 }),
        max_capture,
    )
    .await?;
    Ok(TailChunk {
        content: res.stdout,
        bytes: res.stdout_bytes,
        exit_code: res.exit_code,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_go_through_the_shared_quoter() {
        // This module used to carry its own escaper with a "looks safe, skip
        // the quotes" fast path. One quoter, one behaviour.
        assert_eq!(shell_quote("/var/log/syslog"), "'/var/log/syslog'");
        assert_eq!(shell_quote("/tmp/has space.log"), "'/tmp/has space.log'");
        assert_eq!(shell_quote("o'brien.log"), "'o'\\''brien.log'");
    }
}
