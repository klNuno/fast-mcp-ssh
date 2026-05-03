use std::time::Duration;

use crate::errors::Result;
use crate::session::{Session, exec::exec};

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
    let path_q = shell_escape(path);
    let cmd = if follow {
        format!(
            "timeout {sec} tail -n {lines} -F {path_q} 2>/dev/null; true",
            sec = max_wait.as_secs().max(1)
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

fn shell_escape(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-'))
    {
        s.to_string()
    } else {
        let mut out = String::with_capacity(s.len() + 4);
        out.push('\'');
        for c in s.chars() {
            if c == '\'' {
                out.push_str("'\\''");
            } else {
                out.push(c);
            }
        }
        out.push('\'');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_simple() {
        assert_eq!(shell_escape("/var/log/syslog"), "/var/log/syslog");
    }

    #[test]
    fn escape_complex() {
        assert_eq!(shell_escape("/tmp/has space.log"), "'/tmp/has space.log'");
        assert_eq!(shell_escape("o'brien.log"), "'o'\\''brien.log'");
    }
}
