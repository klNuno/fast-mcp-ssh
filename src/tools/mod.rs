//! MCP tool implementations, split by domain. Each submodule declares its own
//! `#[tool_router]` block on `SshServer`; `SshServer::tool_router` sums them.

use std::time::Duration;

use rmcp::{ErrorData as McpError, model::*, schemars};
use serde::Deserialize;

use crate::config::AuthMethod;
use crate::errors::SshError;
use crate::session::exec;

pub mod discovery;
pub mod files;
pub mod net;
pub mod ops;
pub mod run;
pub mod session;
pub mod visual;

pub(crate) const DEFAULT_TIMEOUT: u64 = 60;
/// Hard cap on per-call timeouts. Prevents an AI-supplied `timeout=u64::MAX`
/// from holding a channel slot indefinitely.
pub(crate) const MAX_TIMEOUT_SECS: u64 = 600;
pub(crate) const MAX_FOLLOW_SECS: u64 = 600;
pub(crate) const INLINE_MAX_BYTES: usize = 256 * 1024;
/// Hard cap on a single command string. Refuses oversize inputs before they
/// reach the SSH channel.
pub(crate) const MAX_CMD_BYTES: usize = 64 * 1024;
/// Hard cap on `exec_batch` fan-out. Past this an AI is almost certainly
/// looping when it should be using a script.
pub(crate) const MAX_BATCH_CMDS: usize = 64;
/// Hard cap on inline `wr` content. Larger files should go through `up`.
pub(crate) const MAX_WRITE_INLINE_BYTES: usize = 8 * 1024 * 1024;
/// Cap on a single SFTP listing returned in one call. Pagination via
/// `offset` lets the AI walk past it.
pub(crate) const MAX_LS_ENTRIES: usize = 1000;

pub(crate) fn clamp_timeout(t: Option<u64>) -> Duration {
    Duration::from_secs(t.unwrap_or(DEFAULT_TIMEOUT).clamp(1, MAX_TIMEOUT_SECS))
}

pub(crate) fn validate_cmd(cmd: &str) -> Result<(), McpError> {
    if cmd.len() > MAX_CMD_BYTES {
        return Err(SshError::Config(format!(
            "cmd too large: {} bytes (max {})",
            cmd.len(),
            MAX_CMD_BYTES
        ))
        .into_mcp());
    }
    Ok(())
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct HostOnlyArgs {
    /// Host alias. Omit if a default_host is configured.
    #[serde(default)]
    pub host: Option<String>,
}

pub(crate) fn auth_str(a: AuthMethod) -> &'static str {
    match a {
        AuthMethod::Key => "key",
        AuthMethod::Agent => "agent",
        AuthMethod::Password => "password",
    }
}

pub(crate) fn text(s: String) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(s)])
}

impl crate::server::SshServer {
    /// Re-run the remote path guard against what the path actually resolves to
    /// server-side. SFTP follows symlinks, so `ln -s /etc/shadow /tmp/s` would
    /// otherwise launder a blocked read through a harmless-looking string.
    /// Costs one FXP_REALPATH on the already-open SFTP channel.
    pub(crate) async fn guard_resolved(
        &self,
        host: &str,
        tool: &'static str,
        session: &crate::session::Session,
        path: &str,
        write: bool,
    ) -> Result<(), McpError> {
        let resolved = match crate::sftp::resolve_path(session, path).await {
            Ok(p) => p,
            // A path that cannot be resolved at all is left to the operation
            // itself to fail on; the string guard already ran.
            Err(_) => return Ok(()),
        };
        if resolved == path {
            return Ok(());
        }
        let guards = self.guards().for_host(host);
        let verdict = if write {
            guards.check_sftp_write(&resolved)
        } else {
            guards.check_sftp_read(&resolved)
        };
        if let Err(e) = verdict {
            let msg = format!("{path} resolves to {resolved}: {e}");
            self.audit.write(
                host,
                tool,
                Some(path),
                None,
                None,
                None,
                None,
                Some(&msg),
                Some(msg.clone()),
            );
            return Err(SshError::BlockedByGuard {
                name: "resolved-path".into(),
                pattern: msg,
            }
            .into_mcp());
        }
        Ok(())
    }
}

pub(crate) fn batch_preview(r: &exec::ExecResult, verbose: bool) -> String {
    let (src, max) = if r.exit_code != 0 {
        let stderr_trimmed = r.stderr.trim();
        let s: &str = if !stderr_trimmed.is_empty() {
            stderr_trimmed
        } else {
            r.stdout.as_str()
        };
        (s, 200)
    } else if verbose {
        (r.stdout.as_str(), 200)
    } else {
        (r.stdout.as_str(), 40)
    };
    let mut end = max.min(src.len());
    while end < src.len() && !src.is_char_boundary(end) {
        end -= 1;
    }
    src[..end].replace('\n', " ")
}
