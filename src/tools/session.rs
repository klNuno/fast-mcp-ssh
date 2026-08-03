//! Session-lifecycle tools: `disconnect`, `disconnect_all`, `reload`, `shells`.

use std::sync::Arc;

use rmcp::{
    ErrorData as McpError, handler::server::wrapper::Parameters, model::*, schemars, tool,
    tool_router,
};
use serde::Deserialize;

use crate::audit::AuditRecord;
use crate::config::Config;
use crate::errors::SshError;
use crate::guards::GuardCache;
use crate::output::Toon;
use crate::server::SshServer;
use crate::tools::{HostOnlyArgs, MAX_NAMED_PTYS, text};

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ShellsArgs {
    /// Host alias. Omit if a default_host is configured.
    #[serde(default)]
    pub host: Option<String>,
    /// Shell name to close. `*` closes every shell on the host, the default
    /// one included. Omit to only list.
    #[serde(default)]
    pub close: Option<String>,
}

#[tool_router(router = session_router, vis = "pub")]
impl SshServer {
    #[tool(
        description = "Close persistent SSH session and drop cached PTY. Reopens on next call. Use to free server slot or after credential changes. Not for Ctrl-C — use interrupt.",
        annotations(
            title = "Disconnect",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn disconnect(
        &self,
        Parameters(args): Parameters<HostOnlyArgs>,
    ) -> Result<CallToolResult, McpError> {
        let host_name = self.resolve_host(args.host)?;
        // Take the cached session out of the pool first so any new tool call
        // reconnects on its own. Then send a real SSH disconnect on the handle
        // so the server tears down channels even if another in-flight tool
        // still holds an Arc<Session> clone — without this, the TCP+SSH stays
        // alive for that other call.
        let removed = self.pool.take_session(&host_name);
        if let Some(sess) = removed {
            tracing::info!(host = %host_name, "closing session");
            let _ = sess
                .handle
                .disconnect(russh::Disconnect::ByApplication, "user requested", "")
                .await;
        }
        self.pool.forget_password(&host_name);
        self.audit
            .write(&host_name, "disconnect", AuditRecord::default());
        let mut t = Toon::new();
        t.field("host", &host_name).field("status", "closed");
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "Re-read the config file from disk. Validates, swaps guards atomically, drops sessions for hosts that were removed or whose connection params changed. Returns the diff.",
        annotations(
            title = "Reload",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn reload(&self) -> Result<CallToolResult, McpError> {
        // Config parse (fs + TOML + ~/.ssh/config import) and guard regex
        // compilation are CPU/disk work; offload so in-flight calls on the
        // single-threaded runtime don't stall behind a reload.
        let path = self.config_path.clone();
        let loaded = tokio::task::spawn_blocking(move || {
            let cfg = Config::load(&path)?;
            let guards = GuardCache::build(&cfg)?;
            Ok::<_, SshError>((cfg, guards))
        })
        .await
        .map_err(|e| SshError::Other(format!("reload task: {e}")))
        .and_then(|r| r);
        let (new_cfg, new_guards) = match loaded {
            Ok(v) => v,
            Err(e) => {
                let msg = e.to_string();
                self.audit.write(
                    "*",
                    "reload",
                    AuditRecord {
                        error: Some(msg.clone()),
                        ..Default::default()
                    },
                );
                return Err(e.into_mcp());
            }
        };
        let old_cfg = self.cfg();
        // Swap config + guards atomically. After this, the SessionPool sees
        // the new config too (shared ArcSwap).
        self.cfg_swap.store(Arc::new(new_cfg));
        self.guards_swap.store(Arc::new(new_guards));
        // Approvals were granted against the previous guard set and the
        // previous host list. Neither is in force any more.
        self.forget_confirmations();
        let dropped = self.pool.prune_against(&old_cfg).await;

        let new = self.cfg();
        self.audit.write("*", "reload", AuditRecord::default());
        let mut t = Toon::new();
        t.field("hosts_before", old_cfg.hosts.len());
        t.field("hosts_after", new.hosts.len());
        t.field("sessions_dropped", dropped.len() as u64);
        if !dropped.is_empty() {
            t.field("dropped", dropped.join(","));
        }
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "Close all live SSH sessions. Reopens on next call. Use to free server slots or after credential changes.",
        annotations(
            title = "DisconnectAll",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn disconnect_all(&self) -> Result<CallToolResult, McpError> {
        let names = self.pool.list_active();
        let mut closed = 0u64;
        for name in &names {
            if let Some(sess) = self.pool.take_session(name) {
                let _ = sess
                    .handle
                    .disconnect(russh::Disconnect::ByApplication, "user requested", "")
                    .await;
                self.pool.forget_password(name);
                closed += 1;
            }
        }
        self.audit
            .write("*", "disconnect_all", AuditRecord::default());
        let mut t = Toon::new();
        t.field("closed", closed);
        if !names.is_empty() {
            let joined = names.join(",");
            t.field("hosts", joined);
        }
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "List the persistent PTY shells open on a host, or close one with close=<name> (close=* closes all). Each shell holds an SSH channel slot until closed. Not for killing a running command — use interrupt.",
        annotations(
            title = "Shells",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn shells(
        &self,
        Parameters(args): Parameters<ShellsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let host_name = self.resolve_host(args.host)?;
        let mut t = Toon::new();
        t.field("host", &host_name);
        let Some(session) = self.pool.get(&host_name) else {
            t.field("status", "no active session");
            return Ok(text(t.into_string()));
        };

        if let Some(target) = args.close.as_deref() {
            let closed = if target == "*" {
                session.close_all_ptys().await
            } else {
                usize::from(session.close_pty(Some(target)).await)
            };
            self.audit
                .write(&host_name, "shells", AuditRecord::cmd(target));
            t.field("closed", closed);
            if closed == 0 {
                t.hint("no shell by that name; `shells` with no argument lists them");
            }
        }

        let named = session.named_shells().await;
        t.field("named_count", named.len());
        t.field("named_max", MAX_NAMED_PTYS);
        if !named.is_empty() {
            t.field("named", named.join(","));
        }
        Ok(text(t.into_string()))
    }
}
