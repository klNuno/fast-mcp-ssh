use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

/// Cap on the remembered-approval map. Reached only by a pathological caller.
const MAX_REMEMBERED_CONFIRMATIONS: usize = 512;

use arc_swap::ArcSwap;
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler, elicit_safe,
    handler::server::router::tool::ToolRouter,
    model::*,
    schemars,
    service::{ElicitationError, RequestContext},
    tool_handler,
};
use serde::{Deserialize, Serialize};

use crate::audit::AuditLog;
use crate::config::Config;
use crate::errors::SshError;
use crate::forward::ForwardHandle;
use crate::guards::{GuardCache, GuardCheck};
use crate::session::{Session, SessionPool, pty};

#[derive(Clone)]
pub struct SshServer {
    pub cfg_swap: Arc<ArcSwap<Config>>,
    pub pool: SessionPool,
    pub audit: Arc<AuditLog>,
    pub guards_swap: Arc<ArcSwap<GuardCache>>,
    /// Path used for `reload` so the tool re-reads from the same file the
    /// server started with.
    pub config_path: PathBuf,
    /// Active local→remote port forwards keyed by local port.
    pub forwards: Arc<dashmap::DashMap<u16, ForwardHandle>>,
    /// Commands the user approved through an elicitation, keyed by
    /// `(host, exact command)` and stamped with the approval instant. Only
    /// the server writes here; a caller-supplied "already confirmed" flag
    /// would let the model waive its own confirmation prompts.
    confirmations: Arc<dashmap::DashMap<(String, String), Instant>>,
    /// Per-host profile from the `facts` probe. Read by every tool that has to
    /// pick a backend, so the probe runs once per host per session instead of
    /// once per decision.
    pub(crate) facts_cache: Arc<dashmap::DashMap<String, crate::tools::ops::HostFacts>>,
    /// Built once in `new()` and read by the `#[tool_handler]` router
    /// expression. Rebuilding it per `tools/list` walked every tool's schema
    /// on a hot path for nothing.
    tool_router: ToolRouter<SshServer>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConfirmElicit {
    /// Type "yes" to proceed.
    pub answer: String,
}

elicit_safe!(ConfirmElicit);

impl SshServer {
    pub fn new(
        cfg_swap: Arc<ArcSwap<Config>>,
        pool: SessionPool,
        audit: Arc<AuditLog>,
        guards_swap: Arc<ArcSwap<GuardCache>>,
        config_path: PathBuf,
    ) -> Self {
        Self {
            cfg_swap,
            pool,
            audit,
            guards_swap,
            config_path,
            forwards: Arc::new(dashmap::DashMap::new()),
            confirmations: Arc::new(dashmap::DashMap::new()),
            facts_cache: Arc::new(dashmap::DashMap::new()),
            tool_router: Self::build_tool_router(),
        }
    }

    /// Sum of every per-domain router declared under `crate::tools`.
    fn build_tool_router() -> ToolRouter<SshServer> {
        Self::discovery_router()
            + Self::run_router()
            + Self::files_router()
            + Self::net_router()
            + Self::session_router()
            + Self::ops_router()
            + Self::visual_router()
    }

    /// Snapshot of the current config. Cheap: one atomic `Arc::clone`.
    pub fn cfg(&self) -> Arc<Config> {
        self.cfg_swap.load_full()
    }

    /// Snapshot of the current guard cache.
    pub fn guards(&self) -> Arc<GuardCache> {
        self.guards_swap.load_full()
    }

    pub(crate) fn resolve_host(&self, h: Option<String>) -> Result<String, McpError> {
        h.or_else(|| self.cfg().defaults.default_host.clone())
            .ok_or_else(|| {
                SshError::Config("host required (or set [defaults] default_host)".to_string())
                    .into_mcp()
            })
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for SshServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder().enable_tools().build(),
        )
        .with_server_info(Implementation::from_build_env())
        .with_protocol_version(ProtocolVersion::V_2024_11_05)
        .with_instructions(
            "SSH MCP server.\n\
             - Discovery: run `hosts` first to list targets and session state. `ping` checks reachability.\n\
             - Tool selection: `exec` for stateless one-shot (parallel-safe). `sh` for stateful PTY (cd/export/source persist). `exec_batch` for fan-out parallel commands on one host.\n\
             - Files: prefer SFTP — `ls`/`dn`/`up`/`wr` over equivalent shell tricks. Use `wr` instead of `echo > file` via exec.\n\
             - Logs: stream via `tail` with follow=true. Never run `tail -F` via `sh` (blocks the PTY).\n\
             - Long output: results auto-truncate at 32 KB. Pipe through `grep`/`awk`/`head` server-side to narrow.\n\
             - Errors: guard_blocked = command matched a deny pattern; confirmation_denied = user declined elicit. `data.recovery` hints retry strategy.\n\
             - host arg is optional when [defaults] default_host is set."
                .to_string(),
        )
    }
}

impl SshServer {
    pub(crate) async fn run_guards(
        &self,
        host: &str,
        cmd: &str,
        ctx: &RequestContext<RoleServer>,
    ) -> Result<(), SshError> {
        let guards = self.guards().for_host(host);
        match guards.check(cmd) {
            GuardCheck::Allow => Ok(()),
            GuardCheck::Deny {
                pattern_name,
                pattern,
            } => Err(SshError::BlockedByGuard {
                name: pattern_name,
                pattern,
            }),
            GuardCheck::Confirm { pattern_name } => {
                if self.confirm_remembered(host, cmd) {
                    return Ok(());
                }
                let prompt = format!(
                    "fast-mcp-ssh wants to run a sensitive command on '{host}' (matches '{pattern_name}'):\n\n{cmd}\n\nReply 'yes' to proceed."
                );
                match elicit_confirmation(ctx, &prompt).await {
                    Ok(true) => {
                        self.remember_confirm(host, cmd);
                        Ok(())
                    }
                    Ok(false) => Err(SshError::ConfirmationDenied),
                    Err(e) => {
                        tracing::warn!(?e, "elicitation failed; defaulting to deny (fail-closed)");
                        Err(SshError::ConfirmationDenied)
                    }
                }
            }
        }
    }

    /// True when this exact command was approved on this host inside
    /// `[defaults] confirm_ttl`. Keyed on the full command string, not on the
    /// pattern name: approving `systemctl stop nginx` must not silently
    /// approve `systemctl stop firewalld`.
    pub(crate) fn confirm_remembered(&self, host: &str, cmd: &str) -> bool {
        let ttl = self.cfg().defaults.confirm_ttl.0;
        if ttl.is_zero() {
            return false;
        }
        let key = (host.to_string(), cmd.to_string());
        match self.confirmations.get(&key) {
            Some(at) if at.elapsed() < ttl => true,
            Some(_) => {
                drop(self.confirmations.remove(&key));
                false
            }
            None => false,
        }
    }

    pub(crate) fn remember_confirm(&self, host: &str, cmd: &str) {
        if self.cfg().defaults.confirm_ttl.0.is_zero() {
            return;
        }
        // Bounded so a long-lived server driven by a chatty model cannot grow
        // this map without limit. Oldest-first eviction is not worth a heap
        // here; a full map simply stops remembering and prompts again.
        if self.confirmations.len() >= MAX_REMEMBERED_CONFIRMATIONS {
            self.confirmations
                .retain(|_, at| at.elapsed() < self.cfg().defaults.confirm_ttl.0);
            if self.confirmations.len() >= MAX_REMEMBERED_CONFIRMATIONS {
                return;
            }
        }
        self.confirmations
            .insert((host.to_string(), cmd.to_string()), Instant::now());
    }

    /// Drops every remembered approval. Called by `reload`, since the guard
    /// set the approvals were granted against no longer exists.
    pub(crate) fn forget_confirmations(&self) {
        self.confirmations.clear();
    }

    /// Singleflight: the slot mutex is held across `PtyState::open` so two
    /// concurrent first `sh` calls can't both pay the full PTY init and then
    /// throw one away (which also burned an sshd channel slot for nothing).
    /// `interrupt` briefly contends on the same mutex during an open; the
    /// open is a couple of round-trips, so that's acceptable.
    pub(crate) async fn ensure_pty(
        &self,
        session: &Arc<Session>,
        opts: pty::PtyOpts,
        shell: Option<&str>,
    ) -> Result<Arc<pty::PtyState>, SshError> {
        match shell {
            None => {
                let mut guard = session.pty.lock().await;
                if let Some(state) = guard.as_ref() {
                    return Ok(Arc::clone(state));
                }
                let new_state = Arc::new(pty::PtyState::open(session, opts).await?);
                *guard = Some(Arc::clone(&new_state));
                Ok(new_state)
            }
            Some(name) => {
                let mut guard = session.named_ptys.lock().await;
                if let Some(state) = guard.get(name) {
                    return Ok(Arc::clone(state));
                }
                let new_state = Arc::new(pty::PtyState::open(session, opts).await?);
                guard.insert(name.to_string(), Arc::clone(&new_state));
                Ok(new_state)
            }
        }
    }
}

pub(crate) async fn elicit_confirmation(
    ctx: &RequestContext<RoleServer>,
    prompt: &str,
) -> Result<bool, ElicitationError> {
    let resp: Option<ConfirmElicit> = ctx.peer.elicit(prompt.to_string()).await?;
    Ok(resp
        .map(|r| r.answer.trim().eq_ignore_ascii_case("yes"))
        .unwrap_or(false))
}
