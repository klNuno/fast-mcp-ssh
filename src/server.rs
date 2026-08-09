use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

/// Cap on the remembered-approval map. Reached only by a pathological caller.
const MAX_REMEMBERED_CONFIRMATIONS: usize = 512;

/// How long a finished task stays collectable past the budget its operation
/// was given. A client that polls slowly still gets its result.
const TASK_GRACE_MS: u128 = 120_000;

/// Freshness hint on `tools/list` (SEP-2549). One hour: the set is fixed for
/// the life of the process, and clients cap what they honour anyway.
const TOOL_LIST_TTL_MS: u64 = 60 * 60 * 1000;

use arc_swap::ArcSwap;
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler, elicit_safe,
    handler::server::router::tool::ToolRouter,
    model::*,
    schemars,
    service::{ElicitationError, RequestContext},
    task_manager::{TaskExit, TaskManager, TaskOptions},
    tool_handler,
};
use serde::{Deserialize, Serialize};

use crate::audit::AuditLog;
use crate::config::Config;
use crate::confirm::{self, Answer, Confirm};
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
    /// Long operations handed to a client that declared the tasks extension.
    /// Empty for every other peer, which still gets the blocking call.
    tasks: TaskManager,
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
            tasks: TaskManager::new(),
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
    /// Overrides what `#[tool_handler]` would generate on two points.
    ///
    /// The router stores tools in a `HashMap`, so its natural order changes
    /// from one process to the next; sorting makes the listing byte-identical
    /// across restarts, which is what lets a client's prompt cache hit
    /// (SEP-2549 recommends it for exactly that reason).
    ///
    /// And the generated `ttl_ms` is 0, meaning "never cache". This set is
    /// built once in `new()` and no code path mutates it, `reload` included:
    /// it only ever changes when the binary is replaced, so it is cacheable
    /// for as long as a client is willing to hold it.
    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let mut tools = self.tool_router.list_all();
        tools.sort_by(|a, b| a.name.cmp(&b.name));
        let cache_hints = ctx
            .protocol_version()
            .is_some_and(|v| v >= ProtocolVersion::V_2026_07_28);
        Ok(ListToolsResult {
            result_type: Some(ResultType::COMPLETE),
            tools,
            meta: None,
            next_cursor: None,
            ttl_ms: cache_hints.then_some(TOOL_LIST_TTL_MS),
            cache_scope: cache_hints.then_some(CacheScope::Public),
        })
    }

    /// SEP-2663 `tasks/get`.
    async fn get_task(
        &self,
        request: GetTaskParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<GetTaskResult, McpError> {
        self.tasks.get_task(&request.task_id).map(GetTaskResult::new)
    }

    /// SEP-2663 `tasks/update`: answers to what a running task asked for.
    async fn update_task(
        &self,
        request: UpdateTaskParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        self.tasks
            .update_task(&request.task_id, request.input_responses)
    }

    /// SEP-2663 `tasks/cancel`. Cooperative: the remote command is dropped at
    /// the next await point, which also aborts its SSH channel.
    async fn cancel_task(
        &self,
        request: CancelTaskParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        self.tasks.cancel_task(&request.task_id)
    }

    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_tasks()
                .build(),
        )
        .with_server_info(Implementation::from_build_env())
        // rmcp echoes back whatever version the client asked for when it knows
        // it, so this is only the fallback for an unrecognized one. It still
        // has to be a version that has elicitation: pinned at 2024-11-05, a
        // client landing on the fallback could not answer a confirm prompt and
        // every `confirm_patterns` command failed closed.
        .with_protocol_version(ProtocolVersion::LATEST)
        .with_instructions(
            "SSH MCP server.\n\
             - Discovery: run `hosts` first to list targets and session state. `ping` checks reachability.\n\
             - Tool selection: `exec` for stateless one-shot (parallel-safe). `sh` for stateful PTY (cd/export/source persist). `exec_batch` for fan-out parallel commands on one host.\n\
             - Shells: `sh shell=<name>` opens an isolated PTY that holds a channel slot until closed. `shells` lists them, `shells close=<name>` releases one.\n\
             - Files: prefer SFTP — `ls`/`dn`/`up`/`wr` over equivalent shell tricks. Use `wr` instead of `echo > file` via exec.\n\
             - Logs: stream via `tail` with follow=true. Never run `tail -F` via `sh` (blocks the PTY).\n\
             - Long output: results auto-truncate at 32 KB. Pipe through `grep`/`awk`/`head` server-side to narrow.\n\
             - Long work: `exec` past the default 60s timeout and `tail` with follow=true come back as a task handle when your client supports tasks. Poll `tasks/get`, don't re-issue the call.\n\
             - Errors: guard_blocked = command matched a deny pattern; confirmation_denied = user declined elicit. `data.recovery` hints retry strategy.\n\
             - host arg is optional when [defaults] default_host is set."
                .to_string(),
        )
    }
}

/// Verdict of the guard chain when nothing was blocked.
pub(crate) enum Guarded {
    /// Cleared. The caller may proceed.
    Passed,
    /// A confirmation was queued for the client and no answer exists yet. The
    /// caller must stop and return the interim result built by
    /// [`Confirm::into_input_required`].
    Deferred,
}

impl SshServer {
    pub(crate) async fn run_guards(
        &self,
        host: &str,
        cmd: &str,
        confirm: &mut Confirm<'_>,
    ) -> Result<Guarded, SshError> {
        let guards = self.guards().for_host(host);
        match guards.check(cmd) {
            GuardCheck::Allow => Ok(Guarded::Passed),
            GuardCheck::Deny {
                pattern_name,
                pattern,
            } => Err(SshError::BlockedByGuard {
                name: pattern_name,
                pattern,
            }),
            GuardCheck::Confirm { pattern_name } => {
                if self.confirm_remembered(host, cmd) {
                    return Ok(Guarded::Passed);
                }
                let prompt = format!(
                    "fast-mcp-ssh wants to run a sensitive command on '{host}' (matches '{pattern_name}'):\n\n{cmd}\n\nReply 'yes' to proceed."
                );
                let key = confirm::key_for(&[host, cmd]);
                match confirm.ask(&key, &prompt).await {
                    Answer::Approved => {
                        self.remember_confirm(host, cmd);
                        Ok(Guarded::Passed)
                    }
                    Answer::Denied => Err(SshError::ConfirmationDenied),
                    Answer::Deferred => Ok(Guarded::Deferred),
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

    /// Runs `op` as a task when the caller can poll for one, and inline
    /// otherwise. Only the caller knows whether the operation is long enough
    /// to be worth a handle, so `worth_a_task` is its call; a client that
    /// never declared the tasks extension always gets the blocking result.
    ///
    /// `budget` is how long the operation may run. It sets the task's TTL with
    /// a grace period on top, so a result is still collectable for a while
    /// after the command itself ended.
    pub(crate) async fn task_or_inline<F>(
        &self,
        ctx: &RequestContext<RoleServer>,
        worth_a_task: bool,
        status: impl Into<String>,
        budget: std::time::Duration,
        op: F,
    ) -> Result<CallToolResponse, McpError>
    where
        F: Future<Output = Result<CallToolResult, McpError>> + Send + 'static,
    {
        let supported = ctx
            .client_capabilities()
            .is_some_and(|c| c.supports_tasks());
        if !worth_a_task || !supported {
            return op.await.map(Into::into);
        }
        let ttl_ms = budget.as_millis().saturating_add(TASK_GRACE_MS) as u64;
        let task = self.tasks.spawn(
            TaskOptions::new()
                .with_ttl_ms(ttl_ms)
                .with_status_message(status),
            move |_task_ctx| Box::pin(async move { op.await.map_err(TaskExit::Error) }),
        );
        Ok(CreateTaskResult::new(task).into())
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
                // Each named shell holds a channel slot until the session
                // dies. Unbounded, eight `shell=` names exhaust the default
                // `max_channels_per_host` and every later `exec` on the host
                // times out with no hint about why.
                if guard.len() >= crate::tools::MAX_NAMED_PTYS {
                    return Err(SshError::Config(format!(
                        "too many named shells on this host ({}/{}). Close one with \
                         `shells close=<name>` before opening another.",
                        guard.len(),
                        crate::tools::MAX_NAMED_PTYS
                    )));
                }
                let new_state = Arc::new(pty::PtyState::open(session, opts).await?);
                guard.insert(name.to_string(), Arc::clone(&new_state));
                Ok(new_state)
            }
        }
    }

    /// Drop a PTY whose `run()` failed. A timed-out or closed shell leaves
    /// unread bytes in the channel that would be spliced onto the *next*
    /// call's output, and every later `sh` on that shell inherits the mess
    /// with no way out short of `disconnect`. Dropping it means the next call
    /// pays one PTY open and gets a clean shell.
    pub(crate) async fn evict_broken_pty(
        &self,
        session: &Arc<Session>,
        shell: Option<&str>,
        why: &SshError,
    ) {
        tracing::warn!(shell = ?shell, error = %why, "dropping PTY after a failed run");
        session.close_pty(shell).await;
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
