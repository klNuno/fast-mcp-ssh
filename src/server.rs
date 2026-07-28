use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use base64::Engine;
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler, elicit_safe,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    schemars,
    service::{ElicitationError, RequestContext},
    tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};

use crate::audit::AuditLog;
use crate::config::{AuthMethod, Config};
use crate::errors::SshError;
use crate::forward::{self, ForwardHandle};
use crate::guards::{GuardCache, GuardCheck};
use crate::output::{Toon, truncate_with_hint};
use crate::session::{Session, SessionPool, exec, pty};
use crate::sftp;
use crate::tail;

const DEFAULT_TIMEOUT: u64 = 60;
/// Hard cap on per-call timeouts. Prevents an AI-supplied `timeout=u64::MAX`
/// from holding a channel slot indefinitely.
const MAX_TIMEOUT_SECS: u64 = 600;
const MAX_FOLLOW_SECS: u64 = 600;
const INLINE_MAX_BYTES: usize = 256 * 1024;
/// Hard cap on a single command string. Refuses oversize inputs before they
/// reach the SSH channel.
const MAX_CMD_BYTES: usize = 64 * 1024;
/// Hard cap on `exec_batch` fan-out. Past this an AI is almost certainly
/// looping when it should be using a script.
const MAX_BATCH_CMDS: usize = 64;
/// Hard cap on inline `wr` content. Larger files should go through `up`.
const MAX_WRITE_INLINE_BYTES: usize = 8 * 1024 * 1024;
/// Cap on a single SFTP listing returned in one call. Pagination via
/// `offset` lets the AI walk past it.
const MAX_LS_ENTRIES: usize = 1000;

fn clamp_timeout(t: Option<u64>) -> Duration {
    Duration::from_secs(t.unwrap_or(DEFAULT_TIMEOUT).clamp(1, MAX_TIMEOUT_SECS))
}

fn validate_cmd(cmd: &str) -> Result<(), McpError> {
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
    #[allow(dead_code)]
    tool_router: ToolRouter<SshServer>,
}

// Intentionally no `Debug` derive: the `password` field would otherwise leak
// in clear text if anyone added `tracing::debug!(?args)` later.
#[derive(Deserialize, schemars::JsonSchema)]
pub struct ExecArgs {
    /// Host alias. Omit if a default_host is configured.
    #[serde(default)]
    pub host: Option<String>,
    /// Command for the remote login shell. Pipes/redirects supported.
    pub cmd: String,
    /// Per-call timeout. Default 60s. Format: "30s", "5m", "2h", "500ms" or seconds as integer.
    #[serde(default)]
    pub timeout: Option<u64>,
    /// Password for password-auth hosts. Cached in memory after first call.
    #[serde(default)]
    pub password: Option<String>,
    /// Set true to bypass a confirm-prompt guard after seeing it once.
    #[serde(default)]
    pub confirm: Option<bool>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct ExecBatchArgs {
    /// Host alias. Omit if a default_host is configured.
    #[serde(default)]
    pub host: Option<String>,
    /// Commands run in parallel on fresh exec channels (capped by max_channels_per_host).
    pub cmds: Vec<String>,
    /// Per-call timeout applied to each command. Default 60s.
    #[serde(default)]
    pub timeout: Option<u64>,
    /// Password for password-auth hosts. Cached after first call.
    #[serde(default)]
    pub password: Option<String>,
    /// Set true to bypass confirm-prompt guards.
    #[serde(default)]
    pub confirm: Option<bool>,
    /// If true, include full preview (200 chars on errors, 40 on success). Default false: errors-only preview.
    #[serde(default)]
    pub verbose: Option<bool>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct ShArgs {
    /// Host alias. Omit if a default_host is configured.
    #[serde(default)]
    pub host: Option<String>,
    /// Command run inside the persistent PTY. cd/export/source persist across calls.
    pub cmd: String,
    /// Per-call timeout. Default 60s.
    #[serde(default)]
    pub timeout: Option<u64>,
    /// Password for password-auth hosts. Cached after first call.
    #[serde(default)]
    pub password: Option<String>,
    /// Set true to bypass confirm-prompt guards.
    #[serde(default)]
    pub confirm: Option<bool>,
    /// PTY width. Default 200. Honored on first sh per host.
    #[serde(default)]
    pub cols: Option<u32>,
    /// PTY height. Default 50. Honored on first sh per host.
    #[serde(default)]
    pub rows: Option<u32>,
    /// Optional shell name for an isolated persistent PTY. Each unique name
    /// gets its own working directory and environment. Omit to use the
    /// default shell.
    #[serde(default)]
    pub shell: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct HostOnlyArgs {
    /// Host alias. Omit if a default_host is configured.
    #[serde(default)]
    pub host: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct OptHostArgs {
    /// Host alias. Omit to query all configured hosts.
    #[serde(default)]
    pub host: Option<String>,
    /// Password for password-auth hosts. Cached after first successful connect. Ignored when targeting all hosts.
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UploadArgs {
    /// Host alias. Omit if a default_host is configured.
    #[serde(default)]
    pub host: Option<String>,
    /// Local source path. `~` expanded.
    pub local: String,
    /// Remote destination path. Parent dir must exist.
    pub remote: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DownloadArgs {
    /// Host alias. Omit if a default_host is configured.
    #[serde(default)]
    pub host: Option<String>,
    /// Remote source path.
    pub remote: String,
    /// Local destination path. Omit to receive content inline (text < 256 KB; binary base64).
    #[serde(default)]
    pub local: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LsArgs {
    /// Host alias. Omit if a default_host is configured.
    #[serde(default)]
    pub host: Option<String>,
    /// Remote directory path. `~` not expanded server-side; use absolute paths.
    pub path: String,
    /// Max entries returned. Default 1000 (also the hard cap).
    #[serde(default)]
    pub limit: Option<u32>,
    /// Skip the first N entries (alphabetical). Use with `limit` to paginate.
    #[serde(default)]
    pub offset: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WriteArgs {
    /// Host alias. Omit if a default_host is configured.
    #[serde(default)]
    pub host: Option<String>,
    /// Remote destination path. Replaces existing file.
    pub remote: String,
    /// File content (UTF-8 text).
    pub content: String,
    /// Octal mode at create time (e.g. 420 = 0o644). Default 0o644.
    #[serde(default)]
    pub mode: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MkdirArgs {
    /// Host alias. Omit if a default_host is configured.
    #[serde(default)]
    pub host: Option<String>,
    /// Remote directory path.
    pub path: String,
    /// If true, create intermediate parents (`mkdir -p`). Default false.
    #[serde(default)]
    pub parents: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RmArgs {
    /// Host alias. Omit if a default_host is configured.
    #[serde(default)]
    pub host: Option<String>,
    /// Remote path (file or directory).
    pub path: String,
    /// If true, recursively delete a directory and its contents. Default false.
    #[serde(default)]
    pub recursive: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct StatArgs {
    /// Host alias. Omit if a default_host is configured.
    #[serde(default)]
    pub host: Option<String>,
    /// Remote path.
    pub path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TailArgs {
    /// Host alias. Omit if a default_host is configured.
    #[serde(default)]
    pub host: Option<String>,
    /// Remote file path.
    pub path: String,
    /// Number of trailing lines to read. Default 100. Ignored when follow=true.
    #[serde(default)]
    pub lines: Option<u32>,
    /// If true, stream new lines for `seconds`. Default false.
    #[serde(default)]
    pub follow: Option<bool>,
    /// Stream duration in seconds when follow=true. Default 5.
    #[serde(default)]
    pub seconds: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ForwardArgs {
    /// Host alias whose SSH session is used as the tunnel transport.
    #[serde(default)]
    pub host: Option<String>,
    /// Local TCP port to bind on 127.0.0.1. Must be free.
    pub local_port: u16,
    /// Remote host the SSH server should connect outbound to. Often
    /// `127.0.0.1` (services bound on the remote box) or a name visible from
    /// the remote box's network.
    pub remote_host: String,
    /// Remote TCP port.
    pub remote_port: u16,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UnforwardArgs {
    /// Local port to release.
    pub local_port: u16,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConfirmElicit {
    /// Type "yes" to proceed.
    pub answer: String,
}

elicit_safe!(ConfirmElicit);

#[tool_router]
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
            tool_router: Self::tool_router(),
        }
    }

    /// Snapshot of the current config. Cheap: one atomic `Arc::clone`.
    pub fn cfg(&self) -> Arc<Config> {
        self.cfg_swap.load_full()
    }

    /// Snapshot of the current guard cache.
    pub fn guards(&self) -> Arc<GuardCache> {
        self.guards_swap.load_full()
    }

    fn resolve_host(&self, h: Option<String>) -> Result<String, McpError> {
        h.or_else(|| self.cfg().defaults.default_host.clone())
            .ok_or_else(|| {
                SshError::Config("host required (or set [defaults] default_host)".to_string())
                    .into_mcp()
            })
    }

    #[tool(
        description = "List configured hosts with session state. Run this first to discover targets.",
        annotations(
            title = "Hosts",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn hosts(&self) -> Result<CallToolResult, McpError> {
        let mut t = Toon::new();
        let cfg = self.cfg();
        let names = cfg.host_names();
        if names.is_empty() {
            t.field("hosts", "none configured");
            t.hint(&format!(
                "edit {} to add hosts",
                cfg.defaults
                    .audit_log_path
                    .parent()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "~/.fast-mcp-ssh".into())
            ));
            return Ok(text(t.into_string()));
        }
        let active = self.pool.list_active();
        let rows: Vec<Vec<String>> = names
            .iter()
            .filter_map(|n| {
                let h = cfg.hosts.get(n)?;
                let session = if active.contains(n) { "live" } else { "idle" };
                Some(vec![
                    n.clone(),
                    h.addr.clone(),
                    h.user.clone(),
                    h.port.to_string(),
                    auth_str(h.auth).into(),
                    session.into(),
                ])
            })
            .collect();
        t.table_strs(
            "hosts",
            &["name", "addr", "user", "port", "auth", "session"],
            &rows,
        );
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "Run one-shot command, stateless. Use for independent or parallelizable commands. Not for cd/export/source — use sh.",
        annotations(
            title = "Exec",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn exec(
        &self,
        Parameters(args): Parameters<ExecArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        validate_cmd(&args.cmd)?;
        let timeout = clamp_timeout(args.timeout);
        let host_name = self.resolve_host(args.host)?;
        let password = args.password.map(zeroize::Zeroizing::new);

        if let Err(e) = self
            .run_guards(&host_name, &args.cmd, args.confirm.unwrap_or(false), &ctx)
            .await
        {
            let err_msg = e.to_string();
            self.audit.write(
                &host_name,
                "exec",
                Some(&args.cmd),
                None,
                None,
                None,
                None,
                Some(&err_msg),
                Some(err_msg.clone()),
            );
            return Err(e.into_mcp());
        }
        let session = self
            .pool
            .get_or_connect(&host_name, password.clone())
            .await
            .map_err(|e| {
                self.audit.write(
                    &host_name,
                    "exec",
                    Some(&args.cmd),
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(e.to_string()),
                );
                e.into_mcp()
            })?;
        if let Some(pw) = password {
            self.pool.cache_password(&host_name, pw);
        }

        let max_capture = self.cfg().defaults.max_capture_bytes;
        let result = exec::exec(&session, &args.cmd, timeout, max_capture)
            .await
            .map_err(|e| {
                self.audit.write(
                    &host_name,
                    "exec",
                    Some(&args.cmd),
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(e.to_string()),
                );
                e.into_mcp()
            })?;

        self.audit.write(
            &host_name,
            "exec",
            Some(&args.cmd),
            Some(result.exit_code),
            Some(result.duration_ms),
            None,
            Some(result.stdout_bytes + result.stderr_bytes),
            None,
            None,
        );
        Ok(text(format_exec(
            &result,
            self.cfg().defaults.truncate_bytes,
        )))
    }

    #[tool(
        description = "Run N parallel commands on one host in one round-trip. Use for independent fan-out (probes, status checks). Not for sequential pipelines — use sh.",
        annotations(
            title = "ExecBatch",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn exec_batch(
        &self,
        Parameters(args): Parameters<ExecBatchArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        if args.cmds.is_empty() {
            return Err(
                SshError::Config("cmds must contain at least one command".into()).into_mcp(),
            );
        }
        if args.cmds.len() > MAX_BATCH_CMDS {
            return Err(SshError::Config(format!(
                "too many commands: {} (max {})",
                args.cmds.len(),
                MAX_BATCH_CMDS
            ))
            .into_mcp());
        }
        for cmd in &args.cmds {
            validate_cmd(cmd)?;
        }
        let timeout = clamp_timeout(args.timeout);
        let host_name = self.resolve_host(args.host)?;
        let bypass = args.confirm.unwrap_or(false);
        let verbose = args.verbose.unwrap_or(false);
        let password = args.password.map(zeroize::Zeroizing::new);

        // Guard the whole batch up front, deduplicating confirm elicitations
        // by pattern name: one user confirmation covers every command in the
        // batch matching the same pattern, instead of K serial prompts.
        let guards = self.guards().for_host(&host_name);
        let mut confirmed: std::collections::HashSet<String> = std::collections::HashSet::new();
        for cmd in &args.cmds {
            let check = guards.check(cmd);
            let err = match check {
                GuardCheck::Allow => None,
                GuardCheck::Deny {
                    pattern_name,
                    pattern,
                } => Some(SshError::BlockedByGuard {
                    name: pattern_name,
                    pattern,
                }),
                GuardCheck::Confirm { pattern_name } => {
                    if bypass || confirmed.contains(&pattern_name) {
                        None
                    } else {
                        let prompt = format!(
                            "fast-mcp-ssh wants to run a sensitive command on '{host_name}' (matches '{pattern_name}'):\n\n{cmd}\n\nConfirming covers every command in this batch matching '{pattern_name}'. Reply 'yes' to proceed."
                        );
                        match elicit_confirmation(&ctx, &prompt).await {
                            Ok(true) => {
                                confirmed.insert(pattern_name);
                                None
                            }
                            Ok(false) => Some(SshError::ConfirmationDenied),
                            Err(e) => {
                                tracing::warn!(
                                    ?e,
                                    "elicitation failed; defaulting to deny (fail-closed)"
                                );
                                Some(SshError::ConfirmationDenied)
                            }
                        }
                    }
                }
            };
            if let Some(e) = err {
                let err_msg = e.to_string();
                self.audit.write(
                    &host_name,
                    "exec_batch",
                    Some(cmd),
                    None,
                    None,
                    None,
                    None,
                    Some(&err_msg),
                    Some(err_msg.clone()),
                );
                return Err(e.into_mcp());
            }
        }

        let session = self
            .pool
            .get_or_connect(&host_name, password.clone())
            .await
            .map_err(|e| e.into_mcp())?;
        if let Some(pw) = password {
            self.pool.cache_password(&host_name, pw);
        }

        let max_capture = self.cfg().defaults.max_capture_bytes;
        // JoinSet aborts in-flight tasks when dropped, so a request cancelled
        // by the client doesn't leave commands running on the remote host.
        // Track cmd-by-task-id so a panicked task still gets audited against
        // the right command.
        let mut set = tokio::task::JoinSet::new();
        let mut by_id: std::collections::HashMap<tokio::task::Id, String> =
            std::collections::HashMap::with_capacity(args.cmds.len());
        for cmd in args.cmds.into_iter() {
            let s = Arc::clone(&session);
            let cmd_for_task = cmd.clone();
            let abort =
                set.spawn(async move { exec::exec(&s, &cmd_for_task, timeout, max_capture).await });
            by_id.insert(abort.id(), cmd);
        }

        let mut t = Toon::new();
        t.field("host", &host_name);
        let mut rows: Vec<Vec<String>> = Vec::new();
        while let Some(joined) = set.join_next_with_id().await {
            match joined {
                Ok((id, Ok(r))) => {
                    let cmd = by_id.remove(&id).unwrap_or_default();
                    let preview = batch_preview(&r, verbose);
                    self.audit.write(
                        &host_name,
                        "exec_batch",
                        Some(&cmd),
                        Some(r.exit_code),
                        Some(r.duration_ms),
                        None,
                        Some(r.stdout_bytes),
                        None,
                        None,
                    );
                    rows.push(vec![
                        cmd,
                        r.exit_code.to_string(),
                        r.duration_ms.to_string(),
                        r.stdout_bytes.to_string(),
                        preview,
                    ]);
                }
                Ok((id, Err(e))) => {
                    let cmd = by_id.remove(&id).unwrap_or_default();
                    let err_msg = e.to_string();
                    self.audit.write(
                        &host_name,
                        "exec_batch",
                        Some(&cmd),
                        None,
                        None,
                        None,
                        None,
                        None,
                        Some(err_msg.clone()),
                    );
                    rows.push(vec![cmd, "-1".into(), "0".into(), "0".into(), err_msg]);
                }
                Err(e) => {
                    let id = e.id();
                    let cmd = by_id.remove(&id).unwrap_or_else(|| "-".into());
                    let err_msg = e.to_string();
                    self.audit.write(
                        &host_name,
                        "exec_batch",
                        Some(&cmd),
                        None,
                        None,
                        None,
                        None,
                        None,
                        Some(err_msg.clone()),
                    );
                    rows.push(vec![cmd, "-1".into(), "0".into(), "0".into(), err_msg]);
                }
            }
        }
        t.table_strs("results", &["cmd", "exit", "ms", "bytes", "preview"], &rows);
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "Stateful PTY shell. Use for cd/export/activate venv/sequential pipelines. Not for parallel work — use exec_batch.",
        annotations(
            title = "Sh",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn sh(
        &self,
        Parameters(args): Parameters<ShArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        validate_cmd(&args.cmd)?;
        let timeout = clamp_timeout(args.timeout);
        let host_name = self.resolve_host(args.host)?;
        let password = args.password.map(zeroize::Zeroizing::new);

        if let Err(e) = self
            .run_guards(&host_name, &args.cmd, args.confirm.unwrap_or(false), &ctx)
            .await
        {
            let err_msg = e.to_string();
            self.audit.write(
                &host_name,
                "sh",
                Some(&args.cmd),
                None,
                None,
                None,
                None,
                Some(&err_msg),
                Some(err_msg.clone()),
            );
            return Err(e.into_mcp());
        }

        let session = self
            .pool
            .get_or_connect(&host_name, password.clone())
            .await
            .map_err(|e| e.into_mcp())?;
        if let Some(pw) = password {
            self.pool.cache_password(&host_name, pw);
        }

        let max_capture = self.cfg().defaults.max_capture_bytes;
        let opts = pty::PtyOpts {
            cols: args.cols.unwrap_or(pty::DEFAULT_PTY_COLS),
            rows: args.rows.unwrap_or(pty::DEFAULT_PTY_ROWS),
            max_capture,
        };
        let pty_state = self
            .ensure_pty(&session, opts, args.shell.as_deref())
            .await
            .map_err(|e| e.into_mcp())?;
        let (output, exit_code) = pty_state
            .run(&args.cmd, timeout, max_capture)
            .await
            .map_err(|e| e.into_mcp())?;
        session.touch();

        let bytes = output.len();
        self.audit.write(
            &host_name,
            "sh",
            Some(&args.cmd),
            Some(exit_code),
            None,
            None,
            Some(bytes),
            None,
            None,
        );

        let mut t = Toon::new();
        t.field("host", &host_name);
        if let Some(s) = &args.shell {
            t.field("shell", s.as_str());
        }
        t.field("exit_code", exit_code as i64);
        t.field("bytes", bytes);
        let (display, _) = truncate_with_hint(&output, self.cfg().defaults.truncate_bytes);
        t.block("stdout", &display);
        if exit_code != 0 {
            t.hint("non-zero exit. cd preserved across sh calls.");
        }
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "TCP+SSH+auth liveness probe. Use to verify reachability before exec/sftp. With host probes one; without args probes all in parallel. Password arg only honored when host is specified.",
        annotations(
            title = "Ping",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn ping(
        &self,
        Parameters(args): Parameters<OptHostArgs>,
    ) -> Result<CallToolResult, McpError> {
        let (targets, password): (Vec<String>, Option<zeroize::Zeroizing<String>>) = match args.host
        {
            Some(h) => (vec![h], args.password.map(zeroize::Zeroizing::new)),
            None => (self.cfg().host_names(), None),
        };
        let mut handles = Vec::new();
        for name in targets {
            let pool = self.pool.clone();
            let pw = password.clone();
            handles.push(tokio::spawn(async move {
                let start = std::time::Instant::now();
                let res = pool.get_or_connect(&name, pw.clone()).await;
                let elapsed = start.elapsed().as_millis() as u64;
                match res {
                    Ok(_) => {
                        if let Some(p) = pw {
                            pool.cache_password(&name, p);
                        }
                        (name, "ok".to_string(), elapsed, None)
                    }
                    Err(e) => (name, "fail".to_string(), elapsed, Some(e.to_string())),
                }
            }));
        }
        let mut rows = Vec::new();
        for h in handles {
            if let Ok((name, status, ms, err)) = h.await {
                rows.push(vec![
                    name,
                    status,
                    ms.to_string(),
                    err.unwrap_or_else(|| "-".into()),
                ]);
            }
        }
        let mut t = Toon::new();
        t.table_strs("ping", &["host", "status", "ms", "error"], &rows);
        Ok(text(t.into_string()))
    }

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
        self.audit.write(
            &host_name,
            "disconnect",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let mut t = Toon::new();
        t.field("host", &host_name).field("status", "closed");
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "Open local TCP forward: 127.0.0.1:<local_port> -> remote_host:remote_port via SSH. Returns once the listener is bound; tunnel lives in background until unforward.",
        annotations(
            title = "Forward",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn forward(
        &self,
        Parameters(args): Parameters<ForwardArgs>,
    ) -> Result<CallToolResult, McpError> {
        let host_name = self.resolve_host(args.host)?;
        if self.forwards.contains_key(&args.local_port) {
            return Err(SshError::Config(format!(
                "local port {} already forwarded; unforward first",
                args.local_port
            ))
            .into_mcp());
        }
        let session = self
            .pool
            .get_or_connect(&host_name, None)
            .await
            .map_err(|e| e.into_mcp())?;
        let handle = forward::start(
            session,
            host_name.clone(),
            args.local_port,
            args.remote_host.clone(),
            args.remote_port,
        )
        .await
        .map_err(|e| e.into_mcp())?;
        let bound = handle.bound_addr;
        self.forwards.insert(args.local_port, handle);
        self.audit.write(
            &host_name,
            "forward",
            Some(&format!(
                "127.0.0.1:{} -> {}:{}",
                args.local_port, args.remote_host, args.remote_port
            )),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let mut t = Toon::new();
        t.field("host", &host_name)
            .field("local", bound.to_string())
            .field(
                "remote",
                format!("{}:{}", args.remote_host, args.remote_port),
            )
            .field("status", "listening");
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "Stop a local forward by local port. Existing in-flight connections drain naturally.",
        annotations(
            title = "Unforward",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn unforward(
        &self,
        Parameters(args): Parameters<UnforwardArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut t = Toon::new();
        t.field("local_port", args.local_port as u64);
        match self.forwards.remove(&args.local_port) {
            Some((_, handle)) => {
                let host = handle.host_alias.clone();
                handle.stop();
                self.audit.write(
                    &host,
                    "unforward",
                    Some(&format!("port={}", args.local_port)),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                );
                t.field("status", "stopped");
            }
            None => {
                t.field("status", "no such forward");
            }
        }
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "List active local→remote forwards.",
        annotations(
            title = "Forwards",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn forwards(&self) -> Result<CallToolResult, McpError> {
        let rows: Vec<Vec<String>> = self
            .forwards
            .iter()
            .map(|e| {
                let h = e.value();
                vec![
                    h.host_alias.clone(),
                    h.bound_addr.to_string(),
                    format!("{}:{}", h.remote_host, h.remote_port),
                ]
            })
            .collect();
        let mut t = Toon::new();
        t.table_strs("forwards", &["host", "local", "remote"], &rows);
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
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(msg.clone()),
                );
                return Err(e.into_mcp());
            }
        };
        let old_cfg = self.cfg();
        // Swap config + guards atomically. After this, the SessionPool sees
        // the new config too (shared ArcSwap).
        self.cfg_swap.store(Arc::new(new_cfg));
        self.guards_swap.store(Arc::new(new_guards));
        let dropped = self.pool.prune_against(&old_cfg).await;

        let new = self.cfg();
        self.audit
            .write("*", "reload", None, None, None, None, None, None, None);
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
        self.audit.write(
            "*",
            "disconnect_all",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let mut t = Toon::new();
        t.field("closed", closed);
        if !names.is_empty() {
            let joined = names.join(",");
            t.field("hosts", joined);
        }
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "Send Ctrl-C (SIGINT) to the PTY foreground command. Use to stop a runaway sh command. Keeps session and shell state. Not for full disconnect — use disconnect.",
        annotations(
            title = "Interrupt",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn interrupt(
        &self,
        Parameters(args): Parameters<HostOnlyArgs>,
    ) -> Result<CallToolResult, McpError> {
        let host_name = self.resolve_host(args.host)?;
        let session = match self.pool.get(&host_name) {
            Some(s) => s,
            None => {
                let mut t = Toon::new();
                t.field("host", &host_name)
                    .field("status", "no active session");
                return Ok(text(t.into_string()));
            }
        };
        let mut pty_states: Vec<Arc<pty::PtyState>> = Vec::new();
        if let Some(p) = session.pty.lock().await.as_ref() {
            pty_states.push(Arc::clone(p));
        }
        for p in session.named_ptys.lock().await.values() {
            pty_states.push(Arc::clone(p));
        }
        let mut t = Toon::new();
        t.field("host", &host_name);
        let mut pty_acted = false;
        for p in &pty_states {
            p.interrupt().await.map_err(|e| e.into_mcp())?;
            pty_acted = true;
        }
        let exec_aborted = session.cancel_all_execs().await;
        self.audit.write(
            &host_name,
            "interrupt",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        t.field("pty_sigint", pty_acted);
        t.field("exec_aborted", exec_aborted as u64);
        if !pty_acted && exec_aborted == 0 {
            t.field("status", "no in-flight commands");
        } else {
            t.field("status", "interrupt fired");
        }
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "SFTP upload local→remote, streamed in 256 KB chunks. Use for transferring local files to remote. Not for inline content — use wr.",
        annotations(
            title = "Up",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn up(
        &self,
        Parameters(args): Parameters<UploadArgs>,
    ) -> Result<CallToolResult, McpError> {
        let host_name = self.resolve_host(args.host)?;
        if let Err(e) = self
            .guards()
            .for_host(&host_name)
            .check_sftp_write(&args.remote)
        {
            self.audit.write(
                &host_name,
                "up",
                Some(&args.remote),
                None,
                None,
                None,
                None,
                Some(&e.to_string()),
                Some(e.to_string()),
            );
            return Err(e.into_mcp());
        }
        let session = self
            .pool
            .get_or_connect(&host_name, None)
            .await
            .map_err(|e| e.into_mcp())?;
        let local = PathBuf::from(shellexpand::tilde(&args.local).into_owned());
        let r = sftp::upload(&session, &local, &args.remote)
            .await
            .map_err(|e| e.into_mcp())?;
        self.audit.write(
            &host_name,
            "up",
            Some(&format!("{} -> {}", args.local, args.remote)),
            None,
            Some(r.duration_ms),
            Some(r.bytes),
            None,
            None,
            None,
        );
        let mut t = Toon::new();
        t.field("host", &host_name)
            .field("local", &args.local)
            .field("remote", &args.remote)
            .field("bytes", r.bytes)
            .field("ms", r.duration_ms as u64);
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "SFTP download remote file. With local=<path> writes to disk; without returns inline (text<256KB or base64). Use for fetching files. Not for tailing logs — use tail.",
        annotations(
            title = "Dn",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn dn(
        &self,
        Parameters(args): Parameters<DownloadArgs>,
    ) -> Result<CallToolResult, McpError> {
        let host_name = self.resolve_host(args.host)?;
        if let Err(e) = self
            .guards()
            .for_host(&host_name)
            .check_sftp_read(&args.remote)
        {
            self.audit.write(
                &host_name,
                "dn",
                Some(&args.remote),
                None,
                None,
                None,
                None,
                Some(&e.to_string()),
                Some(e.to_string()),
            );
            return Err(e.into_mcp());
        }
        let session = self
            .pool
            .get_or_connect(&host_name, None)
            .await
            .map_err(|e| e.into_mcp())?;
        let local_path = args
            .local
            .as_deref()
            .map(|s| PathBuf::from(shellexpand::tilde(s).into_owned()));
        let (r, content) = sftp::download(
            &session,
            &args.remote,
            local_path.as_deref(),
            INLINE_MAX_BYTES,
        )
        .await
        .map_err(|e| e.into_mcp())?;
        self.audit.write(
            &host_name,
            "dn",
            Some(&args.remote),
            None,
            Some(r.duration_ms),
            None,
            Some(r.bytes),
            None,
            None,
        );

        let mut t = Toon::new();
        t.field("host", &host_name)
            .field("remote", &args.remote)
            .field("bytes", r.bytes)
            .field("ms", r.duration_ms as u64);
        if let Some(buf) = content {
            if sftp::looks_binary(&buf) {
                let encoded = base64::engine::general_purpose::STANDARD.encode(&buf);
                t.field("encoding", "base64");
                t.block("content", &encoded);
            } else {
                let s = String::from_utf8_lossy(&buf);
                let (display, _) = truncate_with_hint(&s, self.cfg().defaults.truncate_bytes);
                t.block("content", &display);
            }
        } else if let Some(p) = args.local.as_deref() {
            t.field("local", p);
        } else {
            // Inline requested but the remote file exceeds the cap; nothing
            // was transferred (`bytes` reports the remote size).
            t.field("content", "(too large for inline; rerun with local=<path>)");
        }
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "SFTP list directory. Use for browsing remote filesystem. Returns name/kind/size/mode/mtime. Not for shell glob — use exec with `ls`.",
        annotations(
            title = "Ls",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn ls(&self, Parameters(args): Parameters<LsArgs>) -> Result<CallToolResult, McpError> {
        let host_name = self.resolve_host(args.host)?;
        if let Err(e) = self
            .guards()
            .for_host(&host_name)
            .check_sftp_read(&args.path)
        {
            self.audit.write(
                &host_name,
                "ls",
                Some(&args.path),
                None,
                None,
                None,
                None,
                Some(&e.to_string()),
                Some(e.to_string()),
            );
            return Err(e.into_mcp());
        }
        let session = self
            .pool
            .get_or_connect(&host_name, None)
            .await
            .map_err(|e| e.into_mcp())?;
        let mut entries = sftp::list_dir(&session, &args.path)
            .await
            .map_err(|e| e.into_mcp())?;
        let total = entries.len();
        let offset = args.offset.unwrap_or(0) as usize;
        let limit = args
            .limit
            .map(|n| n as usize)
            .unwrap_or(MAX_LS_ENTRIES)
            .min(MAX_LS_ENTRIES);
        let page: Vec<sftp::ListEntry> = if offset >= entries.len() {
            Vec::new()
        } else {
            entries.drain(offset..).take(limit).collect()
        };
        self.audit.write(
            &host_name,
            "ls",
            Some(&args.path),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let rows: Vec<Vec<String>> = page
            .iter()
            .map(|e| {
                vec![
                    e.name.clone(),
                    e.kind.into(),
                    e.size.to_string(),
                    format!("{:o}", e.mode & 0o7777),
                    e.mtime.to_string(),
                ]
            })
            .collect();
        let mut t = Toon::new();
        t.field("host", &host_name).field("path", &args.path);
        t.field("total", total)
            .field("offset", offset)
            .field("returned", page.len());
        if offset + page.len() < total {
            t.hint(&format!(
                "more entries; re-run with offset={}",
                offset + page.len()
            ));
        }
        t.table_strs("entries", &["name", "kind", "size", "mode", "mtime"], &rows);
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "SFTP write inline content to remote file (replaces). Use instead of `echo > file` via exec. Atomic mode set at create time.",
        annotations(
            title = "Wr",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn wr(
        &self,
        Parameters(args): Parameters<WriteArgs>,
    ) -> Result<CallToolResult, McpError> {
        let host_name = self.resolve_host(args.host)?;
        if args.content.len() > MAX_WRITE_INLINE_BYTES {
            return Err(SshError::Config(format!(
                "content too large: {} bytes (max {} — use `up` for larger files)",
                args.content.len(),
                MAX_WRITE_INLINE_BYTES
            ))
            .into_mcp());
        }
        if let Err(e) = self
            .guards()
            .for_host(&host_name)
            .check_sftp_write(&args.remote)
        {
            self.audit.write(
                &host_name,
                "wr",
                Some(&args.remote),
                None,
                None,
                None,
                None,
                Some(&e.to_string()),
                Some(e.to_string()),
            );
            return Err(e.into_mcp());
        }
        let session = self
            .pool
            .get_or_connect(&host_name, None)
            .await
            .map_err(|e| e.into_mcp())?;
        let r = sftp::write_inline(&session, &args.remote, args.content.as_bytes(), args.mode)
            .await
            .map_err(|e| e.into_mcp())?;
        self.audit.write(
            &host_name,
            "wr",
            Some(&args.remote),
            None,
            Some(r.duration_ms),
            Some(r.bytes),
            None,
            None,
            None,
        );
        let mut t = Toon::new();
        t.field("host", &host_name)
            .field("remote", &args.remote)
            .field("bytes", r.bytes)
            .field("ms", r.duration_ms as u64);
        if let Some(m) = args.mode {
            t.field("mode", format!("{m:o}"));
        }
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "SFTP create directory. parents=true acts like `mkdir -p`. Use instead of `exec mkdir` to save a shell round-trip.",
        annotations(
            title = "Mkdir",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn mkdir(
        &self,
        Parameters(args): Parameters<MkdirArgs>,
    ) -> Result<CallToolResult, McpError> {
        let host_name = self.resolve_host(args.host)?;
        if let Err(e) = self
            .guards()
            .for_host(&host_name)
            .check_sftp_write(&args.path)
        {
            self.audit.write(
                &host_name,
                "mkdir",
                Some(&args.path),
                None,
                None,
                None,
                None,
                Some(&e.to_string()),
                Some(e.to_string()),
            );
            return Err(e.into_mcp());
        }
        let session = self
            .pool
            .get_or_connect(&host_name, None)
            .await
            .map_err(|e| e.into_mcp())?;
        sftp::mkdir(&session, &args.path, args.parents.unwrap_or(false))
            .await
            .map_err(|e| e.into_mcp())?;
        self.audit.write(
            &host_name,
            "mkdir",
            Some(&args.path),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let mut t = Toon::new();
        t.field("host", &host_name)
            .field("path", &args.path)
            .field("status", "created");
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "SFTP remove file. recursive=true for directories. Refuses sensitive system paths. Not for symlink targets — use exec.",
        annotations(
            title = "Rm",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn rm(
        &self,
        Parameters(args): Parameters<RmArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let host_name = self.resolve_host(args.host)?;
        if let Err(e) = self
            .guards()
            .for_host(&host_name)
            .check_sftp_write(&args.path)
        {
            self.audit.write(
                &host_name,
                "rm",
                Some(&args.path),
                None,
                None,
                None,
                None,
                Some(&e.to_string()),
                Some(e.to_string()),
            );
            return Err(e.into_mcp());
        }
        let recursive = args.recursive.unwrap_or(false);
        if recursive {
            // Recursive delete is one of the highest-blast-radius operations
            // this server exposes; always elicit before proceeding.
            let prompt = format!(
                "fast-mcp-ssh wants to recursively delete '{}' on host '{host_name}'. Reply 'yes' to proceed.",
                args.path
            );
            match elicit_confirmation(&ctx, &prompt).await {
                Ok(true) => {}
                Ok(false) => return Err(SshError::ConfirmationDenied.into_mcp()),
                Err(e) => {
                    tracing::warn!(?e, "rm recursive elicit failed; deny");
                    return Err(SshError::ConfirmationDenied.into_mcp());
                }
            }
        }
        let session = self
            .pool
            .get_or_connect(&host_name, None)
            .await
            .map_err(|e| e.into_mcp())?;
        let removed = sftp::remove(&session, &args.path, recursive)
            .await
            .map_err(|e| e.into_mcp())?;
        self.audit.write(
            &host_name,
            "rm",
            Some(&args.path),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let mut t = Toon::new();
        t.field("host", &host_name)
            .field("path", &args.path)
            .field("removed", removed);
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "SFTP stat path. Returns kind/size/mode/mtime/uid/gid. Use to check existence + metadata. Not for content — use dn.",
        annotations(
            title = "Stat",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn stat(
        &self,
        Parameters(args): Parameters<StatArgs>,
    ) -> Result<CallToolResult, McpError> {
        let host_name = self.resolve_host(args.host)?;
        if let Err(e) = self
            .guards()
            .for_host(&host_name)
            .check_sftp_read(&args.path)
        {
            self.audit.write(
                &host_name,
                "stat",
                Some(&args.path),
                None,
                None,
                None,
                None,
                Some(&e.to_string()),
                Some(e.to_string()),
            );
            return Err(e.into_mcp());
        }
        let session = self
            .pool
            .get_or_connect(&host_name, None)
            .await
            .map_err(|e| e.into_mcp())?;
        let s = sftp::stat(&session, &args.path)
            .await
            .map_err(|e| e.into_mcp())?;
        self.audit.write(
            &host_name,
            "stat",
            Some(&args.path),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let mut t = Toon::new();
        t.field("host", &host_name)
            .field("path", &args.path)
            .field("kind", s.kind)
            .field("size", s.size)
            .field("mode", format!("{:o}", s.mode & 0o7777))
            .field("mtime", s.mtime)
            .field("uid", s.uid as u64)
            .field("gid", s.gid as u64);
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "Read end of file (last N lines) or run `timeout N tail -F` and return the buffered output at the end. Note: MCP returns one response per call, so follow output is delivered after `seconds` elapses, not streamed.",
        annotations(
            title = "Tail",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn tail(
        &self,
        Parameters(args): Parameters<TailArgs>,
    ) -> Result<CallToolResult, McpError> {
        let host_name = self.resolve_host(args.host)?;
        let session = self
            .pool
            .get_or_connect(&host_name, None)
            .await
            .map_err(|e| e.into_mcp())?;
        let lines = args.lines.unwrap_or(100);
        let follow = args.follow.unwrap_or(false);
        let secs = Duration::from_secs(args.seconds.unwrap_or(5).clamp(1, MAX_FOLLOW_SECS));
        let max_capture = self.cfg().defaults.max_capture_bytes;
        let chunk = tail::tail(&session, &args.path, lines, follow, secs, max_capture)
            .await
            .map_err(|e| e.into_mcp())?;
        self.audit.write(
            &host_name,
            "tail",
            Some(&args.path),
            Some(chunk.exit_code),
            None,
            None,
            Some(chunk.bytes),
            None,
            None,
        );
        let mut t = Toon::new();
        t.field("host", &host_name)
            .field("path", &args.path)
            .field("bytes", chunk.bytes)
            .field("follow", follow);
        let (display, total) =
            truncate_with_hint(&chunk.content, self.cfg().defaults.truncate_bytes);
        if let Some(n) = total {
            t.field("truncated_bytes", n);
        }
        t.block("content", &display);
        Ok(text(t.into_string()))
    }
}

#[tool_handler]
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
    async fn run_guards(
        &self,
        host: &str,
        cmd: &str,
        bypass_confirm: bool,
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
                if bypass_confirm {
                    return Ok(());
                }
                let prompt = format!(
                    "fast-mcp-ssh wants to run a sensitive command on '{host}' (matches '{pattern_name}'):\n\n{cmd}\n\nReply 'yes' to proceed."
                );
                match elicit_confirmation(ctx, &prompt).await {
                    Ok(true) => Ok(()),
                    Ok(false) => Err(SshError::ConfirmationDenied),
                    Err(e) => {
                        tracing::warn!(?e, "elicitation failed; defaulting to deny (fail-closed)");
                        Err(SshError::ConfirmationDenied)
                    }
                }
            }
        }
    }

    /// Singleflight: the slot mutex is held across `PtyState::open` so two
    /// concurrent first `sh` calls can't both pay the full PTY init and then
    /// throw one away (which also burned an sshd channel slot for nothing).
    /// `interrupt` briefly contends on the same mutex during an open; the
    /// open is a couple of round-trips, so that's acceptable.
    async fn ensure_pty(
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

fn auth_str(a: AuthMethod) -> &'static str {
    match a {
        AuthMethod::Key => "key",
        AuthMethod::Agent => "agent",
        AuthMethod::Password => "password",
    }
}

fn text(s: String) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(s)])
}

fn batch_preview(r: &exec::ExecResult, verbose: bool) -> String {
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

fn format_exec(r: &exec::ExecResult, truncate: usize) -> String {
    let mut t = Toon::new();
    t.field("exit_code", r.exit_code as i64)
        .field("duration_ms", r.duration_ms as u64);
    if r.timed_out {
        t.field("timed_out", true);
    }
    if r.interrupted {
        t.field("interrupted", true);
    }
    if r.capture_capped {
        t.field("capture_capped", true);
    }
    if r.connection_lost {
        t.field("connection_lost", true);
    }
    let (stdout_disp, stdout_full) = truncate_with_hint(&r.stdout, truncate);
    let (stderr_disp, stderr_full) = truncate_with_hint(&r.stderr, truncate.min(2048));
    if let Some(n) = stdout_full {
        t.field("stdout_bytes", r.stdout_bytes)
            .field("stdout_total_bytes", n);
    }
    if let Some(n) = stderr_full {
        t.field("stderr_bytes", r.stderr_bytes)
            .field("stderr_total_bytes", n);
    }
    t.block("stdout", &stdout_disp);
    if !r.stderr.is_empty() {
        t.block("stderr", &stderr_disp);
    }
    if r.exit_code != 0 && !r.timed_out {
        t.hint("non-zero exit. inspect stderr.");
    }
    t.into_string()
}

async fn elicit_confirmation(
    ctx: &RequestContext<RoleServer>,
    prompt: &str,
) -> Result<bool, ElicitationError> {
    let resp: Option<ConfirmElicit> = ctx.peer.elicit(prompt.to_string()).await?;
    Ok(resp
        .map(|r| r.answer.trim().eq_ignore_ascii_case("yes"))
        .unwrap_or(false))
}
