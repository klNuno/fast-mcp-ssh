use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    elicit_safe,
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
use crate::guards::{GuardCache, GuardCheck};
use crate::output::{Toon, truncate_with_hint};
use crate::session::{Session, SessionPool, exec, pty};
use crate::sftp;
use crate::tail;

const DEFAULT_TIMEOUT: u64 = 60;
const INLINE_MAX_BYTES: usize = 256 * 1024;

#[derive(Clone)]
pub struct SshServer {
    pub cfg: Arc<Config>,
    pub pool: SessionPool,
    pub audit: Arc<AuditLog>,
    pub guards: Arc<GuardCache>,
    #[allow(dead_code)]
    tool_router: ToolRouter<SshServer>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ExecArgs {
    /// Host alias from hosts.toml.
    pub host: String,
    /// Command to run. Passed to the remote login shell, so pipes/redirects work.
    pub cmd: String,
    /// Timeout in seconds (default 60).
    #[serde(default)]
    pub timeout: Option<u64>,
    /// Password for `auth = "password"` hosts. Cached in memory only.
    #[serde(default)]
    pub password: Option<String>,
    /// Force confirmation acknowledgment without elicitation. Use after a confirm prompt.
    #[serde(default)]
    pub confirm: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ShArgs {
    pub host: String,
    pub cmd: String,
    #[serde(default)]
    pub timeout: Option<u64>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub confirm: Option<bool>,
    /// Optional PTY width (cols). Default 200. Only honored on the first sh call per host.
    #[serde(default)]
    pub cols: Option<u32>,
    /// Optional PTY height (rows). Default 50. Only honored on the first sh call per host.
    #[serde(default)]
    pub rows: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct HostOnlyArgs {
    pub host: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct OptHostArgs {
    /// Host alias. Omit to query all configured hosts.
    #[serde(default)]
    pub host: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UploadArgs {
    pub host: String,
    /// Local file path on the operator machine.
    pub local: String,
    /// Remote destination path.
    pub remote: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DownloadArgs {
    pub host: String,
    pub remote: String,
    /// Local destination path. Omit to receive the file content inline (text only, < 256 KB).
    #[serde(default)]
    pub local: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LsArgs {
    pub host: String,
    pub path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WriteArgs {
    pub host: String,
    pub remote: String,
    pub content: String,
    /// Octal mode (e.g. 0o644 = 420). Optional.
    #[serde(default)]
    pub mode: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TailArgs {
    pub host: String,
    pub path: String,
    /// Lines from the end (default 100).
    #[serde(default)]
    pub lines: Option<u32>,
    /// If true, follow new lines for up to `seconds`.
    #[serde(default)]
    pub follow: Option<bool>,
    /// Max wait in seconds when follow=true (default 5).
    #[serde(default)]
    pub seconds: Option<u64>,
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
        cfg: Arc<Config>,
        pool: SessionPool,
        audit: Arc<AuditLog>,
        guards: Arc<GuardCache>,
    ) -> Self {
        Self {
            cfg,
            pool,
            audit,
            guards,
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "List configured hosts. No args. Returns name/addr/user/port plus active session state.",
        annotations(
            title = "List hosts",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false,
        )
    )]
    async fn hosts(&self) -> Result<CallToolResult, McpError> {
        let mut t = Toon::new();
        let names = self.cfg.host_names();
        if names.is_empty() {
            t.field("hosts", "none configured");
            t.hint(&format!(
                "edit {} to add hosts",
                self.cfg
                    .defaults
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
            .map(|n| {
                let h = &self.cfg.hosts[n];
                let session = if active.contains(n) { "live" } else { "idle" };
                vec![
                    n.clone(),
                    h.addr.clone(),
                    h.user.clone(),
                    h.port.to_string(),
                    auth_str(h.auth).into(),
                    session.into(),
                ]
            })
            .collect();
        t.table_strs("hosts", &["name", "addr", "user", "port", "auth", "session"], &rows);
        t.hint("exec host=<name> cmd=<...>  |  sh host=<name> cmd=<...>  |  ping");
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "Run a one-shot command on a host (stateless, parallel-safe). Returns stdout, stderr, exit_code, duration_ms. Persistent TCP+auth, no shell state between calls.",
        annotations(
            title = "Exec",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true,
        )
    )]
    async fn exec(
        &self,
        Parameters(args): Parameters<ExecArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let timeout = Duration::from_secs(args.timeout.unwrap_or(DEFAULT_TIMEOUT));
        let host_name = args.host.clone();

        if let Err(e) = self.run_guards(&host_name, &args.cmd, args.confirm.unwrap_or(false), &ctx).await {
            self.audit.write(&host_name, "exec", Some(&args.cmd), None, None, None, None, Some(&format!("{e}")), Some(e.to_string()));
            return Err(e.into_mcp());
        }
        let session = self
            .pool
            .get_or_connect(&host_name, args.password.clone())
            .await
            .map_err(|e| { self.audit.write(&host_name, "exec", Some(&args.cmd), None, None, None, None, None, Some(e.to_string())); e.into_mcp() })?;
        if let Some(pw) = args.password {
            self.pool.cache_password(&host_name, pw);
        }

        let result = exec::exec(&session, &args.cmd, timeout)
            .await
            .map_err(|e| { self.audit.write(&host_name, "exec", Some(&args.cmd), None, None, None, None, None, Some(e.to_string())); e.into_mcp() })?;

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
        Ok(text(format_exec(&result, self.cfg.defaults.truncate_bytes)))
    }

    #[tool(
        description = "Run a command in the persistent PTY shell on a host. cd, export, history persist between calls. Slower & less parallel-safe than exec — use for stateful sequences only.",
        annotations(
            title = "Shell (stateful)",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true,
        )
    )]
    async fn sh(
        &self,
        Parameters(args): Parameters<ShArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let timeout = Duration::from_secs(args.timeout.unwrap_or(DEFAULT_TIMEOUT));
        let host_name = args.host.clone();

        if let Err(e) = self.run_guards(&host_name, &args.cmd, args.confirm.unwrap_or(false), &ctx).await {
            self.audit.write(&host_name, "sh", Some(&args.cmd), None, None, None, None, Some(&format!("{e}")), Some(e.to_string()));
            return Err(e.into_mcp());
        }

        let session = self
            .pool
            .get_or_connect(&host_name, args.password.clone())
            .await
            .map_err(|e| e.into_mcp())?;
        if let Some(pw) = args.password {
            self.pool.cache_password(&host_name, pw);
        }

        let opts = pty::PtyOpts {
            cols: args.cols.unwrap_or(pty::DEFAULT_PTY_COLS),
            rows: args.rows.unwrap_or(pty::DEFAULT_PTY_ROWS),
        };
        let pty_state = self.ensure_pty(&session, opts).await.map_err(|e| e.into_mcp())?;
        let (output, exit_code) = pty_state.run(&args.cmd, timeout).await.map_err(|e| e.into_mcp())?;
        session.touch();

        let bytes = output.len();
        self.audit.write(&host_name, "sh", Some(&args.cmd), Some(exit_code), None, None, Some(bytes), None, None);

        let mut t = Toon::new();
        t.field("host", &host_name);
        t.field("exit_code", exit_code as i64);
        t.field("bytes", bytes);
        let (display, _) = truncate_with_hint(&output, self.cfg.defaults.truncate_bytes);
        t.raw_line("stdout: |");
        for line in display.lines() {
            t.raw_line(&format!("  {line}"));
        }
        if exit_code != 0 {
            t.hint("non-zero exit. cd is preserved across sh calls.");
        }
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "Health check. With host=<name> probes that host. With no args, probes all configured hosts in parallel.",
        annotations(
            title = "Ping",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true,
        )
    )]
    async fn ping(
        &self,
        Parameters(args): Parameters<OptHostArgs>,
    ) -> Result<CallToolResult, McpError> {
        let targets: Vec<String> = match args.host {
            Some(h) => vec![h],
            None => self.cfg.host_names(),
        };
        let mut handles = Vec::new();
        for name in targets {
            let pool = self.pool.clone();
            handles.push(tokio::spawn(async move {
                let start = std::time::Instant::now();
                let res = pool.get_or_connect(&name, None).await;
                let elapsed = start.elapsed().as_millis() as u64;
                match res {
                    Ok(_) => (name, "ok".to_string(), elapsed, None),
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
        description = "Close the persistent PTY + SSH session for a host. Frees the connection. Reopens automatically on next call. (Use 'interrupt' to send Ctrl-C without closing.)",
        annotations(
            title = "Disconnect session",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false,
        )
    )]
    async fn disconnect(
        &self,
        Parameters(args): Parameters<HostOnlyArgs>,
    ) -> Result<CallToolResult, McpError> {
        let host_name = args.host.clone();
        if let Some(s) = self.pool.list_active().iter().find(|n| **n == host_name) {
            tracing::info!(host = %s, "closing session");
        }
        self.pool.drop_session(&host_name);
        self.pool.forget_password(&host_name);
        self.audit.write(&host_name, "disconnect", None, None, None, None, None, None, None);
        let mut t = Toon::new();
        t.field("host", &host_name).field("status", "closed");
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "Send Ctrl-C (SIGINT) to the foreground command on the persistent PTY. Use to abort a long-running 'sh' command without dropping the session.",
        annotations(
            title = "Interrupt PTY",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = true,
        )
    )]
    async fn interrupt(
        &self,
        Parameters(args): Parameters<HostOnlyArgs>,
    ) -> Result<CallToolResult, McpError> {
        let host_name = args.host.clone();
        let session = match self.pool.get(&host_name) {
            Some(s) => s,
            None => {
                let mut t = Toon::new();
                t.field("host", &host_name).field("status", "no active session");
                return Ok(text(t.into_string()));
            }
        };
        let pty_state = {
            let guard = session.pty.lock().await;
            guard.as_ref().map(Arc::clone)
        };
        let mut t = Toon::new();
        t.field("host", &host_name);
        match pty_state {
            Some(p) => {
                p.interrupt().await.map_err(|e| e.into_mcp())?;
                self.audit.write(&host_name, "interrupt", None, None, None, None, None, None, None);
                t.field("status", "sigint sent");
            }
            None => {
                t.field("status", "no pty open");
            }
        }
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "Upload a local file to a remote host via SFTP. Persistent connection.",
        annotations(
            title = "Upload",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = true,
        )
    )]
    async fn up(
        &self,
        Parameters(args): Parameters<UploadArgs>,
    ) -> Result<CallToolResult, McpError> {
        let session = self
            .pool
            .get_or_connect(&args.host, None)
            .await
            .map_err(|e| e.into_mcp())?;
        let local = PathBuf::from(shellexpand::full(&args.local).map_err(|e| McpError::invalid_params(e.to_string(), None))?.into_owned());
        let r = sftp::upload(&session, &local, &args.remote).await.map_err(|e| e.into_mcp())?;
        self.audit.write(&args.host, "up", Some(&format!("{} -> {}", args.local, args.remote)), None, Some(r.duration_ms), Some(r.bytes), None, None, None);
        let mut t = Toon::new();
        t.field("host", &args.host)
            .field("local", &args.local)
            .field("remote", &args.remote)
            .field("bytes", r.bytes)
            .field("ms", r.duration_ms as u64);
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "Download a remote file via SFTP. With local= writes to disk; without, returns the content inline (text under 256 KB; binary returned base64-encoded).",
        annotations(
            title = "Download",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true,
        )
    )]
    async fn dn(
        &self,
        Parameters(args): Parameters<DownloadArgs>,
    ) -> Result<CallToolResult, McpError> {
        let session = self
            .pool
            .get_or_connect(&args.host, None)
            .await
            .map_err(|e| e.into_mcp())?;
        let local_path = match &args.local {
            Some(s) => Some(PathBuf::from(shellexpand::full(s).map_err(|e| McpError::invalid_params(e.to_string(), None))?.into_owned())),
            None => None,
        };
        let (r, content) = sftp::download(&session, &args.remote, local_path.as_deref()).await.map_err(|e| e.into_mcp())?;
        self.audit.write(&args.host, "dn", Some(&args.remote), None, Some(r.duration_ms), None, Some(r.bytes), None, None);

        let mut t = Toon::new();
        t.field("host", &args.host)
            .field("remote", &args.remote)
            .field("bytes", r.bytes)
            .field("ms", r.duration_ms as u64);
        if let Some(buf) = content {
            if buf.len() > INLINE_MAX_BYTES {
                t.field("content", "(too large for inline; rerun with local=<path>)");
            } else if sftp::looks_binary(&buf) {
                let encoded = base64::engine::general_purpose::STANDARD.encode(&buf);
                t.field("encoding", "base64");
                t.raw_line("content: |");
                for chunk in encoded.as_bytes().chunks(76) {
                    t.raw_line(&format!("  {}", String::from_utf8_lossy(chunk)));
                }
            } else {
                let s = String::from_utf8_lossy(&buf);
                let (display, _) = truncate_with_hint(&s, self.cfg.defaults.truncate_bytes);
                t.raw_line("content: |");
                for line in display.lines() {
                    t.raw_line(&format!("  {line}"));
                }
            }
        } else if let Some(p) = args.local.as_deref() {
            t.field("local", p);
        }
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "List a remote directory via SFTP. Returns name/kind/size/mode/mtime.",
        annotations(
            title = "List directory",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true,
        )
    )]
    async fn ls(
        &self,
        Parameters(args): Parameters<LsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let session = self
            .pool
            .get_or_connect(&args.host, None)
            .await
            .map_err(|e| e.into_mcp())?;
        let entries = sftp::list_dir(&session, &args.path).await.map_err(|e| e.into_mcp())?;
        self.audit.write(&args.host, "ls", Some(&args.path), None, None, None, None, None, None);
        let rows: Vec<Vec<String>> = entries
            .iter()
            .map(|e| vec![
                e.name.clone(),
                e.kind.into(),
                e.size.to_string(),
                format!("{:o}", e.mode & 0o7777),
                e.mtime.to_string(),
            ])
            .collect();
        let mut t = Toon::new();
        t.field("host", &args.host).field("path", &args.path);
        t.table_strs("entries", &["name", "kind", "size", "mode", "mtime"], &rows);
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "Write a file inline on the remote host via SFTP (replaces any existing file). Optional octal mode.",
        annotations(
            title = "Write file",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = true,
        )
    )]
    async fn wr(
        &self,
        Parameters(args): Parameters<WriteArgs>,
    ) -> Result<CallToolResult, McpError> {
        let session = self
            .pool
            .get_or_connect(&args.host, None)
            .await
            .map_err(|e| e.into_mcp())?;
        let r = sftp::write_inline(&session, &args.remote, args.content.as_bytes(), args.mode).await.map_err(|e| e.into_mcp())?;
        self.audit.write(&args.host, "wr", Some(&args.remote), None, Some(r.duration_ms), Some(r.bytes), None, None, None);
        let mut t = Toon::new();
        t.field("host", &args.host)
            .field("remote", &args.remote)
            .field("bytes", r.bytes)
            .field("ms", r.duration_ms as u64);
        if let Some(m) = args.mode {
            t.field("mode", format!("{m:o}"));
        }
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "Tail a remote file. follow=true streams new lines for `seconds` (default 5). follow=false (default) returns the last `lines` lines.",
        annotations(
            title = "Tail file",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true,
        )
    )]
    async fn tail(
        &self,
        Parameters(args): Parameters<TailArgs>,
    ) -> Result<CallToolResult, McpError> {
        let session = self
            .pool
            .get_or_connect(&args.host, None)
            .await
            .map_err(|e| e.into_mcp())?;
        let lines = args.lines.unwrap_or(100);
        let follow = args.follow.unwrap_or(false);
        let secs = Duration::from_secs(args.seconds.unwrap_or(5));
        let chunk = tail::tail(&session, &args.path, lines, follow, secs).await.map_err(|e| e.into_mcp())?;
        self.audit.write(&args.host, "tail", Some(&args.path), Some(chunk.exit_code), None, None, Some(chunk.bytes), None, None);
        let mut t = Toon::new();
        t.field("host", &args.host)
            .field("path", &args.path)
            .field("bytes", chunk.bytes)
            .field("follow", follow);
        let (display, total) = truncate_with_hint(&chunk.content, self.cfg.defaults.truncate_bytes);
        if let Some(n) = total {
            t.field("truncated_bytes", n);
        }
        t.raw_line("content: |");
        for line in display.lines() {
            t.raw_line(&format!("  {line}"));
        }
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
            "Fast SSH MCP server. Persistent connections per host. \
             Tools: hosts, exec (stateless), sh (PTY persistent state), ping, disconnect, interrupt, up, dn, ls, wr, tail. \
             Output is TOON-formatted. Run `hosts` first to discover available targets."
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
        let guards = self.guards.for_host(host);
        match guards.check(cmd) {
            GuardCheck::Allow => Ok(()),
            GuardCheck::Deny { pattern_name, pattern } => Err(SshError::BlockedByGuard { name: pattern_name, pattern }),
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

    async fn ensure_pty(
        &self,
        session: &Arc<Session>,
        opts: pty::PtyOpts,
    ) -> Result<Arc<pty::PtyState>, SshError> {
        let mut guard = session.pty.lock().await;
        if let Some(state) = guard.as_ref() {
            return Ok(Arc::clone(state));
        }
        let new_state = Arc::new(pty::PtyState::open(session, opts).await?);
        *guard = Some(Arc::clone(&new_state));
        Ok(new_state)
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
    CallToolResult::success(vec![Content::text(s)])
}

fn format_exec(r: &exec::ExecResult, truncate: usize) -> String {
    let mut t = Toon::new();
    t.field("exit_code", r.exit_code as i64)
        .field("duration_ms", r.duration_ms as u64)
        .field("stdout_bytes", r.stdout_bytes)
        .field("stderr_bytes", r.stderr_bytes);
    if r.timed_out {
        t.field("timed_out", true);
    }
    let (stdout_disp, stdout_full) = truncate_with_hint(&r.stdout, truncate);
    let (stderr_disp, stderr_full) = truncate_with_hint(&r.stderr, truncate.min(2048));
    if let Some(n) = stdout_full {
        t.field("stdout_total_bytes", n);
    }
    if let Some(n) = stderr_full {
        t.field("stderr_total_bytes", n);
    }
    t.raw_line("stdout: |");
    for line in stdout_disp.lines() {
        t.raw_line(&format!("  {line}"));
    }
    if !r.stderr.is_empty() {
        t.raw_line("stderr: |");
        for line in stderr_disp.lines() {
            t.raw_line(&format!("  {line}"));
        }
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
