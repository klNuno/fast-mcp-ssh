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
    /// Host alias. Omit if a default_host is configured.
    #[serde(default)]
    pub host: Option<String>,
    /// Command for the remote login shell. Pipes/redirects supported.
    pub cmd: String,
    #[serde(default)]
    pub timeout: Option<u64>,
    #[serde(default)]
    pub password: Option<String>,
    /// Bypass confirm prompt after seeing one.
    #[serde(default)]
    pub confirm: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ExecBatchArgs {
    #[serde(default)]
    pub host: Option<String>,
    /// Commands run in parallel on fresh exec channels (capped by max_channels_per_host).
    pub cmds: Vec<String>,
    #[serde(default)]
    pub timeout: Option<u64>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub confirm: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ShArgs {
    #[serde(default)]
    pub host: Option<String>,
    pub cmd: String,
    #[serde(default)]
    pub timeout: Option<u64>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub confirm: Option<bool>,
    /// PTY width. Default 200. Honored on first sh per host.
    #[serde(default)]
    pub cols: Option<u32>,
    /// PTY height. Default 50.
    #[serde(default)]
    pub rows: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct HostOnlyArgs {
    #[serde(default)]
    pub host: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct OptHostArgs {
    /// Host alias. Omit to query all configured hosts.
    #[serde(default)]
    pub host: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UploadArgs {
    #[serde(default)]
    pub host: Option<String>,
    pub local: String,
    pub remote: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DownloadArgs {
    #[serde(default)]
    pub host: Option<String>,
    pub remote: String,
    /// Local path. Omit to receive content inline (text < 256 KB; binary base64).
    #[serde(default)]
    pub local: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LsArgs {
    #[serde(default)]
    pub host: Option<String>,
    pub path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WriteArgs {
    #[serde(default)]
    pub host: Option<String>,
    pub remote: String,
    pub content: String,
    /// Octal mode (e.g. 420 = 0o644).
    #[serde(default)]
    pub mode: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TailArgs {
    #[serde(default)]
    pub host: Option<String>,
    pub path: String,
    #[serde(default)]
    pub lines: Option<u32>,
    #[serde(default)]
    pub follow: Option<bool>,
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

    fn resolve_host(&self, h: Option<String>) -> Result<String, McpError> {
        h.or_else(|| self.cfg.defaults.default_host.clone())
            .ok_or_else(|| McpError::invalid_params(
                "host required (or set [defaults] default_host)".to_string(),
                None,
            ))
    }

    #[tool(
        description = "List configured hosts with session state.",
        annotations(title = "Hosts", read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = false)
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
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "Run command, stateless. Returns stdout/stderr/exit_code/duration_ms.",
        annotations(title = "Exec", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true)
    )]
    async fn exec(
        &self,
        Parameters(args): Parameters<ExecArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let timeout = Duration::from_secs(args.timeout.unwrap_or(DEFAULT_TIMEOUT));
        let host_name = self.resolve_host(args.host)?;

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

        let max_capture = self.cfg.defaults.max_capture_bytes;
        let result = exec::exec(&session, &args.cmd, timeout, max_capture)
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
        description = "Run N commands in parallel on one host. One round-trip; stateless per command.",
        annotations(title = "ExecBatch", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true)
    )]
    async fn exec_batch(
        &self,
        Parameters(args): Parameters<ExecBatchArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let timeout = Duration::from_secs(args.timeout.unwrap_or(DEFAULT_TIMEOUT));
        let host_name = self.resolve_host(args.host)?;
        let bypass = args.confirm.unwrap_or(false);

        for cmd in &args.cmds {
            if let Err(e) = self.run_guards(&host_name, cmd, bypass, &ctx).await {
                self.audit.write(&host_name, "exec_batch", Some(cmd), None, None, None, None, Some(&format!("{e}")), Some(e.to_string()));
                return Err(e.into_mcp());
            }
        }

        let session = self
            .pool
            .get_or_connect(&host_name, args.password.clone())
            .await
            .map_err(|e| e.into_mcp())?;
        if let Some(pw) = args.password {
            self.pool.cache_password(&host_name, pw);
        }

        let max_capture = self.cfg.defaults.max_capture_bytes;
        let mut handles = Vec::with_capacity(args.cmds.len());
        for cmd in args.cmds.into_iter() {
            let s = Arc::clone(&session);
            handles.push(tokio::spawn(async move {
                let r = exec::exec(&s, &cmd, timeout, max_capture).await;
                (cmd, r)
            }));
        }

        let mut t = Toon::new();
        t.field("host", &host_name);
        let mut rows: Vec<Vec<String>> = Vec::new();
        for h in handles {
            match h.await {
                Ok((cmd, Ok(r))) => {
                    let preview_len = r.stdout.len().min(80);
                    let preview = r.stdout[..preview_len].replace('\n', " ");
                    rows.push(vec![
                        cmd,
                        r.exit_code.to_string(),
                        r.duration_ms.to_string(),
                        r.stdout_bytes.to_string(),
                        preview,
                    ]);
                    self.audit.write(&host_name, "exec_batch", None, Some(r.exit_code), Some(r.duration_ms), None, Some(r.stdout_bytes), None, None);
                }
                Ok((cmd, Err(e))) => {
                    rows.push(vec![cmd, "-1".into(), "0".into(), "0".into(), e.to_string()]);
                }
                Err(e) => {
                    rows.push(vec!["-".into(), "-1".into(), "0".into(), "0".into(), e.to_string()]);
                }
            }
        }
        t.table_strs("results", &["cmd", "exit", "ms", "bytes", "preview"], &rows);
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "Run command in persistent PTY. cd/export persist. Slower; use for stateful sequences.",
        annotations(title = "Sh", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true)
    )]
    async fn sh(
        &self,
        Parameters(args): Parameters<ShArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let timeout = Duration::from_secs(args.timeout.unwrap_or(DEFAULT_TIMEOUT));
        let host_name = self.resolve_host(args.host)?;

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

        let max_capture = self.cfg.defaults.max_capture_bytes;
        let opts = pty::PtyOpts {
            cols: args.cols.unwrap_or(pty::DEFAULT_PTY_COLS),
            rows: args.rows.unwrap_or(pty::DEFAULT_PTY_ROWS),
            max_capture,
        };
        let pty_state = self.ensure_pty(&session, opts).await.map_err(|e| e.into_mcp())?;
        let (output, exit_code) = pty_state.run(&args.cmd, timeout, max_capture).await.map_err(|e| e.into_mcp())?;
        session.touch();

        let bytes = output.len();
        self.audit.write(&host_name, "sh", Some(&args.cmd), Some(exit_code), None, None, Some(bytes), None, None);

        let mut t = Toon::new();
        t.field("host", &host_name);
        t.field("exit_code", exit_code as i64);
        t.field("bytes", bytes);
        let (display, _) = truncate_with_hint(&output, self.cfg.defaults.truncate_bytes);
        t.block("stdout", &display);
        if exit_code != 0 {
            t.hint("non-zero exit. cd preserved across sh calls.");
        }
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "Health check. With host probes one; without args probes all in parallel.",
        annotations(title = "Ping", read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = true)
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
        description = "Close persistent session. Reopens on next call. Use 'interrupt' for Ctrl-C.",
        annotations(title = "Disconnect", read_only_hint = false, destructive_hint = false, idempotent_hint = true, open_world_hint = false)
    )]
    async fn disconnect(
        &self,
        Parameters(args): Parameters<HostOnlyArgs>,
    ) -> Result<CallToolResult, McpError> {
        let host_name = self.resolve_host(args.host)?;
        if self.pool.list_active().iter().any(|n| n == &host_name) {
            tracing::info!(host = %host_name, "closing session");
        }
        self.pool.drop_session(&host_name);
        self.pool.forget_password(&host_name);
        self.audit.write(&host_name, "disconnect", None, None, None, None, None, None, None);
        let mut t = Toon::new();
        t.field("host", &host_name).field("status", "closed");
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "Send Ctrl-C to PTY foreground command. Keeps session.",
        annotations(title = "Interrupt", read_only_hint = false, destructive_hint = true, idempotent_hint = true, open_world_hint = true)
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
        description = "SFTP upload local→remote. Streamed, 256 KB chunks.",
        annotations(title = "Up", read_only_hint = false, destructive_hint = true, idempotent_hint = true, open_world_hint = true)
    )]
    async fn up(
        &self,
        Parameters(args): Parameters<UploadArgs>,
    ) -> Result<CallToolResult, McpError> {
        let host_name = self.resolve_host(args.host)?;
        let session = self
            .pool
            .get_or_connect(&host_name, None)
            .await
            .map_err(|e| e.into_mcp())?;
        let local = PathBuf::from(shellexpand::full(&args.local).map_err(|e| McpError::invalid_params(e.to_string(), None))?.into_owned());
        let r = sftp::upload(&session, &local, &args.remote).await.map_err(|e| e.into_mcp())?;
        self.audit.write(&host_name, "up", Some(&format!("{} -> {}", args.local, args.remote)), None, Some(r.duration_ms), Some(r.bytes), None, None, None);
        let mut t = Toon::new();
        t.field("host", &host_name)
            .field("local", &args.local)
            .field("remote", &args.remote)
            .field("bytes", r.bytes)
            .field("ms", r.duration_ms as u64);
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "SFTP download. With local= writes file; without, returns inline (text<256KB or base64).",
        annotations(title = "Dn", read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = true)
    )]
    async fn dn(
        &self,
        Parameters(args): Parameters<DownloadArgs>,
    ) -> Result<CallToolResult, McpError> {
        let host_name = self.resolve_host(args.host)?;
        let session = self
            .pool
            .get_or_connect(&host_name, None)
            .await
            .map_err(|e| e.into_mcp())?;
        let local_path = match &args.local {
            Some(s) => Some(PathBuf::from(shellexpand::full(s).map_err(|e| McpError::invalid_params(e.to_string(), None))?.into_owned())),
            None => None,
        };
        let (r, content) = sftp::download(&session, &args.remote, local_path.as_deref()).await.map_err(|e| e.into_mcp())?;
        self.audit.write(&host_name, "dn", Some(&args.remote), None, Some(r.duration_ms), None, Some(r.bytes), None, None);

        let mut t = Toon::new();
        t.field("host", &host_name)
            .field("remote", &args.remote)
            .field("bytes", r.bytes)
            .field("ms", r.duration_ms as u64);
        if let Some(buf) = content {
            if buf.len() > INLINE_MAX_BYTES {
                t.field("content", "(too large for inline; rerun with local=<path>)");
            } else if sftp::looks_binary(&buf) {
                let encoded = base64::engine::general_purpose::STANDARD.encode(&buf);
                t.field("encoding", "base64");
                t.block("content", &encoded);
            } else {
                let s = String::from_utf8_lossy(&buf);
                let (display, _) = truncate_with_hint(&s, self.cfg.defaults.truncate_bytes);
                t.block("content", &display);
            }
        } else if let Some(p) = args.local.as_deref() {
            t.field("local", p);
        }
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "SFTP list dir. Returns name/kind/size/mode/mtime.",
        annotations(title = "Ls", read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = true)
    )]
    async fn ls(
        &self,
        Parameters(args): Parameters<LsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let host_name = self.resolve_host(args.host)?;
        let session = self
            .pool
            .get_or_connect(&host_name, None)
            .await
            .map_err(|e| e.into_mcp())?;
        let entries = sftp::list_dir(&session, &args.path).await.map_err(|e| e.into_mcp())?;
        self.audit.write(&host_name, "ls", Some(&args.path), None, None, None, None, None, None);
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
        t.field("host", &host_name).field("path", &args.path);
        t.table_strs("entries", &["name", "kind", "size", "mode", "mtime"], &rows);
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "SFTP write file (replaces). Optional octal mode at create time.",
        annotations(title = "Wr", read_only_hint = false, destructive_hint = true, idempotent_hint = true, open_world_hint = true)
    )]
    async fn wr(
        &self,
        Parameters(args): Parameters<WriteArgs>,
    ) -> Result<CallToolResult, McpError> {
        let host_name = self.resolve_host(args.host)?;
        let session = self
            .pool
            .get_or_connect(&host_name, None)
            .await
            .map_err(|e| e.into_mcp())?;
        let r = sftp::write_inline(&session, &args.remote, args.content.as_bytes(), args.mode).await.map_err(|e| e.into_mcp())?;
        self.audit.write(&host_name, "wr", Some(&args.remote), None, Some(r.duration_ms), Some(r.bytes), None, None, None);
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
        description = "Tail file. follow=true streams new lines for `seconds` (default 5); else last `lines`.",
        annotations(title = "Tail", read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = true)
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
        let secs = Duration::from_secs(args.seconds.unwrap_or(5));
        let max_capture = self.cfg.defaults.max_capture_bytes;
        let chunk = tail::tail(&session, &args.path, lines, follow, secs, max_capture).await.map_err(|e| e.into_mcp())?;
        self.audit.write(&host_name, "tail", Some(&args.path), Some(chunk.exit_code), None, None, Some(chunk.bytes), None, None);
        let mut t = Toon::new();
        t.field("host", &host_name)
            .field("path", &args.path)
            .field("bytes", chunk.bytes)
            .field("follow", follow);
        let (display, total) = truncate_with_hint(&chunk.content, self.cfg.defaults.truncate_bytes);
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
        .with_instructions("SSH MCP. Run 'hosts' to list targets. exec=stateless, sh=PTY-stateful.".to_string())
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
    if r.capture_capped {
        t.field("capture_capped", true);
    }
    let (stdout_disp, stdout_full) = truncate_with_hint(&r.stdout, truncate);
    let (stderr_disp, stderr_full) = truncate_with_hint(&r.stderr, truncate.min(2048));
    if let Some(n) = stdout_full {
        t.field("stdout_total_bytes", n);
    }
    if let Some(n) = stderr_full {
        t.field("stderr_total_bytes", n);
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
