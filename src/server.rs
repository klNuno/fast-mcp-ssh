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
/// Hard cap on per-call timeouts. Prevents an AI-supplied `timeout=u64::MAX`
/// from holding a channel slot indefinitely.
const MAX_TIMEOUT_SECS: u64 = 600;
const MAX_FOLLOW_SECS: u64 = 600;
const INLINE_MAX_BYTES: usize = 256 * 1024;

fn clamp_timeout(t: Option<u64>) -> Duration {
    Duration::from_secs(t.unwrap_or(DEFAULT_TIMEOUT).clamp(1, MAX_TIMEOUT_SECS))
}

#[derive(Clone)]
pub struct SshServer {
    pub cfg: Arc<Config>,
    pub pool: SessionPool,
    pub audit: Arc<AuditLog>,
    pub guards: Arc<GuardCache>,
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
            .ok_or_else(|| {
                SshError::Config("host required (or set [defaults] default_host)".to_string())
                    .into_mcp()
            })
    }

    #[tool(
        description = "List configured hosts with session state. Run this first to discover targets.",
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
            .filter_map(|n| {
                let h = self.cfg.hosts.get(n)?;
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
        t.table_strs("hosts", &["name", "addr", "user", "port", "auth", "session"], &rows);
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "Run one-shot command, stateless. Use for independent or parallelizable commands. Not for cd/export/source — use sh.",
        annotations(title = "Exec", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true)
    )]
    async fn exec(
        &self,
        Parameters(args): Parameters<ExecArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let timeout = clamp_timeout(args.timeout);
        let host_name = self.resolve_host(args.host)?;

        if let Err(e) = self.run_guards(&host_name, &args.cmd, args.confirm.unwrap_or(false), &ctx).await {
            let err_msg = e.to_string();
            self.audit.write(&host_name, "exec", Some(&args.cmd), None, None, None, None, Some(&err_msg), Some(err_msg.clone()));
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
        description = "Run N parallel commands on one host in one round-trip. Use for independent fan-out (probes, status checks). Not for sequential pipelines — use sh.",
        annotations(title = "ExecBatch", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true)
    )]
    async fn exec_batch(
        &self,
        Parameters(args): Parameters<ExecBatchArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let timeout = clamp_timeout(args.timeout);
        let host_name = self.resolve_host(args.host)?;
        let bypass = args.confirm.unwrap_or(false);
        let verbose = args.verbose.unwrap_or(false);

        for cmd in &args.cmds {
            if let Err(e) = self.run_guards(&host_name, cmd, bypass, &ctx).await {
                let err_msg = e.to_string();
                self.audit.write(&host_name, "exec_batch", Some(cmd), None, None, None, None, Some(&err_msg), Some(err_msg.clone()));
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
        // JoinSet aborts in-flight tasks when dropped, so a request cancelled
        // by the client doesn't leave commands running on the remote host.
        let mut set = tokio::task::JoinSet::new();
        for cmd in args.cmds.into_iter() {
            let s = Arc::clone(&session);
            set.spawn(async move {
                let r = exec::exec(&s, &cmd, timeout, max_capture).await;
                (cmd, r)
            });
        }

        let mut t = Toon::new();
        t.field("host", &host_name);
        let mut rows: Vec<Vec<String>> = Vec::new();
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok((cmd, Ok(r))) => {
                    let preview = batch_preview(&r, verbose);
                    self.audit.write(&host_name, "exec_batch", Some(&cmd), Some(r.exit_code), Some(r.duration_ms), None, Some(r.stdout_bytes), None, None);
                    rows.push(vec![
                        cmd,
                        r.exit_code.to_string(),
                        r.duration_ms.to_string(),
                        r.stdout_bytes.to_string(),
                        preview,
                    ]);
                }
                Ok((cmd, Err(e))) => {
                    let err_msg = e.to_string();
                    self.audit.write(&host_name, "exec_batch", Some(&cmd), None, None, None, None, None, Some(err_msg.clone()));
                    rows.push(vec![cmd, "-1".into(), "0".into(), "0".into(), err_msg]);
                }
                Err(e) => {
                    let err_msg = e.to_string();
                    self.audit.write(&host_name, "exec_batch", None, None, None, None, None, None, Some(err_msg.clone()));
                    rows.push(vec!["-".into(), "-1".into(), "0".into(), "0".into(), err_msg]);
                }
            }
        }
        t.table_strs("results", &["cmd", "exit", "ms", "bytes", "preview"], &rows);
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "Stateful PTY shell. Use for cd/export/activate venv/sequential pipelines. Not for parallel work — use exec_batch.",
        annotations(title = "Sh", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true)
    )]
    async fn sh(
        &self,
        Parameters(args): Parameters<ShArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let timeout = clamp_timeout(args.timeout);
        let host_name = self.resolve_host(args.host)?;

        if let Err(e) = self.run_guards(&host_name, &args.cmd, args.confirm.unwrap_or(false), &ctx).await {
            let err_msg = e.to_string();
            self.audit.write(&host_name, "sh", Some(&args.cmd), None, None, None, None, Some(&err_msg), Some(err_msg.clone()));
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
        description = "TCP+SSH+auth liveness probe. Use to verify reachability before exec/sftp. With host probes one; without args probes all in parallel. Password arg only honored when host is specified.",
        annotations(title = "Ping", read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = true)
    )]
    async fn ping(
        &self,
        Parameters(args): Parameters<OptHostArgs>,
    ) -> Result<CallToolResult, McpError> {
        let (targets, password): (Vec<String>, Option<String>) = match args.host {
            Some(h) => (vec![h], args.password),
            None => (self.cfg.host_names(), None),
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
        annotations(title = "Disconnect", read_only_hint = false, destructive_hint = false, idempotent_hint = true, open_world_hint = false)
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
        self.audit.write(&host_name, "disconnect", None, None, None, None, None, None, None);
        let mut t = Toon::new();
        t.field("host", &host_name).field("status", "closed");
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "Send Ctrl-C (SIGINT) to the PTY foreground command. Use to stop a runaway sh command. Keeps session and shell state. Not for full disconnect — use disconnect.",
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
        description = "SFTP upload local→remote, streamed in 256 KB chunks. Use for transferring local files to remote. Not for inline content — use wr.",
        annotations(title = "Up", read_only_hint = false, destructive_hint = true, idempotent_hint = true, open_world_hint = true)
    )]
    async fn up(
        &self,
        Parameters(args): Parameters<UploadArgs>,
    ) -> Result<CallToolResult, McpError> {
        let host_name = self.resolve_host(args.host)?;
        if let Err(e) = self.guards.for_host(&host_name).check_sftp_write(&args.remote) {
            self.audit.write(&host_name, "up", Some(&args.remote), None, None, None, None, Some(&e.to_string()), Some(e.to_string()));
            return Err(e.into_mcp());
        }
        let session = self
            .pool
            .get_or_connect(&host_name, None)
            .await
            .map_err(|e| e.into_mcp())?;
        let local = PathBuf::from(shellexpand::tilde(&args.local).into_owned());
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
        description = "SFTP download remote file. With local=<path> writes to disk; without returns inline (text<256KB or base64). Use for fetching files. Not for tailing logs — use tail.",
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
        let local_path = args
            .local
            .as_deref()
            .map(|s| PathBuf::from(shellexpand::tilde(s).into_owned()));
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
        description = "SFTP list directory. Use for browsing remote filesystem. Returns name/kind/size/mode/mtime. Not for shell glob — use exec with `ls`.",
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
        description = "SFTP write inline content to remote file (replaces). Use instead of `echo > file` via exec. Atomic mode set at create time.",
        annotations(title = "Wr", read_only_hint = false, destructive_hint = true, idempotent_hint = true, open_world_hint = true)
    )]
    async fn wr(
        &self,
        Parameters(args): Parameters<WriteArgs>,
    ) -> Result<CallToolResult, McpError> {
        let host_name = self.resolve_host(args.host)?;
        if let Err(e) = self.guards.for_host(&host_name).check_sftp_write(&args.remote) {
            self.audit.write(&host_name, "wr", Some(&args.remote), None, None, None, None, Some(&e.to_string()), Some(e.to_string()));
            return Err(e.into_mcp());
        }
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
        description = "Read end of file (last N lines) or stream new lines for N seconds. Use for logs and live debugging. Not for `tail -F` via sh — that blocks the PTY.",
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
        let secs = Duration::from_secs(args.seconds.unwrap_or(5).clamp(1, MAX_FOLLOW_SECS));
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
        // Fast path: cached PTY.
        if let Some(state) = session.pty.lock().await.as_ref() {
            return Ok(Arc::clone(state));
        }
        // Slow path: do the multi-second `PtyState::open` *outside* the
        // option-mutex so concurrent `interrupt`/`disconnect` and other tools
        // touching `session.pty` don't block on it. A racing sibling that
        // also opens a PTY simply discards its channel — rare and cheap.
        let new_state = Arc::new(pty::PtyState::open(session, opts).await?);
        let mut guard = session.pty.lock().await;
        if let Some(existing) = guard.as_ref() {
            return Ok(Arc::clone(existing));
        }
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

fn batch_preview(r: &exec::ExecResult, verbose: bool) -> String {
    let (src, max) = if r.exit_code != 0 {
        let stderr_trimmed = r.stderr.trim();
        let s: &str = if !stderr_trimmed.is_empty() { stderr_trimmed } else { r.stdout.as_str() };
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
