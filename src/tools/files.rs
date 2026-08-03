//! Filesystem tools: `ls`, `stat`, `dn`, `up`, `cp`, `wr`, `mkdir`, `rm`, `tail`.

use std::time::Duration;

use base64::Engine;
use rmcp::{
    ErrorData as McpError, RoleServer, handler::server::wrapper::Parameters, model::*, schemars,
    service::RequestContext, tool, tool_router,
};
use serde::Deserialize;

use crate::audit::AuditRecord;
use crate::errors::SshError;
use crate::guards;
use crate::output::{Toon, truncate_with_hint};
use crate::server::{SshServer, elicit_confirmation};
use crate::sftp;
use crate::tail;
use crate::tools::{
    INLINE_MAX_BYTES, MAX_FOLLOW_SECS, MAX_LS_ENTRIES, MAX_WRITE_INLINE_BYTES, shell_quote, text,
};

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
pub struct CopyArgs {
    /// Source host alias.
    pub from_host: String,
    /// Source path on `from_host`.
    pub from: String,
    /// Destination host alias. May be the same as `from_host`.
    pub to_host: String,
    /// Destination path on `to_host`. Parent dir must exist.
    pub to: String,
    /// Compare sha256 on both hosts after the copy. Default true.
    #[serde(default)]
    pub verify: Option<bool>,
    /// Octal mode at create time (e.g. 420 = 0o644). Default: the source mode.
    #[serde(default)]
    pub mode: Option<u32>,
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

#[tool_router(router = files_router, vis = "pub")]
impl SshServer {
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
                AuditRecord::blocked(&args.remote, &e.to_string()),
            );
            return Err(e.into_mcp());
        }
        let session = self
            .pool
            .get_or_connect(&host_name, None)
            .await
            .map_err(|e| e.into_mcp())?;
        self.guard_resolved(&host_name, "up", &session, &args.remote, true)
            .await?;
        // The local side is the operator's own box: without this, `up` is an
        // exfiltration primitive pointed at ~/.ssh or a browser cookie store.
        let local = guards::resolve_local_path(&args.local);
        if let Err(e) = guards::check_local_read(&local) {
            self.audit.write(
                &host_name,
                "up",
                AuditRecord::blocked(&args.local, &e.to_string()),
            );
            return Err(e.into_mcp());
        }
        let r = sftp::upload(&session, &local, &args.remote)
            .await
            .map_err(|e| e.into_mcp())?;
        self.audit.write(
            &host_name,
            "up",
            AuditRecord {
                cmd: Some(&format!("{} -> {}", args.local, args.remote)),
                duration_ms: Some(r.duration_ms),
                bytes_in: Some(r.bytes),
                ..Default::default()
            },
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
                AuditRecord::blocked(&args.remote, &e.to_string()),
            );
            return Err(e.into_mcp());
        }
        let session = self
            .pool
            .get_or_connect(&host_name, None)
            .await
            .map_err(|e| e.into_mcp())?;
        self.guard_resolved(&host_name, "dn", &session, &args.remote, false)
            .await?;
        // Remote-controlled bytes landing on the operator's own filesystem:
        // a `dn` into ~/.bashrc or an autostart folder is code execution here.
        let local_path = args.local.as_deref().map(guards::resolve_local_path);
        if let Some(p) = local_path.as_deref()
            && let Err(e) = guards::check_local_write(p)
        {
            let reason = e.to_string();
            self.audit.write(
                &host_name,
                "dn",
                AuditRecord {
                    cmd: args.local.as_deref(),
                    blocked: Some(&reason),
                    error: Some(reason.clone()),
                    ..Default::default()
                },
            );
            return Err(e.into_mcp());
        }
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
            AuditRecord {
                cmd: Some(&args.remote),
                duration_ms: Some(r.duration_ms),
                bytes_out: Some(r.bytes),
                ..Default::default()
            },
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
        description = "Copy a file host→host over SFTP without touching local disk. Use when both hosts are configured, even if they cannot reach each other. Not for local↔remote — use up/dn.",
        annotations(
            title = "Cp",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn cp(&self, Parameters(args): Parameters<CopyArgs>) -> Result<CallToolResult, McpError> {
        let from_host = self.resolve_host(Some(args.from_host))?;
        let to_host = self.resolve_host(Some(args.to_host))?;
        // Both ends are guarded by the host they belong to: reading
        // /etc/shadow is refused by the source's bank, and landing a payload
        // in the destination's authorized_keys by the destination's.
        if let Err(e) = self
            .guards()
            .for_host(&from_host)
            .check_sftp_read(&args.from)
        {
            self.audit.write(
                &from_host,
                "cp",
                AuditRecord::blocked(&args.from, &e.to_string()),
            );
            return Err(e.into_mcp());
        }
        if let Err(e) = self.guards().for_host(&to_host).check_sftp_write(&args.to) {
            self.audit.write(
                &to_host,
                "cp",
                AuditRecord::blocked(&args.to, &e.to_string()),
            );
            return Err(e.into_mcp());
        }
        let (src, dst) = tokio::try_join!(
            self.pool.get_or_connect(&from_host, None),
            self.pool.get_or_connect(&to_host, None),
        )
        .map_err(|e| e.into_mcp())?;
        self.guard_resolved(&from_host, "cp", &src, &args.from, false)
            .await?;
        self.guard_resolved(&to_host, "cp", &dst, &args.to, true)
            .await?;

        let r = sftp::copy_between(&src, &args.from, &dst, &args.to, args.mode)
            .await
            .map_err(|e| e.into_mcp())?;

        let mut t = Toon::new();
        t.field("from", format!("{from_host}:{}", args.from))
            .field("to", format!("{to_host}:{}", args.to))
            .field("bytes", r.bytes)
            .field("ms", r.duration_ms as u64);
        if r.duration_ms > 0 {
            let mbps = (r.bytes as f64 / 1_048_576.0) / (r.duration_ms as f64 / 1000.0);
            t.field("mbps", format!("{mbps:.1}"));
        }
        // Hashing on both hosts rather than on the bytes in flight: those came
        // out of one buffer, so they can only prove the buffer agrees with
        // itself. This catches a short write at the destination.
        if args.verify.unwrap_or(true) {
            match self
                .sha256_pair(&from_host, &src, &args.from, &to_host, &dst, &args.to)
                .await
            {
                Ok((a, b)) if a == b => {
                    t.field("verified", true).field("sha256", &a);
                }
                Ok((a, b)) => {
                    let msg = format!("sha256 mismatch: {from_host} {a}, {to_host} {b}");
                    self.audit
                        .write(&to_host, "cp", AuditRecord::blocked(&args.to, &msg));
                    return Err(SshError::Other(msg).into_mcp());
                }
                // A missing `sha256sum` is not a reason to fail a copy that
                // otherwise succeeded, but it must not silently read as verified.
                Err(why) => {
                    t.field("verified", false).field("verify_skipped", &why);
                }
            }
        }
        self.audit.write(
            &to_host,
            "cp",
            AuditRecord {
                cmd: Some(&format!("{from_host}:{} -> {}", args.from, args.to)),
                duration_ms: Some(r.duration_ms),
                bytes_in: Some(r.bytes),
                ..Default::default()
            },
        );
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
                AuditRecord::blocked(&args.path, &e.to_string()),
            );
            return Err(e.into_mcp());
        }
        let session = self
            .pool
            .get_or_connect(&host_name, None)
            .await
            .map_err(|e| e.into_mcp())?;
        self.guard_resolved(&host_name, "ls", &session, &args.path, false)
            .await?;
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
        self.audit
            .write(&host_name, "ls", AuditRecord::cmd(&args.path));
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
                AuditRecord::blocked(&args.remote, &e.to_string()),
            );
            return Err(e.into_mcp());
        }
        let session = self
            .pool
            .get_or_connect(&host_name, None)
            .await
            .map_err(|e| e.into_mcp())?;
        self.guard_resolved(&host_name, "wr", &session, &args.remote, true)
            .await?;
        let r = sftp::write_inline(&session, &args.remote, args.content.as_bytes(), args.mode)
            .await
            .map_err(|e| e.into_mcp())?;
        self.audit.write(
            &host_name,
            "wr",
            AuditRecord {
                cmd: Some(&args.remote),
                duration_ms: Some(r.duration_ms),
                bytes_in: Some(r.bytes),
                ..Default::default()
            },
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
                AuditRecord::blocked(&args.path, &e.to_string()),
            );
            return Err(e.into_mcp());
        }
        let session = self
            .pool
            .get_or_connect(&host_name, None)
            .await
            .map_err(|e| e.into_mcp())?;
        self.guard_resolved(&host_name, "mkdir", &session, &args.path, true)
            .await?;
        sftp::mkdir(&session, &args.path, args.parents.unwrap_or(false))
            .await
            .map_err(|e| e.into_mcp())?;
        self.audit
            .write(&host_name, "mkdir", AuditRecord::cmd(&args.path));
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
                AuditRecord::blocked(&args.path, &e.to_string()),
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
        self.guard_resolved(&host_name, "rm", &session, &args.path, true)
            .await?;
        let removed = sftp::remove(&session, &args.path, recursive)
            .await
            .map_err(|e| e.into_mcp())?;
        self.audit
            .write(&host_name, "rm", AuditRecord::cmd(&args.path));
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
                AuditRecord::blocked(&args.path, &e.to_string()),
            );
            return Err(e.into_mcp());
        }
        let session = self
            .pool
            .get_or_connect(&host_name, None)
            .await
            .map_err(|e| e.into_mcp())?;
        self.guard_resolved(&host_name, "stat", &session, &args.path, false)
            .await?;
        let s = sftp::stat(&session, &args.path)
            .await
            .map_err(|e| e.into_mcp())?;
        self.audit
            .write(&host_name, "stat", AuditRecord::cmd(&args.path));
        let mut t = Toon::new();
        t.field("host", &host_name)
            .field("path", &args.path)
            .field("kind", s.kind)
            .field("size", s.size)
            .field("mode", format!("{:o}", s.mode & 0o7777))
            .field("mtime", s.mtime)
            .field("uid", s.uid as u64)
            .field("gid", s.gid as u64);
        if let Some(link_target) = &s.target {
            t.field("target", link_target);
        }
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
        // `tail` reads a remote file just as much as `dn` does, and it shipped
        // with no guard at all: `tail path=/etc/shadow lines=5000` walked
        // straight past the sensitive-read list that every other read tool
        // enforces. Same two checks as `dn`, string then resolved.
        if let Err(e) = self
            .guards()
            .for_host(&host_name)
            .check_sftp_read(&args.path)
        {
            self.audit.write(
                &host_name,
                "tail",
                AuditRecord::blocked(&args.path, &e.to_string()),
            );
            return Err(e.into_mcp());
        }
        let session = self
            .pool
            .get_or_connect(&host_name, None)
            .await
            .map_err(|e| e.into_mcp())?;
        self.guard_resolved(&host_name, "tail", &session, &args.path, false)
            .await?;
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
            AuditRecord {
                cmd: Some(&args.path),
                exit_code: Some(chunk.exit_code),
                bytes_out: Some(chunk.bytes),
                ..Default::default()
            },
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

impl SshServer {
    /// sha256 of both files, computed by the hosts themselves and in parallel.
    /// `Err(reason)` means the digest could not be taken at all, which the
    /// caller reports as unverified rather than as a failed copy.
    async fn sha256_pair(
        &self,
        from_host: &str,
        src: &crate::session::Session,
        from: &str,
        to_host: &str,
        dst: &crate::session::Session,
        to: &str,
    ) -> Result<(String, String), String> {
        let timeout = Duration::from_secs(120);
        let cap = self.cfg().defaults.max_capture_bytes;
        // `shasum` is the macOS spelling; the fallback costs nothing when the
        // first one exists.
        let cmd = |path: &str| {
            let q = shell_quote(path);
            format!("sha256sum -- {q} 2>/dev/null || shasum -a 256 -- {q}")
        };
        let (cmd_from, cmd_to) = (cmd(from), cmd(to));
        let (a, b) = tokio::join!(
            crate::session::exec::exec(src, &cmd_from, timeout, cap),
            crate::session::exec::exec(dst, &cmd_to, timeout, cap),
        );
        let parse = |r: crate::errors::Result<crate::session::exec::ExecResult>| {
            let r = r.map_err(|e| e.to_string())?;
            if r.exit_code != 0 {
                return Err(format!("sha256sum unavailable (exit {})", r.exit_code));
            }
            r.stdout
                .split_whitespace()
                .next()
                .filter(|h| h.len() == 64)
                .map(str::to_string)
                .ok_or_else(|| "unparseable sha256sum output".to_string())
        };
        match (parse(a), parse(b)) {
            (Ok(a), Ok(b)) => Ok((a, b)),
            (Err(e), _) => Err(format!("{from_host}: {e}")),
            (_, Err(e)) => Err(format!("{to_host}: {e}")),
        }
    }
}
