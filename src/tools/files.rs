//! Filesystem tools: `ls`, `stat`, `dn`, `up`, `wr`, `mkdir`, `rm`, `tail`.

use std::path::PathBuf;
use std::time::Duration;

use base64::Engine;
use rmcp::{
    ErrorData as McpError, RoleServer, handler::server::wrapper::Parameters, model::*, schemars,
    service::RequestContext, tool, tool_router,
};
use serde::Deserialize;

use crate::errors::SshError;
use crate::output::{Toon, truncate_with_hint};
use crate::server::{SshServer, elicit_confirmation};
use crate::sftp;
use crate::tail;
use crate::tools::{
    INLINE_MAX_BYTES, MAX_FOLLOW_SECS, MAX_LS_ENTRIES, MAX_WRITE_INLINE_BYTES, text,
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
