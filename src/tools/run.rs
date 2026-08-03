//! Command execution tools: `exec`, `exec_batch`, `sh`, `interrupt`.

use std::sync::Arc;

use rmcp::{
    ErrorData as McpError, RoleServer, handler::server::wrapper::Parameters, model::*, schemars,
    service::RequestContext, tool, tool_router,
};
use serde::Deserialize;

use crate::audit::AuditRecord;
use crate::errors::SshError;
use crate::guards::{CompiledGuards, GuardCheck};
use crate::output::{Toon, truncate_with_hint};
use crate::server::{SshServer, elicit_confirmation};
use crate::session::{exec, pty};
use crate::tools::{
    HostOnlyArgs, MAX_BATCH_CMDS, batch_preview, clamp_timeout, text, validate_cmd,
};

// Intentionally no `Debug` derive: the `password` field would otherwise leak
// in clear text if anyone added `tracing::debug!(?args)` later.
#[derive(Deserialize, schemars::JsonSchema)]
pub struct ExecArgs {
    /// Host alias. Omit if a default_host is configured.
    #[serde(default)]
    pub host: Option<String>,
    /// Command for the remote login shell. Pipes/redirects supported.
    pub cmd: String,
    /// Per-call timeout in whole seconds. Default 60, max 600.
    #[serde(default)]
    pub timeout: Option<u64>,
    /// Password for password-auth hosts. Cached in memory after first call.
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct ExecBatchArgs {
    /// Host alias. Omit if a default_host is configured.
    #[serde(default)]
    pub host: Option<String>,
    /// Commands run in parallel on fresh exec channels (capped by max_channels_per_host).
    pub cmds: Vec<String>,
    /// Per-call timeout in whole seconds, applied to each command. Default 60, max 600.
    #[serde(default)]
    pub timeout: Option<u64>,
    /// Password for password-auth hosts. Cached after first call.
    #[serde(default)]
    pub password: Option<String>,
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
    /// Per-call timeout in whole seconds. Default 60, max 600.
    #[serde(default)]
    pub timeout: Option<u64>,
    /// Password for password-auth hosts. Cached after first call.
    #[serde(default)]
    pub password: Option<String>,
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

#[tool_router(router = run_router, vis = "pub")]
impl SshServer {
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

        if let Err(e) = self.run_guards(&host_name, &args.cmd, &ctx).await {
            self.audit.write(
                &host_name,
                "exec",
                AuditRecord::blocked(&args.cmd, &e.to_string()),
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
                    AuditRecord::failed(&args.cmd, e.to_string()),
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
                    AuditRecord::failed(&args.cmd, e.to_string()),
                );
                e.into_mcp()
            })?;

        self.audit.write(
            &host_name,
            "exec",
            AuditRecord {
                cmd: Some(&args.cmd),
                exit_code: Some(result.exit_code),
                duration_ms: Some(result.duration_ms),
                bytes_out: Some(result.stdout_bytes + result.stderr_bytes),
                ..Default::default()
            },
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
        let verbose = args.verbose.unwrap_or(false);
        let password = args.password.map(zeroize::Zeroizing::new);

        // Guard the whole batch up front. Confirm elicitations are still
        // deduplicated by pattern name so a batch of twenty `systemctl stop`
        // does not become twenty prompts, but the prompt now lists every
        // command the approval covers. Showing one command and silently
        // approving the rest is exactly what `confirm_remembered` refuses to
        // do on the single-command path.
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
                    if confirmed.contains(&pattern_name) || self.confirm_remembered(&host_name, cmd)
                    {
                        None
                    } else {
                        let covered = covered_by_pattern(&guards, &args.cmds, &pattern_name);
                        let prompt = confirm_batch_prompt(&host_name, &pattern_name, &covered);
                        match elicit_confirmation(&ctx, &prompt).await {
                            Ok(true) => {
                                // Remember each covered command on its own key,
                                // so the approval the user actually read is the
                                // approval that gets replayed.
                                for c in &covered {
                                    self.remember_confirm(&host_name, c);
                                }
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
                self.audit.write(
                    &host_name,
                    "exec_batch",
                    AuditRecord::blocked(cmd, &e.to_string()),
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
        // Bound the fan-out to the host's own channel budget. Spawning all 64
        // allowed commands against a default `max_channels_per_host = 8` meant
        // the overflow sat in `acquire_channel` and died at its 15s timeout
        // with `ChannelLimit` — a queue reported as a failure. One slot is
        // left for the session's SFTP subsystem and PTY.
        let fanout = Arc::new(tokio::sync::Semaphore::new(
            session.max_channels().saturating_sub(1).max(1),
        ));
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
            let gate = Arc::clone(&fanout);
            let abort = set.spawn(async move {
                let _slot = gate
                    .acquire_owned()
                    .await
                    .map_err(|_| SshError::Other("batch fan-out semaphore closed".into()))?;
                exec::exec(&s, &cmd_for_task, timeout, max_capture).await
            });
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
                        AuditRecord {
                            cmd: Some(&cmd),
                            exit_code: Some(r.exit_code),
                            duration_ms: Some(r.duration_ms),
                            bytes_out: Some(r.stdout_bytes),
                            ..Default::default()
                        },
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
                        AuditRecord::failed(&cmd, err_msg.clone()),
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
                        AuditRecord::failed(&cmd, err_msg.clone()),
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

        if let Err(e) = self.run_guards(&host_name, &args.cmd, &ctx).await {
            self.audit.write(
                &host_name,
                "sh",
                AuditRecord::blocked(&args.cmd, &e.to_string()),
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
        let (output, exit_code) = match pty_state.run(&args.cmd, timeout, max_capture).await {
            Ok(v) => v,
            Err(e) => {
                // A run that never saw its sentinel leaves unread bytes in the
                // channel. Keeping the shell would splice them onto the next
                // call's output; drop it so the next `sh` opens a clean one.
                self.evict_broken_pty(&session, args.shell.as_deref(), &e)
                    .await;
                self.audit.write(
                    &host_name,
                    "sh",
                    AuditRecord::failed(&args.cmd, e.to_string()),
                );
                return Err(e.into_mcp());
            }
        };
        session.touch();

        let bytes = output.len();
        self.audit.write(
            &host_name,
            "sh",
            AuditRecord {
                cmd: Some(&args.cmd),
                exit_code: Some(exit_code),
                bytes_out: Some(bytes),
                ..Default::default()
            },
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
        self.audit
            .write(&host_name, "interrupt", AuditRecord::default());
        t.field("pty_sigint", pty_acted);
        t.field("exec_aborted", exec_aborted as u64);
        if !pty_acted && exec_aborted == 0 {
            t.field("status", "no in-flight commands");
        } else {
            t.field("status", "interrupt fired");
        }
        Ok(text(t.into_string()))
    }
}

/// Every command in the batch that the same confirm pattern would stop, in
/// submission order. This is the set one approval waives, so it is also the
/// set the prompt has to show.
fn covered_by_pattern(guards: &CompiledGuards, cmds: &[String], pattern_name: &str) -> Vec<String> {
    cmds.iter()
        .filter(|c| {
            matches!(
                guards.check(c),
                GuardCheck::Confirm { pattern_name: ref p } if p == pattern_name
            )
        })
        .cloned()
        .collect()
}

/// Elicitation text for a batch confirmation. Lists every command covered so
/// the operator approves what they can actually see; a single-command batch
/// reads like the single-command prompt.
fn confirm_batch_prompt(host: &str, pattern_name: &str, covered: &[String]) -> String {
    let listed = covered
        .iter()
        .map(|c| format!("  - {c}"))
        .collect::<Vec<_>>()
        .join("\n");
    if covered.len() == 1 {
        return format!(
            "fast-mcp-ssh wants to run a sensitive command on '{host}' (matches '{pattern_name}'):\n\n{}\n\nReply 'yes' to proceed.",
            covered[0]
        );
    }
    format!(
        "fast-mcp-ssh wants to run {} sensitive commands on '{host}' (all match '{pattern_name}'):\n\n{listed}\n\nReplying 'yes' approves all {} of them. Reply 'yes' to proceed.",
        covered.len(),
        covered.len()
    )
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Guards;

    fn guards() -> CompiledGuards {
        CompiledGuards::compile(&Guards::default()).expect("default guards compile")
    }

    #[test]
    fn covered_set_is_every_command_the_pattern_stops() {
        let cmds: Vec<String> = [
            "systemctl stop nginx",
            "ls -la /etc",
            "systemctl stop firewalld",
            "reboot",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let covered = covered_by_pattern(&guards(), &cmds, "systemctl-stop");
        assert_eq!(
            covered,
            vec!["systemctl stop nginx", "systemctl stop firewalld"]
        );
    }

    #[test]
    fn batch_prompt_names_every_command_it_approves() {
        // The whole point of the fix: approving `stop nginx` must not silently
        // approve `stop firewalld` behind a prompt that never showed it.
        let covered = vec![
            "systemctl stop nginx".to_string(),
            "systemctl stop firewalld".to_string(),
        ];
        let prompt = confirm_batch_prompt("box1", "systemctl-stop", &covered);
        assert!(prompt.contains("systemctl stop nginx"), "got: {prompt}");
        assert!(prompt.contains("systemctl stop firewalld"), "got: {prompt}");
        assert!(prompt.contains("approves all 2"), "got: {prompt}");
    }

    #[test]
    fn single_command_batch_reads_like_the_single_command_prompt() {
        let covered = vec!["reboot".to_string()];
        let prompt = confirm_batch_prompt("box1", "reboot", &covered);
        assert!(prompt.contains("a sensitive command"), "got: {prompt}");
        assert!(!prompt.contains("approves all"), "got: {prompt}");
    }
}
