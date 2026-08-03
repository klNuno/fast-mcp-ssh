//! Host introspection tools: `facts`, `sys`, `svc`.
//!
//! Every probe here runs a machine-readable invocation rather than the
//! human-facing one. `df -PT -B1` instead of `df -h`, `systemctl show
//! --property=...` instead of `systemctl status`, `journalctl -o json`
//! instead of the pager format. Column-aligned human output is what models
//! mis-parse, and re-emitting it costs tokens that carry no information.

use std::collections::BTreeMap;

use rmcp::{
    ErrorData as McpError, RoleServer, handler::server::wrapper::Parameters, model::*, schemars,
    service::RequestContext, tool, tool_router,
};
use serde::Deserialize;

use crate::audit::AuditRecord;
use crate::errors::SshError;
use crate::output::Toon;
use crate::server::SshServer;
use crate::session::exec;
use crate::tools::{clamp_timeout, shell_quote, text};

/// Probe script for `facts`. POSIX sh only: it has to run under dash, ash and
/// busybox, not just bash. Emits `key=value` lines and never fails the call,
/// so a missing tool yields an absent key rather than a non-zero exit.
pub(crate) const FACTS_PROBE: &str = r#"
p() { printf '%s=%s\n' "$1" "$2"; }
p os "$(uname -s 2>/dev/null)"
p kernel "$(uname -r 2>/dev/null)"
p arch "$(uname -m 2>/dev/null)"
p hostname "$(uname -n 2>/dev/null)"
if [ -r /etc/os-release ]; then
  . /etc/os-release 2>/dev/null
  p distro "${ID:-}"
  p distro_version "${VERSION_ID:-}"
fi
[ -r /proc/uptime ] && p uptime_s "$(cut -d' ' -f1 /proc/uptime 2>/dev/null)"
p cpus "$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null)"
if [ -r /proc/meminfo ]; then
  p mem_total_kb "$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null)"
  p mem_avail_kb "$(awk '/^MemAvailable:/{print $2}' /proc/meminfo 2>/dev/null)"
fi
p root_free_kb "$(df -Pk / 2>/dev/null | awk 'NR==2{print $4}')"
if [ -d /run/systemd/system ]; then p init systemd
elif [ -d /run/openrc ]; then p init openrc
elif [ -x /sbin/init ]; then p init sysv
fi
for m in apt-get dnf yum apk pacman zypper brew; do
  command -v "$m" >/dev/null 2>&1 && { p pkg_mgr "$m"; break; }
done
p shell "$(basename "${SHELL:-sh}" 2>/dev/null)"
if [ -f /.dockerenv ]; then p container docker
elif grep -qi microsoft /proc/sys/kernel/osrelease 2>/dev/null; then p container wsl
elif grep -qa 'lxc\|docker\|containerd' /proc/1/cgroup 2>/dev/null; then p container yes
else p container none
fi
if sudo -n true >/dev/null 2>&1; then p sudo_nopasswd yes; else p sudo_nopasswd no; fi
h=
# Every name another tool gates on has to be in this list, or that tool reads
# the absence as "not installed" and refuses on a host that has it: `sys
# what=net` did exactly that for `ss`, on every host, and `shot` never picked
# `spectacle`.
for c in rg rsync tmux screen python3 node jq git docker podman systemctl ss curl wget tar zstd sha256sum grim scrot import gnome-screenshot spectacle; do
  command -v "$c" >/dev/null 2>&1 && h="$h,$c"
done
p has "${h#,}"
"#;

/// Cached per-host profile. Every other tool that has to pick between two
/// backends (ripgrep or grep, docker or podman, which screenshot binary
/// exists) reads this instead of probing again.
#[derive(Debug, Clone, Default)]
pub struct HostFacts {
    pub fields: BTreeMap<String, String>,
}

impl HostFacts {
    fn parse(raw: &str) -> Self {
        let mut fields = BTreeMap::new();
        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let v = v.trim();
                if !v.is_empty() {
                    fields.insert(k.trim().to_string(), v.to_string());
                }
            }
        }
        Self { fields }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(|s| s.as_str())
    }

    /// True when the remote has the named binary on `PATH`, per the probe.
    pub fn has(&self, tool: &str) -> bool {
        self.get("has")
            .map(|list| list.split(',').any(|t| t == tool))
            .unwrap_or(false)
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FactsArgs {
    /// Host alias. Omit if a default_host is configured.
    #[serde(default)]
    pub host: Option<String>,
    /// Re-probe instead of returning the cached profile.
    #[serde(default)]
    pub refresh: Option<bool>,
}

#[derive(Debug, Clone, Copy, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum SysView {
    /// Processes by CPU share.
    Ps,
    /// Filesystem usage in bytes.
    Df,
    /// Memory and swap from /proc/meminfo.
    Mem,
    /// Listening TCP and UDP sockets with owning process.
    Net,
    /// Directory sizes under `path`, largest first.
    Du,
    /// Logged-in users.
    Who,
    /// Load average and PSI pressure stalls.
    Load,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SysArgs {
    /// Host alias. Omit if a default_host is configured.
    #[serde(default)]
    pub host: Option<String>,
    /// Which view to return.
    pub what: SysView,
    /// Row cap for ps/du/who. Default 15.
    #[serde(default)]
    pub top: Option<u32>,
    /// Directory for `du`. Default "/".
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum SvcAction {
    Status,
    Logs,
    Start,
    Stop,
    Restart,
    Reload,
    Enable,
    Disable,
    /// List units in a failed state. `unit` is ignored.
    Failed,
}

impl SvcAction {
    fn is_mutating(self) -> bool {
        matches!(
            self,
            SvcAction::Start
                | SvcAction::Stop
                | SvcAction::Restart
                | SvcAction::Reload
                | SvcAction::Enable
                | SvcAction::Disable
        )
    }

    fn verb(self) -> &'static str {
        match self {
            SvcAction::Start => "start",
            SvcAction::Stop => "stop",
            SvcAction::Restart => "restart",
            SvcAction::Reload => "reload",
            SvcAction::Enable => "enable",
            SvcAction::Disable => "disable",
            _ => "",
        }
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SvcArgs {
    /// Host alias. Omit if a default_host is configured.
    #[serde(default)]
    pub host: Option<String>,
    /// systemd unit name. Required for every action except `failed`.
    #[serde(default)]
    pub unit: Option<String>,
    /// What to do. Default `status`.
    #[serde(default)]
    pub action: Option<SvcAction>,
    /// Journal lines for `logs`. Default 50, max 500.
    #[serde(default)]
    pub lines: Option<u32>,
}

/// Properties pulled by `svc status`. `systemctl show --value` returns them
/// one per line in this exact order, with an empty line for anything unset,
/// so the parse is positional and needs no key matching.
const SVC_PROPS: &[&str] = &[
    "LoadState",
    "ActiveState",
    "SubState",
    "UnitFileState",
    "MainPID",
    "MemoryCurrent",
    "TasksCurrent",
    "ActiveEnterTimestamp",
    "Result",
];

/// Rejects unit names that could break out of the shell word they are
/// interpolated into. systemd unit names use a narrow character set, so this
/// costs nothing legitimate.
fn validate_unit(unit: &str) -> Result<(), McpError> {
    if unit.is_empty() || unit.len() > 256 {
        return Err(SshError::Config("unit name empty or too long".into()).into_mcp());
    }
    let ok = unit
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | ':' | '\\'));
    if !ok {
        return Err(SshError::Config(format!(
            "refusing unit name with shell metacharacters: {unit}"
        ))
        .into_mcp());
    }
    Ok(())
}

#[tool_router(router = ops_router, vis = "pub")]
impl SshServer {
    #[tool(
        description = "Cached host profile: os, kernel, cpus, memory, disk, init, package manager, container kind, sudo, installed tools. Run once instead of a dozen probe execs.",
        annotations(
            title = "Facts",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn facts(
        &self,
        Parameters(args): Parameters<FactsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let host_name = self.resolve_host(args.host)?;
        let refresh = args.refresh.unwrap_or(false);
        let facts = self.host_facts(&host_name, refresh).await?;

        let mut t = Toon::new();
        t.field("host", host_name.as_str());
        for (k, v) in &facts.fields {
            if k == "has" {
                continue;
            }
            t.field(k, v.as_str());
        }
        if let Some(h) = facts.get("has") {
            t.field("has", h);
        }
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "Structured system state: ps, df, mem, net, du, who, load. Parsed tables, not the human output of top/free.",
        annotations(
            title = "Sys",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn sys(&self, Parameters(args): Parameters<SysArgs>) -> Result<CallToolResult, McpError> {
        let host_name = self.resolve_host(args.host)?;
        let top = args.top.unwrap_or(15).clamp(1, 200);
        let session = self
            .pool
            .get_or_connect(&host_name, None)
            .await
            .map_err(|e| e.into_mcp())?;
        let max_capture = self.cfg().defaults.max_capture_bytes;
        let timeout = clamp_timeout(Some(30));

        let cmd = match args.what {
            SysView::Ps => format!(
                "ps -eo pid,ppid,user,pcpu,pmem,rss,etimes,stat,comm --sort=-pcpu --no-headers 2>/dev/null | head -n {top}"
            ),
            SysView::Df => "df -PT -B1 2>/dev/null | tail -n +2".to_string(),
            SysView::Mem => {
                "awk '/^(MemTotal|MemFree|MemAvailable|Buffers|Cached|SwapTotal|SwapFree|Dirty):/{print $1, $2}' /proc/meminfo 2>/dev/null"
                    .to_string()
            }
            SysView::Net => {
                // Alpine ships without iproute2, and `ss` missing looks exactly
                // like "nothing is listening" once stderr is swallowed. Say so
                // instead of returning an empty table.
                if !self.host_facts(&host_name, false).await?.has("ss") {
                    return Err(SshError::Config(format!(
                        "`ss` is not installed on '{host_name}', so the net view has no source \
                         (Alpine: apk add iproute2). Use exec with netstat if that is all the host has."
                    ))
                    .into_mcp());
                }
                "{ ss -ltnpH 2>/dev/null; ss -lunpH 2>/dev/null; } | head -n 200".to_string()
            }
            SysView::Du => {
                let path = args.path.as_deref().unwrap_or("/");
                format!(
                    "du -x -d 1 -B1 {} 2>/dev/null | sort -rn | head -n {top}",
                    shell_quote(path)
                )
            }
            SysView::Who => format!("who -u 2>/dev/null | head -n {top}"),
            SysView::Load => {
                "cat /proc/loadavg 2>/dev/null; for f in cpu io memory; do [ -r /proc/pressure/$f ] && sed \"s/^/$f /\" /proc/pressure/$f; done 2>/dev/null"
                    .to_string()
            }
        };

        let r = exec::exec(&session, &cmd, timeout, max_capture)
            .await
            .map_err(|e| e.into_mcp())?;
        self.audit.write(
            &host_name,
            "sys",
            AuditRecord {
                cmd: Some(&cmd),
                exit_code: Some(r.exit_code),
                bytes_out: Some(r.stdout_bytes),
                ..Default::default()
            },
        );

        let mut t = Toon::new();
        t.field("host", host_name.as_str());
        match args.what {
            SysView::Ps => {
                let rows = split_columns(&r.stdout, 9);
                t.table_strs(
                    "ps",
                    &[
                        "pid", "ppid", "user", "cpu", "mem", "rss", "secs", "stat", "comm",
                    ],
                    &rows,
                );
            }
            SysView::Df => {
                let rows = split_columns(&r.stdout, 7);
                t.table_strs(
                    "df",
                    &["fs", "type", "bytes", "used", "avail", "pct", "mount"],
                    &rows,
                );
            }
            SysView::Mem => {
                for line in r.stdout.lines() {
                    if let Some((k, v)) = line.trim().split_once(' ') {
                        t.field(k.trim_end_matches(':'), v.trim());
                    }
                }
                t.hint("values in kB");
            }
            SysView::Net => {
                let rows = parse_ss(&r.stdout);
                t.table_strs("listening", &["proto", "local", "process"], &rows);
            }
            SysView::Du => {
                let rows = split_columns(&r.stdout, 2);
                t.table_strs("du", &["bytes", "path"], &rows);
            }
            SysView::Who => {
                let rows = split_columns(&r.stdout, 5);
                t.table_strs("who", &["user", "tty", "date", "time", "idle"], &rows);
            }
            SysView::Load => {
                t.block("load", r.stdout.trim());
            }
        }
        if r.stdout.trim().is_empty() && !r.stderr.trim().is_empty() {
            t.field("stderr", r.stderr.trim());
        }
        Ok(text(t.into_string()))
    }

    #[tool(
        description = "systemd units: status, logs, start, stop, restart, reload, enable, disable, failed. Parsed properties and JSON journal, never pager output.",
        annotations(
            title = "Svc",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn svc(
        &self,
        Parameters(args): Parameters<SvcArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let host_name = self.resolve_host(args.host)?;
        let action = args.action.unwrap_or(SvcAction::Status);
        let lines = args.lines.unwrap_or(50).clamp(1, 500);

        let unit = match (&args.unit, action) {
            (_, SvcAction::Failed) => String::new(),
            (Some(u), _) => {
                validate_unit(u)?;
                u.clone()
            }
            (None, _) => {
                return Err(SshError::Config(
                    "unit is required for every action except 'failed'".into(),
                )
                .into_mcp());
            }
        };

        let cmd = match action {
            SvcAction::Failed => {
                "systemctl list-units --state=failed --no-legend --plain 2>/dev/null".to_string()
            }
            SvcAction::Status => format!(
                "systemctl show {} --property={} --value 2>/dev/null",
                shell_quote(&unit),
                SVC_PROPS.join(",")
            ),
            SvcAction::Logs => format!(
                "journalctl -u {} -n {lines} -o json --no-pager 2>/dev/null",
                shell_quote(&unit)
            ),
            a => format!("systemctl {} {}", a.verb(), shell_quote(&unit)),
        };

        // Mutating actions go through the guard chain like any other command,
        // so `systemctl stop` still trips the default confirm pattern.
        if action.is_mutating()
            && let Err(e) = self.run_guards(&host_name, &cmd, &ctx).await
        {
            self.audit.write(
                &host_name,
                "svc",
                AuditRecord::blocked(&cmd, &e.to_string()),
            );
            return Err(e.into_mcp());
        }

        let session = self
            .pool
            .get_or_connect(&host_name, None)
            .await
            .map_err(|e| e.into_mcp())?;
        let max_capture = self.cfg().defaults.max_capture_bytes;
        let timeout = clamp_timeout(Some(60));

        // Capture the pre-state so a restart that lands in `failed` can be
        // reported as such without a second round trip from the caller.
        let before = if action == SvcAction::Restart || action == SvcAction::Start {
            unit_active_state(&session, &unit, max_capture).await
        } else {
            None
        };

        let r = exec::exec(&session, &cmd, timeout, max_capture)
            .await
            .map_err(|e| e.into_mcp())?;
        self.audit.write(
            &host_name,
            "svc",
            AuditRecord {
                cmd: Some(&cmd),
                exit_code: Some(r.exit_code),
                bytes_out: Some(r.stdout_bytes),
                ..Default::default()
            },
        );

        let mut t = Toon::new();
        t.field("host", host_name.as_str());
        match action {
            SvcAction::Failed => {
                let rows = split_columns(&r.stdout, 4);
                if rows.is_empty() {
                    t.field("failed", "none");
                } else {
                    t.table_strs("failed", &["unit", "load", "active", "sub"], &rows);
                }
            }
            SvcAction::Status => {
                t.field("unit", unit.as_str());
                for (name, value) in SVC_PROPS.iter().zip(r.stdout.lines()) {
                    let v = value.trim();
                    if !v.is_empty() && v != "[not set]" {
                        t.field(&camel_to_snake(name), v);
                    }
                }
            }
            SvcAction::Logs => {
                let rows = parse_journal_json(&r.stdout);
                t.table_strs("lines", &["ts", "prio", "msg"], &rows);
            }
            _ => {
                t.field("unit", unit.as_str());
                t.field("action", action.verb());
                t.field("exit", r.exit_code);
                // A restart that succeeds at the systemctl level but lands in
                // `failed` is the most common follow-up question. Answer it
                // here instead of making the caller ask.
                if let Some(state) = unit_active_state(&session, &unit, max_capture).await {
                    t.field("active", state.as_str());
                    if let Some(prev) = before {
                        t.field("active_before", prev.as_str());
                    }
                    if state == "failed" {
                        let tail = format!(
                            "journalctl -u {} -n 30 -o cat --no-pager 2>/dev/null",
                            shell_quote(&unit)
                        );
                        if let Ok(j) = exec::exec(&session, &tail, timeout, max_capture).await {
                            t.block("journal_tail", j.stdout.trim());
                        }
                    }
                }
                if !r.stderr.trim().is_empty() {
                    t.field("stderr", r.stderr.trim());
                }
            }
        }
        Ok(text(t.into_string()))
    }
}

/// One `systemctl show` round trip for the single property worth polling
/// after a mutating action. Returns `None` when systemd is not the init.
async fn unit_active_state(
    session: &crate::session::Session,
    unit: &str,
    max_capture: usize,
) -> Option<String> {
    let cmd = format!(
        "systemctl show {} --property=ActiveState --value 2>/dev/null",
        shell_quote(unit)
    );
    let r = exec::exec(
        session,
        &cmd,
        std::time::Duration::from_secs(15),
        max_capture,
    )
    .await
    .ok()?;
    let s = r.stdout.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// Splits whitespace-separated output into rows of `cols` fields, with the
/// last column absorbing the remaining whitespace so paths and command lines
/// survive intact. Short rows are padded so the table stays rectangular.
fn split_columns(out: &str, cols: usize) -> Vec<Vec<String>> {
    out.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|line| {
            let head: Vec<String> = line
                .split_whitespace()
                .take(cols.saturating_sub(1))
                .map(str::to_string)
                .collect();
            let rest: String = line
                .split_whitespace()
                .skip(head.len())
                .collect::<Vec<_>>()
                .join(" ");
            let mut fields = head;
            if !rest.is_empty() {
                fields.push(rest);
            }
            while fields.len() < cols {
                fields.push("-".to_string());
            }
            fields.truncate(cols);
            fields
        })
        .collect()
}

/// `ss -ltnpH` emits `State Recv-Q Send-Q Local Peer Process`. Only the
/// address and the owning process carry information for a caller asking what
/// is listening.
fn parse_ss(out: &str) -> Vec<Vec<String>> {
    out.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let local = f.get(3)?;
            let proto = if line.contains("UNCONN") {
                "udp"
            } else {
                "tcp"
            };
            let process = f
                .get(5)
                .copied()
                .unwrap_or("-")
                .trim_start_matches("users:((")
                .trim_end_matches("))");
            Some(vec![
                proto.to_string(),
                (*local).to_string(),
                process.to_string(),
            ])
        })
        .collect()
}

/// journald emits about thirty fields per entry. Three of them answer the
/// question the caller actually asked.
fn parse_journal_json(out: &str) -> Vec<Vec<String>> {
    out.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|line| {
            let v: serde_json::Value = serde_json::from_str(line).ok()?;
            let ts = v
                .get("__REALTIME_TIMESTAMP")
                .and_then(|t| t.as_str())
                .and_then(|t| t.parse::<i64>().ok())
                .map(format_epoch_us)
                .unwrap_or_else(|| "-".into());
            let prio = v
                .get("PRIORITY")
                .and_then(|p| p.as_str())
                .unwrap_or("-")
                .to_string();
            let msg = match v.get("MESSAGE") {
                Some(serde_json::Value::String(s)) => s.clone(),
                // journald returns a byte array when the message is not valid
                // UTF-8. Rendering it lossily beats dropping the line.
                Some(serde_json::Value::Array(a)) => String::from_utf8_lossy(
                    &a.iter()
                        .filter_map(|b| b.as_u64().map(|n| n as u8))
                        .collect::<Vec<u8>>(),
                )
                .into_owned(),
                _ => return None,
            };
            Some(vec![ts, prio, msg])
        })
        .collect()
}

/// Microseconds since the epoch to RFC 3339.
fn format_epoch_us(us: i64) -> String {
    let secs = us / 1_000_000;
    time::OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|d| {
            d.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| secs.to_string())
}

/// `ActiveState` to `active_state`, `MainPID` to `main_pid`. An underscore
/// goes in only at a lower-to-upper boundary or before the final capital of
/// an acronym run, so `PID` does not become `p_i_d`.
fn camel_to_snake(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len() + 4);
    for (i, &c) in chars.iter().enumerate() {
        if c.is_ascii_uppercase() && i != 0 {
            let prev_lower = chars[i - 1].is_ascii_lowercase() || chars[i - 1].is_ascii_digit();
            let next_lower = chars.get(i + 1).is_some_and(|n| n.is_ascii_lowercase());
            if prev_lower || next_lower {
                out.push('_');
            }
        }
        out.push(c.to_ascii_lowercase());
    }
    out
}

impl SshServer {
    /// Returns the cached profile for `host`, probing once when absent or
    /// when `refresh` is set. Shared by every tool that has to choose a
    /// backend.
    pub(crate) async fn host_facts(
        &self,
        host: &str,
        refresh: bool,
    ) -> Result<HostFacts, McpError> {
        if !refresh && let Some(f) = self.facts_cache.get(host) {
            return Ok(f.clone());
        }
        let session = self
            .pool
            .get_or_connect(host, None)
            .await
            .map_err(|e| e.into_mcp())?;
        let max_capture = self.cfg().defaults.max_capture_bytes;
        let r = exec::exec(
            &session,
            FACTS_PROBE,
            std::time::Duration::from_secs(30),
            max_capture,
        )
        .await
        .map_err(|e| e.into_mcp())?;
        let facts = HostFacts::parse(&r.stdout);
        if facts.fields.is_empty() {
            return Err(SshError::Other(format!(
                "host profile probe returned nothing (exit {}): {}",
                r.exit_code,
                r.stderr.trim()
            ))
            .into_mcp());
        }
        self.facts_cache.insert(host.to_string(), facts.clone());
        Ok(facts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_probe_output() {
        let f = HostFacts::parse("os=Linux\nkernel=6.1.0\nhas=rg,jq\nempty=\n\ndistro=debian\n");
        assert_eq!(f.get("os"), Some("Linux"));
        assert_eq!(f.get("distro"), Some("debian"));
        assert_eq!(f.get("empty"), None);
        assert!(f.has("rg"));
        assert!(f.has("jq"));
        assert!(!f.has("r"));
        assert!(!f.has("docker"));
    }

    #[test]
    fn probe_value_may_contain_equals() {
        let f = HostFacts::parse("cmdline=a=b=c\n");
        assert_eq!(f.get("cmdline"), Some("a=b=c"));
    }

    #[test]
    fn splits_columns_keeping_tail() {
        let rows = split_columns("1 2 root 0.5 0.1 100 20 S my command here\n", 9);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].len(), 9);
        assert_eq!(rows[0][8], "my command here");
    }

    #[test]
    fn splits_columns_pads_short_rows() {
        let rows = split_columns("only two\n", 5);
        assert_eq!(rows[0], vec!["only", "two", "-", "-", "-"]);
    }

    #[test]
    fn splits_columns_handles_runs_of_spaces() {
        let rows = split_columns("a    b     c\n", 3);
        assert_eq!(rows[0], vec!["a", "b", "c"]);
    }

    #[test]
    fn parses_ss_listening() {
        let out = "LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n\
                   UNCONN 0 0 0.0.0.0:68 0.0.0.0:* users:((\"dhclient\",pid=2,fd=6))\n";
        let rows = parse_ss(out);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0][0], "tcp");
        assert_eq!(rows[0][1], "0.0.0.0:22");
        assert!(rows[0][2].contains("sshd"));
        assert_eq!(rows[1][0], "udp");
    }

    #[test]
    fn parses_journal_json_lines() {
        let out = "{\"__REALTIME_TIMESTAMP\":\"1700000000000000\",\"PRIORITY\":\"6\",\"MESSAGE\":\"started\"}\n\
                   {\"PRIORITY\":\"3\",\"MESSAGE\":\"boom\"}\n\
                   not json\n";
        let rows = parse_journal_json(out);
        assert_eq!(rows.len(), 2);
        assert!(rows[0][0].starts_with("2023-11-14"));
        assert_eq!(rows[0][2], "started");
        assert_eq!(rows[1][0], "-");
        assert_eq!(rows[1][2], "boom");
    }

    #[test]
    fn parses_journal_binary_message() {
        let out = r#"{"PRIORITY":"6","MESSAGE":[104,105]}"#;
        let rows = parse_journal_json(out);
        assert_eq!(rows[0][2], "hi");
    }

    #[test]
    fn rejects_unit_with_metacharacters() {
        assert!(validate_unit("nginx.service").is_ok());
        assert!(validate_unit("getty@tty1.service").is_ok());
        assert!(validate_unit("a; rm -rf /").is_err());
        assert!(validate_unit("$(id)").is_err());
        assert!(validate_unit("").is_err());
    }

    /// Extract the binary names the probe actually looks for, so a test can
    /// assert a gate and the probe agree.
    fn probed_binaries() -> Vec<&'static str> {
        FACTS_PROBE
            .lines()
            .find(|l| l.trim_start().starts_with("for c in "))
            .expect("probe has a `for c in` loop")
            .trim()
            .trim_start_matches("for c in ")
            .trim_end_matches("; do")
            .split_whitespace()
            .collect()
    }

    #[test]
    fn every_gated_binary_is_actually_probed() {
        // `sys what=net` gates on `has("ss")`. `ss` was missing from the probe,
        // so the view refused on every host, installed or not.
        let probed = probed_binaries();
        assert!(probed.contains(&"ss"), "probed: {probed:?}");
    }

    #[test]
    fn probe_reports_a_binary_it_looks_for() {
        let f = HostFacts::parse("has=ss,jq\n");
        assert!(f.has("ss"));
        assert!(!f.has("spectacle"));
    }

    #[test]
    fn camel_to_snake_property_names() {
        assert_eq!(camel_to_snake("ActiveState"), "active_state");
        assert_eq!(camel_to_snake("MainPID"), "main_pid");
        assert_eq!(camel_to_snake("SubState"), "sub_state");
        assert_eq!(camel_to_snake("Result"), "result");
    }
}
