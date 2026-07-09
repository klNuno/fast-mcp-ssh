use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;

use regex::{Regex, RegexSet};

use crate::config::{Config, Guards, NamedPattern, default_confirm_patterns, default_deny_patterns};
use crate::errors::{Result, SshError};

#[derive(Debug, Clone)]
pub struct CompiledPattern {
    pub name: String,
    pub re: Regex,
}

/// Vector of named patterns + a `RegexSet` over the same patterns.
/// `RegexSet::is_match` is a single DFA pass, ~O(n) instead of looping
/// `Regex::is_match` per pattern. We only fall back to the per-pattern Regex
/// (to identify which one fired) after the set has confirmed at least one
/// match.
#[derive(Debug, Clone)]
pub struct PatternBank {
    patterns: Vec<CompiledPattern>,
    set: RegexSet,
}

impl PatternBank {
    fn new(patterns: Vec<CompiledPattern>) -> Result<Self> {
        let set = RegexSet::new(patterns.iter().map(|p| p.re.as_str())).map_err(|e| {
            SshError::Config(format!("regex set compile failed: {e}"))
        })?;
        Ok(Self { patterns, set })
    }

    fn matched(&self, cmd: &str) -> Option<&CompiledPattern> {
        if self.patterns.is_empty() {
            return None;
        }
        let m = self.set.matches(cmd);
        if !m.matched_any() {
            return None;
        }
        let first = m.iter().next()?;
        self.patterns.get(first)
    }
}

#[derive(Debug, Clone)]
pub struct CompiledGuards {
    pub deny: PatternBank,
    pub confirm: PatternBank,
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardCheck {
    Allow,
    Confirm { pattern_name: String },
    Deny { pattern_name: String, pattern: String },
}

impl CompiledGuards {
    #[allow(dead_code)] // kept for ad-hoc one-off compilation; production path uses GuardCache.
    pub fn from_config(cfg: &Config, host_name: &str) -> Result<Self> {
        let host_guards = cfg
            .hosts
            .get(host_name)
            .and_then(|h| h.guards.clone())
            .unwrap_or_else(|| cfg.defaults.guards.clone());
        Self::compile(&host_guards)
    }

    pub fn compile(g: &Guards) -> Result<Self> {
        let mut deny = Vec::new();
        let mut confirm = Vec::new();
        if g.use_default_deny {
            for p in default_deny_patterns() {
                deny.push(compile_one(&p)?);
            }
        }
        if g.use_default_confirm {
            for p in default_confirm_patterns() {
                confirm.push(compile_one(&p)?);
            }
        }
        for p in &g.deny {
            deny.push(compile_one(p)?);
        }
        for p in &g.confirm {
            confirm.push(compile_one(p)?);
        }
        Ok(Self {
            deny: PatternBank::new(deny)?,
            confirm: PatternBank::new(confirm)?,
            read_only: g.read_only,
        })
    }

    pub fn check(&self, cmd: &str) -> GuardCheck {
        // Single RegexSet pass per bank. A separate `is_match` pre-check
        // would re-scan the command a second time on every hit.
        if let Some(p) = self.deny.matched(cmd) {
            return GuardCheck::Deny {
                pattern_name: p.name.clone(),
                pattern: p.re.as_str().to_string(),
            };
        }
        if self.read_only && looks_writeful(cmd) {
            return GuardCheck::Deny {
                pattern_name: "read-only".into(),
                pattern: "host marked read_only".into(),
            };
        }
        if let Some(p) = self.confirm.matched(cmd) {
            return GuardCheck::Confirm { pattern_name: p.name.clone() };
        }
        GuardCheck::Allow
    }

    /// Guard for SFTP write paths (`wr` / `up`). Refuses on read_only hosts and
    /// on a small set of sensitive paths (authorized_keys, sudoers, cron, shadow,
    /// passwd, systemd units). Path is matched server-side as the AI sees it.
    pub fn check_sftp_write(&self, remote_path: &str) -> Result<()> {
        if self.read_only {
            return Err(SshError::BlockedByGuard {
                name: "read-only".into(),
                pattern: "host marked read_only".into(),
            });
        }
        if sensitive_write_path_re().is_match(remote_path) {
            return Err(SshError::BlockedByGuard {
                name: "sensitive-path".into(),
                pattern: "write to sensitive system path blocked".into(),
            });
        }
        Ok(())
    }

    /// Guard for SFTP read paths (`dn` / `ls` / `stat`). Blocks reads of
    /// private keys, shadow files, sudoers, and cloud-credential files
    /// regardless of `read_only`. Read-only hosts still allow safe reads.
    pub fn check_sftp_read(&self, remote_path: &str) -> Result<()> {
        if sensitive_read_path_re().is_match(remote_path) {
            return Err(SshError::BlockedByGuard {
                name: "sensitive-read".into(),
                pattern: "read of sensitive system path blocked".into(),
            });
        }
        Ok(())
    }
}

fn sensitive_read_path_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?ix)
            (?:^|/)
            (?:
                shadow | gshadow
              | sudoers
              | id_(?:rsa|ed25519|ecdsa|dsa|sk)
              | identity
            )
            $
            |
            (?:^|/)\.ssh/id_[a-z0-9_]+$
            |
            (?:^|/)\.aws/credentials$
            |
            (?:^|/)\.kube/config$
            |
            (?:^|/)\.docker/config\.json$
            |
            (?:^|/)\.config/gcloud/(?:application_default_credentials|credentials)\.json$
            |
            (?:^|/)\.netrc$
            |
            (?:^|/)\.pgpass$
            |
            (?:^|/)etc/(?:shadow|gshadow|sudoers)$
            |
            (?:^|/)etc/sudoers\.d/.+$
            |
            (?:^|/)etc/ssh/ssh_host_[a-z0-9_]+_key$
            |
            (?:^|/)proc/[0-9]+/(?:mem|environ)$
            "#,
        )
        .expect("sensitive_read_path_re valid")
    })
}

fn sensitive_write_path_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?ix)
            (?:^|/)
            (?:
                \.ssh/(?:authorized_keys|known_hosts|id_[a-z0-9]+)
              | sudoers
              | shadow | gshadow | passwd | group
              | crontab
            )
            $
            |
            (?:^|/)
            (?:
                etc/(?:sudoers\.d|cron\.(?:d|hourly|daily|weekly|monthly)|init\.d|systemd/system|pam\.d|ssh)/.*
              | etc/(?:fstab|hosts|resolv\.conf|nsswitch\.conf|environment)
              | boot/.*
            )
            $"#,
        )
        .expect("sensitive_write_path_re valid")
    })
}

/// Pre-compiled guard cache keyed by host name. The `default` slot holds
/// the global rules used for any host that does not declare its own block.
#[derive(Debug, Clone)]
pub struct GuardCache {
    default: Arc<CompiledGuards>,
    by_host: HashMap<String, Arc<CompiledGuards>>,
}

impl GuardCache {
    pub fn build(cfg: &Config) -> Result<Self> {
        let default = Arc::new(CompiledGuards::compile(&cfg.defaults.guards)?);
        let mut by_host = HashMap::with_capacity(cfg.hosts.len());
        for (name, host) in &cfg.hosts {
            if let Some(g) = &host.guards {
                by_host.insert(name.clone(), Arc::new(CompiledGuards::compile(g)?));
            }
        }
        Ok(Self { default, by_host })
    }

    pub fn for_host(&self, host: &str) -> Arc<CompiledGuards> {
        self.by_host
            .get(host)
            .cloned()
            .unwrap_or_else(|| Arc::clone(&self.default))
    }
}

fn compile_one(p: &NamedPattern) -> Result<CompiledPattern> {
    let re = Regex::new(&p.pattern).map_err(|e| {
        SshError::Config(format!("bad regex in guard '{}': {e}", p.name))
    })?;
    Ok(CompiledPattern { name: p.name.clone(), re })
}

/// Commands that always write/mutate filesystem state. Matched on the first
/// token of each pipeline segment, case-insensitive. Read-only mode blocks
/// any segment whose first token is in this set.
const ALWAYS_WRITE: &[&str] = &[
    "rm", "mv", "cp", "mkdir", "rmdir", "chmod", "chown", "ln", "touch",
    "dd", "mkfs", "shred", "fallocate", "truncate", "tee", "sponge",
    "reboot", "shutdown", "halt", "poweroff",
];

/// Commands whose write nature depends on the second token. Matched as
/// `(first, second)` after lowercasing.
const SUBCOMMAND_WRITE: &[(&str, &str)] = &[
    ("systemctl", "restart"), ("systemctl", "stop"), ("systemctl", "start"),
    ("systemctl", "enable"), ("systemctl", "disable"), ("systemctl", "mask"),
    ("systemctl", "unmask"), ("systemctl", "reload"),
    ("service", "restart"), ("service", "stop"), ("service", "start"),
    ("docker", "run"), ("docker", "rm"), ("docker", "rmi"),
    ("docker", "stop"), ("docker", "start"), ("docker", "restart"),
    ("docker", "kill"), ("docker", "exec"), ("docker", "compose"),
    ("docker", "build"), ("docker", "pull"), ("docker", "push"),
    ("apt", "install"), ("apt", "upgrade"), ("apt", "remove"), ("apt", "purge"),
    ("apt", "autoremove"),
    ("apt-get", "install"), ("apt-get", "upgrade"), ("apt-get", "remove"),
    ("apt-get", "purge"),
    ("yum", "install"), ("yum", "remove"), ("yum", "update"),
    ("dnf", "install"), ("dnf", "remove"), ("dnf", "update"),
    ("pacman", "-S"), ("pacman", "-R"), ("pacman", "-U"), ("pacman", "-Syu"),
    ("pip", "install"), ("pip", "uninstall"),
    ("pip3", "install"), ("pip3", "uninstall"),
    ("npm", "install"), ("npm", "i"), ("npm", "uninstall"),
    ("yarn", "add"), ("yarn", "remove"),
    ("pnpm", "add"), ("pnpm", "remove"),
    ("git", "push"), ("git", "reset"), ("git", "checkout"),
    ("git", "rebase"), ("git", "merge"), ("git", "pull"),
    ("git", "commit"), ("git", "clean"),
];

/// Tokenized read-only check. Splits `cmd` into pipeline segments
/// (`| && || ; \n`), respects single/double quotes, and detects:
/// 1. any redirection operator (`>`, `>>`, `<<`, `<`) outside quotes,
/// 2. any segment whose first token is in `ALWAYS_WRITE`,
/// 3. any segment whose first two tokens match `SUBCOMMAND_WRITE`.
///
/// Replaces the previous substring scan that bypassed on `cmd>file`
/// (no spaces) and false-positived on `echo 'rm '`.
fn looks_writeful(cmd: &str) -> bool {
    let segs = parse_segments(cmd);
    for seg in segs {
        if seg.has_redirect {
            return true;
        }
        let Some(first) = &seg.first else { continue };
        let lc1 = first.to_ascii_lowercase();
        if ALWAYS_WRITE.contains(&lc1.as_str()) {
            return true;
        }
        if let Some(second) = &seg.second {
            let lc2 = second.to_ascii_lowercase();
            if SUBCOMMAND_WRITE
                .iter()
                .any(|(c, sub)| *c == lc1 && *sub == lc2)
            {
                return true;
            }
        }
    }
    false
}

#[derive(Default, Debug)]
struct Segment {
    first: Option<String>,
    second: Option<String>,
    has_redirect: bool,
}

/// Walk `cmd` once, splitting on top-level `|`, `||`, `&&`, `;`, `\n`.
/// Tracks single/double quote state. Records the first two whitespace-separated
/// tokens of each segment plus whether any redirect operator appears.
fn parse_segments(cmd: &str) -> Vec<Segment> {
    let mut out = Vec::new();
    let mut cur = Segment::default();
    let mut buf = String::new();
    let mut tokens_seen = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    let mut iter = cmd.chars().peekable();

    let push_token = |buf: &mut String, cur: &mut Segment, tokens_seen: &mut usize| {
        if buf.is_empty() {
            return;
        }
        match *tokens_seen {
            0 => cur.first = Some(std::mem::take(buf)),
            1 => cur.second = Some(std::mem::take(buf)),
            _ => buf.clear(),
        }
        *tokens_seen += 1;
    };
    let push_segment = |out: &mut Vec<Segment>, cur: &mut Segment, buf: &mut String, tokens_seen: &mut usize| {
        push_token(buf, cur, tokens_seen);
        out.push(std::mem::take(cur));
        *tokens_seen = 0;
    };

    while let Some(c) = iter.next() {
        if in_single {
            if c == '\'' {
                in_single = false;
            } else {
                buf.push(c);
            }
            continue;
        }
        if in_double {
            if c == '"' {
                in_double = false;
            } else if c == '\\' {
                if let Some(&next) = iter.peek() {
                    if matches!(next, '"' | '\\' | '$' | '`' | '\n') {
                        buf.push(iter.next().unwrap());
                        continue;
                    }
                }
                buf.push(c);
            } else {
                buf.push(c);
            }
            continue;
        }

        match c {
            '\'' => in_single = true,
            '"' => in_double = true,
            '\\' => {
                if let Some(next) = iter.next() {
                    buf.push(next);
                }
            }
            '|' => {
                push_segment(&mut out, &mut cur, &mut buf, &mut tokens_seen);
                if matches!(iter.peek(), Some('|')) {
                    iter.next();
                }
            }
            '&' => {
                if matches!(iter.peek(), Some('&')) {
                    iter.next();
                    push_segment(&mut out, &mut cur, &mut buf, &mut tokens_seen);
                }
                // standalone `&` (background) — treat as segment break
                else {
                    push_segment(&mut out, &mut cur, &mut buf, &mut tokens_seen);
                }
            }
            ';' | '\n' => {
                push_segment(&mut out, &mut cur, &mut buf, &mut tokens_seen);
            }
            '>' | '<' => {
                cur.has_redirect = true;
                push_token(&mut buf, &mut cur, &mut tokens_seen);
                // skip combined `>>`, `<<`, `>&`
                if matches!(iter.peek(), Some('>') | Some('<') | Some('&')) {
                    iter.next();
                }
            }
            c if c.is_whitespace() => {
                push_token(&mut buf, &mut cur, &mut tokens_seen);
            }
            _ => {
                buf.push(c);
            }
        }
    }
    push_segment(&mut out, &mut cur, &mut buf, &mut tokens_seen);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_rm_rf_root() {
        let g = CompiledGuards::compile(&Guards::default()).unwrap();
        assert!(matches!(g.check("rm -rf /"), GuardCheck::Deny { .. }));
        assert!(matches!(g.check("rm -rf /usr"), GuardCheck::Deny { .. }));
        assert!(matches!(g.check("rm -rf ./tmp"), GuardCheck::Allow));
    }

    #[test]
    fn deny_rm_rf_root_bypass_attempts() {
        let g = CompiledGuards::compile(&Guards::default()).unwrap();
        for cmd in [
            "rm -rf '/'",
            "rm -rf \"/\"",
            "rm -rf //",
            "rm -rf /*",
            "rm -rf -- /",
            "RM -rf /",
            "rm --recursive --force /",
            "rm -fr /",
            "rm -Rf /",
        ] {
            assert!(matches!(g.check(cmd), GuardCheck::Deny { .. }), "should deny: {cmd:?}");
        }
        for cmd in [
            "rm ./tmp",
            "rm -rf ~/tmp",
            "rm foo/bar",
            "ls /",
            // Deeper absolute paths are legitimate day-to-day deletes; the
            // guard only covers root itself and first-level root dirs.
            "rm -f /tmp/t.log",
            "rm -rf /tmp/bench-mkdir",
            "rm -rf /home/user/project/target",
        ] {
            assert!(!matches!(g.check(cmd), GuardCheck::Deny { .. }), "should allow: {cmd:?}");
        }
        // Root dir with trailing slash still denied.
        assert!(matches!(g.check("rm -rf /etc/"), GuardCheck::Deny { .. }));
    }

    #[test]
    fn confirm_shutdown() {
        let g = CompiledGuards::compile(&Guards::default()).unwrap();
        match g.check("sudo shutdown -h now") {
            GuardCheck::Confirm { pattern_name } => assert_eq!(pattern_name, "shutdown"),
            other => panic!("expected confirm, got {other:?}"),
        }
    }

    #[test]
    fn read_only_blocks_write() {
        let gc = Guards { read_only: true, ..Default::default() };
        let g = CompiledGuards::compile(&gc).unwrap();
        assert!(matches!(g.check("rm /tmp/foo"), GuardCheck::Deny { .. }));
        assert!(matches!(g.check("ls /tmp"), GuardCheck::Allow));
    }

    #[test]
    fn read_only_no_substring_false_positives() {
        // The previous `lc.contains("rm ")` substring check tripped on quoted echos.
        // Tokenization should accept these on a read_only host.
        let gc = Guards { read_only: true, ..Default::default() };
        let g = CompiledGuards::compile(&gc).unwrap();
        for cmd in [
            "echo 'rm '",
            "echo \"rm test\"",
            "grep 'mv foo' /var/log/syslog",
            "ls -la 'has > sign'",
            "cat /tmp/firmware.bin",
        ] {
            assert!(!matches!(g.check(cmd), GuardCheck::Deny { .. }), "should allow: {cmd:?}");
        }
    }

    #[test]
    fn read_only_blocks_no_space_redirects() {
        // `cmd>file` (no spaces) bypassed the old substring check.
        let gc = Guards { read_only: true, ..Default::default() };
        let g = CompiledGuards::compile(&gc).unwrap();
        for cmd in ["echo hi>file", "echo hi >file", "echo hi> file", "tail -f log >> out"] {
            assert!(matches!(g.check(cmd), GuardCheck::Deny { .. }), "should deny: {cmd:?}");
        }
    }

    #[test]
    fn read_only_pipeline_segments() {
        let gc = Guards { read_only: true, ..Default::default() };
        let g = CompiledGuards::compile(&gc).unwrap();
        // Read in first segment, write in second — still writes overall.
        assert!(matches!(g.check("ls /tmp | tee out"), GuardCheck::Deny { .. }));
        // All-read pipeline.
        assert!(!matches!(g.check("cat /etc/hostname | head -c 16"), GuardCheck::Deny { .. }));
    }

    #[test]
    fn dd_disk_blocked() {
        let g = CompiledGuards::compile(&Guards::default()).unwrap();
        assert!(matches!(g.check("dd if=/dev/zero of=/dev/sda"), GuardCheck::Deny { .. }));
    }

    #[test]
    fn forkbomb_blocked() {
        let g = CompiledGuards::compile(&Guards::default()).unwrap();
        assert!(matches!(g.check(":(){ :|:& };:"), GuardCheck::Deny { .. }));
    }

    #[test]
    fn allow_simple_ls() {
        let g = CompiledGuards::compile(&Guards::default()).unwrap();
        assert_eq!(g.check("ls -la /etc"), GuardCheck::Allow);
    }

    #[test]
    fn sftp_read_blocks_sensitive_paths() {
        let g = CompiledGuards::compile(&Guards::default()).unwrap();
        for path in [
            "/etc/shadow",
            "/etc/sudoers",
            "/etc/sudoers.d/01_users",
            "/root/.ssh/id_rsa",
            "/home/alice/.ssh/id_ed25519",
            "/home/alice/.aws/credentials",
            "/home/alice/.kube/config",
            "/home/alice/.docker/config.json",
            "/home/alice/.config/gcloud/credentials.json",
            "/home/alice/.netrc",
            "/home/alice/.pgpass",
            "/etc/ssh/ssh_host_rsa_key",
            "/proc/123/environ",
        ] {
            assert!(g.check_sftp_read(path).is_err(), "should block: {path}");
        }
    }

    #[test]
    fn sftp_read_allows_safe_paths() {
        let g = CompiledGuards::compile(&Guards::default()).unwrap();
        for path in [
            "/etc/hostname",
            "/var/log/syslog",
            "/home/alice/.ssh/authorized_keys",
            "/home/alice/.ssh/id_rsa.pub",
            "/home/alice/notes.txt",
        ] {
            assert!(g.check_sftp_read(path).is_ok(), "should allow: {path}");
        }
    }
}
