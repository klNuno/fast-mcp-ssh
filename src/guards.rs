use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::OnceLock;

use regex::{Regex, RegexSet};

use crate::config::{
    Config, Guards, NamedPattern, config_dir, default_confirm_patterns, default_deny_patterns,
};
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
        let set = RegexSet::new(patterns.iter().map(|p| p.re.as_str()))
            .map_err(|e| SshError::Config(format!("regex set compile failed: {e}")))?;
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
    /// Normalized local paths exempt from the sensitive-path banks. Slashed,
    /// trailing slash stripped, case-folded on Windows only.
    local_read_allow: Vec<String>,
    local_write_allow: Vec<String>,
    /// The server's own files in the same comparison form: its config
    /// directory, the config file, every key and the audit log. Filled by
    /// `GuardCache::build`, which has the config; no allowlist entry opens them.
    owned: Arc<[String]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardCheck {
    Allow,
    Confirm {
        pattern_name: String,
    },
    Deny {
        pattern_name: String,
        pattern: String,
    },
}

impl CompiledGuards {
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
            local_read_allow: compile_local_allow(&g.local_read_allow, "local_read_allow")?,
            local_write_allow: compile_local_allow(&g.local_write_allow, "local_write_allow")?,
            owned: Arc::from(Vec::new()),
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
            return GuardCheck::Confirm {
                pattern_name: p.name.clone(),
            };
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

    /// Refuse a local read of private keys, credential files, browser cookie
    /// stores or `.env` files. Without it `up` is an exfiltration primitive.
    /// A key is recognised by its first bytes too, since `keys/prod` matches
    /// no path pattern. `local_read_allow` exempts a path the operator wrote
    /// down in advance, except the server's own files.
    pub fn check_local_read(&self, resolved: &Path) -> Result<()> {
        self.check_owned(resolved)?;
        if path_within(&self.local_read_allow, resolved) {
            return Ok(());
        }
        if local_read_path_re().is_match(&slashed(resolved)) || holds_private_key(resolved) {
            return Err(SshError::BlockedByGuard {
                name: "local-read".into(),
                pattern: "read of sensitive local path blocked; only the operator can allow it, \
                          by listing this path under local_read_allow in \
                          ~/.fast-mcp-ssh/hosts.toml"
                    .into(),
            });
        }
        Ok(())
    }

    /// Refuse a local write that would land on shell startup files, SSH
    /// material, credential stores or an autostart directory. A `dn` of
    /// attacker-chosen remote content into `~/.bashrc` is code execution on
    /// the operator's box. `local_write_allow` exempts a path the operator
    /// wrote down in advance, except the server's own files.
    pub fn check_local_write(&self, resolved: &Path) -> Result<()> {
        self.check_owned(resolved)?;
        if path_within(&self.local_write_allow, resolved) {
            return Ok(());
        }
        let s = slashed(resolved);
        if local_write_path_re().is_match(&s) || is_home_dotrc(resolved) {
            return Err(SshError::BlockedByGuard {
                name: "local-write".into(),
                pattern: "write to sensitive local path blocked; only the operator can allow it, \
                          by listing this path under local_write_allow in \
                          ~/.fast-mcp-ssh/hosts.toml"
                    .into(),
            });
        }
        Ok(())
    }

    /// The server's keys reach every configured host, and a `dn` over its
    /// config followed by `reload` would rewrite the guards. Neither
    /// direction is ever open to a tool call.
    fn check_owned(&self, resolved: &Path) -> Result<()> {
        if path_within(&self.owned, resolved) {
            return Err(SshError::BlockedByGuard {
                name: "local-own".into(),
                pattern: "fast-mcp-ssh's own config, keys, host pins and audit log are out of \
                          reach of every tool call; no allowlist entry lifts this"
                    .into(),
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
            (?:^|/)\.config/gcloud/.+$
            |
            (?:^|/)\.azure/.+$
            |
            (?:^|/)\.git-credentials$
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
                # authorized_keys2 is still in sshd's default AuthorizedKeysFile,
                # and ~/.ssh/rc is executed by sshd on every login — both were
                # reachable past the old `authorized_keys|known_hosts|id_*` list.
                \.ssh/(?:authorized_keys2?|known_hosts2?|id_[a-z0-9]+|rc|config|environment)
              | sudoers
              | shadow | gshadow | passwd | group
              | crontab
            )
            $
            |
            (?:^|/)
            (?:
                etc/(?:sudoers\.d|cron\.(?:d|hourly|daily|weekly|monthly)|init\.d|systemd/system|pam\.d|ssh|profile\.d)/.*
              | etc/(?:fstab|hosts|resolv\.conf|nsswitch\.conf|environment|profile|ld\.so\.preload|ld\.so\.conf)
              | etc/ld\.so\.conf\.d/.*
              | (?:usr/)?lib/systemd/(?:system|user)/.*
              | var/spool/cron/.*
              | root/\.ssh/.*
              | boot/.*
            )
            $"#,
        )
        .expect("sensitive_write_path_re valid")
    })
}

// ---------------------------------------------------------------------------
// Local filesystem guards.
//
// `dn local=<path>` writes remote-controlled bytes onto the operator's own
// machine and `up local=<path>` ships the operator's own bytes to a remote
// host. Both checks hang off `CompiledGuards` so `local_read_allow` /
// `local_write_allow` can name an exception, and both fall back to the
// pattern bank when the path is not on that list. The exception is deliberately
// config-only: nothing a tool call carries can widen it, which is what a
// caller asking the operator for permission mid-call cannot achieve.
// ---------------------------------------------------------------------------

/// Expand `~`, make absolute, then resolve the parent through the real
/// filesystem. Matching the raw string would let `~/x/../.bashrc` or a
/// symlinked directory land on a protected file the argument never named.
/// The parent may not exist yet (`dn` creates it), so fall back to a lexical
/// resolve rather than skipping the guard.
pub fn resolve_local_path(raw: &str) -> PathBuf {
    let mut p = PathBuf::from(shellexpand::tilde(raw).into_owned());
    if p.is_relative()
        && let Ok(cwd) = std::env::current_dir()
    {
        p = cwd.join(p);
    }
    if let (Some(parent), Some(name)) = (p.parent(), p.file_name())
        && let Ok(real) = parent.canonicalize()
    {
        return lexical_normalize(&real.join(name));
    }
    lexical_normalize(&p)
}

/// Normalize one allowlist entry at config-load time, so a typo is a startup
/// error rather than a guard that silently never fires. Rejects the entries
/// that would hand back the whole filesystem.
fn compile_local_allow(entries: &[String], field: &str) -> Result<Vec<String>> {
    let mut out = Vec::with_capacity(entries.len());
    for raw in entries {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(SshError::Config(format!("{field}: empty path")));
        }
        if raw.contains('*') || raw.contains('?') {
            return Err(SshError::Config(format!(
                "{field}: globs are not supported, name the file or its directory: {raw}"
            )));
        }
        let resolved = resolve_local_path(raw);
        if resolved.parent().is_none() {
            return Err(SshError::Config(format!(
                "{field}: a filesystem root allows everything: {raw}"
            )));
        }
        if is_operator_home(&resolved) {
            return Err(SshError::Config(format!(
                "{field}: the home directory allows everything under it: {raw}"
            )));
        }
        let norm = fold_path(resolved.as_path());
        if norm.is_empty() {
            return Err(SshError::Config(format!("{field}: empty path: {raw}")));
        }
        out.push(norm);
    }
    Ok(out)
}

/// True when `path` is one of `entries` itself or sits under one. A
/// directory entry covers its whole subtree; matching is textual on the
/// already-resolved path, so `..` and symlinked parents cannot smuggle a
/// protected file in under an allowed prefix.
fn path_within(entries: &[String], path: &Path) -> bool {
    if entries.is_empty() {
        return false;
    }
    let p = fold_path(path);
    entries.iter().any(|e| {
        p == *e
            || (p.len() > e.len()
                && p.starts_with(e.as_str())
                && p.as_bytes().get(e.len()) == Some(&b'/'))
    })
}

/// How much of a local file `holds_private_key` reads. Every key format it
/// knows opens with its marker, so the window only has to cover a comment or
/// a stray header before it.
const KEY_SNIFF_BYTES: u64 = 8 * 1024;

/// A private key named like any other file (`keys/prod`, `deploy_backup`)
/// slips past every path pattern, so `up` also reads the file's first bytes.
/// Only a regular file is opened: a FIFO would block the runtime on `open`.
fn holds_private_key(path: &Path) -> bool {
    use std::io::Read;
    if !std::fs::metadata(path).is_ok_and(|m| m.is_file()) {
        return false;
    }
    let Ok(f) = std::fs::File::open(path) else {
        return false;
    };
    let mut head = Vec::new();
    if f.take(KEY_SNIFF_BYTES).read_to_end(&mut head).is_err() {
        return false;
    }
    looks_like_private_key(&head)
}

/// PEM and OpenSSH keys open with a `-----BEGIN ... PRIVATE KEY-----` line
/// (RSA, EC, DSA, OPENSSH, ENCRYPTED, PGP's `PRIVATE KEY BLOCK`); PuTTY keys
/// with `PuTTY-User-Key-File-`. A certificate or a public key has neither.
fn looks_like_private_key(head: &[u8]) -> bool {
    if find_bytes(head, b"PuTTY-User-Key-File-").is_some() {
        return true;
    }
    let mut rest = head;
    while let Some(i) = find_bytes(rest, b"-----BEGIN ") {
        let label = &rest[i + b"-----BEGIN ".len()..];
        let end = find_bytes(label, b"-----").unwrap_or(label.len());
        if find_bytes(&label[..end], b"PRIVATE KEY").is_some() {
            return true;
        }
        rest = &label[end..];
    }
    false
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Comparison form of a path: forward slashes, no trailing slash, case-folded
/// on Windows only. Folding on Linux would let an entry match a sibling
/// directory that differs by case, and an allowlist must never be looser than
/// what the operator wrote.
fn fold_path(p: &Path) -> String {
    let s = slashed(p);
    let s = s.trim_end_matches('/');
    if cfg!(windows) {
        s.to_ascii_lowercase()
    } else {
        s.to_string()
    }
}

/// The operator's home directory itself, not a path under it.
fn is_operator_home(path: &Path) -> bool {
    let home = shellexpand::tilde("~");
    if home.as_ref() == "~" {
        return false;
    }
    let h = fold_path(Path::new(home.as_ref()));
    !h.is_empty() && fold_path(path) == h
}

fn local_write_path_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?ix)
            # Shell startup files — sourced by the next interactive shell.
            (?:^|/)\.(?:bashrc|bash_profile|bash_login|bash_logout|profile
                      |zshrc|zshenv|zprofile|zlogin|zlogout|kshrc|cshrc|tcshrc)$
            |
            (?:^|/)\.config/fish/(?:config\.fish|conf\.d/.+|functions/.+)$
            |
            # Anything under .ssh/ — keys, config (ProxyCommand), known_hosts.
            (?:^|/)\.ssh/.+$
            |
            (?:^|/)\.(?:gitconfig|npmrc|pypirc|netrc|pgpass|curlrc|wgetrc)$
            |
            (?:^|/)\.aws/.+$
            |
            (?:^|/)\.config/gcloud/.+$
            |
            (?:^|/)\.kube/.+$
            |
            (?:^|/)\.docker/.+$
            |
            # Crontab spools, both Debian and RedHat layouts.
            (?:^|/)(?:var/spool/cron|etc/cron\.d|etc/cron\.(?:hourly|daily|weekly|monthly))/.+$
            |
            (?:^|/)\.config/(?:autostart|systemd/user)/.+$
            |
            # Windows autostart: a dropped file runs at next logon.
            # `\x20`, not a literal space: `(?x)` strips whitespace inside
            # character classes too, so `[ ]` would parse as an unclosed class.
            (?:^|/)start\x20menu/programs/startup/.+$
            "#,
        )
        .expect("local_write_path_re valid")
    })
}

fn local_read_path_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?ix)
            # Private keys. The char class excludes `.` so `id_rsa.pub` — which
            # is meant to be copied around — stays readable.
            (?:^|/)\.ssh/id_[a-z0-9_-]+$
            |
            \.(?:pem|key|pfx|p12)$
            |
            (?:^|/)\.aws/credentials$
            |
            (?:^|/)\.config/gcloud/.+$
            |
            (?:^|/)\.kube/config$
            |
            (?:^|/)\.docker/config\.json$
            |
            (?:^|/)\.(?:netrc|npmrc|pypirc|pgpass|git-credentials)$
            |
            # Browser cookie / saved-password stores: session-token theft.
            (?:^|/)(?:cookies\.sqlite|cookies|login\x20data|key[34]\.db|logins\.json)$
            |
            (?:^|/)\.env(?:\.[a-z0-9_.-]+)?$
            "#,
        )
        .expect("local_read_path_re valid")
    })
}

/// Catch-all for dotfiles the explicit list misses: any `.<something>rc`
/// directly under the operator's home is a startup file for *some* tool.
/// Scoped to home so an unrelated `./.foorc` in a scratch dir stays writable.
fn is_home_dotrc(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if name.len() < 4 || !name.starts_with('.') || !name.to_ascii_lowercase().ends_with("rc") {
        return false;
    }
    let home = shellexpand::tilde("~");
    if home.as_ref() == "~" {
        return false;
    }
    let h = slashed(Path::new(home.as_ref()))
        .trim_end_matches('/')
        .to_ascii_lowercase();
    if h.is_empty() {
        return false;
    }
    let p = slashed(path).to_ascii_lowercase();
    p.len() > h.len() && p.starts_with(&h) && p.as_bytes().get(h.len()) == Some(&b'/')
}

/// Forward-slash view of a path, with the Windows `\\?\` verbatim prefix that
/// `canonicalize` adds stripped, so one regex covers both platforms.
fn slashed(p: &Path) -> String {
    let s = p.to_string_lossy().replace('\\', "/");
    match s.strip_prefix("//?/") {
        Some(rest) => rest.to_string(),
        None => s,
    }
}

/// Resolve `.` and `..` without touching the filesystem. Used for the tail of
/// a path whose parent does not exist yet.
fn lexical_normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
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
        let owned = owned_paths(cfg);
        let compile = |g: &Guards| -> Result<Arc<CompiledGuards>> {
            let mut c = CompiledGuards::compile(g)?;
            for (field, entries) in [
                ("local_read_allow", &c.local_read_allow),
                ("local_write_allow", &c.local_write_allow),
            ] {
                if let Some(e) = entries.iter().find(|e| path_within(&owned, Path::new(e))) {
                    return Err(SshError::Config(format!(
                        "{field}: {e} is one of fast-mcp-ssh's own files, which stay blocked"
                    )));
                }
            }
            c.owned = Arc::clone(&owned);
            Ok(Arc::new(c))
        };
        let default = compile(&cfg.defaults.guards)?;
        let mut by_host = HashMap::with_capacity(cfg.hosts.len());
        for (name, host) in &cfg.hosts {
            if let Some(g) = &host.guards {
                by_host.insert(name.clone(), compile(g)?);
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

    /// How many hosts replace the default block. A host with its own
    /// `[host.<name>.guards]` ignores `[defaults.guards]` entirely, so the
    /// count is what `check` prints to make that substitution visible.
    pub fn host_override_count(&self) -> usize {
        self.by_host.len()
    }
}

/// Everything the server itself trusts, wherever the config put it: the
/// config directory (keys, host pins, default audit log), the config file,
/// each host key, and the audit log with its rotated generations.
fn owned_paths(cfg: &Config) -> Arc<[String]> {
    let audit = &cfg.defaults.audit_log_path;
    let mut paths = vec![config_dir(), audit.clone()];
    for n in 1..=cfg.defaults.audit_keep_files {
        let mut rotated = audit.clone().into_os_string();
        rotated.push(format!(".{n}"));
        paths.push(PathBuf::from(rotated));
    }
    paths.extend(cfg.source.clone());
    for host in cfg.hosts.values() {
        paths.extend(host.all_keys());
    }
    let mut out: Vec<String> = paths
        .iter()
        .map(|p| fold_path(&resolve_local_path(&p.to_string_lossy())))
        .filter(|s| !s.is_empty())
        .collect();
    out.sort();
    out.dedup();
    Arc::from(out)
}

fn compile_one(p: &NamedPattern) -> Result<CompiledPattern> {
    let re = Regex::new(&p.pattern)
        .map_err(|e| SshError::Config(format!("bad regex in guard '{}': {e}", p.name)))?;
    Ok(CompiledPattern {
        name: p.name.clone(),
        re,
    })
}

/// Commands that always write/mutate filesystem state. Matched on the first
/// token of each pipeline segment, case-insensitive. Read-only mode blocks
/// any segment whose first token is in this set.
const ALWAYS_WRITE: &[&str] = &[
    "rm",
    "mv",
    "cp",
    "mkdir",
    "rmdir",
    "chmod",
    "chown",
    "ln",
    "touch",
    "dd",
    "mkfs",
    "shred",
    "fallocate",
    "truncate",
    "tee",
    "sponge",
    "reboot",
    "shutdown",
    "halt",
    "poweroff",
];

/// Commands whose write nature depends on the second token. Matched as
/// `(first, second)` after lowercasing.
const SUBCOMMAND_WRITE: &[(&str, &str)] = &[
    ("systemctl", "restart"),
    ("systemctl", "stop"),
    ("systemctl", "start"),
    ("systemctl", "enable"),
    ("systemctl", "disable"),
    ("systemctl", "mask"),
    ("systemctl", "unmask"),
    ("systemctl", "reload"),
    ("service", "restart"),
    ("service", "stop"),
    ("service", "start"),
    ("docker", "run"),
    ("docker", "rm"),
    ("docker", "rmi"),
    ("docker", "stop"),
    ("docker", "start"),
    ("docker", "restart"),
    ("docker", "kill"),
    ("docker", "exec"),
    ("docker", "compose"),
    ("docker", "build"),
    ("docker", "pull"),
    ("docker", "push"),
    ("apt", "install"),
    ("apt", "upgrade"),
    ("apt", "remove"),
    ("apt", "purge"),
    ("apt", "autoremove"),
    ("apt-get", "install"),
    ("apt-get", "upgrade"),
    ("apt-get", "remove"),
    ("apt-get", "purge"),
    ("yum", "install"),
    ("yum", "remove"),
    ("yum", "update"),
    ("dnf", "install"),
    ("dnf", "remove"),
    ("dnf", "update"),
    ("pacman", "-S"),
    ("pacman", "-R"),
    ("pacman", "-U"),
    ("pacman", "-Syu"),
    ("pip", "install"),
    ("pip", "uninstall"),
    ("pip3", "install"),
    ("pip3", "uninstall"),
    ("npm", "install"),
    ("npm", "i"),
    ("npm", "uninstall"),
    ("yarn", "add"),
    ("yarn", "remove"),
    ("pnpm", "add"),
    ("pnpm", "remove"),
    ("git", "push"),
    ("git", "reset"),
    ("git", "checkout"),
    ("git", "rebase"),
    ("git", "merge"),
    ("git", "pull"),
    ("git", "commit"),
    ("git", "clean"),
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
    let push_segment =
        |out: &mut Vec<Segment>, cur: &mut Segment, buf: &mut String, tokens_seen: &mut usize| {
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
                if let Some(&next) = iter.peek()
                    && matches!(next, '"' | '\\' | '$' | '`' | '\n')
                {
                    buf.push(iter.next().unwrap());
                    continue;
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
            assert!(
                matches!(g.check(cmd), GuardCheck::Deny { .. }),
                "should deny: {cmd:?}"
            );
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
            assert!(
                !matches!(g.check(cmd), GuardCheck::Deny { .. }),
                "should allow: {cmd:?}"
            );
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
        let gc = Guards {
            read_only: true,
            ..Default::default()
        };
        let g = CompiledGuards::compile(&gc).unwrap();
        assert!(matches!(g.check("rm /tmp/foo"), GuardCheck::Deny { .. }));
        assert!(matches!(g.check("ls /tmp"), GuardCheck::Allow));
    }

    #[test]
    fn read_only_no_substring_false_positives() {
        // The previous `lc.contains("rm ")` substring check tripped on quoted echos.
        // Tokenization should accept these on a read_only host.
        let gc = Guards {
            read_only: true,
            ..Default::default()
        };
        let g = CompiledGuards::compile(&gc).unwrap();
        for cmd in [
            "echo 'rm '",
            "echo \"rm test\"",
            "grep 'mv foo' /var/log/syslog",
            "ls -la 'has > sign'",
            "cat /tmp/firmware.bin",
        ] {
            assert!(
                !matches!(g.check(cmd), GuardCheck::Deny { .. }),
                "should allow: {cmd:?}"
            );
        }
    }

    #[test]
    fn read_only_blocks_no_space_redirects() {
        // `cmd>file` (no spaces) bypassed the old substring check.
        let gc = Guards {
            read_only: true,
            ..Default::default()
        };
        let g = CompiledGuards::compile(&gc).unwrap();
        for cmd in [
            "echo hi>file",
            "echo hi >file",
            "echo hi> file",
            "tail -f log >> out",
        ] {
            assert!(
                matches!(g.check(cmd), GuardCheck::Deny { .. }),
                "should deny: {cmd:?}"
            );
        }
    }

    #[test]
    fn read_only_pipeline_segments() {
        let gc = Guards {
            read_only: true,
            ..Default::default()
        };
        let g = CompiledGuards::compile(&gc).unwrap();
        // Read in first segment, write in second — still writes overall.
        assert!(matches!(
            g.check("ls /tmp | tee out"),
            GuardCheck::Deny { .. }
        ));
        // All-read pipeline.
        assert!(!matches!(
            g.check("cat /etc/hostname | head -c 16"),
            GuardCheck::Deny { .. }
        ));
    }

    #[test]
    fn dd_disk_blocked() {
        let g = CompiledGuards::compile(&Guards::default()).unwrap();
        assert!(matches!(
            g.check("dd if=/dev/zero of=/dev/sda"),
            GuardCheck::Deny { .. }
        ));
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

    #[test]
    fn sftp_read_blocks_added_paths() {
        let g = CompiledGuards::compile(&Guards::default()).unwrap();
        for path in [
            "/proc/1/environ",
            "/etc/sudoers",
            "/home/alice/.config/gcloud/access_tokens.db",
            "/home/alice/.azure/msal_token_cache.json",
            "/home/alice/.git-credentials",
        ] {
            assert!(g.check_sftp_read(path).is_err(), "should block: {path}");
        }
        for path in ["/home/alice/.config/nvim/init.lua", "/proc/cpuinfo"] {
            assert!(g.check_sftp_read(path).is_ok(), "should allow: {path}");
        }
    }

    #[test]
    fn sftp_write_blocks_sensitive_paths() {
        let g = CompiledGuards::compile(&Guards::default()).unwrap();
        for path in [
            // The two bypasses the old `.ssh/(authorized_keys|known_hosts|id_*)`
            // list left open.
            "/home/alice/.ssh/authorized_keys2",
            "/home/alice/.ssh/rc",
            "/home/alice/.ssh/config",
            "/etc/ld.so.preload",
            "/etc/ld.so.conf.d/local.conf",
            "/var/spool/cron/crontabs/root",
            "/etc/cron.d/backup",
            "/etc/sudoers",
            "/etc/sudoers.d/90-cloud",
            "/lib/systemd/system/ssh.service",
            "/usr/lib/systemd/system/ssh.service",
            "/etc/systemd/system/evil.service",
            "/etc/profile.d/evil.sh",
            "/etc/pam.d/sshd",
            "/root/.ssh/authorized_keys",
        ] {
            assert!(g.check_sftp_write(path).is_err(), "should block: {path}");
        }
    }

    #[test]
    fn sftp_write_allows_safe_paths() {
        let g = CompiledGuards::compile(&Guards::default()).unwrap();
        for path in [
            "/tmp/deploy.sh",
            "/home/alice/project/src/main.rs",
            "/var/spooled/notes.txt",
            "/opt/app/config.yaml",
            "/home/alice/.ssh_backup_notes",
        ] {
            assert!(g.check_sftp_write(path).is_ok(), "should allow: {path}");
        }
    }

    /// Guards with no allowlist: what every host gets until the operator
    /// writes one down.
    fn local_guards() -> CompiledGuards {
        CompiledGuards::compile(&Guards::default()).expect("default guards compile")
    }

    #[test]
    fn local_write_blocks_startup_and_credential_paths() {
        let g = local_guards();
        for path in [
            "/home/alice/.bashrc",
            "/home/alice/.bash_profile",
            "/home/alice/.profile",
            "/home/alice/.zshrc",
            "/home/alice/.zshenv",
            "/home/alice/.zprofile",
            "/home/alice/.config/fish/config.fish",
            "/home/alice/.ssh/authorized_keys",
            "/home/alice/.ssh/config",
            "/home/alice/.gitconfig",
            "/home/alice/.npmrc",
            "/home/alice/.pypirc",
            "/home/alice/.netrc",
            "/home/alice/.aws/credentials",
            "/home/alice/.config/gcloud/settings.json",
            "/home/alice/.kube/config",
            "/home/alice/.docker/config.json",
            "/var/spool/cron/crontabs/alice",
            "/etc/cron.d/job",
            "C:/Users/alice/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/x.bat",
        ] {
            assert!(
                g.check_local_write(Path::new(path)).is_err(),
                "should block: {path}"
            );
        }
    }

    #[test]
    fn local_write_allows_ordinary_paths() {
        let g = local_guards();
        for path in [
            "/home/alice/downloads/report.pdf",
            "/tmp/out.log",
            "/home/alice/project/.env.example.txt",
            "C:/Users/alice/Downloads/build.zip",
        ] {
            assert!(
                g.check_local_write(Path::new(path)).is_ok(),
                "should allow: {path}"
            );
        }
    }

    #[test]
    fn local_write_blocks_parent_traversal() {
        // `..` in the argument must not dodge the match. The middle component
        // is deliberately non-existent so the lexical fallback is exercised on
        // every platform.
        let raw = "~/fast-mcp-ssh-no-such-dir/../.bashrc";
        let resolved = resolve_local_path(raw);
        assert!(
            local_guards().check_local_write(&resolved).is_err(),
            "traversal should still hit the guard: {}",
            resolved.display()
        );
    }

    #[test]
    fn local_write_blocks_home_dotrc_catchall() {
        let g = local_guards();
        let home = PathBuf::from(shellexpand::tilde("~").into_owned());
        assert!(g.check_local_write(&home.join(".vimrc")).is_err());
        assert!(g.check_local_write(&home.join(".inputrc")).is_err());
        // Same name outside home is nobody's startup file.
        assert!(
            g.check_local_write(Path::new("/tmp/scratch/.vimrc"))
                .is_ok()
        );
        // Not an rc file.
        assert!(g.check_local_write(&home.join(".vimrc.bak")).is_ok());
    }

    #[test]
    fn local_read_blocks_secrets() {
        let g = local_guards();
        for path in [
            "/home/alice/.ssh/id_rsa",
            "/home/alice/.ssh/id_ed25519",
            "/home/alice/keys/server.pem",
            "/home/alice/keys/server.key",
            "/home/alice/.aws/credentials",
            "/home/alice/.config/gcloud/credentials.db",
            "/home/alice/.kube/config",
            "/home/alice/.docker/config.json",
            "/home/alice/.netrc",
            "/home/alice/.npmrc",
            "/home/alice/.pypirc",
            "/home/alice/.mozilla/firefox/p/cookies.sqlite",
            "C:/Users/alice/AppData/Local/Google/Chrome/User Data/Default/Login Data",
            "C:/Users/alice/AppData/Local/Google/Chrome/User Data/Default/Cookies",
            "/home/alice/app/.env",
            "/home/alice/app/.env.production",
        ] {
            assert!(
                g.check_local_read(Path::new(path)).is_err(),
                "should block: {path}"
            );
        }
    }

    #[test]
    fn local_read_allows_ordinary_paths() {
        let g = local_guards();
        for path in [
            "/home/alice/.ssh/id_rsa.pub",
            "/home/alice/.ssh/known_hosts",
            "/home/alice/project/main.rs",
            "/home/alice/project/env.example",
            "/tmp/build.tar.gz",
        ] {
            assert!(
                g.check_local_read(Path::new(path)).is_ok(),
                "should allow: {path}"
            );
        }
    }

    /// Guards holding one read exception, plus the resolver the call sites
    /// run before the guard. Both sides go through `resolve_local_path` so the
    /// test says the same thing on Windows, where a rootless `/srv/...` picks
    /// up the current drive.
    fn read_allow(entry: &str) -> CompiledGuards {
        let gc = Guards {
            local_read_allow: vec![entry.into()],
            ..Default::default()
        };
        CompiledGuards::compile(&gc).expect("allowlist compiles")
    }

    #[test]
    fn local_read_allow_exempts_the_listed_file_only() {
        let g = read_allow("/srv/deploy/admin.key");
        assert!(
            g.check_local_read(&resolve_local_path("/srv/deploy/admin.key"))
                .is_ok()
        );
        // Sibling secret in the same directory is still blocked.
        assert!(
            g.check_local_read(&resolve_local_path("/srv/deploy/other.key"))
                .is_err()
        );
        // A path that only shares a textual prefix is not "under" the entry.
        assert!(
            g.check_local_read(&resolve_local_path("/srv/deploy/admin.keyring.pem"))
                .is_err()
        );
    }

    #[test]
    fn local_read_allow_covers_a_directory_subtree() {
        let g = read_allow("/srv/deploy/");
        assert!(
            g.check_local_read(&resolve_local_path("/srv/deploy/admin.key"))
                .is_ok()
        );
        assert!(
            g.check_local_read(&resolve_local_path("/srv/deploy/sub/github.key"))
                .is_ok()
        );
        assert!(
            g.check_local_read(&resolve_local_path("/srv/other/admin.key"))
                .is_err()
        );
    }

    #[test]
    fn local_write_allow_is_separate_from_read() {
        // Allowing a read never grants the write side.
        let g = read_allow("/srv/deploy");
        assert!(
            g.check_local_write(&resolve_local_path("/srv/deploy/.bashrc"))
                .is_err()
        );
    }

    #[test]
    fn local_allow_refuses_entries_that_open_everything() {
        for entry in ["/", "~", "  ", "/srv/*.key"] {
            let gc = Guards {
                local_read_allow: vec![entry.into()],
                ..Default::default()
            };
            assert!(
                CompiledGuards::compile(&gc).is_err(),
                "should refuse entry: {entry:?}"
            );
        }
    }

    #[test]
    fn local_allow_entry_survives_traversal_in_the_call() {
        // The call site resolves before the guard, so `..` cannot walk out of
        // the allowed subtree and back into a protected one.
        let g = read_allow("/srv/deploy");
        let escaped = resolve_local_path("/srv/deploy/../secrets/admin.key");
        assert!(g.check_local_read(&escaped).is_err());
    }

    #[test]
    fn guard_cache_build_rejects_a_bad_allowlist_entry() {
        // The entry is valid TOML and only dies when the guards compile, which
        // is why `check` builds the cache instead of stopping at the parse.
        let cfg: Config = toml::from_str(
            r#"
            [defaults.guards]
            local_read_allow = ["/srv/*.key"]
            "#,
        )
        .expect("config parses");
        assert!(GuardCache::build(&cfg).is_err());
    }

    /// A config whose one host authenticates with `key`, parsed without
    /// `load` so the key does not have to pass `validate`.
    fn cfg_naming_key(key: &Path, guards: &str) -> Config {
        toml::from_str(&format!(
            r#"
            [defaults.guards]
            {guards}

            [host.k]
            addr = "1.2.3.4"
            user = "root"
            key = "{}"
            "#,
            slashed(key)
        ))
        .expect("config parses")
    }

    fn resolved(p: &Path) -> PathBuf {
        resolve_local_path(&slashed(p))
    }

    #[test]
    fn own_files_are_out_of_reach_both_ways() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("prod");
        let notes = dir.path().join("notes.txt");
        std::fs::write(&key, "k").unwrap();
        std::fs::write(&notes, "n").unwrap();
        let g = GuardCache::build(&cfg_naming_key(&key, ""))
            .unwrap()
            .for_host("k");
        // A key with no extension matches no path pattern; the config names it.
        assert!(g.check_local_read(&resolved(&key)).is_err());
        assert!(g.check_local_write(&resolved(&key)).is_err());
        // A `dn` over the config and a `reload` would rewrite the guards.
        let hosts_toml = resolved(&config_dir().join("hosts.toml"));
        assert!(g.check_local_write(&hosts_toml).is_err());
        assert!(g.check_local_read(&hosts_toml).is_err());
        assert!(g.check_local_read(&resolved(&notes)).is_ok());
    }

    #[test]
    fn allowlist_cannot_open_own_files() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("prod");
        let notes = dir.path().join("notes.txt");
        std::fs::write(&key, "k").unwrap();
        std::fs::write(&notes, "n").unwrap();
        let naming_key = format!(r#"local_read_allow = ["{}"]"#, slashed(&key));
        let err = GuardCache::build(&cfg_naming_key(&key, &naming_key)).unwrap_err();
        assert!(err.to_string().contains("own files"), "got: {err}");
        // Allowing the directory is fine, the key inside it stays blocked.
        let naming_dir = format!(r#"local_read_allow = ["{}"]"#, slashed(dir.path()));
        let g = GuardCache::build(&cfg_naming_key(&key, &naming_dir))
            .unwrap()
            .for_host("k");
        assert!(g.check_local_read(&resolved(&key)).is_err());
        assert!(g.check_local_read(&resolved(&notes)).is_ok());
    }

    #[test]
    fn local_read_blocks_a_key_by_its_content() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("backup");
        let cert = dir.path().join("site.crt");
        std::fs::write(
            &key,
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbg==\n-----END OPENSSH PRIVATE KEY-----\n",
        )
        .unwrap();
        std::fs::write(
            &cert,
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let g = local_guards();
        assert!(g.check_local_read(&resolved(&key)).is_err());
        assert!(g.check_local_read(&resolved(&cert)).is_ok());
        // The operator can still ship one on purpose.
        let g = read_allow(&slashed(&key));
        assert!(g.check_local_read(&resolved(&key)).is_ok());
    }

    #[test]
    fn private_key_markers() {
        for head in [
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
            "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "PuTTY-User-Key-File-3: ssh-ed25519",
            "# deploy key\n-----BEGIN OPENSSH PRIVATE KEY-----",
        ] {
            assert!(
                looks_like_private_key(head.as_bytes()),
                "should flag: {head}"
            );
        }
        for head in [
            "",
            "-----BEGIN CERTIFICATE-----",
            "-----BEGIN PUBLIC KEY-----",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 user@host",
            "-----BEGIN CERTIFICATE-----\nPRIVATE KEY named in the body",
        ] {
            assert!(
                !looks_like_private_key(head.as_bytes()),
                "should pass: {head}"
            );
        }
    }

    #[test]
    fn lexical_normalize_drops_traversal() {
        assert_eq!(
            slashed(&lexical_normalize(Path::new("/a/b/../c/./d"))),
            "/a/c/d"
        );
        // Popping past the root stays at the root rather than escaping.
        assert_eq!(slashed(&lexical_normalize(Path::new("/../../etc"))), "/etc");
    }
}
