use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};

use crate::errors::{Result, SshError};

const DEFAULT_DENY: &[(&str, &str)] = &[
    // Matches: rm -rf /, rm -rf '/', rm -rf "/", rm -rf //, rm -rf /*,
    // rm -rf -- /, rm --recursive --force /, rm -rf /etc, RM -rf /, etc.
    // Won't match relative paths (./tmp, ../foo).
    (
        "rm-rf-root",
        r#"(?im)\brm\b(?:\s+(?:-{1,2}[a-zA-Z\-]+|--))*\s+['"]?/+\*?[a-zA-Z]*['"]?(\s|$|/)"#,
    ),
    ("dd-disk", r#"(?im)\bdd\b.*\bof\s*=\s*['"]?/dev/(sd|nvme|hd|vd)"#),
    ("mkfs", r#"(?im)\bmkfs(\.[a-z0-9]+)?\s+['"]?/dev/"#),
    ("forkbomb", r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
    ("redirect-disk", r#">\s*['"]?/dev/(sd|nvme|hd|vd)"#),
    // chmod root: only literal `/` (filesystem root) is denied. `/etc` is allowed
    // by design — escalate via per-host guards if you want broader coverage.
    (
        "chmod-root",
        r#"(?im)\bchmod\b(?:\s+(?:-{1,2}[a-zA-Z\-]+|--))*\s+[0-7]{3,4}\s+['"]?/+['"]?(\s|$)"#,
    ),
];

const DEFAULT_CONFIRM: &[(&str, &str)] = &[
    ("shutdown", r"(?im)\b(shutdown|halt|poweroff)\b"),
    ("reboot", r"(?im)\breboot\b"),
    ("sql-drop", r"(?i)\bDROP\s+(TABLE|DATABASE|SCHEMA)\b"),
    ("sql-truncate", r"(?i)\bTRUNCATE\s+TABLE\b"),
    ("systemctl-stop", r"(?im)\bsystemctl\s+(stop|disable|mask)\b"),
    ("docker-rm", r"(?im)\bdocker\s+(rm|rmi|volume\s+rm|system\s+prune)\b"),
];

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default, rename = "host")]
    pub hosts: HashMap<String, Host>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Defaults {
    #[serde(default = "default_true")]
    pub import_ssh_config: bool,
    #[serde(default = "default_output")]
    pub output: OutputFmt,
    #[serde(default = "default_idle")]
    pub session_idle_timeout: HumanDuration,
    #[serde(default = "default_true")]
    pub audit_log: bool,
    #[serde(default = "default_audit_path")]
    pub audit_log_path: PathBuf,
    #[serde(default)]
    pub guards: Guards,
    #[serde(default = "default_keepalive")]
    pub keepalive: HumanDuration,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout: HumanDuration,
    #[serde(default = "default_truncate")]
    pub truncate_bytes: usize,
    #[serde(default = "default_max_capture")]
    pub max_capture_bytes: usize,
    #[serde(default = "default_max_channels")]
    pub max_channels_per_host: usize,
    #[serde(default)]
    pub strict_host_key_checking: StrictHostKey,
    /// Optional default host alias used when a tool call omits `host`.
    #[serde(default)]
    pub default_host: Option<String>,
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            import_ssh_config: true,
            output: OutputFmt::Toon,
            session_idle_timeout: default_idle(),
            audit_log: true,
            audit_log_path: default_audit_path(),
            guards: Guards::default(),
            keepalive: default_keepalive(),
            connect_timeout: default_connect_timeout(),
            truncate_bytes: default_truncate(),
            max_capture_bytes: default_max_capture(),
            max_channels_per_host: default_max_channels(),
            strict_host_key_checking: StrictHostKey::default(),
            default_host: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StrictHostKey {
    /// Pin on first connect, reject on mismatch.
    #[default]
    Tofu,
    /// Reject any host not already pinned.
    Strict,
    /// Accept anything (legacy 0.1.0 behavior).
    Off,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OutputFmt {
    Toon,
    Json,
    Text,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Host {
    pub addr: String,
    pub user: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub auth: AuthMethod,
    /// Primary private key path (back-compat with single-key configs).
    #[serde(default)]
    pub key: Option<PathBuf>,
    /// Optional list of additional candidate keys, tried in order after `key`.
    /// Useful when migrating between ed25519/rsa or when a host accepts
    /// multiple identities.
    #[serde(default)]
    pub keys: Option<Vec<PathBuf>>,
    #[serde(default)]
    pub guards: Option<Guards>,
    #[serde(default)]
    pub known_host_fingerprint: Option<String>,
}

impl Host {
    /// Iterates over every configured key path in priority order.
    pub fn all_keys(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if let Some(k) = &self.key {
            out.push(k.clone());
        }
        if let Some(extra) = &self.keys {
            for k in extra {
                if !out.iter().any(|p| p == k) {
                    out.push(k.clone());
                }
            }
        }
        out
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    #[default]
    Key,
    Agent,
    Password,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Guards {
    #[serde(default = "default_true")]
    pub use_default_deny: bool,
    #[serde(default = "default_true")]
    pub use_default_confirm: bool,
    #[serde(default)]
    pub deny: Vec<NamedPattern>,
    #[serde(default)]
    pub confirm: Vec<NamedPattern>,
    #[serde(default)]
    pub read_only: bool,
}

impl Default for Guards {
    fn default() -> Self {
        Self {
            use_default_deny: true,
            use_default_confirm: true,
            deny: Vec::new(),
            confirm: Vec::new(),
            read_only: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NamedPattern {
    pub name: String,
    pub pattern: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HumanDuration(pub Duration);

impl<'de> Deserialize<'de> for HumanDuration {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        parse_duration(&s).map(HumanDuration).map_err(serde::de::Error::custom)
    }
}

impl Serialize for HumanDuration {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{}s", self.0.as_secs()))
    }
}

fn parse_duration(s: &str) -> std::result::Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".into());
    }
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = num.parse().map_err(|e| format!("bad number in duration '{s}': {e}"))?;
    let mult = match unit.trim() {
        "" | "s" | "sec" | "secs" => 1,
        "ms" => 0,
        "m" | "min" | "mins" => 60,
        "h" | "hr" | "hrs" => 3600,
        "d" | "day" | "days" => 86400,
        other => return Err(format!("unknown unit '{other}' in duration '{s}'")),
    };
    if mult == 0 {
        Ok(Duration::from_millis(n))
    } else {
        Ok(Duration::from_secs(n * mult))
    }
}

fn default_true() -> bool { true }
fn default_port() -> u16 { 22 }
fn default_output() -> OutputFmt { OutputFmt::Toon }
fn default_idle() -> HumanDuration { HumanDuration(Duration::from_secs(900)) }
fn default_keepalive() -> HumanDuration { HumanDuration(Duration::from_secs(30)) }
fn default_connect_timeout() -> HumanDuration { HumanDuration(Duration::from_secs(15)) }
fn default_truncate() -> usize { 32 * 1024 }
fn default_max_capture() -> usize { 256 * 1024 }
fn default_max_channels() -> usize { 8 }
fn default_audit_path() -> PathBuf {
    config_dir().join("audit.log")
}

pub fn config_dir() -> PathBuf {
    if let Ok(env) = std::env::var("FAST_MCP_SSH_HOME") {
        return PathBuf::from(env);
    }
    dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join(".fast-mcp-ssh")
}

pub fn default_config_path() -> PathBuf {
    config_dir().join("hosts.toml")
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(SshError::Config(format!(
                "config not found at {} — see examples/hosts.toml",
                path.display()
            )));
        }
        let raw = std::fs::read_to_string(path)?;
        let mut cfg: Config = toml::from_str(&raw)?;
        if cfg.defaults.import_ssh_config {
            cfg.merge_ssh_config();
        }
        // Expand `~` after the ssh_config import so identity files imported
        // from `~/.ssh/config` (where `IdentityFile ~/.ssh/id_rsa` keeps the
        // literal `~`) get normalized too.
        cfg.expand_paths();
        cfg.validate()?;
        Ok(cfg)
    }

    /// Catches the common misconfigurations at startup so the first tool
    /// call doesn't have to discover them. Refuses:
    /// * `default_host` pointing at an undeclared alias
    /// * `auth = "key"` with no `key` and no `keys[]`
    /// * `auth = "password"` is fine — password is supplied per-call
    /// * `auth = "agent"` is fine — no key path needed
    pub fn validate(&self) -> Result<()> {
        if let Some(dh) = &self.defaults.default_host {
            if !self.hosts.contains_key(dh) {
                return Err(SshError::Config(format!(
                    "default_host '{dh}' is not declared in [host.*]"
                )));
            }
        }
        for (name, h) in &self.hosts {
            if matches!(h.auth, AuthMethod::Key) && h.all_keys().is_empty() {
                return Err(SshError::Config(format!(
                    "host '{name}': auth = \"key\" but no `key` or `keys[]` set"
                )));
            }
            if h.addr.trim().is_empty() {
                return Err(SshError::Config(format!("host '{name}': addr is empty")));
            }
            if h.user.trim().is_empty() {
                return Err(SshError::Config(format!("host '{name}': user is empty")));
            }
        }
        Ok(())
    }

    pub fn host(&self, name: &str) -> Result<&Host> {
        self.hosts
            .get(name)
            .ok_or_else(|| SshError::UnknownHost(name.to_string()))
    }

    pub fn host_names(&self) -> Vec<String> {
        let mut v: Vec<_> = self.hosts.keys().cloned().collect();
        v.sort();
        v
    }

    fn expand_paths(&mut self) {
        for h in self.hosts.values_mut() {
            if let Some(k) = &h.key {
                if let Some(s) = k.to_str() {
                    if let Ok(expanded) = shellexpand::full(s) {
                        h.key = Some(PathBuf::from(expanded.into_owned()));
                    }
                }
            }
            if let Some(extra) = h.keys.as_mut() {
                for k in extra.iter_mut() {
                    if let Some(s) = k.to_str() {
                        if let Ok(expanded) = shellexpand::full(s) {
                            *k = PathBuf::from(expanded.into_owned());
                        }
                    }
                }
            }
        }
        if let Some(s) = self.defaults.audit_log_path.to_str() {
            if let Ok(expanded) = shellexpand::full(s) {
                self.defaults.audit_log_path = PathBuf::from(expanded.into_owned());
            }
        }
    }

    fn merge_ssh_config(&mut self) {
        // Best-effort import of ~/.ssh/config aliases. Reads via ssh2-config-rs
        // and adds any non-wildcard host that is not already declared in hosts.toml.
        let p = match dirs::home_dir() {
            Some(h) => h.join(".ssh").join("config"),
            None => return,
        };
        if !p.exists() {
            return;
        }
        use std::io::BufReader;
        use ssh2_config_rs::{ParseRule, SshConfig};
        let file = match std::fs::File::open(&p) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(?e, "open ~/.ssh/config failed");
                return;
            }
        };
        let mut reader = BufReader::new(file);
        let parsed = match SshConfig::default().parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(?e, "parse ~/.ssh/config failed");
                return;
            }
        };
        for host_block in parsed.get_hosts() {
            for pattern in host_block.pattern.iter() {
                let alias = pattern.pattern.as_str();
                if alias.contains('*') || alias.contains('?') {
                    continue;
                }
                if self.hosts.contains_key(alias) {
                    continue;
                }
                let resolved = parsed.query(alias);
                let Some(addr) = resolved.host_name.clone() else { continue };
                let user = resolved.user.clone().unwrap_or_else(|| "root".into());
                let port = resolved.port.unwrap_or(22);
                let key = resolved
                    .identity_file
                    .as_ref()
                    .and_then(|v| v.first().cloned());
                self.hosts.insert(
                    alias.to_string(),
                    Host {
                        addr,
                        user,
                        port,
                        auth: if key.is_some() { AuthMethod::Key } else { AuthMethod::Agent },
                        key,
                        keys: None,
                        guards: None,
                        known_host_fingerprint: None,
                    },
                );
            }
        }
    }
}

pub fn default_deny_patterns() -> Vec<NamedPattern> {
    DEFAULT_DENY
        .iter()
        .map(|(n, p)| NamedPattern { name: (*n).into(), pattern: (*p).into() })
        .collect()
}

pub fn default_confirm_patterns() -> Vec<NamedPattern> {
    DEFAULT_CONFIRM
        .iter()
        .map(|(n, p)| NamedPattern { name: (*n).into(), pattern: (*p).into() })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_units() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("15m").unwrap(), Duration::from_secs(900));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert!(parse_duration("xyz").is_err());
    }

    #[test]
    fn parse_minimal_toml() {
        let raw = r#"
            [host.test]
            addr = "1.2.3.4"
            user = "root"
        "#;
        let c: Config = toml::from_str(raw).unwrap();
        assert_eq!(c.hosts.len(), 1);
        let h = &c.hosts["test"];
        assert_eq!(h.port, 22);
        assert_eq!(h.user, "root");
        assert!(matches!(h.auth, AuthMethod::Key));
    }

    #[test]
    fn validate_rejects_unknown_default_host() {
        let raw = r#"
            [defaults]
            default_host = "nope"

            [host.real]
            addr = "1.2.3.4"
            user = "root"
        "#;
        let c: Config = toml::from_str(raw).unwrap();
        let err = c.validate().unwrap_err();
        assert!(err.to_string().contains("default_host"), "got: {err}");
    }

    #[test]
    fn validate_rejects_auth_key_without_key() {
        let raw = r#"
            [host.k]
            addr = "1.2.3.4"
            user = "root"
            auth = "key"
        "#;
        let c: Config = toml::from_str(raw).unwrap();
        let err = c.validate().unwrap_err();
        assert!(err.to_string().contains("auth"), "got: {err}");
    }

    #[test]
    fn validate_accepts_multi_keys() {
        let raw = r#"
            [host.k]
            addr = "1.2.3.4"
            user = "root"
            auth = "key"
            keys = ["~/a", "~/b"]
        "#;
        let c: Config = toml::from_str(raw).unwrap();
        c.validate().expect("ok");
        let h = &c.hosts["k"];
        assert_eq!(h.all_keys().len(), 2);
    }

    #[test]
    fn parse_full_toml() {
        let raw = r#"
            [defaults]
            output = "json"
            session_idle_timeout = "5m"

            [host.box1]
            addr = "10.0.0.1"
            user = "ops"
            port = 2222
            auth = "agent"
        "#;
        let c: Config = toml::from_str(raw).unwrap();
        assert_eq!(c.defaults.output, OutputFmt::Json);
        assert_eq!(c.defaults.session_idle_timeout.0, Duration::from_secs(300));
        assert_eq!(c.hosts["box1"].port, 2222);
        assert!(matches!(c.hosts["box1"].auth, AuthMethod::Agent));
    }
}
