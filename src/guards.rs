use regex::Regex;

use crate::config::{Config, Guards, NamedPattern, default_confirm_patterns, default_deny_patterns};
use crate::errors::{Result, SshError};

#[derive(Debug, Clone)]
pub struct CompiledPattern {
    pub name: String,
    pub re: Regex,
}

#[derive(Debug, Clone)]
pub struct CompiledGuards {
    pub deny: Vec<CompiledPattern>,
    pub confirm: Vec<CompiledPattern>,
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardCheck {
    Allow,
    Confirm { pattern_name: String },
    Deny { pattern_name: String, pattern: String },
}

impl CompiledGuards {
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
        Ok(Self { deny, confirm, read_only: g.read_only })
    }

    pub fn check(&self, cmd: &str) -> GuardCheck {
        for p in &self.deny {
            if p.re.is_match(cmd) {
                return GuardCheck::Deny {
                    pattern_name: p.name.clone(),
                    pattern: p.re.as_str().to_string(),
                };
            }
        }
        if self.read_only && looks_writeful(cmd) {
            return GuardCheck::Deny {
                pattern_name: "read-only".into(),
                pattern: "host marked read_only".into(),
            };
        }
        for p in &self.confirm {
            if p.re.is_match(cmd) {
                return GuardCheck::Confirm { pattern_name: p.name.clone() };
            }
        }
        GuardCheck::Allow
    }
}

fn compile_one(p: &NamedPattern) -> Result<CompiledPattern> {
    let re = Regex::new(&p.pattern).map_err(|e| {
        SshError::Config(format!("bad regex in guard '{}': {e}", p.name))
    })?;
    Ok(CompiledPattern { name: p.name.clone(), re })
}

const WRITE_HEURISTICS: &[&str] = &[
    " > ", " >> ", "| tee ", "rm ", "mv ", "cp ", "mkdir ", "rmdir ",
    "chmod ", "chown ", "ln ", "touch ", "dd ", "mkfs", "shred ",
    "systemctl restart", "systemctl stop", "systemctl start", "systemctl enable",
    "systemctl disable", "reboot", "shutdown", "halt", "poweroff",
    "docker run", "docker rm", "docker stop", "docker start", "docker restart",
    "docker compose up", "docker compose down", "docker compose restart",
    "apt install", "apt upgrade", "apt remove", "apt purge",
    "yum install", "dnf install", "pacman -S", "pip install",
    "npm install", "git push", "git reset", "git checkout",
];

fn looks_writeful(cmd: &str) -> bool {
    let lc = cmd.to_lowercase();
    WRITE_HEURISTICS.iter().any(|h| lc.contains(h))
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
}
