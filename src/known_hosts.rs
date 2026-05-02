//! Lightweight known_hosts storage. Keeps fingerprints in
//! `~/.fast-mcp-ssh/known_hosts.toml` so we never touch the user's
//! `~/.ssh/known_hosts` (which has a different format and is owned by
//! the regular ssh client).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

use crate::config::config_dir;
use crate::errors::{Result, SshError};

#[derive(Default, Debug, Serialize, Deserialize)]
struct Stored {
    #[serde(default)]
    host: HashMap<String, Entry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Entry {
    fingerprint: String,
}

pub enum KnownHostMatch {
    Ok,
    Mismatch { expected: String },
    Unknown,
}

pub struct KnownHostsStore {
    path: PathBuf,
    inner: RwLock<Stored>,
}

impl KnownHostsStore {
    pub fn open_or_create() -> Result<std::sync::Arc<Self>> {
        let path = config_dir().join("known_hosts.toml");
        let stored: Stored = if path.exists() {
            let raw = std::fs::read_to_string(&path)?;
            toml::from_str(&raw).unwrap_or_default()
        } else {
            Stored::default()
        };
        Ok(std::sync::Arc::new(Self {
            path,
            inner: RwLock::new(stored),
        }))
    }

    pub fn check(&self, host: &str, fingerprint: &str) -> KnownHostMatch {
        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(_) => return KnownHostMatch::Unknown,
        };
        match guard.host.get(host) {
            Some(e) if e.fingerprint == fingerprint => KnownHostMatch::Ok,
            Some(e) => KnownHostMatch::Mismatch {
                expected: e.fingerprint.clone(),
            },
            None => KnownHostMatch::Unknown,
        }
    }

    pub fn add(&self, host: &str, fingerprint: &str) -> Result<()> {
        {
            let mut guard = self.inner.write().map_err(|_| SshError::Other("known_hosts lock poisoned".into()))?;
            guard.host.insert(
                host.to_string(),
                Entry {
                    fingerprint: fingerprint.to_string(),
                },
            );
        }
        self.flush()
    }

    fn flush(&self) -> Result<()> {
        let guard = self
            .inner
            .read()
            .map_err(|_| SshError::Other("known_hosts lock poisoned".into()))?;
        let serialized = toml::to_string_pretty(&*guard)
            .map_err(|e| SshError::Config(format!("serialize known_hosts: {e}")))?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.path, serialized)?;
        Ok(())
    }
}
