//! Lightweight known_hosts storage. Keeps fingerprints in
//! `~/.fast-mcp-ssh/known_hosts.toml` so we never touch the user's
//! `~/.ssh/known_hosts` (which has a different format and is owned by
//! the regular ssh client).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, RwLock};

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
    /// Serializes flushes so two TOFU writers can't race the
    /// `read-snapshot → write tmp → rename` sequence and produce a
    /// truncated file or interleaved renames.
    flush_lock: Mutex<()>,
}

impl KnownHostsStore {
    pub fn open_or_create() -> Result<std::sync::Arc<Self>> {
        let path = config_dir().join("known_hosts.toml");
        let stored: Stored = if path.exists() {
            let raw = std::fs::read_to_string(&path)?;
            // Refuse to start on a corrupted file rather than silently
            // dropping pinned fingerprints — re-pinning under TOFU on the
            // next connect would accept any MITM.
            toml::from_str(&raw).map_err(|e| {
                SshError::Config(format!(
                    "{}: parse failed ({e}). Move the file aside if you intend to reset.",
                    path.display()
                ))
            })?
        } else {
            Stored::default()
        };
        Ok(std::sync::Arc::new(Self {
            path,
            inner: RwLock::new(stored),
            flush_lock: Mutex::new(()),
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
        let _flush_guard = self
            .flush_lock
            .lock()
            .map_err(|_| SshError::Other("known_hosts flush_lock poisoned".into()))?;
        let serialized = {
            let guard = self
                .inner
                .read()
                .map_err(|_| SshError::Other("known_hosts lock poisoned".into()))?;
            toml::to_string_pretty(&*guard)
                .map_err(|e| SshError::Config(format!("serialize known_hosts: {e}")))?
        };
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Atomic write: tmp + rename. A crash mid-write leaves either the old
        // file or the tmp file (which we ignore on next start), never a
        // truncated TOML.
        let tmp = self.path.with_extension("toml.tmp");
        std::fs::write(&tmp, serialized)?;
        std::fs::rename(&tmp, &self.path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }
}
