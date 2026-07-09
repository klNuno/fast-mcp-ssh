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
    /// Serializes flushes so two TOFU writers can't race the
    /// `read-snapshot → write tmp → rename` sequence and produce a
    /// truncated file or interleaved renames. Async so it can be held
    /// across the `spawn_blocking` file write.
    flush_lock: tokio::sync::Mutex<()>,
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
            flush_lock: tokio::sync::Mutex::new(()),
        }))
    }

    /// Key fingerprint storage by `addr:port` (transport identity) plus a
    /// secondary lookup by alias for back-compat with pre-0.2.0 files that
    /// pinned by alias only.
    fn endpoint_key(addr: &str, port: u16) -> String {
        format!("{addr}:{port}")
    }

    pub fn check(&self, host: &str, addr: &str, port: u16, fingerprint: &str) -> KnownHostMatch {
        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(_) => return KnownHostMatch::Unknown,
        };
        let endpoint = Self::endpoint_key(addr, port);
        if let Some(e) = guard.host.get(&endpoint) {
            return if e.fingerprint == fingerprint {
                KnownHostMatch::Ok
            } else {
                KnownHostMatch::Mismatch {
                    expected: e.fingerprint.clone(),
                }
            };
        }
        // Fallback to alias-keyed legacy entries.
        if let Some(e) = guard.host.get(host) {
            return if e.fingerprint == fingerprint {
                KnownHostMatch::Ok
            } else {
                KnownHostMatch::Mismatch {
                    expected: e.fingerprint.clone(),
                }
            };
        }
        KnownHostMatch::Unknown
    }

    pub async fn add(&self, host: &str, addr: &str, port: u16, fingerprint: &str) -> Result<()> {
        {
            let mut guard = self.inner.write().map_err(|_| SshError::Other("known_hosts lock poisoned".into()))?;
            let endpoint = Self::endpoint_key(addr, port);
            guard.host.insert(
                endpoint,
                Entry {
                    fingerprint: fingerprint.to_string(),
                },
            );
            // Drop any stale alias-keyed entry so future TOFU checks rely on
            // the addr:port form only.
            guard.host.remove(host);
        }
        self.flush().await
    }

    async fn flush(&self) -> Result<()> {
        let _flush_guard = self.flush_lock.lock().await;
        let serialized = {
            let guard = self
                .inner
                .read()
                .map_err(|_| SshError::Other("known_hosts lock poisoned".into()))?;
            toml::to_string_pretty(&*guard)
                .map_err(|e| SshError::Config(format!("serialize known_hosts: {e}")))?
        };
        // Offload the file write: this runs mid-handshake on a current_thread
        // runtime, and a slow disk (or AV scanning the rename) would stall
        // every in-flight call.
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            // Atomic write: tmp + rename. A crash mid-write leaves either the
            // old file or the tmp file (which we ignore on next start), never
            // a truncated TOML.
            let tmp = path.with_extension("toml.tmp");
            std::fs::write(&tmp, serialized)?;
            std::fs::rename(&tmp, &path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
            Ok(())
        })
        .await
        .map_err(|e| SshError::Other(format!("known_hosts flush task: {e}")))?
    }
}
