pub mod connect;
pub mod exec;
pub mod pty;

use std::{
    sync::Arc,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use dashmap::DashMap;
use russh_sftp::client::SftpSession;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::config::Config;
use crate::errors::{Result, SshError};

pub use connect::SshHandle;

/// One persistent SSH connection per host.
/// `handle` is the russh client handle (TCP+SSH session). Channels are spawned per-call (`exec`)
/// or kept alive (`pty`, `sftp`).
pub struct Session {
    pub handle: SshHandle,
    pub pty: Mutex<Option<Arc<pty::PtyState>>>,
    pub sftp: Mutex<Option<Arc<SftpSession>>>,
    last_used_ms: AtomicU64,
    started: Instant,
}

impl Session {
    pub fn new(handle: SshHandle) -> Self {
        Self {
            handle,
            pty: Mutex::new(None),
            sftp: Mutex::new(None),
            last_used_ms: AtomicU64::new(0),
            started: Instant::now(),
        }
    }

    pub fn touch(&self) {
        let elapsed = self.started.elapsed().as_millis() as u64;
        self.last_used_ms.store(elapsed, Ordering::Relaxed);
    }

    fn idle_for(&self, now: Instant) -> Duration {
        let last_ms = self.last_used_ms.load(Ordering::Relaxed);
        let now_ms = now.duration_since(self.started).as_millis() as u64;
        Duration::from_millis(now_ms.saturating_sub(last_ms))
    }

    /// Lazily open and cache an SFTP subsystem on this session. Subsequent calls
    /// return the cached `Arc<SftpSession>`. Saves a channel-open + subsystem
    /// round-trip per SFTP operation.
    pub async fn sftp(&self) -> Result<Arc<SftpSession>> {
        let mut guard = self.sftp.lock().await;
        if let Some(s) = guard.as_ref() {
            return Ok(Arc::clone(s));
        }
        let channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(SshError::from)?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(SshError::from)?;
        let sftp = SftpSession::new(channel.into_stream())
            .await
            .map_err(SshError::from)?;
        let arc = Arc::new(sftp);
        *guard = Some(Arc::clone(&arc));
        Ok(arc)
    }
}

/// Holds active sessions keyed by host name. Re-uses connections; cleans up idle ones.
#[derive(Clone)]
pub struct SessionPool {
    sessions: Arc<DashMap<String, Arc<Session>>>,
    pub config: Arc<Config>,
    /// Cached passwords from elicitation (host -> password). Memory only, never persisted.
    /// `Zeroizing` wipes the buffer when the entry is dropped.
    passwords: Arc<DashMap<String, Zeroizing<String>>>,
    idle_timeout: Duration,
}

impl SessionPool {
    pub fn new(config: Arc<Config>) -> Self {
        let idle_timeout = config.defaults.session_idle_timeout.0;
        Self {
            sessions: Arc::new(DashMap::new()),
            config,
            passwords: Arc::new(DashMap::new()),
            idle_timeout,
        }
    }

    pub fn cached_password(&self, host: &str) -> Option<String> {
        self.passwords.get(host).map(|v| v.as_str().to_string())
    }

    pub fn cache_password(&self, host: &str, pw: String) {
        self.passwords.insert(host.to_string(), Zeroizing::new(pw));
    }

    pub fn forget_password(&self, host: &str) {
        self.passwords.remove(host);
    }

    pub fn list_active(&self) -> Vec<String> {
        let mut v: Vec<String> = self.sessions.iter().map(|e| e.key().clone()).collect();
        v.sort();
        v
    }

    pub fn drop_session(&self, host: &str) {
        self.sessions.remove(host);
    }

    pub fn get(&self, host: &str) -> Option<Arc<Session>> {
        self.sessions.get(host).map(|s| s.clone())
    }

    /// Get an existing live session, or open a new one.
    pub async fn get_or_connect(
        &self,
        host_name: &str,
        password_override: Option<String>,
    ) -> Result<Arc<Session>> {
        if let Some(s) = self.sessions.get(host_name) {
            let sess = s.clone();
            drop(s);
            if connect::is_handle_alive(&sess.handle).await {
                sess.touch();
                return Ok(sess);
            }
            tracing::warn!(host = %host_name, "stale session detected, reconnecting");
            self.sessions.remove(host_name);
        }

        let host = self.config.host(host_name)?.clone();
        let password = password_override.or_else(|| self.cached_password(host_name));
        let handle = connect::open(&self.config, host_name, &host, password.as_deref()).await?;
        let session = Arc::new(Session::new(handle));
        session.touch();
        self.sessions.insert(host_name.to_string(), session.clone());
        Ok(session)
    }

    pub async fn evict_idle(&self) {
        let now = Instant::now();
        let to_evict: Vec<String> = self
            .sessions
            .iter()
            .filter_map(|entry| {
                if entry.value().idle_for(now) > self.idle_timeout {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();
        for k in to_evict {
            tracing::info!(host = %k, "evicting idle session");
            self.sessions.remove(&k);
        }
    }
}
