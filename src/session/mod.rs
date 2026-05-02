pub mod connect;
pub mod exec;
pub mod pty;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use dashmap::DashMap;
use tokio::sync::Mutex;

use crate::config::Config;
use crate::errors::Result;

pub use connect::SshHandle;

/// One persistent SSH connection per host.
/// `handle` is the russh client handle (TCP+SSH session). Channels are spawned per-call (`exec`)
/// or kept alive (`pty`).
pub struct Session {
    pub handle: SshHandle,
    pub pty: Mutex<Option<Arc<pty::PtyState>>>,
    pub last_used: Mutex<Instant>,
}

impl Session {
    pub fn new(handle: SshHandle) -> Self {
        Self {
            handle,
            pty: Mutex::new(None),
            last_used: Mutex::new(Instant::now()),
        }
    }

    pub async fn touch(&self) {
        *self.last_used.lock().await = Instant::now();
    }
}

/// Holds active sessions keyed by host name. Re-uses connections; cleans up idle ones.
#[derive(Clone)]
pub struct SessionPool {
    sessions: Arc<DashMap<String, Arc<Session>>>,
    pub config: Arc<Config>,
    /// Cached passwords from elicitation (host -> password). Memory only, never persisted.
    passwords: Arc<DashMap<String, String>>,
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
        self.passwords.get(host).map(|v| v.clone())
    }

    pub fn cache_password(&self, host: &str, pw: String) {
        self.passwords.insert(host.to_string(), pw);
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
                sess.touch().await;
                return Ok(sess);
            }
            tracing::warn!(host = %host_name, "stale session detected, reconnecting");
            self.sessions.remove(host_name);
        }

        let host = self.config.host(host_name)?.clone();
        let password = password_override.or_else(|| self.cached_password(host_name));
        let handle = connect::open(&host, password.as_deref()).await?;
        let session = Arc::new(Session::new(handle));
        self.sessions.insert(host_name.to_string(), session.clone());
        Ok(session)
    }

    pub async fn evict_idle(&self) {
        let now = Instant::now();
        let to_evict: Vec<String> = {
            let mut v = Vec::new();
            for entry in self.sessions.iter() {
                let last = *entry.value().last_used.lock().await;
                if now.duration_since(last) > self.idle_timeout {
                    v.push(entry.key().clone());
                }
            }
            v
        };
        for k in to_evict {
            tracing::info!(host = %k, "evicting idle session");
            self.sessions.remove(&k);
        }
    }
}

