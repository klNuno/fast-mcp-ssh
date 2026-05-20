pub mod connect;
pub mod exec;
pub mod pty;

use std::{
    sync::Arc,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use dashmap::DashMap;
use russh::client;
use russh_sftp::client::SftpSession;
use tokio::sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

use crate::config::{Config, StrictHostKey};
use crate::errors::{Result, SshError};
use crate::known_hosts::KnownHostsStore;

pub use connect::SshHandle;

/// Default number of pre-opened spare channels held per session.
/// Each spare costs one slot against sshd `MaxSessions`. Two is a safe
/// default with the standard `MaxSessions=10`.
const DEFAULT_POOL_TARGET: usize = 2;

/// A pre-opened SSH session channel held in the pool. Owns the semaphore
/// permit so concurrency accounting stays correct when the channel is
/// consumed by `exec`.
pub struct ParkedChannel {
    pub channel: russh::Channel<russh::client::Msg>,
    pub permit: OwnedSemaphorePermit,
}

/// One persistent SSH connection per host.
/// `handle` is the russh client handle (TCP+SSH session). Channels are spawned per-call (`exec`)
/// or kept alive (`pty`, `sftp`).
pub struct Session {
    pub handle: SshHandle,
    pub pty: Mutex<Option<Arc<pty::PtyState>>>,
    pub sftp: Mutex<Option<Arc<SftpSession>>>,
    /// Caps concurrent open channels for this host so we don't exceed sshd
    /// `MaxSessions` (default 10).
    channel_limit: Arc<Semaphore>,
    /// Pool of pre-opened session channels. Each entry has already paid the
    /// `CHANNEL_OPEN`/`CHANNEL_OPEN_CONFIRMATION` round-trip, so an exec call
    /// can grab one and immediately send the exec request (-1 RTT).
    channel_pool: Mutex<Vec<ParkedChannel>>,
    pool_target: usize,
    /// Notified whenever the pool is drained or a refill should be considered.
    refill_notify: Arc<Notify>,
    last_used_ms: AtomicU64,
    started: Instant,
}

impl Session {
    pub fn new(handle: SshHandle, max_channels: usize) -> Self {
        Self {
            handle,
            pty: Mutex::new(None),
            sftp: Mutex::new(None),
            channel_limit: Arc::new(Semaphore::new(max_channels.max(1))),
            channel_pool: Mutex::new(Vec::with_capacity(DEFAULT_POOL_TARGET)),
            pool_target: DEFAULT_POOL_TARGET.min(max_channels.saturating_sub(1).max(0)),
            refill_notify: Arc::new(Notify::new()),
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

    /// Acquire a channel slot. Holds back if too many channels already open.
    pub async fn acquire_channel(&self) -> Result<OwnedSemaphorePermit> {
        Arc::clone(&self.channel_limit)
            .acquire_owned()
            .await
            .map_err(|_| SshError::Other("channel semaphore closed".into()))
    }

    /// Take a pre-opened channel + its permit from the pool, or open a fresh
    /// one. Always notifies the refill task so the pool topples back up.
    pub async fn take_or_open_channel(
        &self,
    ) -> Result<(russh::Channel<russh::client::Msg>, OwnedSemaphorePermit)> {
        let parked = self.channel_pool.lock().await.pop();
        if let Some(p) = parked {
            self.refill_notify.notify_one();
            return Ok((p.channel, p.permit));
        }
        let permit = self.acquire_channel().await?;
        let channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(SshError::from)?;
        self.refill_notify.notify_one();
        Ok((channel, permit))
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
        // want_reply=false saves the SUCCESS round-trip; russh-sftp issues
        // its own INIT on the stream and surfaces a hard error if the
        // subsystem isn't actually live.
        channel
            .request_subsystem(false, "sftp")
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

/// Per-host slot used to serialize concurrent first-time connections so two
/// callers don't both run a full SSH handshake. The mutex protects the
/// "currently connecting" critical section. The cached session lives in
/// `SessionPool.sessions` once the handshake completes.
type ConnectLock = Arc<Mutex<()>>;

/// Holds active sessions keyed by host name. Re-uses connections; cleans up idle ones.
#[derive(Clone)]
pub struct SessionPool {
    sessions: Arc<DashMap<String, Arc<Session>>>,
    pub config: Arc<Config>,
    /// Cached passwords from elicitation (host -> password). Memory only, never persisted.
    /// `Zeroizing` wipes the buffer when the entry is dropped.
    passwords: Arc<DashMap<String, Zeroizing<String>>>,
    /// Per-host singleflight locks for `get_or_connect`.
    connect_locks: Arc<DashMap<String, ConnectLock>>,
    idle_timeout: Duration,
    max_channels: usize,
    ssh_cfg: Arc<client::Config>,
    known_hosts: Option<Arc<KnownHostsStore>>,
}

impl SessionPool {
    pub fn new(config: Arc<Config>) -> Result<Self> {
        let idle_timeout = config.defaults.session_idle_timeout.0;
        let max_channels = config.defaults.max_channels_per_host;
        let ssh_cfg = connect::build_client_config(&config);
        let known_hosts = if matches!(config.defaults.strict_host_key_checking, StrictHostKey::Off) {
            None
        } else {
            Some(KnownHostsStore::open_or_create()?)
        };
        Ok(Self {
            sessions: Arc::new(DashMap::new()),
            config,
            passwords: Arc::new(DashMap::new()),
            connect_locks: Arc::new(DashMap::new()),
            idle_timeout,
            max_channels,
            ssh_cfg,
            known_hosts,
        })
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

    /// Remove the cached session and return it so the caller can run an
    /// explicit shutdown (e.g. send SSH `disconnect`) before the `Arc` drops.
    pub fn take_session(&self, host: &str) -> Option<Arc<Session>> {
        self.sessions.remove(host).map(|(_, v)| v)
    }

    pub fn get(&self, host: &str) -> Option<Arc<Session>> {
        self.sessions.get(host).map(|s| s.clone())
    }

    /// Get an existing live session, or open a new one. Singleflight per host:
    /// concurrent callers for the same host all wait for one handshake.
    pub async fn get_or_connect(
        &self,
        host_name: &str,
        password_override: Option<String>,
    ) -> Result<Arc<Session>> {
        // Fast path: cached and alive.
        if let Some(s) = self.fresh_session(host_name).await {
            return Ok(s);
        }

        // Slow path: serialize concurrent opens for this host. Validate the
        // host name before allocating a lock — otherwise a spammed-with-bogus
        // input would leak entries into `connect_locks`.
        let _ = self.config.host(host_name)?;
        let lock = if let Some(existing) = self.connect_locks.get(host_name) {
            Arc::clone(existing.value())
        } else {
            Arc::clone(
                self.connect_locks
                    .entry(host_name.to_string())
                    .or_insert_with(|| Arc::new(Mutex::new(())))
                    .value(),
            )
        };
        let _guard = lock.lock().await;

        // Re-check inside the critical section in case a sibling already opened.
        if let Some(s) = self.fresh_session(host_name).await {
            return Ok(s);
        }

        let host = self.config.host(host_name)?.clone();
        let password = password_override.or_else(|| self.cached_password(host_name));
        let handle = match connect::open(
            &self.config,
            host_name,
            &host,
            password.as_deref(),
            Arc::clone(&self.ssh_cfg),
            self.known_hosts.clone(),
        )
        .await
        {
            Ok(h) => h,
            Err(e @ SshError::AuthFailed { .. }) => {
                // Cached password is wrong; drop it so the next call can
                // retry with a fresh `password=` argument instead of looping
                // on the bad cache.
                self.passwords.remove(host_name);
                return Err(e);
            }
            Err(e) => return Err(e),
        };
        let session = Arc::new(Session::new(handle, self.max_channels));
        session.touch();
        self.sessions.insert(host_name.to_string(), session.clone());
        if session.pool_target > 0 {
            spawn_pool_refill(Arc::downgrade(&session));
        }
        Ok(session)
    }

    async fn fresh_session(&self, host_name: &str) -> Option<Arc<Session>> {
        let entry = self.sessions.get(host_name)?;
        let sess = entry.clone();
        drop(entry);
        if connect::is_handle_alive(&sess.handle).await {
            sess.touch();
            return Some(sess);
        }
        tracing::warn!(host = %host_name, "stale session detected, will reconnect");
        self.sessions.remove(host_name);
        None
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

/// Background task that keeps a session's `channel_pool` topped up to
/// `pool_target`. Holds only a weak reference so the session can drop
/// (and the task self-exits) when the pool evicts the session.
fn spawn_pool_refill(weak: std::sync::Weak<Session>) {
    tokio::spawn(async move {
        loop {
            let Some(session) = weak.upgrade() else { return };
            // SSH connection died; stop refilling.
            if session.handle.is_closed() {
                return;
            }
            let pool_len = session.channel_pool.lock().await.len();
            if pool_len >= session.pool_target {
                let notify = Arc::clone(&session.refill_notify);
                drop(session);
                notify.notified().await;
                continue;
            }
            // Try to reserve a channel slot without blocking exec calls.
            // If everything is in use, back off briefly and re-check.
            let permit = match Arc::clone(&session.channel_limit).try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    drop(session);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            match session.handle.channel_open_session().await {
                Ok(channel) => {
                    session
                        .channel_pool
                        .lock()
                        .await
                        .push(ParkedChannel { channel, permit });
                }
                Err(e) => {
                    drop(permit);
                    if session.handle.is_closed() {
                        tracing::debug!(?e, "pool refill: handle closed, stopping");
                        return;
                    }
                    tracing::debug!(?e, "pool refill: open failed, retrying");
                    drop(session);
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    });
}
