pub mod connect;
pub mod exec;
pub mod pty;

use std::{
    collections::HashMap,
    sync::Arc,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
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
/// How long a call waits for a free channel slot before giving up with
/// `ChannelLimit`. Long enough to ride out a burst of parallel `exec`s, short
/// enough that a leaked slot surfaces as an actionable error.
const CHANNEL_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(15);

/// A pre-opened SSH session channel held in the pool. Owns the semaphore
/// permit so concurrency accounting stays correct when the channel is
/// consumed by `exec`.
pub struct ParkedChannel {
    pub channel: russh::Channel<russh::client::Msg>,
    pub permit: OwnedSemaphorePermit,
}

/// Cached SFTP subsystem plus the semaphore permit for its channel, so the
/// long-lived SFTP channel counts against `max_channels_per_host`.
struct SftpState {
    session: Arc<SftpSession>,
    _permit: OwnedSemaphorePermit,
}

/// One persistent SSH connection per host.
/// `handle` is the russh client handle (TCP+SSH session). Channels are spawned per-call (`exec`)
/// or kept alive (`pty`, `sftp`).
pub struct Session {
    pub handle: SshHandle,
    /// Default unnamed PTY (back-compat with single-shell `sh` usage).
    pub pty: Mutex<Option<Arc<pty::PtyState>>>,
    /// Named PTYs keyed by user-supplied shell name. Each name is an
    /// independent persistent shell with its own working directory and
    /// environment.
    pub named_ptys: Mutex<HashMap<String, Arc<pty::PtyState>>>,
    sftp: Mutex<Option<SftpState>>,
    /// Caps concurrent open channels for this host so we don't exceed sshd
    /// `MaxSessions` (default 10).
    channel_limit: Arc<Semaphore>,
    /// The configured cap, kept for the `ChannelLimit` error message.
    max_channels: usize,
    /// Pool of pre-opened session channels. Each entry has already paid the
    /// `CHANNEL_OPEN`/`CHANNEL_OPEN_CONFIRMATION` round-trip, so an exec call
    /// can grab one and immediately send the exec request (-1 RTT).
    channel_pool: Mutex<Vec<ParkedChannel>>,
    pool_target: usize,
    /// Notified whenever the pool is drained or a refill should be considered.
    refill_notify: Arc<Notify>,
    last_used_ms: AtomicU64,
    started: Instant,
    /// Keeps the bastion session alive for the lifetime of this session.
    /// Without this, the parent handle drops and the direct-tcpip transport
    /// dies under us. Underscored because it is held purely for liveness.
    _proxy_parent: Option<Arc<Session>>,
    /// Channel slot on the bastion consumed by the ProxyJump direct-tcpip
    /// transport, held for the lifetime of this session.
    _proxy_permit: Option<OwnedSemaphorePermit>,
    /// In-flight `exec` cancellation tokens keyed by an incrementing id.
    /// `interrupt` walks this map to abort runaway commands without
    /// disconnecting the whole session.
    exec_cancels: Mutex<HashMap<u64, Arc<Notify>>>,
    next_exec_id: AtomicU64,
}

impl Session {
    #[allow(dead_code)]
    pub fn new(handle: SshHandle, max_channels: usize) -> Self {
        Self::new_with_parent(handle, max_channels, None, None)
    }

    pub fn new_with_parent(
        handle: SshHandle,
        max_channels: usize,
        parent: Option<Arc<Session>>,
        proxy_permit: Option<OwnedSemaphorePermit>,
    ) -> Self {
        Self {
            handle,
            pty: Mutex::new(None),
            named_ptys: Mutex::new(HashMap::new()),
            sftp: Mutex::new(None),
            channel_limit: Arc::new(Semaphore::new(max_channels.max(1))),
            max_channels: max_channels.max(1),
            channel_pool: Mutex::new(Vec::with_capacity(DEFAULT_POOL_TARGET)),
            pool_target: DEFAULT_POOL_TARGET.min(max_channels.saturating_sub(1)),
            refill_notify: Arc::new(Notify::new()),
            last_used_ms: AtomicU64::new(0),
            started: Instant::now(),
            _proxy_parent: parent,
            _proxy_permit: proxy_permit,
            exec_cancels: Mutex::new(HashMap::new()),
            next_exec_id: AtomicU64::new(0),
        }
    }

    /// Register a cancellation token for an in-flight exec call. Returns a
    /// guard whose `Drop` deregisters automatically — exec callers should
    /// hold it for the full duration of the call.
    pub async fn register_exec(&self, notify: Arc<Notify>) -> u64 {
        let id = self.next_exec_id.fetch_add(1, Ordering::Relaxed);
        self.exec_cancels.lock().await.insert(id, notify);
        id
    }

    pub async fn deregister_exec(&self, id: u64) {
        self.exec_cancels.lock().await.remove(&id);
    }

    /// Notify every in-flight exec on this session. Returns the count of
    /// notifications fired.
    pub async fn cancel_all_execs(&self) -> usize {
        let map = self.exec_cancels.lock().await;
        let n = map.len();
        for n in map.values() {
            n.notify_waiters();
        }
        n
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
    /// Bounded: an unbounded wait would hang the call forever behind a leaked
    /// forward or a stuck PTY, with no hint about which knob to turn.
    pub async fn acquire_channel(&self) -> Result<OwnedSemaphorePermit> {
        let sem = Arc::clone(&self.channel_limit);
        let start = Instant::now();
        match tokio::time::timeout(CHANNEL_ACQUIRE_TIMEOUT, sem.acquire_owned()).await {
            Ok(Ok(p)) => Ok(p),
            Ok(Err(_)) => Err(SshError::Other("channel semaphore closed".into())),
            Err(_) => Err(SshError::ChannelLimit {
                limit: self.max_channels,
                waited_ms: start.elapsed().as_millis() as u64,
            }),
        }
    }

    /// Take a pre-opened channel + its permit from the pool, or open a fresh
    /// one. Always notifies the refill task so the pool topples back up.
    /// The bool is true when the channel came from the pool — parked channels
    /// can have been closed server-side while waiting, so callers on that
    /// path should retry once with a fresh channel on immediate failure.
    pub async fn take_or_open_channel(
        &self,
    ) -> Result<(
        russh::Channel<russh::client::Msg>,
        OwnedSemaphorePermit,
        bool,
    )> {
        let parked = self.channel_pool.lock().await.pop();
        if let Some(p) = parked {
            self.refill_notify.notify_one();
            return Ok((p.channel, p.permit, true));
        }
        let permit = self.acquire_channel().await?;
        let channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(SshError::from)?;
        self.refill_notify.notify_one();
        Ok((channel, permit, false))
    }

    /// Lazily open and cache an SFTP subsystem on this session. Subsequent calls
    /// return the cached `Arc<SftpSession>`. Saves a channel-open + subsystem
    /// round-trip per SFTP operation. The channel comes from the pre-warmed
    /// pool when available and its semaphore permit is held for the lifetime
    /// of the cached subsystem.
    pub async fn sftp(&self) -> Result<Arc<SftpSession>> {
        let mut guard = self.sftp.lock().await;
        if let Some(s) = guard.as_ref() {
            return Ok(Arc::clone(&s.session));
        }
        let (channel, permit, _) = self.take_or_open_channel().await?;
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
        *guard = Some(SftpState {
            session: Arc::clone(&arc),
            _permit: permit,
        });
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
    pub config: Arc<ArcSwap<Config>>,
    /// Cached passwords from elicitation (host -> password). Memory only, never persisted.
    /// `Zeroizing` wipes the buffer when the entry is dropped.
    passwords: Arc<DashMap<String, Zeroizing<String>>>,
    /// Key path that last authenticated per host, tried first on reconnect so
    /// multi-key configs don't re-pay an auth round-trip per rejected key.
    key_cache: Arc<DashMap<String, std::path::PathBuf>>,
    /// Per-host singleflight locks for `get_or_connect`.
    connect_locks: Arc<DashMap<String, ConnectLock>>,
    idle_timeout: Duration,
    max_channels: usize,
    ssh_cfg: Arc<client::Config>,
    known_hosts: Option<Arc<KnownHostsStore>>,
}

impl SessionPool {
    pub fn new(config: Arc<ArcSwap<Config>>) -> Result<Self> {
        let snapshot = config.load();
        let idle_timeout = snapshot.defaults.session_idle_timeout.0;
        let max_channels = snapshot.defaults.max_channels_per_host;
        let ssh_cfg = connect::build_client_config(&snapshot);
        let known_hosts = if matches!(
            snapshot.defaults.strict_host_key_checking,
            StrictHostKey::Off
        ) {
            None
        } else {
            Some(KnownHostsStore::open_or_create()?)
        };
        drop(snapshot);
        Ok(Self {
            sessions: Arc::new(DashMap::new()),
            config,
            passwords: Arc::new(DashMap::new()),
            key_cache: Arc::new(DashMap::new()),
            connect_locks: Arc::new(DashMap::new()),
            idle_timeout,
            max_channels,
            ssh_cfg,
            known_hosts,
        })
    }

    /// Drop cached sessions for hosts that no longer exist in the current
    /// config, and for hosts whose connection-relevant fields changed
    /// (addr, port, user, auth, key paths, proxy_jump). Returns the dropped
    /// host names.
    pub async fn prune_against(&self, old: &Config) -> Vec<String> {
        let new = self.config.load();
        let mut dropped = Vec::new();
        let names: Vec<String> = self.sessions.iter().map(|e| e.key().clone()).collect();
        for name in names {
            let keep = match (old.hosts.get(&name), new.hosts.get(&name)) {
                (_, None) => false,
                (Some(o), Some(n)) => {
                    o.addr == n.addr
                        && o.port == n.port
                        && o.user == n.user
                        && o.auth == n.auth
                        && o.all_keys() == n.all_keys()
                        && o.proxy_jump == n.proxy_jump
                }
                (None, Some(_)) => true,
            };
            if !keep {
                if let Some(sess) = self.take_session(&name) {
                    let _ = sess
                        .handle
                        .disconnect(russh::Disconnect::ByApplication, "reload", "")
                        .await;
                }
                self.forget_password(&name);
                dropped.push(name);
            }
        }
        dropped
    }

    pub fn cached_password(&self, host: &str) -> Option<Zeroizing<String>> {
        self.passwords
            .get(host)
            .map(|v| Zeroizing::new(v.as_str().to_string()))
    }

    pub fn cache_password(&self, host: &str, pw: Zeroizing<String>) {
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
        password_override: Option<Zeroizing<String>>,
    ) -> Result<Arc<Session>> {
        // Fast path: cached and alive.
        if let Some(s) = self.fresh_session(host_name).await {
            return Ok(s);
        }

        // Slow path: serialize concurrent opens for this host. Validate the
        // host name before allocating a lock — otherwise a spammed-with-bogus
        // input would leak entries into `connect_locks`.
        let _ = self.config.load().host(host_name)?;
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

        let cfg = self.config.load_full();
        let host = cfg.host(host_name)?.clone();

        // Resolve the proxy_jump chain first (recursively). Validation at
        // config load forbids cycles, so this terminates.
        let parent = if let Some(parent_alias) = &host.proxy_jump {
            Some(Box::pin(self.get_or_connect(parent_alias, None)).await?)
        } else {
            None
        };
        // The ProxyJump direct-tcpip transport occupies a channel on the
        // bastion for this session's whole lifetime; count it.
        let proxy_permit = match &parent {
            Some(p) => Some(p.acquire_channel().await?),
            None => None,
        };

        let password = password_override.or_else(|| self.cached_password(host_name));
        let preferred_key = self.key_cache.get(host_name).map(|e| e.value().clone());
        let (handle, used_key) = match connect::open(
            &cfg,
            host_name,
            &host,
            password.as_deref().map(|s| s.as_str()),
            Arc::clone(&self.ssh_cfg),
            self.known_hosts.clone(),
            parent.as_deref(),
            preferred_key.as_deref(),
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
        if let Some(k) = used_key {
            self.key_cache.insert(host_name.to_string(), k);
        }
        let session = Arc::new(Session::new_with_parent(
            handle,
            self.max_channels,
            parent,
            proxy_permit,
        ));
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
            let Some(session) = weak.upgrade() else {
                return;
            };
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
            // Reserve a channel slot. Waiting on the semaphore (instead of
            // try_acquire + sleep polling) means the refill starts its open
            // the instant a slot frees after a burst, so the next exec finds
            // a parked channel instead of re-paying the CHANNEL_OPEN RTT.
            // Hold only the semaphore Arc across the wait so the session can
            // still drop (and this task exit) while we're parked.
            let sem = Arc::clone(&session.channel_limit);
            drop(session);
            let permit = match sem.acquire_owned().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let Some(session) = weak.upgrade() else {
                return;
            };
            if session.handle.is_closed() {
                return;
            }
            // Re-check: the pool may have been refilled by returned channels
            // while we waited for a slot.
            if session.channel_pool.lock().await.len() >= session.pool_target {
                continue;
            }
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
