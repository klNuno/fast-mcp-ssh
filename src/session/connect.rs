use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use russh::Preferred;
use russh::client::{self, Handle};
use russh::keys::ssh_key::{Algorithm, EcdsaCurve, HashAlg};
use russh::keys::{PrivateKeyWithHashAlg, load_secret_key};

use crate::config::{AuthMethod, Config, Host, StrictHostKey};
use crate::errors::{Result, SshError};
use crate::known_hosts::{KnownHostMatch, KnownHostsStore};
use crate::session::Session;

pub type SshHandle = Handle<ClientHandler>;

// russh enforces maximum_packet_size <= 65535 (RFC 4253 §6.1).
const DEFAULT_MAX_PACKET: u32 = 65_535;
const DEFAULT_WINDOW: u32 = 8 * 1024 * 1024;

/// Host-key algorithms we advertise. Same order as `Preferred::DEFAULT` minus
/// `Algorithm::Rsa { hash: None }`, which is `ssh-rsa` with a SHA-1 signature.
/// Kex, ciphers and MACs are already SHA-1-free upstream; this brings host
/// keys in line. rsa-sha2-512/256 stay, so RSA host keys still negotiate.
const KEY_ALGORITHMS: &[Algorithm] = &[
    Algorithm::Ed25519,
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP256,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP384,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP521,
    },
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha512),
    },
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha256),
    },
];

/// Why the handler refused the server key. russh turns `Ok(false)` into a
/// generic error that would fall through to `internal_error` / `retry_later`,
/// so the reason travels out of the handler through a shared cell and `open`
/// reads it after a failed handshake.
#[derive(Debug)]
pub enum KeyRejection {
    Mismatch { expected: String, actual: String },
    Unknown { actual: String },
    Store(String),
}

pub struct ClientHandler {
    pub host_name: String,
    pub addr: String,
    pub port: u16,
    pub expected_fingerprint: Option<String>,
    pub strict: StrictHostKey,
    pub store: Option<Arc<KnownHostsStore>>,
    rejection: Arc<ArcSwapOption<KeyRejection>>,
}

impl ClientHandler {
    fn reject(&self, reason: KeyRejection) -> std::result::Result<bool, russh::Error> {
        self.rejection.store(Some(Arc::new(reason)));
        Ok(false)
    }
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        let actual = server_public_key
            .fingerprint(russh::keys::HashAlg::Sha256)
            .to_string();

        if let Some(expected) = &self.expected_fingerprint {
            if actual != *expected {
                tracing::warn!(host = %self.host_name, %expected, %actual, "server fingerprint mismatch (config)");
                return self.reject(KeyRejection::Mismatch {
                    expected: expected.clone(),
                    actual,
                });
            }
            return Ok(true);
        }

        match self.strict {
            StrictHostKey::Off => Ok(true),
            StrictHostKey::Strict | StrictHostKey::Tofu => {
                let Some(store) = self.store.as_ref() else {
                    return self.reject(KeyRejection::Store(
                        "known_hosts store unavailable while host key checking is enabled".into(),
                    ));
                };
                match store.check(&self.host_name, &self.addr, self.port, &actual) {
                    KnownHostMatch::Ok => Ok(true),
                    KnownHostMatch::Mismatch { expected } => {
                        tracing::warn!(host = %self.host_name, %expected, %actual, "known_hosts fingerprint mismatch");
                        self.reject(KeyRejection::Mismatch { expected, actual })
                    }
                    KnownHostMatch::Unavailable(why) => {
                        tracing::error!(host = %self.host_name, %why, "known_hosts unreadable");
                        self.reject(KeyRejection::Store(why))
                    }
                    KnownHostMatch::Unknown => {
                        if matches!(self.strict, StrictHostKey::Tofu) {
                            if let Err(e) = store
                                .add(&self.host_name, &self.addr, self.port, &actual)
                                .await
                            {
                                tracing::error!(?e, "TOFU write known_hosts failed");
                                return self.reject(KeyRejection::Store(format!(
                                    "could not persist the new fingerprint: {e}"
                                )));
                            }
                            // warn, not info: the first connect to a new host
                            // is the TOFU window — if it was MITM'd, future
                            // connects pin the attacker. Caller should verify
                            // out-of-band on first use.
                            tracing::warn!(
                                host = %self.host_name,
                                fingerprint = %actual,
                                "TOFU: pinned new server fingerprint on first connect; verify out-of-band"
                            );
                            Ok(true)
                        } else {
                            tracing::warn!(host = %self.host_name, "strict host key checking: host unknown");
                            self.reject(KeyRejection::Unknown { actual })
                        }
                    }
                }
            }
        }
    }
}

/// Turn a handshake failure into the host-key rejection the handler recorded,
/// when there is one. Without this a changed key reaches the caller as a
/// generic russh error whose recovery hint says "retry".
fn handshake_error(
    host_name: &str,
    cell: &ArcSwapOption<KeyRejection>,
    e: russh::Error,
) -> SshError {
    let Some(reason) = cell.load_full() else {
        return SshError::from(e);
    };
    match &*reason {
        KeyRejection::Mismatch { expected, actual } => SshError::FingerprintMismatch {
            host: host_name.to_string(),
            expected: expected.clone(),
            actual: actual.clone(),
        },
        KeyRejection::Unknown { actual } => SshError::Config(format!(
            "host '{host_name}' is not in known_hosts and strict_host_key_checking = \"strict\". \
             Verify the fingerprint {actual} out-of-band, then pin it as \
             known_host_fingerprint for the host in hosts.toml."
        )),
        KeyRejection::Store(why) => SshError::Other(format!(
            "host key check for '{host_name}' could not complete: {why}"
        )),
    }
}

/// Build a russh client config once. Cached on the SessionPool so we don't
/// rebuild it per connect.
pub fn build_client_config(cfg: &Config) -> Arc<client::Config> {
    Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(300)),
        keepalive_interval: Some(cfg.defaults.keepalive.0),
        keepalive_max: 3,
        maximum_packet_size: DEFAULT_MAX_PACKET,
        window_size: DEFAULT_WINDOW,
        nodelay: true,
        preferred: Preferred {
            key: Cow::Borrowed(KEY_ALGORITHMS),
            ..Preferred::DEFAULT
        },
        ..Default::default()
    })
}

#[allow(clippy::too_many_arguments)] // single internal call site (SessionPool::get_or_connect)
pub async fn open(
    cfg: &Config,
    host_name: &str,
    host: &Host,
    password: Option<&str>,
    ssh_cfg: Arc<client::Config>,
    store: Option<Arc<KnownHostsStore>>,
    proxy_parent: Option<&Session>,
    preferred_key: Option<&std::path::Path>,
) -> Result<(SshHandle, Option<std::path::PathBuf>)> {
    let strict = cfg.defaults.strict_host_key_checking;
    let store = if matches!(strict, StrictHostKey::Off) {
        None
    } else {
        store
    };
    // Shared with the handler so a host-key refusal survives russh collapsing
    // `Ok(false)` into an opaque error.
    let rejection = Arc::new(ArcSwapOption::<KeyRejection>::empty());
    let handler = ClientHandler {
        host_name: host_name.to_string(),
        addr: host.addr.clone(),
        port: host.port,
        expected_fingerprint: host.known_host_fingerprint.clone(),
        strict,
        store,
        rejection: Arc::clone(&rejection),
    };

    let connect_timeout = cfg.defaults.connect_timeout.0;
    let mut session = if let Some(parent) = proxy_parent {
        // ProxyJump: open a direct-tcpip channel on the bastion and run the
        // SSH handshake over it. Keeps the bastion's TCP+SSH session alive
        // via `Session::_proxy_parent` on the caller side.
        let channel = match tokio::time::timeout(
            connect_timeout,
            parent.handle.channel_open_direct_tcpip(
                host.addr.clone(),
                host.port as u32,
                "127.0.0.1".to_string(),
                0,
            ),
        )
        .await
        {
            Ok(r) => r.map_err(SshError::from)?,
            Err(_) => return Err(SshError::Timeout(connect_timeout.as_millis() as u64)),
        };
        let stream = channel.into_stream();
        match tokio::time::timeout(
            connect_timeout,
            client::connect_stream(ssh_cfg, stream, handler),
        )
        .await
        {
            Ok(r) => r.map_err(|e| handshake_error(host_name, &rejection, e))?,
            Err(_) => return Err(SshError::Timeout(connect_timeout.as_millis() as u64)),
        }
    } else {
        let addr = (host.addr.as_str(), host.port);
        match tokio::time::timeout(connect_timeout, client::connect(ssh_cfg, addr, handler)).await {
            Ok(r) => r.map_err(|e| handshake_error(host_name, &rejection, e))?,
            Err(_) => return Err(SshError::Timeout(connect_timeout.as_millis() as u64)),
        }
    };

    let user = host.user.clone();
    let mut used_key = None;
    match host.auth {
        AuthMethod::Key => {
            used_key = Some(authenticate_key(&mut session, host, preferred_key).await?);
        }
        AuthMethod::Agent => authenticate_agent(&mut session, &user).await?,
        AuthMethod::Password => {
            let pw = password.ok_or_else(|| SshError::PasswordRequired(host.addr.clone()))?;
            let res = session
                .authenticate_password(&user, pw)
                .await
                .map_err(SshError::from)?;
            if !res.success() {
                return Err(SshError::AuthFailed {
                    user: user.clone(),
                    host: host.addr.clone(),
                });
            }
        }
    }
    Ok((session, used_key))
}

/// Try configured keys in order, preferring the one that authenticated last
/// time (avoids burning an auth round-trip per rejected key on reconnect).
/// Returns the path of the key that succeeded so the caller can cache it.
async fn authenticate_key(
    session: &mut SshHandle,
    host: &Host,
    preferred_key: Option<&std::path::Path>,
) -> Result<std::path::PathBuf> {
    let mut key_paths = host.all_keys();
    if key_paths.is_empty() {
        return Err(SshError::Config(format!(
            "auth=key but no key path for {}",
            host.addr
        )));
    }
    if let Some(pref) = preferred_key
        && let Some(idx) = key_paths.iter().position(|p| p == pref)
    {
        key_paths.swap(0, idx);
    }
    let hash = session
        .best_supported_rsa_hash()
        .await
        .map_err(SshError::from)?
        .flatten();
    let mut last_err: Option<SshError> = None;
    for key_path in &key_paths {
        // File read + key parse are synchronous; offload so a slow disk
        // doesn't stall the single-threaded runtime mid-handshake.
        let path_for_load = key_path.clone();
        let loaded = tokio::task::spawn_blocking(move || load_secret_key(&path_for_load, None))
            .await
            .map_err(|e| SshError::Other(format!("key load task: {e}")))?;
        let key = match loaded {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(path = %key_path.display(), error = ?e, "load key failed; trying next");
                last_err = Some(SshError::Config(format!(
                    "load key {}: {e}",
                    key_path.display()
                )));
                continue;
            }
        };
        let res = session
            .authenticate_publickey(&host.user, PrivateKeyWithHashAlg::new(Arc::new(key), hash))
            .await
            .map_err(SshError::from)?;
        if res.success() {
            return Ok(key_path.clone());
        }
        last_err = Some(SshError::AuthFailed {
            user: host.user.clone(),
            host: host.addr.clone(),
        });
    }
    Err(last_err.unwrap_or_else(|| SshError::AuthFailed {
        user: host.user.clone(),
        host: host.addr.clone(),
    }))
}

async fn authenticate_agent(session: &mut SshHandle, user: &str) -> Result<()> {
    use russh::keys::agent::client::AgentClient;

    #[cfg(windows)]
    let mut agent = {
        let stream = tokio::net::windows::named_pipe::ClientOptions::new()
            .open(r"\\.\pipe\openssh-ssh-agent")
            .map_err(|e| SshError::Config(format!("OpenSSH agent named pipe unavailable: {e} (start ssh-agent service or use auth=key)")))?;
        AgentClient::connect(stream)
    };

    #[cfg(unix)]
    let mut agent = {
        let sock_path = std::env::var("SSH_AUTH_SOCK")
            .map_err(|_| SshError::Config("SSH_AUTH_SOCK not set".into()))?;
        let stream = tokio::net::UnixStream::connect(&sock_path)
            .await
            .map_err(|e| SshError::Config(format!("ssh-agent connect ({sock_path}): {e}")))?;
        AgentClient::connect(stream)
    };

    let identities = agent
        .request_identities()
        .await
        .map_err(|e| SshError::Config(format!("agent identities: {e}")))?;
    if identities.is_empty() {
        return Err(SshError::Config(
            "ssh-agent has no identities loaded".into(),
        ));
    }
    for ident in identities {
        let pubkey = ident.public_key().into_owned();
        let res = session
            .authenticate_publickey_with(user, pubkey, None, &mut agent)
            .await
            .map_err(|e| SshError::Config(format!("agent auth: {e}")))?;
        if res.success() {
            return Ok(());
        }
    }
    Err(SshError::AuthFailed {
        user: user.to_string(),
        host: "agent".into(),
    })
}

pub async fn is_handle_alive(handle: &SshHandle) -> bool {
    !handle.is_closed()
}
