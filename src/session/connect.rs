use std::sync::Arc;
use std::time::Duration;

use russh::client::{self, Handle};
use russh::keys::{PrivateKeyWithHashAlg, load_secret_key};

use crate::config::{AuthMethod, Config, Host, StrictHostKey};
use crate::errors::{Result, SshError};
use crate::known_hosts::{KnownHostMatch, KnownHostsStore};

pub type SshHandle = Handle<ClientHandler>;

// russh enforces maximum_packet_size <= 65535 (RFC 4253 §6.1).
const DEFAULT_MAX_PACKET: u32 = 65_535;
const DEFAULT_WINDOW: u32 = 8 * 1024 * 1024;

pub struct ClientHandler {
    pub host_name: String,
    pub expected_fingerprint: Option<String>,
    pub strict: StrictHostKey,
    pub store: Option<Arc<KnownHostsStore>>,
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
                return Ok(false);
            }
            return Ok(true);
        }

        match self.strict {
            StrictHostKey::Off => Ok(true),
            StrictHostKey::Strict | StrictHostKey::Tofu => {
                let Some(store) = self.store.as_ref() else {
                    return Ok(matches!(self.strict, StrictHostKey::Off));
                };
                match store.check(&self.host_name, &actual) {
                    KnownHostMatch::Ok => Ok(true),
                    KnownHostMatch::Mismatch { expected } => {
                        tracing::warn!(host = %self.host_name, %expected, %actual, "known_hosts fingerprint mismatch");
                        Ok(false)
                    }
                    KnownHostMatch::Unknown => {
                        if matches!(self.strict, StrictHostKey::Tofu) {
                            if let Err(e) = store.add(&self.host_name, &actual) {
                                tracing::error!(?e, "TOFU write known_hosts failed");
                                return Ok(false);
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
                            Ok(false)
                        }
                    }
                }
            }
        }
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
        ..Default::default()
    })
}

pub async fn open(
    cfg: &Config,
    host_name: &str,
    host: &Host,
    password: Option<&str>,
    ssh_cfg: Arc<client::Config>,
    store: Option<Arc<KnownHostsStore>>,
) -> Result<SshHandle> {
    let strict = cfg.defaults.strict_host_key_checking;
    let store = if matches!(strict, StrictHostKey::Off) { None } else { store };
    let handler = ClientHandler {
        host_name: host_name.to_string(),
        expected_fingerprint: host.known_host_fingerprint.clone(),
        strict,
        store,
    };
    let addr = (host.addr.as_str(), host.port);

    let connect_timeout = cfg.defaults.connect_timeout.0;
    let mut session = match tokio::time::timeout(
        connect_timeout,
        client::connect(ssh_cfg, addr, handler),
    )
    .await
    {
        Ok(r) => r.map_err(SshError::from)?,
        Err(_) => return Err(SshError::Timeout(connect_timeout.as_millis() as u64)),
    };

    let user = host.user.clone();
    match host.auth {
        AuthMethod::Key => authenticate_key(&mut session, host).await?,
        AuthMethod::Agent => authenticate_agent(&mut session, &user).await?,
        AuthMethod::Password => {
            let pw = password.ok_or_else(|| SshError::PasswordRequired(host.addr.clone()))?;
            let res = session
                .authenticate_password(&user, pw)
                .await
                .map_err(SshError::from)?;
            if !res.success() {
                return Err(SshError::AuthFailed { user: user.clone(), host: host.addr.clone() });
            }
        }
    }
    Ok(session)
}

async fn authenticate_key(session: &mut SshHandle, host: &Host) -> Result<()> {
    let key_path = host
        .key
        .as_ref()
        .ok_or_else(|| SshError::Config(format!("auth=key but no key path for {}", host.addr)))?;
    let key = load_secret_key(key_path, None)
        .map_err(|e| SshError::Config(format!("load key {}: {e}", key_path.display())))?;
    let hash = session.best_supported_rsa_hash().await.map_err(SshError::from)?.flatten();
    let res = session
        .authenticate_publickey(&host.user, PrivateKeyWithHashAlg::new(Arc::new(key), hash))
        .await
        .map_err(SshError::from)?;
    if !res.success() {
        return Err(SshError::AuthFailed { user: host.user.clone(), host: host.addr.clone() });
    }
    Ok(())
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
        return Err(SshError::Config("ssh-agent has no identities loaded".into()));
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
    Err(SshError::AuthFailed { user: user.to_string(), host: "agent".into() })
}

pub async fn is_handle_alive(handle: &SshHandle) -> bool {
    !handle.is_closed()
}
