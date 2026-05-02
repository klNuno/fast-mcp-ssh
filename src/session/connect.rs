use std::sync::Arc;
use std::time::Duration;

use russh::client::{self, Handle};
use russh::keys::{PrivateKeyWithHashAlg, load_secret_key};

use crate::config::{AuthMethod, Config, Host, StrictHostKey};
use crate::errors::{Result, SshError};
use crate::known_hosts::{KnownHostMatch, KnownHostsStore};

pub type SshHandle = Handle<ClientHandler>;

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
                            tracing::info!(host = %self.host_name, %actual, "TOFU: pinned new fingerprint");
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

pub async fn open(
    cfg: &Config,
    host_name: &str,
    host: &Host,
    password: Option<&str>,
) -> Result<SshHandle> {
    let ssh_cfg = client::Config {
        inactivity_timeout: Some(Duration::from_secs(300)),
        keepalive_interval: Some(cfg.defaults.keepalive.0),
        keepalive_max: 3,
        ..Default::default()
    };
    let ssh_cfg = Arc::new(ssh_cfg);
    let store = if matches!(cfg.defaults.strict_host_key_checking, StrictHostKey::Off) {
        None
    } else {
        Some(KnownHostsStore::open_or_create()?)
    };
    let handler = ClientHandler {
        host_name: host_name.to_string(),
        expected_fingerprint: host.known_host_fingerprint.clone(),
        strict: cfg.defaults.strict_host_key_checking,
        store,
    };
    let addr = (host.addr.as_str(), host.port);

    let mut session = client::connect(ssh_cfg, addr, handler)
        .await
        .map_err(SshError::from)?;

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
