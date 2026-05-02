use thiserror::Error;

#[derive(Debug, Error)]
pub enum SshError {
    #[error("host '{0}' not found in config")]
    UnknownHost(String),

    #[error("blocked by guard '{name}': {pattern}")]
    BlockedByGuard { name: String, pattern: String },

    #[error("user denied confirmation for command")]
    ConfirmationDenied,

    #[error("authentication failed for {user}@{host}")]
    AuthFailed { user: String, host: String },

    #[error("password required for host '{0}'")]
    PasswordRequired(String),

    #[error("command timed out after {0}ms")]
    Timeout(u64),

    #[error("config error: {0}")]
    Config(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("ssh: {0}")]
    Russh(#[from] russh::Error),

    #[error("sftp: {0}")]
    Sftp(#[from] russh_sftp::client::error::Error),

    #[error("regex: {0}")]
    Regex(#[from] regex::Error),

    #[error("toml: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("{0}")]
    Other(String),
}

impl From<anyhow::Error> for SshError {
    fn from(e: anyhow::Error) -> Self {
        SshError::Other(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, SshError>;

impl SshError {
    pub fn into_mcp(self) -> rmcp::ErrorData {
        rmcp::ErrorData::internal_error(self.to_string(), None)
    }
}
