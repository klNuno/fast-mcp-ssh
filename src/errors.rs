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

    #[allow(dead_code)] // reserved for explicit fingerprint surfacing in a future change
    #[error("server fingerprint mismatch for '{host}': expected {expected}, got {actual}")]
    FingerprintMismatch {
        host: String,
        expected: String,
        actual: String,
    },

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

/// Custom JSON-RPC codes outside the reserved range.
const CODE_GUARD_BLOCKED: i32 = -32001;
const CODE_CONFIRMATION_DENIED: i32 = -32002;
const CODE_TIMEOUT: i32 = -32003;
const CODE_FINGERPRINT_MISMATCH: i32 = -32004;
const CODE_AUTH_FAILED: i32 = -32005;

impl SshError {
    pub fn into_mcp(self) -> rmcp::ErrorData {
        use rmcp::model::ErrorCode;
        use serde_json::json;

        let msg = self.to_string();
        match self {
            SshError::UnknownHost(name) => rmcp::ErrorData::invalid_params(
                msg,
                Some(json!({ "kind": "unknown_host", "host": name })),
            ),
            SshError::Config(_) => rmcp::ErrorData::invalid_params(
                msg,
                Some(json!({ "kind": "config" })),
            ),
            SshError::PasswordRequired(host) => rmcp::ErrorData::invalid_params(
                msg,
                Some(json!({ "kind": "password_required", "host": host })),
            ),
            SshError::BlockedByGuard { name, pattern } => rmcp::ErrorData::new(
                ErrorCode(CODE_GUARD_BLOCKED),
                msg,
                Some(json!({ "kind": "guard_blocked", "guard": name, "pattern": pattern })),
            ),
            SshError::ConfirmationDenied => rmcp::ErrorData::new(
                ErrorCode(CODE_CONFIRMATION_DENIED),
                msg,
                Some(json!({ "kind": "confirmation_denied" })),
            ),
            SshError::Timeout(ms) => rmcp::ErrorData::new(
                ErrorCode(CODE_TIMEOUT),
                msg,
                Some(json!({ "kind": "timeout", "ms": ms })),
            ),
            SshError::FingerprintMismatch { host, expected, actual } => rmcp::ErrorData::new(
                ErrorCode(CODE_FINGERPRINT_MISMATCH),
                msg,
                Some(json!({
                    "kind": "fingerprint_mismatch",
                    "host": host,
                    "expected": expected,
                    "actual": actual,
                })),
            ),
            SshError::AuthFailed { user, host } => rmcp::ErrorData::new(
                ErrorCode(CODE_AUTH_FAILED),
                msg,
                Some(json!({ "kind": "auth_failed", "user": user, "host": host })),
            ),
            SshError::Io(_)
            | SshError::Russh(_)
            | SshError::Sftp(_)
            | SshError::Regex(_)
            | SshError::Toml(_)
            | SshError::Other(_) => rmcp::ErrorData::internal_error(msg, None),
        }
    }
}
