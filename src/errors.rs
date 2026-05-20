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

/// Recovery hint surfaced in error `data.recovery` so an LLM can pick a retry
/// strategy without re-asking the user. Stable string contract; do not rename.
fn recovery_for(err: &SshError) -> &'static str {
    match err {
        SshError::Timeout(_) => "retry_later",
        SshError::UnknownHost(_)
        | SshError::Config(_)
        | SshError::PasswordRequired(_) => "check_input",
        SshError::BlockedByGuard { .. } | SshError::ConfirmationDenied => "ask_user",
        SshError::AuthFailed { .. } => "ask_user",
        SshError::FingerprintMismatch { .. } => "unrecoverable",
        SshError::Io(_) | SshError::Russh(_) | SshError::Sftp(_) => "retry_later",
        SshError::Regex(_) | SshError::Toml(_) => "check_input",
        SshError::Other(_) => "retry_later",
    }
}

impl SshError {
    pub fn into_mcp(self) -> rmcp::ErrorData {
        use rmcp::model::ErrorCode;
        use serde_json::json;

        let msg = self.to_string();
        let recovery = recovery_for(&self);
        match self {
            SshError::UnknownHost(name) => rmcp::ErrorData::invalid_params(
                msg,
                Some(json!({ "kind": "unknown_host", "host": name, "recovery": recovery })),
            ),
            SshError::Config(_) => rmcp::ErrorData::invalid_params(
                msg,
                Some(json!({ "kind": "config", "recovery": recovery })),
            ),
            SshError::PasswordRequired(host) => rmcp::ErrorData::invalid_params(
                msg,
                Some(json!({ "kind": "password_required", "host": host, "recovery": recovery })),
            ),
            SshError::BlockedByGuard { name, pattern } => rmcp::ErrorData::new(
                ErrorCode(CODE_GUARD_BLOCKED),
                msg,
                Some(json!({ "kind": "guard_blocked", "guard": name, "pattern": pattern, "recovery": recovery })),
            ),
            SshError::ConfirmationDenied => rmcp::ErrorData::new(
                ErrorCode(CODE_CONFIRMATION_DENIED),
                msg,
                Some(json!({ "kind": "confirmation_denied", "recovery": recovery })),
            ),
            SshError::Timeout(ms) => rmcp::ErrorData::new(
                ErrorCode(CODE_TIMEOUT),
                msg,
                Some(json!({ "kind": "timeout", "ms": ms, "recovery": recovery })),
            ),
            SshError::FingerprintMismatch { host, expected, actual } => rmcp::ErrorData::new(
                ErrorCode(CODE_FINGERPRINT_MISMATCH),
                msg,
                Some(json!({
                    "kind": "fingerprint_mismatch",
                    "host": host,
                    "expected": expected,
                    "actual": actual,
                    "recovery": recovery,
                })),
            ),
            SshError::AuthFailed { user, host } => rmcp::ErrorData::new(
                ErrorCode(CODE_AUTH_FAILED),
                msg,
                Some(json!({ "kind": "auth_failed", "user": user, "host": host, "recovery": recovery })),
            ),
            SshError::Russh(e) => map_russh_error(e, msg),
            SshError::Io(_)
            | SshError::Sftp(_)
            | SshError::Regex(_)
            | SshError::Toml(_)
            | SshError::Other(_) => rmcp::ErrorData::internal_error(
                msg,
                Some(json!({ "kind": "internal", "recovery": recovery })),
            ),
        }
    }
}

/// Surface common russh failure modes through the same MCP codes as our own
/// taxonomy instead of collapsing to `internal_error` with a misleading
/// `recovery: retry_later`.
fn map_russh_error(e: russh::Error, msg: String) -> rmcp::ErrorData {
    use rmcp::model::ErrorCode;
    use russh::Error as R;
    use serde_json::json;
    match e {
        R::ConnectionTimeout
        | R::KeepaliveTimeout
        | R::InactivityTimeout
        | R::Elapsed(_) => rmcp::ErrorData::new(
            ErrorCode(CODE_TIMEOUT),
            msg,
            Some(json!({ "kind": "timeout", "recovery": "retry_later" })),
        ),
        R::NotAuthenticated | R::NoAuthMethod | R::UnsupportedAuthMethod => rmcp::ErrorData::new(
            ErrorCode(CODE_AUTH_FAILED),
            msg,
            Some(json!({ "kind": "auth_failed", "recovery": "ask_user" })),
        ),
        R::KeyChanged { line } => rmcp::ErrorData::new(
            ErrorCode(CODE_FINGERPRINT_MISMATCH),
            msg,
            Some(json!({
                "kind": "fingerprint_mismatch",
                "known_hosts_line": line,
                "recovery": "unrecoverable",
            })),
        ),
        R::Disconnect | R::HUP => rmcp::ErrorData::internal_error(
            msg,
            Some(json!({ "kind": "disconnected", "recovery": "retry_later" })),
        ),
        _ => rmcp::ErrorData::internal_error(
            msg,
            Some(json!({ "kind": "internal", "recovery": "retry_later" })),
        ),
    }
}
