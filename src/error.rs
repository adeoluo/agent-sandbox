use std::path::PathBuf;

/// Errors raised while loading policies, evaluating requests, executing commands, or
/// reading and writing the audit log.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("failed to read policy file {path}: {source}")]
    PolicyRead {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse policy: {0}")]
    PolicyParse(String),
    #[error("invalid policy: {0}")]
    PolicyInvalid(String),
    #[error("request denied by {rule}: {reason}")]
    Denied { rule: String, reason: String },
    #[error("failed to spawn {program}: {source}")]
    Spawn {
        program: String,
        source: std::io::Error,
    },
    #[error("OS isolation is required by the policy but unavailable: {0}")]
    IsolationUnavailable(String),
    #[error("audit log error: {0}")]
    Audit(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, SandboxError>;
