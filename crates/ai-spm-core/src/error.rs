use thiserror::Error;

/// Central error type for the AI-SPM application.
#[derive(Debug, Error)]
pub enum AiSpmError {
    // ── Identity Errors ────────────────────────────────────────────────
    #[error("Identity error: {0}")]
    Identity(String),

    #[error("Agent not found: {0}")]
    AgentNotFound(String),

    #[error("Agent already exists: {0}")]
    AgentAlreadyExists(String),

    #[error("SVID expired for agent: {0}")]
    SvidExpired(String),

    #[error("Attestation failed: {0}")]
    AttestationFailed(String),

    // ── Token Errors ───────────────────────────────────────────────────
    #[error("Token expired: {0}")]
    TokenExpired(String),

    #[error("Token invalid: {0}")]
    TokenInvalid(String),

    #[error("Insufficient permissions: {0}")]
    InsufficientPermissions(String),

    // ── Gateway / Policy Errors ────────────────────────────────────────
    #[error("Policy denied: {0}")]
    PolicyDenied(String),

    #[error("Envelope verification failed: {0}")]
    EnvelopeVerificationFailed(String),

    #[error("Replay attack detected: nonce {0} already used")]
    ReplayDetected(String),

    #[error("OPA policy engine error: {0}")]
    OpaError(String),

    // ── Taint / Reasoning Errors ───────────────────────────────────────
    #[error("Taint violation: {0}")]
    TaintViolation(String),

    #[error("Hidden variable not found: {0}")]
    HiddenVariableNotFound(String),

    #[error("Inspector error: {0}")]
    InspectorError(String),

    #[error("Constrained decoding failed: {0}")]
    ConstrainedDecodingFailed(String),

    // ── Audit Errors ───────────────────────────────────────────────────
    #[error("Audit chain integrity violation at sequence {0}")]
    AuditChainViolation(u64),

    #[error("Audit log error: {0}")]
    AuditLogError(String),

    // ── MCP Errors ─────────────────────────────────────────────────────
    #[error("MCP tool poisoning detected: {0}")]
    ToolPoisoning(String),

    #[error("MCP argument validation failed for tool '{tool}': {reason}")]
    McpArgumentValidation { tool: String, reason: String },

    #[error("MCP SSRF attempt detected: {0}")]
    SsrfDetected(String),

    // ── Infrastructure Errors ──────────────────────────────────────────
    #[error("Database error: {0}")]
    Database(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("HTTP request error: {0}")]
    Http(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Cryptographic error: {0}")]
    Crypto(String),
}

// Conversion impls for common error types
impl From<serde_json::Error> for AiSpmError {
    fn from(e: serde_json::Error) -> Self {
        AiSpmError::Serialization(e.to_string())
    }
}

impl From<reqwest::Error> for AiSpmError {
    fn from(e: reqwest::Error) -> Self {
        AiSpmError::Http(e.to_string())
    }
}

/// Convenience Result type for the AI-SPM application.
pub type Result<T> = std::result::Result<T, AiSpmError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = AiSpmError::PolicyDenied("agent not authorized for tool X".into());
        assert!(err.to_string().contains("agent not authorized for tool X"));
    }

    #[test]
    fn test_result_type() {
        let ok: Result<i32> = Ok(42);
        assert_eq!(ok.unwrap(), 42);

        let err: Result<i32> = Err(AiSpmError::TokenExpired("test".into()));
        assert!(err.is_err());
    }

    #[test]
    fn test_from_serde_error() {
        let bad_json = "not json";
        let serde_err = serde_json::from_str::<serde_json::Value>(bad_json).unwrap_err();
        let err: AiSpmError = serde_err.into();
        assert!(matches!(err, AiSpmError::Serialization(_)));
    }
}
