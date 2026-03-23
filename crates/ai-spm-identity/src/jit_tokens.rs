use ai_spm_core::error::{AiSpmError, Result};
use ai_spm_core::types::{AgentId, Permission, ScopedToken, TokenClaims};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::info;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// JIT (Just-in-Time) Scoped Token Manager.
/// Issues time-bound, task-specific credentials for agents.
pub struct JitTokenManager {
    /// HMAC-SHA256 key for signing tokens
    signing_key: Vec<u8>,
    /// Default TTL in seconds
    default_ttl_seconds: u64,
}

impl JitTokenManager {
    /// Create a new JIT token manager with the given HMAC signing key (hex-encoded).
    pub fn new(signing_key_hex: &str, default_ttl_seconds: u64) -> Result<Self> {
        let signing_key = hex::decode(signing_key_hex)
            .map_err(|e| AiSpmError::Crypto(format!("Invalid signing key hex: {}", e)))?;

        if signing_key.len() < 32 {
            return Err(AiSpmError::Crypto(
                "Signing key must be at least 32 bytes".into(),
            ));
        }

        Ok(Self {
            signing_key,
            default_ttl_seconds,
        })
    }

    /// Issue a new scoped token for an agent.
    ///
    /// # Arguments
    /// * `agent_id` - The agent requesting the token
    /// * `scope` - The permissions granted by this token
    /// * `ttl_seconds` - Optional TTL override (uses default if None)
    pub fn issue_token(
        &self,
        agent_id: &AgentId,
        scope: Vec<Permission>,
        ttl_seconds: Option<u64>,
        binary_hash: Option<String>,
    ) -> Result<ScopedToken> {
        let now = Utc::now();
        let ttl = ttl_seconds.unwrap_or(self.default_ttl_seconds);
        let expires_at = now + Duration::seconds(ttl as i64);
        let token_id = Uuid::new_v4();

        // Build the claims payload for signing
        let claims = TokenClaims {
            token_id,
            agent_id: agent_id.clone(),
            scope: scope.clone(),
            issued_at: now,
            expires_at,
            binary_hash: binary_hash.clone(),
        };

        let signature = self.sign_claims(&claims)?;

        let token = ScopedToken {
            token_id,
            agent_id: agent_id.clone(),
            scope,
            issued_at: now,
            expires_at,
            binary_hash,
            signature,
        };

        info!(
            agent_id = %agent_id,
            token_id = %token_id,
            ttl_seconds = ttl,
            "JIT token issued"
        );

        Ok(token)
    }

    /// Validate a scoped token: checks signature, expiry, and returns claims.
    pub fn validate_token(&self, token: &ScopedToken) -> Result<TokenClaims> {
        // Check expiry
        if token.is_expired() {
            return Err(AiSpmError::TokenExpired(format!(
                "Token {} expired at {}",
                token.token_id, token.expires_at
            )));
        }

        // Rebuild claims and verify signature
        let claims = TokenClaims {
            token_id: token.token_id,
            agent_id: token.agent_id.clone(),
            scope: token.scope.clone(),
            issued_at: token.issued_at,
            expires_at: token.expires_at,
            binary_hash: token.binary_hash.clone(),
        };

        let expected_signature = self.sign_claims(&claims)?;
        if token.signature != expected_signature {
            return Err(AiSpmError::TokenInvalid(format!(
                "Token {} signature mismatch",
                token.token_id
            )));
        }

        Ok(claims)
    }

    /// Check if a token grants a specific permission.
    pub fn check_permission(
        &self,
        token: &ScopedToken,
        resource: &str,
        action: &str,
    ) -> Result<bool> {
        let _claims = self.validate_token(token)?;

        for perm in &token.scope {
            if perm.resource == resource || perm.resource == "*" {
                if perm.actions.contains(&action.to_string())
                    || perm.actions.contains(&"*".to_string())
                {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Compute HMAC-SHA256 signature over the token claims.
    fn sign_claims(&self, claims: &TokenClaims) -> Result<String> {
        let payload = serde_json::to_vec(claims)?;

        let mut mac = HmacSha256::new_from_slice(&self.signing_key)
            .map_err(|e| AiSpmError::Crypto(format!("HMAC init error: {}", e)))?;

        mac.update(&payload);
        let result = mac.finalize();
        Ok(hex::encode(result.into_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_manager() -> JitTokenManager {
        // 32-byte key as hex (64 hex chars)
        let key = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
        JitTokenManager::new(key, 300).unwrap()
    }

    #[test]
    fn test_issue_and_validate_token() {
        let manager = test_manager();
        let agent_id = AgentId::new("spiffe://test/agent-1");
        let scope = vec![Permission {
            resource: "database".into(),
            actions: vec!["read".into()],
        }];

        let token = manager.issue_token(&agent_id, scope, None, None).unwrap();
        assert_eq!(token.agent_id, agent_id);
        assert!(!token.is_expired());

        let claims = manager.validate_token(&token).unwrap();
        assert_eq!(claims.agent_id, agent_id);
        assert_eq!(claims.scope.len(), 1);
    }

    #[test]
    fn test_expired_token() {
        let manager = test_manager();
        let agent_id = AgentId::new("spiffe://test/agent-1");

        // Issue with 0 second TTL
        let token = manager
            .issue_token(&agent_id, vec![], Some(0), None)
            .unwrap();

        std::thread::sleep(std::time::Duration::from_millis(10));
        let result = manager.validate_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_token() {
        let manager = test_manager();
        let agent_id = AgentId::new("spiffe://test/agent-1");

        let mut token = manager.issue_token(&agent_id, vec![], None, None).unwrap();
        // Tamper with the signature
        token.signature = "tampered".to_string();

        let result = manager.validate_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_permission_granted() {
        let manager = test_manager();
        let agent_id = AgentId::new("spiffe://test/agent-1");
        let scope = vec![Permission {
            resource: "database".into(),
            actions: vec!["read".into(), "write".into()],
        }];

        let token = manager.issue_token(&agent_id, scope, None, None).unwrap();
        assert!(manager.check_permission(&token, "database", "read").unwrap());
        assert!(manager.check_permission(&token, "database", "write").unwrap());
        assert!(!manager.check_permission(&token, "database", "delete").unwrap());
        assert!(!manager.check_permission(&token, "s3", "read").unwrap());
    }

    #[test]
    fn test_wildcard_permission() {
        let manager = test_manager();
        let agent_id = AgentId::new("spiffe://test/admin");
        let scope = vec![Permission {
            resource: "*".into(),
            actions: vec!["*".into()],
        }];

        let token = manager.issue_token(&agent_id, scope, None, None).unwrap();
        assert!(manager.check_permission(&token, "anything", "everything").unwrap());
    }

    #[test]
    fn test_short_signing_key_rejected() {
        let result = JitTokenManager::new("abcd", 300);
        assert!(result.is_err());
    }
}
