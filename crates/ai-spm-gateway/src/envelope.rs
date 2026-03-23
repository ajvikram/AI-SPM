use ai_spm_core::error::{AiSpmError, Result};
use ai_spm_core::types::{IntentEnvelope, ToolCallRequest};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, Signature};
use std::collections::HashSet;
use std::sync::Mutex;
use tracing::info;

/// Intent Envelope handler: creates, signs, and verifies tool call envelopes.
pub struct EnvelopeHandler {
    /// LRU-style set of recently seen nonces for replay prevention
    seen_nonces: Mutex<HashSet<String>>,
    max_nonces: usize,
}

impl EnvelopeHandler {
    pub fn new(max_nonces: usize) -> Self {
        Self {
            seen_nonces: Mutex::new(HashSet::new()),
            max_nonces,
        }
    }

    /// Create and sign an Intent Envelope for a tool call request.
    pub fn create_envelope(
        &self,
        request: ToolCallRequest,
        signing_key: &SigningKey,
        public_key_id: &str,
    ) -> Result<IntentEnvelope> {
        let canonical = serde_json::to_vec(&request)?;
        let signature = signing_key.sign(&canonical);

        Ok(IntentEnvelope {
            request,
            signature: signature.to_bytes().to_vec(),
            public_key_id: public_key_id.to_string(),
        })
    }

    /// Verify an Intent Envelope: checks signature and nonce freshness.
    pub fn verify_envelope(
        &self,
        envelope: &IntentEnvelope,
        verifying_key: &VerifyingKey,
    ) -> Result<ToolCallRequest> {
        // Check nonce for replay
        {
            let mut nonces = self.seen_nonces.lock().map_err(|e| {
                AiSpmError::EnvelopeVerificationFailed(format!("Lock poisoned: {}", e))
            })?;

            if nonces.contains(&envelope.request.nonce) {
                return Err(AiSpmError::ReplayDetected(
                    envelope.request.nonce.clone(),
                ));
            }

            // Evict old nonces if at capacity
            if nonces.len() >= self.max_nonces {
                nonces.clear(); // Simple eviction; production would use LRU
            }
            nonces.insert(envelope.request.nonce.clone());
        }

        // Verify Ed25519 signature
        let canonical = serde_json::to_vec(&envelope.request)?;
        let sig_bytes: [u8; 64] = envelope
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| {
                AiSpmError::EnvelopeVerificationFailed("Invalid signature length".into())
            })?;

        let signature = Signature::from_bytes(&sig_bytes);
        verifying_key.verify(&canonical, &signature).map_err(|e| {
            AiSpmError::EnvelopeVerificationFailed(format!("Signature invalid: {}", e))
        })?;

        info!(
            request_id = %envelope.request.request_id,
            agent_id = %envelope.request.agent_id,
            tool = %envelope.request.tool_name,
            "Envelope verified"
        );

        Ok(envelope.request.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ai_spm_core::types::AgentId;
    use rand::rngs::OsRng;

    fn make_request() -> ToolCallRequest {
        ToolCallRequest {
            request_id: Uuid::new_v4(),
            agent_id: AgentId::new("spiffe://test/agent"),
            tool_name: "database_query".into(),
            arguments: serde_json::json!({"query": "SELECT 1"}),
            timestamp: Utc::now(),
            nonce: Uuid::new_v4().to_string(),
        }
    }

    #[test]
    fn test_create_and_verify_envelope() {
        let handler = EnvelopeHandler::new(1000);
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let request = make_request();
        let envelope = handler
            .create_envelope(request.clone(), &signing_key, "key-1")
            .unwrap();

        let verified = handler.verify_envelope(&envelope, &verifying_key).unwrap();
        assert_eq!(verified.tool_name, "database_query");
    }

    #[test]
    fn test_replay_detection() {
        let handler = EnvelopeHandler::new(1000);
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let request = make_request();
        let envelope = handler
            .create_envelope(request, &signing_key, "key-1")
            .unwrap();

        // First verification succeeds
        handler.verify_envelope(&envelope, &verifying_key).unwrap();

        // Second verification fails (replay)
        let result = handler.verify_envelope(&envelope, &verifying_key);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AiSpmError::ReplayDetected(_)
        ));
    }

    #[test]
    fn test_invalid_signature() {
        let handler = EnvelopeHandler::new(1000);
        let signing_key = SigningKey::generate(&mut OsRng);
        let wrong_key = SigningKey::generate(&mut OsRng);
        let wrong_verifying = wrong_key.verifying_key();

        let request = make_request();
        let envelope = handler
            .create_envelope(request, &signing_key, "key-1")
            .unwrap();

        let result = handler.verify_envelope(&envelope, &wrong_verifying);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_envelope() {
        let handler = EnvelopeHandler::new(1000);
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let request = make_request();
        let mut envelope = handler
            .create_envelope(request, &signing_key, "key-1")
            .unwrap();

        // Tamper with the request
        envelope.request.tool_name = "malicious_tool".into();

        let result = handler.verify_envelope(&envelope, &verifying_key);
        assert!(result.is_err());
    }
}
