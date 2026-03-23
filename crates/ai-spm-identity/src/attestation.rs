use ai_spm_core::error::{AiSpmError, Result};
use ai_spm_core::types::{AgentId, Svid};
use chrono::{Duration, Utc};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey, Verifier, Signature};
use rand::rngs::OsRng;
use tracing::info;

use crate::store::IdentityStore;

/// Cryptographic attestation service for issuing and verifying SVIDs.
/// Uses Ed25519 for signing/verification.
pub struct AttestationService {
    store: IdentityStore,
    svid_ttl_seconds: u64,
    /// The CA signing key (in a real deployment, this would be backed by an HSM)
    ca_signing_key: SigningKey,
}

impl AttestationService {
    pub fn new(store: IdentityStore, svid_ttl_seconds: u64) -> Self {
        let ca_signing_key = SigningKey::generate(&mut OsRng);
        Self {
            store,
            svid_ttl_seconds,
            ca_signing_key,
        }
    }

    /// Create with a specific CA signing key (for deterministic testing or key loading).
    pub fn with_ca_key(store: IdentityStore, svid_ttl_seconds: u64, ca_key: SigningKey) -> Self {
        Self {
            store,
            svid_ttl_seconds,
            ca_signing_key: ca_key,
        }
    }

    /// Get the CA verifying (public) key.
    pub fn ca_verifying_key(&self) -> VerifyingKey {
        self.ca_signing_key.verifying_key()
    }

    /// Issue a new SVID for an agent after successful attestation.
    ///
    /// `attestation_proof` is the evidence the agent provides (e.g., Kubernetes
    /// namespace, binary hash). In this implementation, we verify that the agent
    /// exists in the registry and is active.
    pub fn issue_svid(
        &self,
        agent_id: &AgentId,
        _attestation_proof: &[u8],
    ) -> Result<Svid> {
        // Verify agent exists and is active
        let record = self.store.get_agent(agent_id)?;
        if record.status != ai_spm_core::types::AgentStatus::Active {
            return Err(AiSpmError::AttestationFailed(format!(
                "Agent {} is not active (status: {:?})",
                agent_id, record.status
            )));
        }

        // Generate a new Ed25519 keypair for this SVID
        let agent_signing_key = SigningKey::generate(&mut OsRng);
        let agent_verifying_key = agent_signing_key.verifying_key();

        let now = Utc::now();
        let not_after = now + Duration::seconds(self.svid_ttl_seconds as i64);

        // Create a certificate-like structure: CA signs the agent's public key + identity
        let cert_payload = self.build_cert_payload(agent_id, &agent_verifying_key, &now, &not_after);
        let ca_signature = self.ca_signing_key.sign(&cert_payload);

        // The "certificate" is the payload + CA signature
        let mut certificate = cert_payload;
        certificate.extend_from_slice(&ca_signature.to_bytes());

        let svid = Svid {
            agent_id: agent_id.clone(),
            certificate,
            private_key: agent_signing_key.to_bytes().to_vec(),
            issued_at: now,
            not_after,
        };

        // Store the SVID record
        self.store.store_svid(&svid)?;

        info!(
            agent_id = %agent_id,
            expires = %not_after,
            "SVID issued"
        );

        Ok(svid)
    }

    /// Verify an SVID's validity: checks CA signature, expiry, and agent status.
    pub fn verify_svid(&self, svid: &Svid) -> Result<AgentId> {
        // Check expiry
        if svid.is_expired() {
            return Err(AiSpmError::SvidExpired(svid.agent_id.to_string()));
        }

        // Verify the certificate was signed by our CA
        if svid.certificate.len() < 64 {
            return Err(AiSpmError::AttestationFailed(
                "Certificate too short".into(),
            ));
        }

        let sig_offset = svid.certificate.len() - 64;
        let payload = &svid.certificate[..sig_offset];
        let sig_bytes: [u8; 64] = svid.certificate[sig_offset..]
            .try_into()
            .map_err(|_| AiSpmError::AttestationFailed("Invalid signature length".into()))?;

        let signature = Signature::from_bytes(&sig_bytes);
        let ca_verifying_key = self.ca_verifying_key();

        ca_verifying_key
            .verify(payload, &signature)
            .map_err(|e| AiSpmError::AttestationFailed(format!("CA signature invalid: {}", e)))?;

        // Verify agent is still active
        let record = self.store.get_agent(&svid.agent_id)?;
        if record.status != ai_spm_core::types::AgentStatus::Active {
            return Err(AiSpmError::AttestationFailed(format!(
                "Agent {} is no longer active",
                svid.agent_id
            )));
        }

        Ok(svid.agent_id.clone())
    }

    /// Rotate an SVID by issuing a new one (old one remains valid until expiry).
    pub fn rotate_svid(&self, agent_id: &AgentId) -> Result<Svid> {
        info!(agent_id = %agent_id, "Rotating SVID");
        self.issue_svid(agent_id, b"rotation")
    }

    /// Build the payload that the CA signs to create a "certificate".
    fn build_cert_payload(
        &self,
        agent_id: &AgentId,
        verifying_key: &VerifyingKey,
        issued_at: &chrono::DateTime<Utc>,
        not_after: &chrono::DateTime<Utc>,
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(agent_id.as_str().as_bytes());
        payload.extend_from_slice(verifying_key.as_bytes());
        payload.extend_from_slice(issued_at.to_rfc3339().as_bytes());
        payload.extend_from_slice(not_after.to_rfc3339().as_bytes());
        payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::NhiRegistry;
    use std::collections::HashMap;

    fn setup() -> (IdentityStore, AgentId) {
        let store = IdentityStore::in_memory().unwrap();
        let registry = NhiRegistry::new(store.clone());
        let agent_id = AgentId::new("spiffe://test/agent-1");
        registry
            .register_agent(&agent_id, "admin", "Test agent", HashMap::new())
            .unwrap();
        (store, agent_id)
    }

    #[test]
    fn test_issue_and_verify_svid() {
        let (store, agent_id) = setup();
        let service = AttestationService::new(store, 3600);

        let svid = service.issue_svid(&agent_id, b"proof").unwrap();
        assert_eq!(svid.agent_id, agent_id);
        assert!(!svid.is_expired());

        let verified_id = service.verify_svid(&svid).unwrap();
        assert_eq!(verified_id, agent_id);
    }

    #[test]
    fn test_issue_fails_for_unknown_agent() {
        let store = IdentityStore::in_memory().unwrap();
        let service = AttestationService::new(store, 3600);
        let agent_id = AgentId::new("spiffe://test/unknown");

        let result = service.issue_svid(&agent_id, b"proof");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_expired_svid() {
        let (store, agent_id) = setup();
        // TTL of 0 seconds — immediately expired
        let service = AttestationService::new(store, 0);

        let svid = service.issue_svid(&agent_id, b"proof").unwrap();
        // The SVID expires at issuance time + 0 seconds, so it's immediately expired
        // (or at least by the time we check)
        std::thread::sleep(std::time::Duration::from_millis(10));
        let result = service.verify_svid(&svid);
        assert!(result.is_err());
    }

    #[test]
    fn test_rotate_svid() {
        let (store, agent_id) = setup();
        let service = AttestationService::new(store, 3600);

        let svid1 = service.issue_svid(&agent_id, b"proof").unwrap();
        let svid2 = service.rotate_svid(&agent_id).unwrap();

        // Both should be valid
        assert!(service.verify_svid(&svid1).is_ok());
        assert!(service.verify_svid(&svid2).is_ok());

        // They should have different certificates
        assert_ne!(svid1.certificate, svid2.certificate);
    }
}
