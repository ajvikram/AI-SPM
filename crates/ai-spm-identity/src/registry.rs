use ai_spm_core::error::{AiSpmError, Result};
use ai_spm_core::types::{AgentId, AgentRecord, AgentStatus};
use std::collections::HashMap;
use tracing::{info, warn};

use crate::store::IdentityStore;

/// Non-Human Identity (NHI) Registry.
/// Manages agent SPIFFE IDs and their lifecycle.
pub struct NhiRegistry {
    store: IdentityStore,
}

impl NhiRegistry {
    pub fn new(store: IdentityStore) -> Self {
        Self { store }
    }

    /// Register a new agent in the NHI Registry.
    pub fn register_agent(
        &self,
        agent_id: &AgentId,
        owner: &str,
        description: &str,
        metadata: HashMap<String, String>,
    ) -> Result<AgentRecord> {
        // Check if agent already exists
        if self.store.agent_exists(agent_id)? {
            return Err(AiSpmError::AgentAlreadyExists(agent_id.to_string()));
        }

        let now = chrono::Utc::now();
        let record = AgentRecord {
            agent_id: agent_id.clone(),
            owner: owner.to_string(),
            description: description.to_string(),
            metadata,
            status: AgentStatus::Active,
            created_at: now,
            updated_at: now,
        };

        self.store.insert_agent(&record)?;
        info!(agent_id = %agent_id, owner = %owner, "Agent registered");
        Ok(record)
    }

    /// Look up an agent by its ID.
    pub fn lookup_agent(&self, agent_id: &AgentId) -> Result<AgentRecord> {
        self.store.get_agent(agent_id)
    }

    /// List all agents, optionally filtered by status.
    pub fn list_agents(&self, status_filter: Option<AgentStatus>) -> Result<Vec<AgentRecord>> {
        self.store.list_agents(status_filter)
    }

    /// Revoke an agent, marking it as no longer authorized.
    pub fn revoke_agent(&self, agent_id: &AgentId) -> Result<()> {
        let mut record = self.store.get_agent(agent_id)?;
        record.status = AgentStatus::Revoked;
        record.updated_at = chrono::Utc::now();
        self.store.update_agent(&record)?;
        warn!(agent_id = %agent_id, "Agent revoked");
        Ok(())
    }

    /// Suspend an agent temporarily.
    pub fn suspend_agent(&self, agent_id: &AgentId) -> Result<()> {
        let mut record = self.store.get_agent(agent_id)?;
        record.status = AgentStatus::Suspended;
        record.updated_at = chrono::Utc::now();
        self.store.update_agent(&record)?;
        warn!(agent_id = %agent_id, "Agent suspended");
        Ok(())
    }

    /// Reactivate a suspended agent.
    pub fn reactivate_agent(&self, agent_id: &AgentId) -> Result<()> {
        let mut record = self.store.get_agent(agent_id)?;
        if record.status == AgentStatus::Revoked {
            return Err(AiSpmError::Identity(
                "Cannot reactivate a revoked agent".into(),
            ));
        }
        record.status = AgentStatus::Active;
        record.updated_at = chrono::Utc::now();
        self.store.update_agent(&record)?;
        info!(agent_id = %agent_id, "Agent reactivated");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_registry() -> NhiRegistry {
        let store = IdentityStore::in_memory().unwrap();
        NhiRegistry::new(store)
    }

    #[test]
    fn test_register_and_lookup() {
        let registry = test_registry();
        let agent_id = AgentId::new("spiffe://test/agent-1");

        let record = registry
            .register_agent(&agent_id, "admin", "Test agent", HashMap::new())
            .unwrap();
        assert_eq!(record.agent_id, agent_id);
        assert_eq!(record.status, AgentStatus::Active);

        let looked_up = registry.lookup_agent(&agent_id).unwrap();
        assert_eq!(looked_up.owner, "admin");
    }

    #[test]
    fn test_register_duplicate() {
        let registry = test_registry();
        let agent_id = AgentId::new("spiffe://test/agent-1");

        registry
            .register_agent(&agent_id, "admin", "Test", HashMap::new())
            .unwrap();
        let result = registry.register_agent(&agent_id, "admin", "Test", HashMap::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_revoke_agent() {
        let registry = test_registry();
        let agent_id = AgentId::new("spiffe://test/agent-1");

        registry
            .register_agent(&agent_id, "admin", "Test", HashMap::new())
            .unwrap();
        registry.revoke_agent(&agent_id).unwrap();

        let record = registry.lookup_agent(&agent_id).unwrap();
        assert_eq!(record.status, AgentStatus::Revoked);
    }

    #[test]
    fn test_suspend_and_reactivate() {
        let registry = test_registry();
        let agent_id = AgentId::new("spiffe://test/agent-1");

        registry
            .register_agent(&agent_id, "admin", "Test", HashMap::new())
            .unwrap();

        registry.suspend_agent(&agent_id).unwrap();
        let record = registry.lookup_agent(&agent_id).unwrap();
        assert_eq!(record.status, AgentStatus::Suspended);

        registry.reactivate_agent(&agent_id).unwrap();
        let record = registry.lookup_agent(&agent_id).unwrap();
        assert_eq!(record.status, AgentStatus::Active);
    }

    #[test]
    fn test_cannot_reactivate_revoked() {
        let registry = test_registry();
        let agent_id = AgentId::new("spiffe://test/agent-1");

        registry
            .register_agent(&agent_id, "admin", "Test", HashMap::new())
            .unwrap();
        registry.revoke_agent(&agent_id).unwrap();

        let result = registry.reactivate_agent(&agent_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_list_agents_with_filter() {
        let registry = test_registry();
        let agent1 = AgentId::new("spiffe://test/agent-1");
        let agent2 = AgentId::new("spiffe://test/agent-2");

        registry
            .register_agent(&agent1, "admin", "Agent 1", HashMap::new())
            .unwrap();
        registry
            .register_agent(&agent2, "admin", "Agent 2", HashMap::new())
            .unwrap();
        registry.suspend_agent(&agent2).unwrap();

        let active = registry
            .list_agents(Some(AgentStatus::Active))
            .unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].agent_id, agent1);

        let all = registry.list_agents(None).unwrap();
        assert_eq!(all.len(), 2);
    }
}
