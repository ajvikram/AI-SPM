use ai_spm_core::error::{AiSpmError, Result};
use ai_spm_core::types::{AgentId, AgentRecord, AgentStatus, Svid};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// SQLite-backed storage for agent records, SVIDs, and token metadata.
#[derive(Clone)]
pub struct IdentityStore {
    conn: Arc<Mutex<Connection>>,
}

impl IdentityStore {
    /// Open or create a persistent SQLite database.
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)
            .map_err(|e| AiSpmError::Database(format!("Failed to open DB: {}", e)))?;
        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        store.run_migrations()?;
        Ok(store)
    }

    /// Create an in-memory SQLite database (for testing).
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| AiSpmError::Database(format!("Failed to open in-memory DB: {}", e)))?;
        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        store.run_migrations()?;
        Ok(store)
    }

    /// Run database migrations.
    fn run_migrations(&self) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| {
            AiSpmError::Database(format!("Lock poisoned: {}", e))
        })?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                description TEXT NOT NULL,
                metadata TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS svids (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                certificate BLOB NOT NULL,
                issued_at TEXT NOT NULL,
                not_after TEXT NOT NULL,
                FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
            );

            CREATE INDEX IF NOT EXISTS idx_svids_agent_id ON svids(agent_id);
            CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
            ",
        )
        .map_err(|e| AiSpmError::Database(format!("Migration failed: {}", e)))?;

        Ok(())
    }

    /// Check if an agent exists.
    pub fn agent_exists(&self, agent_id: &AgentId) -> Result<bool> {
        let conn = self.conn.lock().map_err(|e| {
            AiSpmError::Database(format!("Lock poisoned: {}", e))
        })?;

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM agents WHERE agent_id = ?1",
                params![agent_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|e| AiSpmError::Database(e.to_string()))?;

        Ok(count > 0)
    }

    /// Insert a new agent record.
    pub fn insert_agent(&self, record: &AgentRecord) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| {
            AiSpmError::Database(format!("Lock poisoned: {}", e))
        })?;

        let metadata_json = serde_json::to_string(&record.metadata)?;
        let status_str = serde_json::to_string(&record.status)?;

        conn.execute(
            "INSERT INTO agents (agent_id, owner, description, metadata, status, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                record.agent_id.as_str(),
                record.owner,
                record.description,
                metadata_json,
                status_str.trim_matches('"'),
                record.created_at.to_rfc3339(),
                record.updated_at.to_rfc3339(),
            ],
        )
        .map_err(|e| AiSpmError::Database(e.to_string()))?;

        Ok(())
    }

    /// Get an agent record by ID.
    pub fn get_agent(&self, agent_id: &AgentId) -> Result<AgentRecord> {
        let conn = self.conn.lock().map_err(|e| {
            AiSpmError::Database(format!("Lock poisoned: {}", e))
        })?;

        let result = conn
            .query_row(
                "SELECT agent_id, owner, description, metadata, status, created_at, updated_at
                 FROM agents WHERE agent_id = ?1",
                params![agent_id.as_str()],
                |row| {
                    let agent_id_str: String = row.get(0)?;
                    let owner: String = row.get(1)?;
                    let description: String = row.get(2)?;
                    let metadata_json: String = row.get(3)?;
                    let status_str: String = row.get(4)?;
                    let created_at_str: String = row.get(5)?;
                    let updated_at_str: String = row.get(6)?;
                    Ok((
                        agent_id_str,
                        owner,
                        description,
                        metadata_json,
                        status_str,
                        created_at_str,
                        updated_at_str,
                    ))
                },
            )
            .optional()
            .map_err(|e| AiSpmError::Database(e.to_string()))?;

        match result {
            Some((aid, owner, desc, meta_json, status_str, created, updated)) => {
                let metadata: HashMap<String, String> =
                    serde_json::from_str(&meta_json).unwrap_or_default();
                let status: AgentStatus = serde_json::from_str(&format!("\"{}\"", status_str))
                    .unwrap_or(AgentStatus::Active);
                let created_at = DateTime::parse_from_rfc3339(&created)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());
                let updated_at = DateTime::parse_from_rfc3339(&updated)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());

                Ok(AgentRecord {
                    agent_id: AgentId::new(aid),
                    owner,
                    description: desc,
                    metadata,
                    status,
                    created_at,
                    updated_at,
                })
            }
            None => Err(AiSpmError::AgentNotFound(agent_id.to_string())),
        }
    }

    /// Update an existing agent record.
    pub fn update_agent(&self, record: &AgentRecord) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| {
            AiSpmError::Database(format!("Lock poisoned: {}", e))
        })?;

        let metadata_json = serde_json::to_string(&record.metadata)?;
        let status_str = serde_json::to_string(&record.status)?;

        let rows = conn
            .execute(
                "UPDATE agents SET owner = ?1, description = ?2, metadata = ?3, status = ?4, updated_at = ?5
                 WHERE agent_id = ?6",
                params![
                    record.owner,
                    record.description,
                    metadata_json,
                    status_str.trim_matches('"'),
                    record.updated_at.to_rfc3339(),
                    record.agent_id.as_str(),
                ],
            )
            .map_err(|e| AiSpmError::Database(e.to_string()))?;

        if rows == 0 {
            return Err(AiSpmError::AgentNotFound(
                record.agent_id.to_string(),
            ));
        }

        Ok(())
    }

    /// List agents, optionally filtered by status.
    pub fn list_agents(&self, status_filter: Option<AgentStatus>) -> Result<Vec<AgentRecord>> {
        let conn = self.conn.lock().map_err(|e| {
            AiSpmError::Database(format!("Lock poisoned: {}", e))
        })?;

        let (query, filter_val) = match &status_filter {
            Some(status) => {
                let s = serde_json::to_string(status)
                    .unwrap_or_default()
                    .trim_matches('"')
                    .to_string();
                (
                    "SELECT agent_id, owner, description, metadata, status, created_at, updated_at
                     FROM agents WHERE status = ?1 ORDER BY created_at DESC",
                    Some(s),
                )
            }
            None => (
                "SELECT agent_id, owner, description, metadata, status, created_at, updated_at
                 FROM agents ORDER BY created_at DESC",
                None,
            ),
        };

        let mut stmt = conn
            .prepare(query)
            .map_err(|e| AiSpmError::Database(e.to_string()))?;

        let rows = if let Some(ref fv) = filter_val {
            stmt.query_map(params![fv], Self::row_to_record)
        } else {
            stmt.query_map([], Self::row_to_record)
        }
        .map_err(|e| AiSpmError::Database(e.to_string()))?;

        let mut agents = Vec::new();
        for row in rows {
            agents.push(row.map_err(|e| AiSpmError::Database(e.to_string()))?);
        }

        Ok(agents)
    }

    /// Store an SVID record.
    pub fn store_svid(&self, svid: &Svid) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| {
            AiSpmError::Database(format!("Lock poisoned: {}", e))
        })?;

        conn.execute(
            "INSERT INTO svids (agent_id, certificate, issued_at, not_after)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                svid.agent_id.as_str(),
                svid.certificate,
                svid.issued_at.to_rfc3339(),
                svid.not_after.to_rfc3339(),
            ],
        )
        .map_err(|e| AiSpmError::Database(e.to_string()))?;

        Ok(())
    }

    /// Get the latest SVID for an agent.
    pub fn get_latest_svid(&self, agent_id: &AgentId) -> Result<Option<Svid>> {
        let conn = self.conn.lock().map_err(|e| {
            AiSpmError::Database(format!("Lock poisoned: {}", e))
        })?;

        let result = conn
            .query_row(
                "SELECT agent_id, certificate, issued_at, not_after
                 FROM svids WHERE agent_id = ?1 ORDER BY issued_at DESC LIMIT 1",
                params![agent_id.as_str()],
                |row| {
                    let agent_id_str: String = row.get(0)?;
                    let certificate: Vec<u8> = row.get(1)?;
                    let issued_at_str: String = row.get(2)?;
                    let not_after_str: String = row.get(3)?;
                    Ok((agent_id_str, certificate, issued_at_str, not_after_str))
                },
            )
            .optional()
            .map_err(|e| AiSpmError::Database(e.to_string()))?;

        match result {
            Some((aid, cert, issued, not_after)) => {
                let issued_at = DateTime::parse_from_rfc3339(&issued)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());
                let not_after_dt = DateTime::parse_from_rfc3339(&not_after)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());

                Ok(Some(Svid {
                    agent_id: AgentId::new(aid),
                    certificate: cert,
                    private_key: Vec::new(), // Private key not stored in DB
                    issued_at,
                    not_after: not_after_dt,
                }))
            }
            None => Ok(None),
        }
    }

    fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<AgentRecord> {
        let agent_id_str: String = row.get(0)?;
        let owner: String = row.get(1)?;
        let description: String = row.get(2)?;
        let metadata_json: String = row.get(3)?;
        let status_str: String = row.get(4)?;
        let created_at_str: String = row.get(5)?;
        let updated_at_str: String = row.get(6)?;

        let metadata: HashMap<String, String> =
            serde_json::from_str(&metadata_json).unwrap_or_default();
        let status: AgentStatus = serde_json::from_str(&format!("\"{}\"", status_str))
            .unwrap_or(AgentStatus::Active);
        let created_at = DateTime::parse_from_rfc3339(&created_at_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());
        let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        Ok(AgentRecord {
            agent_id: AgentId::new(agent_id_str),
            owner,
            description,
            metadata,
            status,
            created_at,
            updated_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migrations_run_successfully() {
        let store = IdentityStore::in_memory().unwrap();
        assert!(!store.agent_exists(&AgentId::new("test")).unwrap());
    }

    #[test]
    fn test_insert_and_get_agent() {
        let store = IdentityStore::in_memory().unwrap();
        let now = Utc::now();

        let mut metadata = HashMap::new();
        metadata.insert("env".into(), "production".into());

        let record = AgentRecord {
            agent_id: AgentId::new("spiffe://test/agent-1"),
            owner: "admin".into(),
            description: "Test agent".into(),
            metadata,
            status: AgentStatus::Active,
            created_at: now,
            updated_at: now,
        };

        store.insert_agent(&record).unwrap();

        let fetched = store.get_agent(&record.agent_id).unwrap();
        assert_eq!(fetched.owner, "admin");
        assert_eq!(
            fetched.metadata.get("env").unwrap(),
            "production"
        );
    }

    #[test]
    fn test_get_nonexistent_agent() {
        let store = IdentityStore::in_memory().unwrap();
        let result = store.get_agent(&AgentId::new("nonexistent"));
        assert!(result.is_err());
    }

    #[test]
    fn test_store_and_get_svid() {
        let store = IdentityStore::in_memory().unwrap();
        let now = Utc::now();
        let agent_id = AgentId::new("spiffe://test/agent-1");

        // Must insert agent first (foreign key)
        let record = AgentRecord {
            agent_id: agent_id.clone(),
            owner: "admin".into(),
            description: "Test".into(),
            metadata: HashMap::new(),
            status: AgentStatus::Active,
            created_at: now,
            updated_at: now,
        };
        store.insert_agent(&record).unwrap();

        let svid = Svid {
            agent_id: agent_id.clone(),
            certificate: vec![1, 2, 3, 4],
            private_key: vec![5, 6, 7, 8],
            issued_at: now,
            not_after: now + chrono::Duration::hours(1),
        };
        store.store_svid(&svid).unwrap();

        let fetched = store.get_latest_svid(&agent_id).unwrap().unwrap();
        assert_eq!(fetched.certificate, vec![1, 2, 3, 4]);
        // Private key should not be stored
        assert!(fetched.private_key.is_empty());
    }
}
