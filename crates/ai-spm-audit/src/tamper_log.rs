use ai_spm_core::error::{AiSpmError, Result};
use ai_spm_core::types::{AgentId, AuditAction, AuditEntry};
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tracing::{info, error};
use uuid::Uuid;

/// Tamper-evident, hash-chained, append-only audit log.
/// Each entry is hashed with SHA-256 and chained to the previous entry.
pub struct AuditLog {
    /// Append-only log file
    log_file_path: String,
    /// SQLite index for queries
    index_conn: Arc<Mutex<Connection>>,
    /// Current sequence number
    sequence: Mutex<u64>,
    /// Hash of the last entry
    last_hash: Mutex<String>,
}

impl AuditLog {
    /// Create or open an audit log.
    pub fn open(log_file_path: &str, index_db_path: &str, genesis_hash: &str) -> Result<Self> {
        // Ensure parent directories exist
        if let Some(parent) = Path::new(log_file_path).parent() {
            fs::create_dir_all(parent)
                .map_err(|e| AiSpmError::AuditLogError(format!("Failed to create log dir: {}", e)))?;
        }
        if let Some(parent) = Path::new(index_db_path).parent() {
            fs::create_dir_all(parent)
                .map_err(|e| AiSpmError::AuditLogError(format!("Failed to create index dir: {}", e)))?;
        }

        let conn = Connection::open(index_db_path)
            .map_err(|e| AiSpmError::Database(format!("Failed to open audit index: {}", e)))?;

        // Create index table
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS audit_index (
                sequence INTEGER PRIMARY KEY,
                entry_hash TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                action_type TEXT NOT NULL,
                reasoning_trace_id TEXT,
                timestamp TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_index(agent_id);
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_index(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_index(action_type);
            ",
        )
        .map_err(|e| AiSpmError::Database(format!("Audit index migration failed: {}", e)))?;

        // Get the last entry to resume the chain
        let (last_seq, last_hash) = conn
            .query_row(
                "SELECT sequence, entry_hash FROM audit_index ORDER BY sequence DESC LIMIT 1",
                [],
                |row| {
                    let seq: u64 = row.get(0)?;
                    let hash: String = row.get(1)?;
                    Ok((seq, hash))
                },
            )
            .optional()
            .map_err(|e| AiSpmError::Database(e.to_string()))?
            .unwrap_or((0, genesis_hash.to_string()));

        Ok(Self {
            log_file_path: log_file_path.to_string(),
            index_conn: Arc::new(Mutex::new(conn)),
            sequence: Mutex::new(last_seq),
            last_hash: Mutex::new(last_hash),
        })
    }

    /// Append a new entry to the audit log.
    pub fn append(
        &self,
        agent_id: &AgentId,
        action: AuditAction,
        reasoning_trace_id: Option<Uuid>,
    ) -> Result<AuditEntry> {
        let timestamp = Utc::now();

        let mut sequence = self.sequence.lock().map_err(|e| {
            AiSpmError::AuditLogError(format!("Lock poisoned: {}", e))
        })?;
        let mut last_hash = self.last_hash.lock().map_err(|e| {
            AiSpmError::AuditLogError(format!("Lock poisoned: {}", e))
        })?;

        *sequence += 1;
        let new_seq = *sequence;

        let entry_hash =
            AuditEntry::compute_hash(new_seq, &last_hash, agent_id, &action, &timestamp);

        let entry = AuditEntry {
            sequence: new_seq,
            previous_hash: last_hash.clone(),
            entry_hash: entry_hash.clone(),
            agent_id: agent_id.clone(),
            action: action.clone(),
            reasoning_trace_id,
            timestamp,
        };

        // Write to append-only log file
        self.write_to_log_file(&entry)?;

        // Write to index
        self.write_to_index(&entry)?;

        *last_hash = entry_hash;

        info!(
            sequence = new_seq,
            agent_id = %agent_id,
            "Audit entry appended"
        );

        Ok(entry)
    }

    /// Verify the integrity of the audit chain between two sequence numbers.
    pub fn verify_chain(&self, from: u64, to: u64) -> Result<bool> {
        let conn = self.index_conn.lock().map_err(|e| {
            AiSpmError::AuditLogError(format!("Lock poisoned: {}", e))
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT sequence, entry_hash, previous_hash, agent_id, action_type, timestamp
                 FROM audit_index WHERE sequence >= ?1 AND sequence <= ?2 ORDER BY sequence ASC",
            )
            .map_err(|e| AiSpmError::Database(e.to_string()))?;

        let rows: Vec<(u64, String, String, String, String, String)> = stmt
            .query_map(params![from, to], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            })
            .map_err(|e| AiSpmError::Database(e.to_string()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| AiSpmError::Database(e.to_string()))?;

        for i in 1..rows.len() {
            let (_, ref prev_hash, _, _, _, _) = rows[i - 1];
            let (_, _, ref expected_prev, _, _, _) = rows[i];

            if prev_hash != expected_prev {
                error!(
                    sequence = rows[i].0,
                    expected = %expected_prev,
                    actual = %prev_hash,
                    "Chain integrity violation"
                );
                return Err(AiSpmError::AuditChainViolation(rows[i].0));
            }
        }

        info!(from = from, to = to, entries = rows.len(), "Chain verified");
        Ok(true)
    }

    /// Query audit entries by agent ID.
    pub fn query_by_agent(&self, agent_id: &AgentId) -> Result<Vec<AuditEntry>> {
        self.query_entries(Some(agent_id), None)
    }

    /// Query audit entries with optional filters.
    pub fn query_entries(
        &self,
        agent_filter: Option<&AgentId>,
        limit: Option<u32>,
    ) -> Result<Vec<AuditEntry>> {
        let conn = self.index_conn.lock().map_err(|e| {
            AiSpmError::AuditLogError(format!("Lock poisoned: {}", e))
        })?;

        let limit_val = limit.unwrap_or(1000) as i64;

        // Read from the log file for full entries; index only has summaries
        // For now, reconstruct from index data
        let query = match agent_filter {
            Some(agent_id) => {
                let mut stmt = conn
                    .prepare(
                        "SELECT sequence, entry_hash, previous_hash, agent_id, action_type, reasoning_trace_id, timestamp
                         FROM audit_index WHERE agent_id = ?1 ORDER BY sequence DESC LIMIT ?2",
                    )
                    .map_err(|e| AiSpmError::Database(e.to_string()))?;

                let results = stmt.query_map(params![agent_id.as_str(), limit_val], Self::row_to_entry_summary)
                    .map_err(|e| AiSpmError::Database(e.to_string()))?
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|e| AiSpmError::Database(e.to_string()))?;
                results
            }
            None => {
                let mut stmt = conn
                    .prepare(
                        "SELECT sequence, entry_hash, previous_hash, agent_id, action_type, reasoning_trace_id, timestamp
                         FROM audit_index ORDER BY sequence DESC LIMIT ?1",
                    )
                    .map_err(|e| AiSpmError::Database(e.to_string()))?;

                let results = stmt.query_map(params![limit_val], Self::row_to_entry_summary)
                    .map_err(|e| AiSpmError::Database(e.to_string()))?
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|e| AiSpmError::Database(e.to_string()))?;
                results
            }
        };

        Ok(query)
    }

    /// Get the total number of entries in the audit log.
    pub fn entry_count(&self) -> Result<u64> {
        let seq = self.sequence.lock().map_err(|e| {
            AiSpmError::AuditLogError(format!("Lock poisoned: {}", e))
        })?;
        Ok(*seq)
    }

    fn write_to_log_file(&self, entry: &AuditEntry) -> Result<()> {
        let json = serde_json::to_string(entry)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_file_path)
            .map_err(|e| AiSpmError::AuditLogError(format!("Failed to open log file: {}", e)))?;

        writeln!(file, "{}", json)
            .map_err(|e| AiSpmError::AuditLogError(format!("Failed to write log: {}", e)))?;

        Ok(())
    }

    fn write_to_index(&self, entry: &AuditEntry) -> Result<()> {
        let conn = self.index_conn.lock().map_err(|e| {
            AiSpmError::AuditLogError(format!("Lock poisoned: {}", e))
        })?;

        let action_type = match &entry.action {
            AuditAction::AgentRegistered { .. } => "agent_registered",
            AuditAction::AgentRevoked => "agent_revoked",
            AuditAction::TokenIssued { .. } => "token_issued",
            AuditAction::ToolCallRequested { .. } => "tool_call_requested",
            AuditAction::PolicyEvaluated { .. } => "policy_evaluated",
            AuditAction::TaintViolation { .. } => "taint_violation",
            AuditAction::ReasoningCompleted { .. } => "reasoning_completed",
            AuditAction::AdversarialProbeRun { .. } => "adversarial_probe",
            AuditAction::HumanApproval { .. } => "human_approval",
            AuditAction::ShellCommandBlocked { .. } => "shell_command_blocked",
            AuditAction::ShellCommandAllowed { .. } => "shell_command_allowed",
            AuditAction::ShellCommandPendingApproval { .. } => "shell_command_pending",
            AuditAction::SensitiveFileAccess { .. } => "sensitive_file_access",
            AuditAction::NetworkRequestBlocked { .. } => "network_request_blocked",
            AuditAction::NetworkRequestAllowed { .. } => "network_request_allowed",
        };

        let trace_id_str = entry.reasoning_trace_id.map(|id| id.to_string());

        conn.execute(
            "INSERT INTO audit_index (sequence, entry_hash, previous_hash, agent_id, action_type, reasoning_trace_id, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                entry.sequence as i64,
                entry.entry_hash,
                entry.previous_hash,
                entry.agent_id.as_str(),
                action_type,
                trace_id_str,
                entry.timestamp.to_rfc3339(),
            ],
        )
        .map_err(|e| AiSpmError::Database(e.to_string()))?;

        Ok(())
    }

    fn row_to_entry_summary(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditEntry> {
        let sequence: i64 = row.get(0)?;
        let entry_hash: String = row.get(1)?;
        let previous_hash: String = row.get(2)?;
        let agent_id_str: String = row.get(3)?;
        let action_type: String = row.get(4)?;
        let trace_id_str: Option<String> = row.get(5)?;
        let timestamp_str: String = row.get(6)?;

        let action = match action_type.as_str() {
            "agent_registered" => AuditAction::AgentRegistered { owner: String::new() },
            "agent_revoked" => AuditAction::AgentRevoked,
            "token_issued" => AuditAction::TokenIssued {
                scope_summary: String::new(),
                ttl_seconds: 0,
            },
            "tool_call_requested" => AuditAction::ToolCallRequested {
                tool_name: String::new(),
            },
            "policy_evaluated" => AuditAction::PolicyEvaluated {
                decision: ai_spm_core::types::PolicyDecision::Allow,
            },
            "taint_violation" => AuditAction::TaintViolation {
                details: String::new(),
            },
            "reasoning_completed" => AuditAction::ReasoningCompleted {
                trace_id: uuid::Uuid::nil(),
            },
            "adversarial_probe" => AuditAction::AdversarialProbeRun {
                strategy: String::new(),
                result: String::new(),
            },
            "human_approval" => AuditAction::HumanApproval {
                action: String::new(),
                approved: false,
            },
            "shell_command_blocked" => AuditAction::ShellCommandBlocked {
                command: String::new(),
                reason: String::new(),
            },
            "shell_command_allowed" => AuditAction::ShellCommandAllowed {
                command: String::new(),
            },
            "shell_command_pending" => AuditAction::ShellCommandPendingApproval {
                command: String::new(),
                reason: String::new(),
            },
            "sensitive_file_access" => AuditAction::SensitiveFileAccess {
                path: String::new(),
                operation: String::new(),
                sensitivity: String::new(),
            },
            _ => AuditAction::AgentRevoked,
        };

        let timestamp = chrono::DateTime::parse_from_rfc3339(&timestamp_str)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(|_| chrono::Utc::now());

        let reasoning_trace_id = trace_id_str.and_then(|s| uuid::Uuid::parse_str(&s).ok());

        Ok(AuditEntry {
            sequence: sequence as u64,
            previous_hash,
            entry_hash,
            agent_id: AgentId::new(agent_id_str),
            action,
            reasoning_trace_id,
            timestamp,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup() -> (AuditLog, tempfile::TempDir) {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.log");
        let index_path = dir.path().join("audit_index.db");
        let genesis = "0".repeat(64);

        let log = AuditLog::open(
            log_path.to_str().unwrap(),
            index_path.to_str().unwrap(),
            &genesis,
        )
        .unwrap();

        (log, dir)
    }

    #[test]
    fn test_append_and_count() {
        let (log, _dir) = setup();
        let agent_id = AgentId::new("spiffe://test/agent");

        log.append(
            &agent_id,
            AuditAction::AgentRegistered {
                owner: "admin".into(),
            },
            None,
        )
        .unwrap();

        assert_eq!(log.entry_count().unwrap(), 1);
    }

    #[test]
    fn test_chain_integrity() {
        let (log, _dir) = setup();
        let agent_id = AgentId::new("spiffe://test/agent");

        for i in 0..5 {
            log.append(
                &agent_id,
                AuditAction::ToolCallRequested {
                    tool_name: format!("tool_{}", i),
                },
                None,
            )
            .unwrap();
        }

        assert!(log.verify_chain(1, 5).is_ok());
    }

    #[test]
    fn test_query_by_agent() {
        let (log, _dir) = setup();
        let agent1 = AgentId::new("spiffe://test/agent-1");
        let agent2 = AgentId::new("spiffe://test/agent-2");

        log.append(&agent1, AuditAction::AgentRegistered { owner: "a".into() }, None)
            .unwrap();
        log.append(&agent2, AuditAction::AgentRegistered { owner: "b".into() }, None)
            .unwrap();
        log.append(&agent1, AuditAction::AgentRevoked, None)
            .unwrap();

        let entries = log.query_by_agent(&agent1).unwrap();
        assert_eq!(entries.len(), 2);
    }
}
