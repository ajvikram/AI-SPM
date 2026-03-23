use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Agent Identity
// ---------------------------------------------------------------------------

/// Unique agent identifier using SPIFFE-style URIs.
/// Example: `spiffe://domain/finance-agent`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(pub String);

impl AgentId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Record of a registered agent in the NHI Registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRecord {
    pub agent_id: AgentId,
    pub owner: String,
    pub description: String,
    pub metadata: HashMap<String, String>,
    pub status: AgentStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    Active,
    Suspended,
    Revoked,
}

// ---------------------------------------------------------------------------
// Cryptographic Attestation (SVID)
// ---------------------------------------------------------------------------

/// Short-lived X.509-style identity document for an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Svid {
    pub agent_id: AgentId,
    /// DER-encoded certificate bytes
    pub certificate: Vec<u8>,
    /// DER-encoded private key bytes (only held by the agent)
    pub private_key: Vec<u8>,
    pub issued_at: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

impl Svid {
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.not_after
    }
}

// ---------------------------------------------------------------------------
// JIT Scoped Tokens
// ---------------------------------------------------------------------------

/// A permission scope for a JIT token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub resource: String,
    pub actions: Vec<String>,
}

/// Time-bound, task-specific credential for an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopedToken {
    pub token_id: Uuid,
    pub agent_id: AgentId,
    pub scope: Vec<Permission>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Optional hash of the agent process binary for attestation
    pub binary_hash: Option<String>,
    /// HMAC-SHA256 signature of the token claims
    pub signature: String,
}

impl ScopedToken {
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

/// Validated claims extracted from a ScopedToken.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub token_id: Uuid,
    pub agent_id: AgentId,
    pub scope: Vec<Permission>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub binary_hash: Option<String>,
}

// ---------------------------------------------------------------------------
// FIDES: Integrity & Confidentiality Labels
// ---------------------------------------------------------------------------

/// Integrity level per the FIDES information-flow control model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityLevel {
    /// Trusted user/system input
    High,
    /// Untrusted external data (web, emails, tool outputs)
    Low,
}

/// Confidentiality label defining who may read the data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidentialityLabel {
    pub authorized_readers: Vec<String>,
}

impl ConfidentialityLabel {
    pub fn public() -> Self {
        Self {
            authorized_readers: vec!["*".to_string()],
        }
    }

    pub fn restricted(readers: Vec<String>) -> Self {
        Self {
            authorized_readers: readers,
        }
    }

    pub fn can_read(&self, reader: &str) -> bool {
        self.authorized_readers.contains(&"*".to_string())
            || self.authorized_readers.contains(&reader.to_string())
    }
}

/// Combined taint label tracking both integrity and confidentiality.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintLabel {
    pub integrity: IntegrityLevel,
    pub confidentiality: ConfidentialityLabel,
}

impl TaintLabel {
    pub fn trusted_public() -> Self {
        Self {
            integrity: IntegrityLevel::High,
            confidentiality: ConfidentialityLabel::public(),
        }
    }

    pub fn untrusted_public() -> Self {
        Self {
            integrity: IntegrityLevel::Low,
            confidentiality: ConfidentialityLabel::public(),
        }
    }

    /// Combine two taint labels. Result takes the lower integrity
    /// and the intersection of authorized readers.
    pub fn merge(&self, other: &TaintLabel) -> TaintLabel {
        let integrity = match (&self.integrity, &other.integrity) {
            (IntegrityLevel::High, IntegrityLevel::High) => IntegrityLevel::High,
            _ => IntegrityLevel::Low,
        };

        // Intersection of authorized readers
        let authorized_readers: Vec<String> = if self
            .confidentiality
            .authorized_readers
            .contains(&"*".to_string())
        {
            other.confidentiality.authorized_readers.clone()
        } else if other
            .confidentiality
            .authorized_readers
            .contains(&"*".to_string())
        {
            self.confidentiality.authorized_readers.clone()
        } else {
            self.confidentiality
                .authorized_readers
                .iter()
                .filter(|r| other.confidentiality.authorized_readers.contains(r))
                .cloned()
                .collect()
        };

        TaintLabel {
            integrity,
            confidentiality: ConfidentialityLabel { authorized_readers },
        }
    }
}

// ---------------------------------------------------------------------------
// OWASP ASI Risk Categories
// ---------------------------------------------------------------------------

/// OWASP Top 10 for Agentic Applications risk categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RiskCategory {
    /// ASI01: Agent Goal Hijack and Narrative Redirection
    #[serde(rename = "ASI01")]
    AgentGoalHijack,
    /// ASI02: Tool Misuse and Exploitation
    #[serde(rename = "ASI02")]
    ToolMisuse,
    /// ASI03: Identity and Privilege Abuse
    #[serde(rename = "ASI03")]
    IdentityAbuse,
    /// ASI04: Supply Chain
    #[serde(rename = "ASI04")]
    SupplyChain,
    /// ASI05: Unexpected Code Execution
    #[serde(rename = "ASI05")]
    CodeExecution,
    /// ASI06: Memory Poisoning
    #[serde(rename = "ASI06")]
    MemoryPoisoning,
    /// ASI07: Communication Spoofing
    #[serde(rename = "ASI07")]
    CommSpoofing,
    /// ASI08: Cascading Failures
    #[serde(rename = "ASI08")]
    CascadingFailures,
    /// ASI09: Human Trust Exploitation
    #[serde(rename = "ASI09")]
    TrustExploitation,
    /// ASI10: Rogue Agents
    #[serde(rename = "ASI10")]
    RogueAgents,
}

impl fmt::Display for RiskCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AgentGoalHijack => write!(f, "ASI01: Agent Goal Hijack"),
            Self::ToolMisuse => write!(f, "ASI02: Tool Misuse"),
            Self::IdentityAbuse => write!(f, "ASI03: Identity Abuse"),
            Self::SupplyChain => write!(f, "ASI04: Supply Chain"),
            Self::CodeExecution => write!(f, "ASI05: Code Execution"),
            Self::MemoryPoisoning => write!(f, "ASI06: Memory Poisoning"),
            Self::CommSpoofing => write!(f, "ASI07: Comm Spoofing"),
            Self::CascadingFailures => write!(f, "ASI08: Cascading Failures"),
            Self::TrustExploitation => write!(f, "ASI09: Trust Exploitation"),
            Self::RogueAgents => write!(f, "ASI10: Rogue Agents"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tool Call & Intent Envelope
// ---------------------------------------------------------------------------

/// A tool call request from an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallRequest {
    pub request_id: Uuid,
    pub agent_id: AgentId,
    pub tool_name: String,
    pub arguments: serde_json::Value,
    pub timestamp: DateTime<Utc>,
    /// Unique nonce to prevent replay attacks
    pub nonce: String,
}

/// Signed wrapper around a tool call request (Intent Envelope).
/// The agent must sign every tool call to prove authenticity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentEnvelope {
    pub request: ToolCallRequest,
    /// Ed25519 signature over the canonical JSON of the request
    pub signature: Vec<u8>,
    /// Identifier for the public key used to sign
    pub public_key_id: String,
}

/// Result of a policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    Deny { reason: String },
    RequireHumanApproval { reason: String },
}

impl PolicyDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, PolicyDecision::Allow)
    }
}

// ---------------------------------------------------------------------------
// Reasoning Traces & Audit
// ---------------------------------------------------------------------------

/// A single step in an agent's reasoning trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningStep {
    pub step_id: Uuid,
    pub parent_id: Option<Uuid>,
    pub action: String,
    pub description: String,
    pub alternatives_considered: Vec<String>,
    pub rejection_reasons: Vec<String>,
    pub confidence: f64,
    pub taint_label: TaintLabel,
    pub timestamp: DateTime<Utc>,
}

/// Complete reasoning trace for an agent's task execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningTrace {
    pub trace_id: Uuid,
    pub agent_id: AgentId,
    pub goal: String,
    pub steps: Vec<ReasoningStep>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Actions recorded in the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditAction {
    AgentRegistered { owner: String },
    AgentRevoked,
    TokenIssued { scope_summary: String, ttl_seconds: u64 },
    ToolCallRequested { tool_name: String },
    PolicyEvaluated { decision: PolicyDecision },
    TaintViolation { details: String },
    ReasoningCompleted { trace_id: Uuid },
    AdversarialProbeRun { strategy: String, result: String },
    HumanApproval { action: String, approved: bool },
    /// Vibe-coding: shell command was blocked
    ShellCommandBlocked { command: String, reason: String },
    /// Vibe-coding: shell command was allowed
    ShellCommandAllowed { command: String },
    /// Vibe-coding: shell command requires approval
    ShellCommandPendingApproval { command: String, reason: String },
    /// Vibe-coding: sensitive file access detected
    SensitiveFileAccess { path: String, operation: String, sensitivity: String },
    /// Vibe-coding: network request dropped
    NetworkRequestBlocked { domain: String, port: u16, reason: String },
    /// Vibe-coding: network request allowed
    NetworkRequestAllowed { domain: String, port: u16 },
}

/// A tamper-evident, hash-chained audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub sequence: u64,
    pub previous_hash: String,
    pub entry_hash: String,
    pub agent_id: AgentId,
    pub action: AuditAction,
    pub reasoning_trace_id: Option<Uuid>,
    pub timestamp: DateTime<Utc>,
}

impl AuditEntry {
    /// Compute the hash for this entry (SHA-256 over sequence + previous_hash + serialized action).
    pub fn compute_hash(
        sequence: u64,
        previous_hash: &str,
        agent_id: &AgentId,
        action: &AuditAction,
        timestamp: &DateTime<Utc>,
    ) -> String {
        use sha2::{Digest, Sha256};
        let payload = serde_json::json!({
            "sequence": sequence,
            "previous_hash": previous_hash,
            "agent_id": agent_id,
            "action": action,
            "timestamp": timestamp.to_rfc3339(),
        });
        let bytes = serde_json::to_vec(&payload).unwrap_or_default();
        let hash = Sha256::digest(&bytes);
        hex::encode(hash)
    }
}

// ---------------------------------------------------------------------------
// Adversarial Testing
// ---------------------------------------------------------------------------

/// Strategy for multi-turn adversarial probing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbingStrategy {
    /// Gradual escalation over multiple turns
    Crescendo,
    /// Automated adversarial testing using attacker LLM
    Goat,
    /// Persona modification to bypass safety
    PersonaModification,
    /// Suppress model's refusal response
    RefusalSuppression,
    /// Split prohibited topics across turns
    TopicSplitting,
}

impl fmt::Display for ProbingStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crescendo => write!(f, "Crescendo"),
            Self::Goat => write!(f, "GOAT"),
            Self::PersonaModification => write!(f, "Persona Modification"),
            Self::RefusalSuppression => write!(f, "Refusal Suppression"),
            Self::TopicSplitting => write!(f, "Topic Splitting"),
        }
    }
}

/// Result of an adversarial probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub probe_id: Uuid,
    pub strategy: ProbingStrategy,
    pub target_agent_id: AgentId,
    pub success: bool,
    pub turns_taken: u32,
    pub max_turns: u32,
    pub vulnerability_type: Option<RiskCategory>,
    pub evidence: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

/// Risk severity classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

// ---------------------------------------------------------------------------
// Compliance & Reporting
// ---------------------------------------------------------------------------

/// NIST AI RMF core functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NistFunction {
    Map,
    Measure,
    Manage,
    Govern,
}

/// Compliance mapping linking security components to frameworks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceMapping {
    pub security_component: String,
    pub risk_addressed: RiskCategory,
    pub compliance_alignment: String,
    pub nist_function: Option<NistFunction>,
}

/// Summary of compliance posture over a time range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceSummary {
    pub total_agents: u64,
    pub active_agents: u64,
    pub total_tool_calls: u64,
    pub policy_denials: u64,
    pub taint_violations: u64,
    pub audit_entries: u64,
    pub chain_integrity_verified: bool,
    pub risk_distribution: HashMap<String, u64>,
    pub mappings: Vec<ComplianceMapping>,
    pub generated_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// MCP (Model Context Protocol) types
// ---------------------------------------------------------------------------

/// An MCP tool definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

/// A sanitized MCP tool definition (stripped of potentially malicious content).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizedTool {
    pub original_name: String,
    pub sanitized_name: String,
    pub sanitized_description: String,
    pub input_schema: serde_json::Value,
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// LLM Inspector types
// ---------------------------------------------------------------------------

/// Structured output from the quarantined LLM inspector.
/// Constrains output to safe, pre-defined schemas only.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum StructuredOutput {
    Bool(bool),
    Category(String),
    KeyValues(HashMap<String, String>),
    Number(f64),
}

/// Reference to a hidden variable in the HIDE store.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VariableRef(pub Uuid);

impl VariableRef {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for VariableRef {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Vibe Coding: Shell Guardrail
// ---------------------------------------------------------------------------

/// Verdict from the shell guardrail policy engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum ShellVerdict {
    /// Command is safe to execute
    Allow,
    /// Command is blocked
    Deny { reason: String, risk: ShellRisk },
    /// Command needs human approval before execution
    RequiresApproval { reason: String, risk: ShellRisk },
}

impl ShellVerdict {
    pub fn is_allowed(&self) -> bool {
        matches!(self, ShellVerdict::Allow)
    }
}

/// Risk category for a blocked/flagged shell command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellRisk {
    /// Destructive file/system operations (rm -rf, mkfs, dd)
    DestructiveOperation,
    /// Credential/secret access (.env, ~/.ssh, ~/.aws)
    CredentialAccess,
    /// Package install without approval (npm, pip, cargo)
    SupplyChain,
    /// Network exfiltration (curl POST with env, scp)
    DataExfiltration,
    /// Privilege escalation (sudo, chmod 777, chown)
    PrivilegeEscalation,
    /// Remote code execution (curl|bash, wget|sh)
    RemoteCodeExec,
    /// Path traversal outside project (../../etc/passwd)
    PathTraversal,
    /// Obfuscated or encoded commands (base64 -d | sh)
    Obfuscation,
}

impl fmt::Display for ShellRisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DestructiveOperation => write!(f, "Destructive Operation"),
            Self::CredentialAccess => write!(f, "Credential Access"),
            Self::SupplyChain => write!(f, "Supply Chain Risk"),
            Self::DataExfiltration => write!(f, "Data Exfiltration"),
            Self::PrivilegeEscalation => write!(f, "Privilege Escalation"),
            Self::RemoteCodeExec => write!(f, "Remote Code Execution"),
            Self::PathTraversal => write!(f, "Path Traversal"),
            Self::Obfuscation => write!(f, "Obfuscated Command"),
        }
    }
}

/// Full evaluation result for a shell command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellEvalResult {
    pub command: String,
    pub parsed_binary: String,
    pub verdict: ShellVerdict,
    pub checks_passed: Vec<String>,
    pub checks_failed: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Vibe Coding: Filesystem Sentinel
// ---------------------------------------------------------------------------

/// Type of file operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileOp {
    Read,
    Write,
    Delete,
    Execute,
}

impl fmt::Display for FileOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => write!(f, "read"),
            Self::Write => write!(f, "write"),
            Self::Delete => write!(f, "delete"),
            Self::Execute => write!(f, "execute"),
        }
    }
}

/// Sensitivity classification for a file path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileSensitivity {
    /// Normal project files
    Normal,
    /// Configuration files (Dockerfile, CI configs, Makefile)
    Config,
    /// Credential/secret files (.env, SSH keys, API tokens)
    Credential,
    /// System files (/etc/*, /usr/*)
    System,
    /// Outside project boundary
    OutOfBounds,
}

impl fmt::Display for FileSensitivity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Normal => write!(f, "Normal"),
            Self::Config => write!(f, "Config"),
            Self::Credential => write!(f, "Credential"),
            Self::System => write!(f, "System"),
            Self::OutOfBounds => write!(f, "Out of Bounds"),
        }
    }
}

/// Result of a filesystem access check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileCheckResult {
    pub path: String,
    pub operation: FileOp,
    pub sensitivity: FileSensitivity,
    pub allowed: bool,
    pub reason: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_id() {
        let id = AgentId::new("spiffe://domain/finance-agent");
        assert_eq!(id.as_str(), "spiffe://domain/finance-agent");
        assert_eq!(format!("{}", id), "spiffe://domain/finance-agent");
    }

    #[test]
    fn test_taint_label_merge_both_high() {
        let a = TaintLabel::trusted_public();
        let b = TaintLabel::trusted_public();
        let merged = a.merge(&b);
        assert_eq!(merged.integrity, IntegrityLevel::High);
    }

    #[test]
    fn test_taint_label_merge_one_low() {
        let a = TaintLabel::trusted_public();
        let b = TaintLabel::untrusted_public();
        let merged = a.merge(&b);
        assert_eq!(merged.integrity, IntegrityLevel::Low);
    }

    #[test]
    fn test_taint_label_merge_confidentiality_intersection() {
        let a = TaintLabel {
            integrity: IntegrityLevel::High,
            confidentiality: ConfidentialityLabel::restricted(vec![
                "alice".into(),
                "bob".into(),
            ]),
        };
        let b = TaintLabel {
            integrity: IntegrityLevel::High,
            confidentiality: ConfidentialityLabel::restricted(vec![
                "bob".into(),
                "charlie".into(),
            ]),
        };
        let merged = a.merge(&b);
        assert_eq!(merged.confidentiality.authorized_readers, vec!["bob".to_string()]);
    }

    #[test]
    fn test_policy_decision_is_allowed() {
        assert!(PolicyDecision::Allow.is_allowed());
        assert!(!PolicyDecision::Deny {
            reason: "test".into()
        }
        .is_allowed());
    }

    #[test]
    fn test_audit_entry_hash_deterministic() {
        let agent_id = AgentId::new("test-agent");
        let action = AuditAction::AgentRegistered {
            owner: "admin".into(),
        };
        let ts = Utc::now();
        let h1 = AuditEntry::compute_hash(1, "genesis", &agent_id, &action, &ts);
        let h2 = AuditEntry::compute_hash(1, "genesis", &agent_id, &action, &ts);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_scoped_token_expiry() {
        let token = ScopedToken {
            token_id: Uuid::new_v4(),
            agent_id: AgentId::new("test"),
            scope: vec![],
            issued_at: Utc::now() - chrono::Duration::hours(2),
            expires_at: Utc::now() - chrono::Duration::hours(1),
            signature: String::new(),
        };
        assert!(token.is_expired());
    }

    #[test]
    fn test_risk_category_display() {
        assert_eq!(
            format!("{}", RiskCategory::AgentGoalHijack),
            "ASI01: Agent Goal Hijack"
        );
    }

    #[test]
    fn test_structured_output_serde() {
        let output = StructuredOutput::Bool(true);
        let json = serde_json::to_string(&output).unwrap();
        let parsed: StructuredOutput = serde_json::from_str(&json).unwrap();
        match parsed {
            StructuredOutput::Bool(v) => assert!(v),
            _ => panic!("Expected Bool"),
        }
    }
}
