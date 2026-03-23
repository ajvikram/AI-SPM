use ai_spm_core::error::Result;
use ai_spm_core::types::{
    AgentId, AuditEntry, ComplianceMapping, ComplianceSummary, NistFunction, RiskCategory,
};
use chrono::Utc;
use std::collections::HashMap;

use crate::tamper_log::AuditLog;

/// Provenance chain: Goal → Plan → Tool Call → Outcome
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProvenanceChain {
    pub agent_id: AgentId,
    pub goal: String,
    pub plan_steps: Vec<String>,
    pub tool_calls: Vec<ToolCallRecord>,
    pub outcome: String,
    pub entries: Vec<AuditEntry>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ToolCallRecord {
    pub tool_name: String,
    pub timestamp: String,
    pub decision: String,
}

/// Risk report mapping agent actions to OWASP ASI categories.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RiskReport {
    pub agent_id: AgentId,
    pub risk_counts: HashMap<String, u64>,
    pub total_actions: u64,
    pub violations: u64,
}

/// Provenance API for querying the audit log.
pub struct ProvenanceService<'a> {
    audit_log: &'a AuditLog,
}

impl<'a> ProvenanceService<'a> {
    pub fn new(audit_log: &'a AuditLog) -> Self {
        Self { audit_log }
    }

    /// Trace provenance for an agent: Goal → Plan → Tool Call → Outcome
    pub fn trace_provenance(&self, agent_id: &AgentId) -> Result<ProvenanceChain> {
        let entries = self.audit_log.query_by_agent(agent_id)?;

        let mut tool_calls = Vec::new();
        let mut plan_steps = Vec::new();

        for entry in &entries {
            match &entry.action {
                ai_spm_core::types::AuditAction::ToolCallRequested { tool_name } => {
                    tool_calls.push(ToolCallRecord {
                        tool_name: tool_name.clone(),
                        timestamp: entry.timestamp.to_rfc3339(),
                        decision: "requested".into(),
                    });
                }
                ai_spm_core::types::AuditAction::PolicyEvaluated { decision } => {
                    let decision_str = match decision {
                        ai_spm_core::types::PolicyDecision::Allow => "allowed",
                        ai_spm_core::types::PolicyDecision::Deny { .. } => "denied",
                        ai_spm_core::types::PolicyDecision::RequireHumanApproval { .. } => {
                            "pending_approval"
                        }
                    };
                    plan_steps.push(format!("Policy evaluation: {}", decision_str));
                }
                _ => {}
            }
        }

        Ok(ProvenanceChain {
            agent_id: agent_id.clone(),
            goal: format!("Agent {} execution trace", agent_id),
            plan_steps,
            tool_calls,
            outcome: format!("{} audit entries recorded", entries.len()),
            entries,
        })
    }

    /// Get risk report for an agent.
    pub fn get_risk_mapping(&self, agent_id: &AgentId) -> Result<RiskReport> {
        let entries = self.audit_log.query_by_agent(agent_id)?;
        let mut risk_counts: HashMap<String, u64> = HashMap::new();
        let mut violations = 0u64;

        for entry in &entries {
            match &entry.action {
                ai_spm_core::types::AuditAction::TaintViolation { .. } => {
                    *risk_counts
                        .entry(RiskCategory::AgentGoalHijack.to_string())
                        .or_insert(0) += 1;
                    violations += 1;
                }
                ai_spm_core::types::AuditAction::PolicyEvaluated {
                    decision: ai_spm_core::types::PolicyDecision::Deny { .. },
                } => {
                    *risk_counts
                        .entry(RiskCategory::ToolMisuse.to_string())
                        .or_insert(0) += 1;
                    violations += 1;
                }
                _ => {}
            }
        }

        Ok(RiskReport {
            agent_id: agent_id.clone(),
            risk_counts,
            total_actions: entries.len() as u64,
            violations,
        })
    }

    /// Generate compliance summary.
    pub fn compliance_summary(&self) -> Result<ComplianceSummary> {
        let entries = self.audit_log.query_entries(None, None)?;
        let total = entries.len() as u64;

        let mut agent_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut policy_denials = 0u64;
        let mut taint_violations = 0u64;
        let mut tool_calls = 0u64;
        let mut risk_distribution: HashMap<String, u64> = HashMap::new();

        for entry in &entries {
            agent_ids.insert(entry.agent_id.to_string());
            match &entry.action {
                ai_spm_core::types::AuditAction::PolicyEvaluated {
                    decision: ai_spm_core::types::PolicyDecision::Deny { .. },
                } => {
                    policy_denials += 1;
                    *risk_distribution
                        .entry("policy_denial".into())
                        .or_insert(0) += 1;
                }
                ai_spm_core::types::AuditAction::TaintViolation { .. } => {
                    taint_violations += 1;
                    *risk_distribution
                        .entry("taint_violation".into())
                        .or_insert(0) += 1;
                }
                ai_spm_core::types::AuditAction::ToolCallRequested { .. } => {
                    tool_calls += 1;
                }
                _ => {}
            }
        }

        let chain_ok = self
            .audit_log
            .verify_chain(1, total)
            .unwrap_or(false);

        let mappings = vec![
            ComplianceMapping {
                security_component: "Integrity Tainting (FIDES)".into(),
                risk_addressed: RiskCategory::AgentGoalHijack,
                compliance_alignment: "NIST AI RMF: Safety/Robustness".into(),
                nist_function: Some(NistFunction::Manage),
            },
            ComplianceMapping {
                security_component: "OPA Gateway".into(),
                risk_addressed: RiskCategory::ToolMisuse,
                compliance_alignment: "SOC 2 / HIPAA: Access Control".into(),
                nist_function: Some(NistFunction::Govern),
            },
            ComplianceMapping {
                security_component: "SPIFFE/SPIRE Identity".into(),
                risk_addressed: RiskCategory::IdentityAbuse,
                compliance_alignment: "Zero Trust Architecture".into(),
                nist_function: Some(NistFunction::Map),
            },
            ComplianceMapping {
                security_component: "Reasoning Traces".into(),
                risk_addressed: RiskCategory::TrustExploitation,
                compliance_alignment: "GDPR: Right to Explanation".into(),
                nist_function: Some(NistFunction::Measure),
            },
        ];

        Ok(ComplianceSummary {
            total_agents: agent_ids.len() as u64,
            active_agents: agent_ids.len() as u64,
            total_tool_calls: tool_calls,
            policy_denials,
            taint_violations,
            audit_entries: total,
            chain_integrity_verified: chain_ok,
            risk_distribution,
            mappings,
            generated_at: Utc::now(),
        })
    }
}
