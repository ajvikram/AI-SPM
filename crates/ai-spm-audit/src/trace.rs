use ai_spm_core::error::{AiSpmError, Result};
use ai_spm_core::types::{AgentId, ReasoningStep, ReasoningTrace};
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Mutex;
use tracing::info;
use uuid::Uuid;

/// Reasoning Trace Collector — captures the Chain-of-Thought reasoning steps
/// during agent execution for audit and observability.
pub struct TraceCollector {
    active_traces: Mutex<HashMap<Uuid, ReasoningTrace>>,
    completed_traces: Mutex<Vec<ReasoningTrace>>,
}

impl TraceCollector {
    pub fn new() -> Self {
        Self {
            active_traces: Mutex::new(HashMap::new()),
            completed_traces: Mutex::new(Vec::new()),
        }
    }

    /// Begin a new reasoning trace for an agent's task.
    pub fn begin_trace(&self, agent_id: &AgentId, goal: &str) -> Result<Uuid> {
        let trace_id = Uuid::new_v4();
        let trace = ReasoningTrace {
            trace_id,
            agent_id: agent_id.clone(),
            goal: goal.to_string(),
            steps: Vec::new(),
            started_at: Utc::now(),
            completed_at: None,
        };

        let mut traces = self.active_traces.lock().map_err(|e| {
            AiSpmError::AuditLogError(format!("Lock poisoned: {}", e))
        })?;
        traces.insert(trace_id, trace);

        info!(trace_id = %trace_id, agent_id = %agent_id, goal = %goal, "Trace started");
        Ok(trace_id)
    }

    /// Add a reasoning step to an active trace.
    pub fn add_step(&self, trace_id: &Uuid, step: ReasoningStep) -> Result<()> {
        let mut traces = self.active_traces.lock().map_err(|e| {
            AiSpmError::AuditLogError(format!("Lock poisoned: {}", e))
        })?;

        let trace = traces.get_mut(trace_id).ok_or_else(|| {
            AiSpmError::AuditLogError(format!("No active trace with ID {}", trace_id))
        })?;

        trace.steps.push(step);
        Ok(())
    }

    /// Complete an active trace and move it to the completed list.
    pub fn complete_trace(&self, trace_id: &Uuid) -> Result<ReasoningTrace> {
        let mut active = self.active_traces.lock().map_err(|e| {
            AiSpmError::AuditLogError(format!("Lock poisoned: {}", e))
        })?;

        let mut trace = active.remove(trace_id).ok_or_else(|| {
            AiSpmError::AuditLogError(format!("No active trace with ID {}", trace_id))
        })?;

        trace.completed_at = Some(Utc::now());

        let mut completed = self.completed_traces.lock().map_err(|e| {
            AiSpmError::AuditLogError(format!("Lock poisoned: {}", e))
        })?;
        completed.push(trace.clone());

        info!(
            trace_id = %trace_id,
            steps = trace.steps.len(),
            "Trace completed"
        );

        Ok(trace)
    }

    /// Get a completed trace by ID.
    pub fn get_trace(&self, trace_id: &Uuid) -> Result<Option<ReasoningTrace>> {
        let completed = self.completed_traces.lock().map_err(|e| {
            AiSpmError::AuditLogError(format!("Lock poisoned: {}", e))
        })?;

        Ok(completed.iter().find(|t| t.trace_id == *trace_id).cloned())
    }

    /// List all completed traces, optionally filtered by agent.
    pub fn list_traces(&self, agent_filter: Option<&AgentId>) -> Result<Vec<ReasoningTrace>> {
        let completed = self.completed_traces.lock().map_err(|e| {
            AiSpmError::AuditLogError(format!("Lock poisoned: {}", e))
        })?;

        let traces = match agent_filter {
            Some(agent_id) => completed
                .iter()
                .filter(|t| t.agent_id == *agent_id)
                .cloned()
                .collect(),
            None => completed.clone(),
        };

        Ok(traces)
    }
}

impl Default for TraceCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ai_spm_core::types::ConfidentialityLabel;

    fn make_step(action: &str) -> ReasoningStep {
        ReasoningStep {
            step_id: Uuid::new_v4(),
            parent_id: None,
            action: action.into(),
            description: format!("Performing {}", action),
            alternatives_considered: vec!["alt_a".into(), "alt_b".into()],
            rejection_reasons: vec!["Not optimal".into()],
            confidence: 0.85,
            taint_label: TaintLabel::trusted_public(),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_trace_lifecycle() {
        let collector = TraceCollector::new();
        let agent_id = AgentId::new("spiffe://test/agent");

        let trace_id = collector
            .begin_trace(&agent_id, "Process refund request")
            .unwrap();

        collector
            .add_step(&trace_id, make_step("read_email"))
            .unwrap();
        collector
            .add_step(&trace_id, make_step("validate_refund"))
            .unwrap();
        collector
            .add_step(&trace_id, make_step("process_payment"))
            .unwrap();

        let trace = collector.complete_trace(&trace_id).unwrap();
        assert_eq!(trace.steps.len(), 3);
        assert!(trace.completed_at.is_some());
    }

    #[test]
    fn test_get_completed_trace() {
        let collector = TraceCollector::new();
        let agent_id = AgentId::new("spiffe://test/agent");

        let trace_id = collector.begin_trace(&agent_id, "Task").unwrap();
        collector.complete_trace(&trace_id).unwrap();

        let trace = collector.get_trace(&trace_id).unwrap();
        assert!(trace.is_some());
    }

    #[test]
    fn test_list_traces_filtered() {
        let collector = TraceCollector::new();
        let agent1 = AgentId::new("spiffe://test/agent-1");
        let agent2 = AgentId::new("spiffe://test/agent-2");

        let t1 = collector.begin_trace(&agent1, "Task 1").unwrap();
        let t2 = collector.begin_trace(&agent2, "Task 2").unwrap();
        let t3 = collector.begin_trace(&agent1, "Task 3").unwrap();

        collector.complete_trace(&t1).unwrap();
        collector.complete_trace(&t2).unwrap();
        collector.complete_trace(&t3).unwrap();

        let agent1_traces = collector.list_traces(Some(&agent1)).unwrap();
        assert_eq!(agent1_traces.len(), 2);

        let all_traces = collector.list_traces(None).unwrap();
        assert_eq!(all_traces.len(), 3);
    }
}
