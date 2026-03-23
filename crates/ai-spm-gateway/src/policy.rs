use ai_spm_core::error::{AiSpmError, Result};
use ai_spm_core::types::{PolicyDecision, ToolCallRequest};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::info;

/// Policy evaluation context sent to OPA.
#[derive(Debug, Serialize)]
struct OpaInput {
    input: OpaRequestInput,
}

#[derive(Debug, Serialize)]
struct OpaRequestInput {
    agent_id: String,
    agent_status: String,
    tool_name: String,
    arguments: serde_json::Value,
    timestamp: String,
    environment: String,
    allowed_tools: Vec<String>,
}

/// OPA response structure.
#[derive(Debug, Deserialize)]
struct OpaResponse {
    result: Option<OpaResult>,
}

#[derive(Debug, Deserialize)]
struct OpaResult {
    #[serde(default)]
    allow: bool,
    #[serde(default)]
    deny: bool,
    #[serde(default)]
    require_human_approval: bool,
    #[serde(default)]
    reason: Option<String>,
}

/// Policy engine trait for evaluating tool call requests.
pub trait PolicyEngine: Send + Sync {
    fn evaluate(
        &self,
        request: &ToolCallRequest,
        context: &PolicyContext,
    ) -> impl std::future::Future<Output = Result<PolicyDecision>> + Send;
}

/// Context for policy evaluation.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyContext {
    pub agent_status: String,
    pub environment: String,
    pub allowed_tools: Vec<String>,
}

/// OPA-based policy engine that communicates with an external OPA server.
pub struct OpaPolicyEngine {
    client: Client,
    opa_url: String,
    policy_path: String,
}

impl OpaPolicyEngine {
    /// Create a new OPA policy engine.
    /// `opa_url`: Base URL of the OPA server (e.g., "http://localhost:8181")
    /// `policy_path`: The OPA policy path (e.g., "v1/data/allow_tool_call")
    pub fn new(opa_url: &str, policy_path: &str, timeout_seconds: u64) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_seconds))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            client,
            opa_url: opa_url.trim_end_matches('/').to_string(),
            policy_path: policy_path.trim_start_matches('/').to_string(),
        }
    }

    /// Push a Rego policy to the OPA server.
    pub async fn push_policy(&self, policy_id: &str, rego_content: &str) -> Result<()> {
        let url = format!("{}/v1/policies/{}", self.opa_url, policy_id);

        let response = self
            .client
            .put(&url)
            .header("Content-Type", "text/plain")
            .body(rego_content.to_string())
            .send()
            .await
            .map_err(|e| AiSpmError::OpaError(format!("Failed to push policy: {}", e)))?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(AiSpmError::OpaError(format!(
                "OPA rejected policy: {}",
                body
            )));
        }

        info!(policy_id = %policy_id, "Policy pushed to OPA");
        Ok(())
    }
}

impl PolicyEngine for OpaPolicyEngine {
    async fn evaluate(
        &self,
        request: &ToolCallRequest,
        context: &PolicyContext,
    ) -> Result<PolicyDecision> {
        let opa_input = OpaInput {
            input: OpaRequestInput {
                agent_id: request.agent_id.to_string(),
                agent_status: context.agent_status.clone(),
                tool_name: request.tool_name.clone(),
                arguments: request.arguments.clone(),
                timestamp: request.timestamp.to_rfc3339(),
                environment: context.environment.clone(),
                allowed_tools: context.allowed_tools.clone(),
            },
        };

        let url = format!("{}/{}", self.opa_url, self.policy_path);

        let response = self
            .client
            .post(&url)
            .json(&opa_input)
            .send()
            .await
            .map_err(|e| AiSpmError::OpaError(format!("OPA request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AiSpmError::OpaError(format!(
                "OPA returned {}: {}",
                status, body
            )));
        }

        let opa_response: OpaResponse = response
            .json()
            .await
            .map_err(|e| AiSpmError::OpaError(format!("Failed to parse OPA response: {}", e)))?;

        let decision = match opa_response.result {
            Some(result) => {
                if result.deny {
                    PolicyDecision::Deny {
                        reason: result
                            .reason
                            .unwrap_or_else(|| "Policy denied the request".into()),
                    }
                } else if result.require_human_approval {
                    PolicyDecision::RequireHumanApproval {
                        reason: result
                            .reason
                            .unwrap_or_else(|| "Human approval required".into()),
                    }
                } else if result.allow {
                    PolicyDecision::Allow
                } else {
                    PolicyDecision::Deny {
                        reason: "No matching policy rule".into(),
                    }
                }
            }
            None => PolicyDecision::Deny {
                reason: "OPA returned no result".into(),
            },
        };

        info!(
            agent_id = %request.agent_id,
            tool = %request.tool_name,
            decision = ?decision,
            "Policy evaluated"
        );

        Ok(decision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_context_creation() {
        let ctx = PolicyContext {
            agent_status: "active".into(),
            environment: "production".into(),
            allowed_tools: vec!["database_query".into(), "send_email".into()],
        };
        assert_eq!(ctx.allowed_tools.len(), 2);
    }

    #[test]
    fn test_opa_engine_url_construction() {
        let engine = OpaPolicyEngine::new(
            "http://localhost:8181/",
            "/v1/data/allow_tool_call",
            30,
        );
        assert_eq!(engine.opa_url, "http://localhost:8181");
        assert_eq!(engine.policy_path, "v1/data/allow_tool_call");
    }
}
