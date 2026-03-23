use crate::error::{AiSpmError, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Top-level application configuration, loaded from TOML files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub identity: IdentityConfig,
    pub gateway: GatewayConfig,
    pub reasoning: ReasoningConfig,
    pub audit: AuditConfig,
    pub redteam: RedteamConfig,
    pub openai: OpenAiConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub log_level: String,
    /// Enable mTLS for inter-service communication
    pub mtls_enabled: bool,
    /// API Key for protecting Gateway and Monitor ingestion endpoints
    pub api_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    /// Path to the SQLite database for the NHI registry
    pub database_path: String,
    /// SVID validity duration in seconds (default: 3600 = 1 hour)
    pub svid_ttl_seconds: u64,
    /// HMAC secret key for signing JIT tokens (hex-encoded)
    pub token_signing_key: String,
    /// Default token TTL in seconds (default: 300 = 5 minutes)
    pub default_token_ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// OPA server base URL (e.g., http://localhost:8181)
    pub opa_url: String,
    /// Path to the directory containing Rego policy files
    pub policies_dir: String,
    /// Maximum nonces to track for replay prevention (LRU cache size)
    pub nonce_cache_size: usize,
    /// Rate limit: max requests per second per agent
    pub rate_limit_per_second: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningConfig {
    /// Maximum number of hidden variables per session
    pub max_hidden_variables: usize,
    /// Default integrity level for external data
    pub default_external_integrity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Path to the append-only audit log file
    pub log_file_path: String,
    /// Path to the SQLite database for audit index
    pub index_database_path: String,
    /// Genesis hash for the first entry in the chain
    pub genesis_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedteamConfig {
    /// Maximum turns for multi-turn probing
    pub max_probe_turns: u32,
    /// Path to the golden dataset directory
    pub golden_dataset_dir: String,
    /// Timeout per probe in seconds
    pub probe_timeout_seconds: u64,
}

/// OpenAI-compatible API configuration with configurable base URL.
/// Supports OpenAI, Azure OpenAI, vLLM, Ollama, and any compatible endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAiConfig {
    /// Base URL for the OpenAI-compatible API.
    /// Defaults to "https://api.openai.com/v1".
    /// Examples:
    ///   - Azure: "https://your-resource.openai.azure.com/openai/deployments/your-deployment"
    ///   - vLLM: "http://localhost:8000/v1"
    ///   - Ollama: "http://localhost:11434/v1"
    pub base_url: String,
    /// API key for authentication
    pub api_key: String,
    /// Model name to use (e.g., "gpt-4o", "gpt-4o-mini")
    pub model: String,
    /// Maximum tokens for the inspector response
    pub max_tokens: u32,
    /// Temperature for the inspector (lower = more deterministic)
    pub temperature: f64,
    /// Request timeout in seconds
    pub timeout_seconds: u64,
}

impl AppConfig {
    /// Load configuration from the given TOML file path, with environment variable overrides.
    pub fn load(config_path: &str) -> Result<Self> {
        let settings = config::Config::builder()
            .add_source(config::File::with_name(config_path))
            .add_source(
                config::Environment::with_prefix("AISPM")
                    .separator("__")
                    .try_parsing(true),
            )
            .build()
            .map_err(|e| AiSpmError::Config(e.to_string()))?;

        settings
            .try_deserialize::<AppConfig>()
            .map_err(|e| AiSpmError::Config(e.to_string()))
    }

    /// Load from a specific path (PathBuf variant).
    pub fn load_from_path(path: &PathBuf) -> Result<Self> {
        Self::load(
            path.to_str()
                .ok_or_else(|| AiSpmError::Config("Invalid config path".into()))?,
        )
    }

    /// Create a default development configuration.
    pub fn development() -> Self {
        Self {
            server: ServerConfig {
                host: "127.0.0.1".into(),
                port: 8080,
                log_level: "debug".into(),
                mtls_enabled: false,
                api_key: "dev-secret-key".into(),
            },
            identity: IdentityConfig {
                database_path: "data/identity.db".into(),
                svid_ttl_seconds: 3600,
                token_signing_key: "0".repeat(64), // 32-byte hex key
                default_token_ttl_seconds: 300,
            },
            gateway: GatewayConfig {
                opa_url: "http://localhost:8181".into(),
                policies_dir: "policies".into(),
                nonce_cache_size: 10_000,
                rate_limit_per_second: 100,
            },
            reasoning: ReasoningConfig {
                max_hidden_variables: 1000,
                default_external_integrity: "low".into(),
            },
            audit: AuditConfig {
                log_file_path: "data/audit.log".into(),
                index_database_path: "data/audit_index.db".into(),
                genesis_hash: "0".repeat(64),
            },
            redteam: RedteamConfig {
                max_probe_turns: 10,
                golden_dataset_dir: "data/golden_datasets".into(),
                probe_timeout_seconds: 120,
            },
            openai: OpenAiConfig {
                base_url: "https://api.openai.com/v1".into(),
                api_key: String::new(),
                model: "gpt-4o-mini".into(),
                max_tokens: 1024,
                temperature: 0.0,
                timeout_seconds: 30,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_development_config() {
        let config = AppConfig::development();
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.openai.base_url, "https://api.openai.com/v1");
        assert_eq!(config.openai.model, "gpt-4o-mini");
        assert_eq!(config.identity.svid_ttl_seconds, 3600);
        assert_eq!(config.gateway.opa_url, "http://localhost:8181");
    }

    #[test]
    fn test_config_serialization() {
        let config = AppConfig::development();
        let json = serde_json::to_string_pretty(&config).unwrap();
        let deserialized: AppConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.server.port, config.server.port);
        assert_eq!(deserialized.openai.base_url, config.openai.base_url);
    }
}
