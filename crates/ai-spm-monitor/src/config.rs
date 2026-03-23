//! Monitor configuration — server mode, remote URL, admin overrides.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuration for the AI-SPM Desktop Monitor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    /// Server mode: "embedded", "remote", or "auto" (try remote, fall back to embedded)
    #[serde(default = "default_server_mode")]
    pub server_mode: String,

    /// Remote server URL (used when server_mode is "remote" or "auto")
    #[serde(default = "default_server_url")]
    pub server_url: String,

    /// API Key for server authentication
    #[serde(default = "default_api_key")]
    pub api_key: String,

    /// Embedded server port (used when server_mode is "embedded")
    #[serde(default = "default_embedded_port")]
    pub embedded_port: u16,

    /// Admin override: if true, forces remote mode and locks the setting
    #[serde(default)]
    pub admin_force_remote: bool,

    /// Admin override: required server URL (cannot be changed by user)
    #[serde(default)]
    pub admin_server_url: Option<String>,

    /// Watch directory (default: current directory)
    #[serde(default)]
    pub watch_dir: Option<String>,

    /// Shell history file path
    #[serde(default)]
    pub history_file: Option<String>,
}

fn default_server_mode() -> String { "auto".to_string() }
fn default_server_url() -> String { "http://127.0.0.1:8080".to_string() }
fn default_api_key() -> String { "secret-test-key".to_string() }
fn default_embedded_port() -> u16 { 8080 }

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            server_mode: default_server_mode(),
            server_url: default_server_url(),
            api_key: default_api_key(),
            embedded_port: default_embedded_port(),
            admin_force_remote: false,
            admin_server_url: None,
            watch_dir: None,
            history_file: None,
        }
    }
}

impl MonitorConfig {
    /// Load config from `~/.ai-spm/monitor.toml`, falling back to defaults.
    pub fn load() -> Self {
        let path = config_path();

        // Check for admin override via environment variable
        let env_force = std::env::var("AI_SPM_FORCE_REMOTE").unwrap_or_default();
        let env_url = std::env::var("AI_SPM_SERVER_URL").ok();

        let mut config = if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(content) => toml_deserialize(&content),
                Err(_) => Self::default(),
            }
        } else {
            Self::default()
        };

        // Environment overrides take precedence
        if env_force == "1" || env_force.to_lowercase() == "true" {
            config.admin_force_remote = true;
        }
        if let Some(url) = env_url {
            config.admin_server_url = Some(url);
        }

        // Apply admin override
        if config.admin_force_remote {
            config.server_mode = "remote".to_string();
            if let Some(ref url) = config.admin_server_url {
                config.server_url = url.clone();
            }
        }

        config
    }

    /// Save config to `~/.ai-spm/monitor.toml`.
    pub fn save(&self) -> Result<(), String> {
        let path = config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let content = toml_serialize(self);
        std::fs::write(&path, content).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Get the effective server URL based on current mode.
    pub fn effective_url(&self) -> String {
        if self.admin_force_remote {
            self.admin_server_url.clone().unwrap_or_else(|| self.server_url.clone())
        } else {
            match self.server_mode.as_str() {
                "embedded" => format!("http://127.0.0.1:{}", self.embedded_port),
                _ => self.server_url.clone(),
            }
        }
    }

    /// Whether admin has locked the settings.
    pub fn is_admin_locked(&self) -> bool {
        self.admin_force_remote
    }

    /// Cycle through server modes (for menu toggle).
    pub fn next_mode(&mut self) {
        if self.admin_force_remote { return; } // locked
        self.server_mode = match self.server_mode.as_str() {
            "auto" => "embedded".to_string(),
            "embedded" => "remote".to_string(),
            "remote" => "auto".to_string(),
            _ => "auto".to_string(),
        };
    }

    /// Display string for current mode.
    pub fn mode_display(&self) -> String {
        if self.admin_force_remote {
            format!("🔒 Remote: {} (admin)", self.effective_url())
        } else {
            match self.server_mode.as_str() {
                "embedded" => format!("📦 Embedded (port {})", self.embedded_port),
                "remote" => format!("🌐 Remote: {}", self.server_url),
                "auto" => format!("🔄 Auto (remote → embedded fallback)"),
                _ => "❓ Unknown".to_string(),
            }
        }
    }
}

pub fn config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".ai-spm").join("monitor.toml")
}

/// Simple TOML serialization (avoid extra dependency).
fn toml_serialize(config: &MonitorConfig) -> String {
    let mut s = String::from("# AI-SPM Monitor Configuration\n\n");
    s.push_str(&format!("server_mode = \"{}\"\n", config.server_mode));
    s.push_str(&format!("server_url = \"{}\"\n", config.server_url));
    s.push_str(&format!("api_key = \"{}\"\n", config.api_key));
    s.push_str(&format!("embedded_port = {}\n", config.embedded_port));
    s.push_str(&format!("admin_force_remote = {}\n", config.admin_force_remote));
    if let Some(ref url) = config.admin_server_url {
        s.push_str(&format!("admin_server_url = \"{}\"\n", url));
    }
    if let Some(ref dir) = config.watch_dir {
        s.push_str(&format!("watch_dir = \"{}\"\n", dir));
    }
    if let Some(ref hist) = config.history_file {
        s.push_str(&format!("history_file = \"{}\"\n", hist));
    }
    s
}

/// Simple TOML deserialization (line-by-line key=value parsing).
fn toml_deserialize(content: &str) -> MonitorConfig {
    let mut config = MonitorConfig::default();
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() { continue; }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim().trim_matches('"');
            match key {
                "server_mode" => config.server_mode = value.to_string(),
                "server_url" => config.server_url = value.to_string(),
                "api_key" => config.api_key = value.to_string(),
                "embedded_port" => config.embedded_port = value.parse().unwrap_or(8080),
                "admin_force_remote" => config.admin_force_remote = value == "true",
                "admin_server_url" => config.admin_server_url = Some(value.to_string()),
                "watch_dir" => config.watch_dir = Some(value.to_string()),
                "history_file" => config.history_file = Some(value.to_string()),
                _ => {}
            }
        }
    }
    config
}
