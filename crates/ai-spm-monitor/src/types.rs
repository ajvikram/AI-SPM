use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A single monitoring event captured by a watcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub severity: Severity,
    pub details: EventDetails,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    ShellCommand,
    FileChange,
    ProcessSpawn,
    NetworkConnection,
    AgentDiscovery,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventDetails {
    ShellCommand {
        command: String,
        verdict: String,       // "allow" | "deny" | "requires_approval"
        risk: Option<String>,  // risk category
        reason: Option<String>,
    },
    FileChange {
        path: String,
        operation: String,    // "create" | "modify" | "delete" | "rename"
        sensitivity: String,  // "normal" | "config" | "credential" | "system"
        allowed: bool,
    },
    ProcessSpawn {
        pid: u32,
        name: String,
        cmd_line: String,
        suspicious: bool,
    },
    NetworkConnection {
        pid: u32,
        process: String,
        remote_addr: String,
        direction: String,  // "outbound" | "inbound"
        suspicious: bool,
    },
    AgentDiscovery {
        agents: Vec<DiscoveredAgent>,
        mcp_servers: Vec<McpServerInfo>,
        extensions: Vec<ExtensionInfo>,
    },
}

/// A discovered AI agent (running process or installed tool).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredAgent {
    pub name: String,
    pub agent_type: String,       // "ide" | "cli" | "extension" | "mcp_server"
    pub version: Option<String>,
    pub pid: Option<u32>,
    pub source: String,           // "process" | "config" | "extension"
    pub status: String,           // "running" | "installed" | "configured"
    pub executable: Option<String>,
}

/// An MCP server discovered from config files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerInfo {
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    pub transport: String,       // "stdio" | "sse"
    pub source_file: String,     // which config file it came from
    pub env_vars: Vec<String>,   // names only (not values) for security
}

/// An AI-related IDE extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionInfo {
    pub id: String,              // e.g. "github.copilot-1.388.0"
    pub name: String,            // e.g. "GitHub Copilot"
    pub version: String,
    pub ide: String,             // "vscode" | "cursor" | "antigravity"
}

/// Summary of a monitoring session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub session_id: String,
    pub started_at: DateTime<Utc>,
    pub total_commands: u32,
    pub total_file_changes: u32,
    pub total_processes: u32,
    pub total_network: u32,
    pub blocked: u32,
    pub flagged: u32,
    pub allowed: u32,
}

impl MonitorEvent {
    pub fn new(event_type: EventType, severity: Severity, details: EventDetails) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type,
            severity,
            details,
        }
    }
}

impl SessionSummary {
    pub fn new() -> Self {
        Self {
            session_id: Uuid::new_v4().to_string(),
            started_at: Utc::now(),
            total_commands: 0,
            total_file_changes: 0,
            total_processes: 0,
            total_network: 0,
            blocked: 0,
            flagged: 0,
            allowed: 0,
        }
    }

    pub fn record_event(&mut self, event: &MonitorEvent) {
        match &event.event_type {
            EventType::ShellCommand => self.total_commands += 1,
            EventType::FileChange => self.total_file_changes += 1,
            EventType::ProcessSpawn => self.total_processes += 1,
            EventType::NetworkConnection => self.total_network += 1,
            EventType::AgentDiscovery => {}, // discovery events don't affect counters
        }
        match &event.severity {
            Severity::Critical => self.blocked += 1,
            Severity::Warning => self.flagged += 1,
            Severity::Info => self.allowed += 1,
        }
    }
}
