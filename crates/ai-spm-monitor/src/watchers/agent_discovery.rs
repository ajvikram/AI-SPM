//! Agent Discovery Watcher — discovers running AI agents, MCP servers, and IDE extensions.
//!
//! Scans three sources:
//! 1. Running processes (matches known AI agent binary names)
//! 2. MCP config files (parses JSON configs from known locations)
//! 3. IDE extension directories (matches known AI-related extension prefixes)

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc;
use sysinfo::{System, ProcessRefreshKind};

use crate::types::*;

// ── Known Agent Signatures ──────────────────────────────────────────

/// Process name patterns for known AI agents/tools.
/// Each entry: (display_name, process_pattern, agent_type)
const KNOWN_AGENTS: &[(&str, &str, &str)] = &[
    // IDEs with AI
    ("Antigravity", "antigravity", "ide"),
    ("Cursor", "cursor", "ide"),
    ("Windsurf", "windsurf", "ide"),
    ("VS Code", "code", "ide"),
    // AI CLIs
    ("Claude Code", "claude", "cli"),
    ("Aider", "aider", "cli"),
    // LLM Runtimes
    ("Ollama", "ollama", "runtime"),
    ("LM Studio", "lm studio", "runtime"),
    ("llama.cpp", "llama-server", "runtime"),
    ("vllm", "vllm", "runtime"),
    // Language servers (AI-powered)
    ("Antigravity Language Server", "language_server_macos", "lsp"),
    ("Copilot Agent", "copilot-agent", "lsp"),
    ("Continue Server", "continue", "lsp"),
    ("Tabby", "tabby", "lsp"),
    ("Cody Agent", "cody-agent", "lsp"),
];

/// IDE extension prefixes that indicate AI capabilities.
const AI_EXTENSION_PREFIXES: &[(&str, &str)] = &[
    ("github.copilot", "GitHub Copilot"),
    ("github.copilot-chat", "GitHub Copilot Chat"),
    ("anthropic.claude-code", "Claude Code"),
    ("automatalabs.copilot-mcp", "Copilot MCP"),
    ("codium.codium", "Codium AI"),
    ("continue.continue", "Continue"),
    ("10nates.ollama-autocoder", "Ollama Autocoder"),
    ("tabnine.tabnine-vscode", "Tabnine"),
    ("codeium.codeium", "Codeium"),
    ("sourcegraph.cody-ai", "Cody AI"),
    ("cursor.cursor", "Cursor AI"),
    ("blackboxapp.blackbox", "Blackbox AI"),
    ("amazonwebservices.codewhisperer", "AWS CodeWhisperer"),
    ("amazonwebservices.amazon-q-vscode", "Amazon Q"),
    ("google.gemicode", "Gemini Code Assist"),
    ("ms-vscode.copilot-mermaid-diagram", "Copilot Mermaid"),
    ("devin.devin", "Devin"),
    ("phind.phind", "Phind"),
];

/// Known MCP config file locations (relative to home directory).
const MCP_CONFIG_PATHS: &[&str] = &[
    ".gemini/antigravity/mcp_config.json",
    ".cursor/mcp.json",
    ".claude/claude_desktop_config.json",
    ".config/claude/claude_desktop_config.json",
    ".config/mcp/config.json",
    "Library/Application Support/Claude/claude_desktop_config.json",
    "Library/Application Support/Cursor/User/globalStorage/mcp.json",
];

/// Extension directories (relative to home).
const EXTENSION_DIRS: &[(&str, &str)] = &[
    (".vscode/extensions", "vscode"),
    (".cursor/extensions", "cursor"),
    (".antigravity/extensions", "antigravity"),
    (".vscode-insiders/extensions", "vscode-insiders"),
];

// ── Public API ──────────────────────────────────────────────────────

/// Starts the agent discovery watcher in a background thread.
/// Emits an `AgentDiscovery` event on every scan cycle with the current state.
pub fn start_agent_discovery(
    tx: mpsc::Sender<MonitorEvent>,
    interval: std::time::Duration,
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    std::thread::spawn(move || {
        let home = match std::env::var("HOME") {
            Ok(h) => PathBuf::from(h),
            Err(_) => {
                tracing::error!("Cannot determine HOME directory for agent discovery");
                return;
            }
        };

        // Run an initial scan immediately
        let event = run_discovery_scan(&home);
        let _ = tx.send(event);
        println!("   🔍 Agent discovery: initial scan complete");

        while running.load(std::sync::atomic::Ordering::Relaxed) {
            std::thread::sleep(interval);
            if !running.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            let event = run_discovery_scan(&home);
            let _ = tx.send(event);
        }
    });
}

/// Performs a single discovery scan and returns a MonitorEvent.
fn run_discovery_scan(home: &PathBuf) -> MonitorEvent {
    let agents = scan_processes();
    let mcp_servers = scan_mcp_configs(home);
    let extensions = scan_extensions(home);

    MonitorEvent::new(
        EventType::AgentDiscovery,
        Severity::Info,
        EventDetails::AgentDiscovery {
            agents,
            mcp_servers,
            extensions,
        },
    )
}

// ── Process Scanner ─────────────────────────────────────────────────

fn scan_processes() -> Vec<DiscoveredAgent> {
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::new().with_cmd(sysinfo::UpdateKind::Always),
    );

    let mut seen: HashMap<String, DiscoveredAgent> = HashMap::new();

    for (pid, process) in sys.processes() {
        let name = process.name().to_string_lossy().to_lowercase();
        let exe = process
            .exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let cmd_line: String = process
            .cmd()
            .iter()
            .map(|s| s.to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join(" ");

        for &(display_name, pattern, agent_type) in KNOWN_AGENTS {
            let pattern_lower = pattern.to_lowercase();
            let matched = name.contains(&pattern_lower)
                || exe.to_lowercase().contains(&pattern_lower);

            if matched {
                // Avoid duplicate entries — use display_name as key, keep highest PID
                let key = display_name.to_string();
                if !seen.contains_key(&key) {
                    // Try to extract version from executable path or command line
                    let version = extract_version_from_path(&exe)
                        .or_else(|| extract_version_from_cmd(&cmd_line));

                    seen.insert(
                        key,
                        DiscoveredAgent {
                            name: display_name.to_string(),
                            agent_type: agent_type.to_string(),
                            version,
                            pid: Some(pid.as_u32()),
                            source: "process".to_string(),
                            status: "running".to_string(),
                            executable: if exe.is_empty() {
                                None
                            } else {
                                Some(exe.clone())
                            },
                        },
                    );
                }
            }
        }
    }

    seen.into_values().collect()
}

/// Extract version from an executable path like "/Applications/Cursor-1.2.3.app/..."
fn extract_version_from_path(path: &str) -> Option<String> {
    // Look for version patterns: X.Y.Z
    let re_pattern = regex_lite::Regex::new(r"(\d+\.\d+\.\d+)").ok()?;
    // Only extract from app name or binary name, not random path segments
    let filename = path.rsplit('/').next().unwrap_or(path);
    re_pattern
        .captures(filename)
        .map(|c| c.get(1).unwrap().as_str().to_string())
}

/// Extract version from command line args like "--version 1.2.3" or "v1.2.3"
fn extract_version_from_cmd(cmd: &str) -> Option<String> {
    let re_pattern = regex_lite::Regex::new(r"[\sv](\d+\.\d+\.\d+)").ok()?;
    re_pattern
        .captures(cmd)
        .map(|c| c.get(1).unwrap().as_str().to_string())
}

// ── MCP Config Scanner ──────────────────────────────────────────────

fn scan_mcp_configs(home: &PathBuf) -> Vec<McpServerInfo> {
    let mut servers = Vec::new();

    for &config_rel in MCP_CONFIG_PATHS {
        let config_path = home.join(config_rel);
        if !config_path.exists() {
            continue;
        }

        match std::fs::read_to_string(&config_path) {
            Ok(content) => {
                let source = config_path.to_string_lossy().to_string();
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) {
                    parse_mcp_json(&parsed, &source, &mut servers);
                }
            }
            Err(e) => {
                tracing::warn!("Cannot read MCP config {}: {}", config_path.display(), e);
            }
        }
    }

    servers
}

/// Parse MCP server definitions from a JSON config.
/// Supports two common formats:
///   1. { "mcpServers": { "name": { "command": "...", "args": [...] } } }
///   2. { "servers": { "name": { "command": "...", "args": [...] } } }
///   3. Top-level array of server objects
fn parse_mcp_json(value: &serde_json::Value, source: &str, servers: &mut Vec<McpServerInfo>) {
    // Format 1: Claude Desktop / Cursor style
    if let Some(mcp_servers) = value
        .get("mcpServers")
        .or_else(|| value.get("mcp_servers"))
        .or_else(|| value.get("servers"))
    {
        if let Some(obj) = mcp_servers.as_object() {
            for (name, config) in obj {
                if let Some(server) = parse_single_mcp_server(name, config, source) {
                    servers.push(server);
                }
            }
            return;
        }
    }

    // Format 2: Top-level object where each key is a server
    if let Some(obj) = value.as_object() {
        for (key, val) in obj {
            // Skip metadata keys
            if key == "version" || key == "schema" || key == "$schema" {
                continue;
            }
            if val.is_object() && (val.get("command").is_some() || val.get("url").is_some()) {
                if let Some(server) = parse_single_mcp_server(key, val, source) {
                    servers.push(server);
                }
            }
        }
    }

    // Format 3: Array of servers
    if let Some(arr) = value.as_array() {
        for (i, item) in arr.iter().enumerate() {
            let name = item
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("unnamed")
                .to_string();
            let key = if name == "unnamed" {
                format!("server-{}", i)
            } else {
                name
            };
            if let Some(server) = parse_single_mcp_server(&key, item, source) {
                servers.push(server);
            }
        }
    }
}

fn parse_single_mcp_server(
    name: &str,
    config: &serde_json::Value,
    source: &str,
) -> Option<McpServerInfo> {
    let command = config
        .get("command")
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_string();

    let url = config
        .get("url")
        .and_then(|u| u.as_str())
        .unwrap_or("")
        .to_string();

    // Must have either a command or a URL
    if command.is_empty() && url.is_empty() {
        return None;
    }

    let args: Vec<String> = config
        .get("args")
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let env_vars: Vec<String> = config
        .get("env")
        .and_then(|e| e.as_object())
        .map(|obj| obj.keys().cloned().collect())
        .unwrap_or_default();

    let transport = if !url.is_empty() {
        "sse".to_string()
    } else {
        config
            .get("transport")
            .and_then(|t| t.as_str())
            .unwrap_or("stdio")
            .to_string()
    };

    let effective_command = if command.is_empty() {
        url
    } else {
        command
    };

    Some(McpServerInfo {
        name: name.to_string(),
        command: effective_command,
        args,
        transport,
        source_file: source.to_string(),
        env_vars,
    })
}

// ── Extension Scanner ───────────────────────────────────────────────

fn scan_extensions(home: &PathBuf) -> Vec<ExtensionInfo> {
    let mut extensions = Vec::new();

    for &(ext_dir_rel, ide_name) in EXTENSION_DIRS {
        let ext_dir = home.join(ext_dir_rel);
        if !ext_dir.is_dir() {
            continue;
        }

        let entries = match std::fs::read_dir(&ext_dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let dir_name = entry.file_name().to_string_lossy().to_string();

            for &(prefix, display_name) in AI_EXTENSION_PREFIXES {
                if dir_name.starts_with(prefix) {
                    // Extract version from dir name: "github.copilot-1.388.0" → "1.388.0"
                    let version = dir_name
                        .strip_prefix(prefix)
                        .and_then(|rest| rest.strip_prefix('-'))
                        .map(|v| {
                            // Strip platform suffix: "1.388.0-darwin-arm64" → "1.388.0"
                            v.split('-')
                                .next()
                                .unwrap_or(v)
                                .to_string()
                        })
                        .unwrap_or_else(|| "unknown".to_string());

                    // Don't add duplicates (same prefix in same IDE)
                    let already_exists = extensions.iter().any(|e: &ExtensionInfo| {
                        e.id.starts_with(prefix) && e.ide == ide_name
                    });

                    if !already_exists {
                        extensions.push(ExtensionInfo {
                            id: dir_name.clone(),
                            name: display_name.to_string(),
                            version,
                            ide: ide_name.to_string(),
                        });
                    }

                    break; // Don't match multiple prefixes for the same extension
                }
            }
        }
    }

    extensions
}
