# AI-SPM User Guide

## Getting Started

AI-SPM (AI Security Posture Management) monitors and secures AI agents running on your system.

### Quick Start
1. **Start the server:** `cargo run --bin ai-spm-monitor`
2. **Open dashboard:** Navigate to `http://localhost:8080`
3. **Auto-discovery** runs automatically, detecting agents, MCP servers, and IDE extensions

---

## Auto Discovery

The discovery engine scans your system for AI-related processes, configurations, and extensions.

### What Gets Detected
- **Running AI agents** — Claude, Copilot, Cursor, Windsurf, Aider, Cline
- **MCP server configurations** — from `claude_desktop_config.json` and similar
- **IDE AI extensions** — VS Code, JetBrains, and other IDE integrations

### Cross-Platform Paths Scanned
| OS | Config Paths |
|---|---|
| macOS | `~/Library/Application Support/`, `~/.config/` |
| Linux | `~/.config/`, `~/.local/share/` |
| Windows | `%APPDATA%\`, `%LOCALAPPDATA%\` |

### Registering Discovered Items
- Click **Register** next to any discovered agent/MCP to create a SPIFFE identity
- Click **Register All** to batch-register everything at once

---

## Agent Registry

The NHI (Non-Human Identity) Registry manages SPIFFE-based identities for all AI agents.

### Registering an Agent
1. Click **+ Register Agent**
2. Enter a SPIFFE ID (e.g., `spiffe://local/agent/my-agent`)
3. Set the owner and description
4. Click **Register**

### SPIFFE IDs
We use SPIFFE (Secure Production Identity Framework For Everyone) URIs:
- Format: `spiffe://<domain>/<type>/<name>`
- Example: `spiffe://local/agent/claude-desktop`

---

## Security Controls

### Gateway (OPA Policy)
Evaluates tool call requests against security policies. Send JSON envelopes to test policy decisions.

### MCP Tester
Validates MCP tool definitions for:
- Suspicious tool descriptions (prompt injection)
- Argument schema validation
- Naming convention compliance

### Shell Guard
Analyzes shell commands for risks:
- **Destructive operations** (rm -rf, mkfs)
- **Credential access** (.env, SSH keys)
- **Supply chain risks** (curl | bash)
- **Data exfiltration** (curl POST with env vars)
- **Privilege escalation** (sudo, chmod 777)

### File Sentinel
Monitors file system access patterns:
- Detects access to sensitive files (credentials, system files)
- Classifies file sensitivity levels
- Blocks out-of-bounds access

### Network Sentinel
Controls external network access by agents, preventing data exfiltration and command-and-control communication through an allowlist/blocklist evaluator.

### OPA Policy Management
Provides a built-in code editor to create, edit, save, and apply Custom Rego policies for the Gateway rules engine.

### Process Binary Attestation
Verifies agent binary hashes during token issuance, visually badging credentials that are running verified, un-tampered binaries.

---

## Observability

### Audit Log
Tamper-proof, hash-chained audit trail of all actions:
- Agent registrations/revocations
- Token issuance
- Policy evaluations
- Shell command decisions
- File access events

### Agent Monitor
Real-time monitoring of AI agent activity:
- Session tracking
- Event timelines
- Activity types and metadata

---

## Compliance & Reporting

### Compliance Dashboard
Overview of security posture across all registered agents.

### Reports
Security standards coverage matrix mapping AI-SPM features to:
- **OWASP Top 10 for LLM Applications** (2025)
- **NIST AI Risk Management Framework** (AI RMF 1.0)
- **MITRE ATLAS** tactics & techniques
- **ISO/IEC 42001** AI Management System
- **EU AI Act** (Regulation 2024/1689)

Export reports as HTML, CSV, or PDF for compliance documentation.

---

## Configuration

### Server Settings
- **Host/Port** — API server bind address
- **Data Directory** — Where AI-SPM stores data

### Monitoring
- **Scan Interval** — How often to scan for agents (seconds)
- **Process Patterns** — Agent process names to detect
- **Watch Paths** — Additional paths to monitor

### Security Policies
- **Shell Default Action** — allow, deny, or prompt for shell commands
- **File Default Action** — allow, deny, or prompt for file access
- **Auto Register** — Automatically register discovered agents

---

## FAQ

**Q: How do I start monitoring?**
A: Run `cargo run --bin ai-spm-monitor` and visit `http://localhost:8080`

**Q: Where is configuration stored?**
A: In `~/.ai-spm/config.json`

**Q: Is the audit log tamper-proof?**
A: Yes, each entry is hash-chained using SHA-256

**Q: What platforms are supported?**
A: macOS, Linux, and Windows (via `sysinfo` crate)
