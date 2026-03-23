# AI-SPM (AI Security Posture Management) User Guide

AI-SPM is a comprehensive security platform designed to secure, audit, and test autonomous AI agents. It provides real-time monitoring of agent behavior, strict policy enforcement, provenance tracking, and an intuitive dashboard to understand your AI security posture.

## Table of Contents
1. [Architecture Overview](#architecture-overview)
2. [Building and Running](#building-and-running)
   - [Starting the Core Server](#1-start-the-core-server)
   - [Starting the Desktop Monitor](#2-start-the-desktop-monitor)
3. [Dashboard Features](#dashboard-features)
   - [1. Discovery & Identity](#1-discovery--identity)
   - [2. Security Controls](#2-security-controls)
   - [3. Observability](#3-observability)
   - [4. Compliance & Reporting](#4-compliance--reporting)
   - [5. System](#5-system)
4. [Command Line Interface (CLI)](#command-line-interface-cli)

---

## Architecture Overview

AI-SPM consists of several core components working in tandem:

*   **`ai-spm-server`**: The central backend service. It manages the agent registry, processes telemetry and audit logs, serves the dashboard API, and evaluates security policies.
*   **`ai-spm-monitor`**: A lightweight macOS/Windows desktop daemon that runs in the background. It monitors system activity (shell commands, file changes, network connections, process spawns) in real-time and streams this telemetry to the `ai-spm-server`. It also actively discovers running AI agents, MCP servers, and installed AI extensions.
*   **Web Dashboard**: A beautiful, real-time UI served by `ai-spm-server` that visualizes agent metrics, monitoring sessions, discovered entities, and security incidents.

---

## Building and Running

AI-SPM is built using Rust. You need `cargo` and the standard Rust toolchain installed.

### 1. Start the Core Server

The core server handles API requests, dashboard serving, and policy decisions.

```bash
# From the project root, start the server
cargo run --bin ai-spm -- serve
```

The server binds to `127.0.0.1:8080` (or `3000` depending on your config). Note: While you can access the dashboard by navigating to `http://localhost:8080` in your web browser, **the primary method is via the Desktop Monitor's native window.**

### 2. Start the Desktop Monitor

The Desktop Monitor tracks system activity and discovers agents. It runs as a background tray application natively on macOS or Windows.

```bash
# In a new terminal window, start the monitor
cargo run --bin ai-spm-monitor
```

Once running, you will see an `AI-SPM` shield icon perfectly integrated into your menu bar or system tray.
- Click **Open Dashboard** to launch the beautiful, native AI-SPM desktop window UI.
- Click **Start Monitoring** to begin capturing shell commands, process spawns, network connections, and file changes.
- Click **View Report** to spawn the live native Agent Activity window directly.

### 3. Remote Telemetry Configuration

If you are running the `ai-spm-server` backend in a cloud environment (or Docker container), you can easily point the desktop monitor to it:

- Click the `AI-SPM` shield icon in your tray.
- Select **"✏️ Edit Config"**. This will launch the `~/.ai-spm/monitor.toml` configuration file in your OS-native text editor.
- Update `server_url` to your remote endpoint and `api_key` to your authorized ingestion token.
- Save the file, return to the tray menu, and click **"🔄 Reload"**. The monitor will hot-reload its routing configuration without dropping the background tracking daemon!

---

## Dashboard Features

The AI-SPM Desktop App provides an intuitive, real-time dashboard spanning Discovery, Security Controls, and Observability.

### 1. Discovery & Identity
This section helps you locate, identify, and authenticate all AI agents running on your machine.

*   **Auto Discovery**: AI-SPM automatically scans your machine for running autonomous agents, Model Context Protocol (MCP) servers, and IDE extensions (such as VS Code Copilot or Cursor). You can see the name, type, and source of every discovered element. Click **Register** on any item to assign it a unique SPIFFE identity.
*   **Dependency Graph**: Maps out the relationships between your local agents, MCP servers, and extensions mapping an interactive network graph. Click an agent node to calculate its **Blast Radius** — visually identifying compromised tools or surfaces.
*   **Agent Registry**: The central repository for all registered AI identities. View all assigned SPIFFE IDs (e.g., `spiffe://local/agent/cursor`). You can manually register new agents, assign owners, provide descriptions, or revoke access for compromised agents.
*   **Tokens**: Agents do not use static, long-lived API keys. Instead, they request Just-In-Time (JIT) tokens. This page lets you manually generate temporary JIT tokens and view all currently active tokens and their expiration times. Tokens are cryptographically tied to the active process binary to prevent theft.

### 2. Security Controls
This section provides interactive playgrounds and management interfaces for runtime guardrails.

*   **Gateway**: The secure intermediary enforcing Intent Envelopes. You can submit JSON payloads representing an agent's intended request and view whether the Gateway allows or denies the request based on active Rego policies.
*   **OPA Policies**: Open Policy Agent (OPA) powers the internal rules engine. Use the built-in code editor to author, view, and save Rego constraints directly. Changes apply immediately to all Gateway evaluations.
*   **MCP Tester**: Test and sanitize Model Context Protocol (MCP) tool schemas. Input a tool's JSON schema and test it against the AI-SPM sanitizer, which automatically strips dangerous permissions (like `shell_execution`) and strictly enforces strong typing.
*   **Shell Guard**: Evaluates shell commands against a strict parser heuristic engine. Test a command (e.g., `rm -rf /`) and the Shell Guard will explain exactly why a command is allowed, flagged, or blocked based on your active OPA policies.
*   **Network Sentinel**: Test outbound domains and IP addresses. The Network Sentinel evaluates traffic against configured allowlists/blocklists to stop unauthorized agent data exfiltration or malicious payload downloads.
*   **File Sentinel**: Protects sensitive system files. The Sentinel ensures agents cannot read system configurations (like `~/.ssh/id_rsa` or browser profile folders) while permitting them necessary access to valid project directories.

### 3. Observability
Strict, tamper-proof historical logging and real-time telemetry.

*   **Audit Log**: Every decision made by the AI-SPM Gateway is recorded in a cryptographically secured, append-only log using SHA-256 hash chaining. You can view chronological agent requests, policy evaluations, and system events.
*   **Agent Monitor**: Provides the real-time telemetry stream of your local machine's activity captured by the desktop daemon. It shows shell commands executed, files modified, network requests, and new processes spawned, automatically flagging high-risk behavior in red.

### 4. Compliance & Reporting
Translate technical security controls into recognizable enterprise compliance frameworks.

*   **Compliance**: Automatically maps your active security controls against recognized standards: NIST AI RMF, SOC 2 Type II, HIPAA, and MITRE ATLAS. It provides a real-time status check on control alignment.
*   **Reports**: Generate artifacts to prove your security posture to auditors or security teams. Export your compliance mapping, audit trails, and policy configurations into shareable HTML, CSV, or PDF formats.

### 5. System

*   **Configuration**: Tweak central AI-SPM settings, such as default token time-to-live intervals, default inspection LLM models, and log file persistence paths.
*   **Security Posture (API Defenses)**: The API Gateway actively blocks Denial-of-Service attacks using strict **2MB Payload Limits** and **LRU Eviction Hashmaps** for telemetry memory. All endpoints also transparently require `X-API-Key` or `Bearer Token` authentication headers matching the `api_key` configured in `default.toml`.
*   **User Guide**: Provides the in-app summary documentation for operating the platform.

---

## Command Line Interface (CLI)

The `ai-spm` binary includes several CLI commands for administration and testing without the frontend dashboard:

```text
Usage: ai-spm [OPTIONS] <COMMAND>

Commands:
  serve          Start the HTTP server
  agent          Manage agent identities
  audit          Query and verify audit logs (e.g., verify cryptographic chain)
  redteam        Run adversarial security benchmarks and probing tests
  init           Generate default configurations and a golden dataset
  audit-session  Audit recent shell history through the built-in guardrails
```

**Example:** Run an adversarial Red Team benchmark against your configured agent integration using Crescendo or Persona Modification:
```bash
cargo run --bin ai-spm -- redteam probe --target "spiffe://local/agent/cursor" --target-url "http://agent/api" --strategy "crescendo" --target-key "fake"
```
