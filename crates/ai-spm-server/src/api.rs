use ai_spm_core::config::AppConfig;
use ai_spm_core::types::*;
use ai_spm_identity::store::IdentityStore;
use ai_spm_identity::registry::NhiRegistry;
use ai_spm_identity::attestation::AttestationService;
use ai_spm_identity::jit_tokens::JitTokenManager;
use ai_spm_gateway::envelope::EnvelopeHandler;
use ai_spm_gateway::mcp::McpMiddleware;
use ai_spm_gateway::shell_guard::ShellGuard;
use ai_spm_gateway::fs_sentinel::FsSentinel;
use ai_spm_audit::tamper_log::AuditLog;
use ai_spm_audit::trace::TraceCollector;
use ai_spm_audit::provenance::ProvenanceService;

use axum::{
    extract::{Json, Query, State, Request, Path},
    http::StatusCode,
    middleware::Next,
    response::{Html, IntoResponse, Response},
    routing::{get, post, delete},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

/// A single monitor session with its events.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MonitorSession {
    pub session_id: String,
    pub started_at: String,
    pub last_updated: String,
    pub total_events: usize,
    pub summary: serde_json::Value,
}

/// Shared application state.
#[allow(dead_code)]
pub struct AppState {
    pub config: AppConfig,
    pub identity_store: IdentityStore,
    pub registry: NhiRegistry,
    pub attestation: AttestationService,
    pub token_manager: JitTokenManager,
    pub envelope_handler: EnvelopeHandler,
    pub mcp_middleware: RwLock<McpMiddleware>,
    pub shell_guard: ShellGuard,
    pub fs_sentinel: FsSentinel,
    pub audit_log: AuditLog,
    pub trace_collector: TraceCollector,
    /// Monitor sessions: session_id -> (session_meta, events)
    pub monitor_sessions: RwLock<HashMap<String, (MonitorSession, Vec<serde_json::Value>)>>,
}

type SharedState = Arc<AppState>;

/// Start the HTTP server.
pub async fn run_server(config: &AppConfig, host: &str, port: u16) -> anyhow::Result<()> {
    // Initialize all services
    let identity_store = IdentityStore::open(&config.identity.database_path)?;
    let registry = NhiRegistry::new(identity_store.clone());
    let attestation = AttestationService::new(
        identity_store.clone(),
        config.identity.svid_ttl_seconds,
    );
    let token_manager = JitTokenManager::new(
        &config.identity.token_signing_key,
        config.identity.default_token_ttl_seconds,
    )?;
    let envelope_handler = EnvelopeHandler::new(config.gateway.nonce_cache_size);
    let mcp_middleware = McpMiddleware::new();
    let shell_guard = ShellGuard::new();
    let fs_sentinel = FsSentinel::new();
    let audit_log = AuditLog::open(
        &config.audit.log_file_path,
        &config.audit.index_database_path,
        &config.audit.genesis_hash,
    )?;
    let trace_collector = TraceCollector::new();

    let state = Arc::new(AppState {
        config: config.clone(),
        identity_store,
        registry,
        attestation,
        token_manager,
        envelope_handler,
        mcp_middleware: RwLock::new(mcp_middleware),
        shell_guard,
        fs_sentinel,
        audit_log,
        trace_collector,
        monitor_sessions: RwLock::new(HashMap::new()),
    });

    let protected_routes = Router::new()
        .route("/api/agents", post(register_agent))
        .route("/api/agents/{id}", delete(revoke_agent))
        .route("/api/tokens/issue", post(issue_token))
        .route("/api/gateway/evaluate", post(evaluate_envelope))
        .route("/api/gateway/mcp/sanitize", post(sanitize_tools))
        .route("/api/gateway/mcp/validate", post(validate_tool_args))
        .route("/api/shell/evaluate", post(evaluate_shell_command))
        .route("/api/fs/check", post(check_file_access))
        .route("/api/network/evaluate", post(evaluate_network))
        .route("/api/monitor/events", post(receive_monitor_events))
        .route("/api/agents/batch-register", post(batch_register_agents))
        .route("/api/policies", post(save_policy))
        .route("/api/policies/:name", delete(delete_policy))
        .route("/api/config", post(save_config))
        .layer(axum::middleware::from_fn_with_state(state.clone(), api_key_auth));

    let app = Router::new()
        // Dashboard UI
        .route("/", get(serve_ui))
        .route("/ui", get(serve_ui))
        .route("/index.html", get(serve_ui))
        .route("/ui/index.html", get(serve_ui))
        .route("/api/agents", get(list_agents))
        .route("/api/agents/{id}", get(get_agent))
        .route("/api/audit/traces", get(list_traces))
        .route("/api/audit/provenance/{agent_id}", get(get_provenance))
        .route("/api/audit/verify", post(verify_chain))
        .route("/api/audit/entries", get(list_audit_entries))
        .route("/api/compliance/summary", get(compliance_summary))
        .route("/api/shell/policy", get(get_shell_policy))
        .route("/api/monitor/sessions", get(list_monitor_sessions))
        .route("/api/monitor/sessions/:session_id", get(get_monitor_session))
        .route("/api/monitor/agents", get(list_discovered_agents))
        .route("/api/dashboard/metrics", get(dashboard_metrics))
        .route("/api/dependency-graph", get(dependency_graph))
        .route("/api/system/info", get(system_info))
        .route("/api/config", get(get_config))
        .route("/api/reports/standards", get(get_standards_coverage))
        .route("/api/policies", get(list_policies))
        .route("/api/tokens", get(list_tokens))
        .route("/health", get(health_check))
        .merge(protected_routes)
        // Middleware
        .layer(axum::extract::DefaultBodyLimit::max(2 * 1024 * 1024))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("{}:{}", host, port)).await?;
    info!("🚀 AI-SPM server listening on {}:{}", host, port);
    println!("🚀 AI-SPM server listening on http://{}:{}", host, port);
    println!("   Dashboard: http://{}:{}/", host, port);
    println!("   Health:    http://{}:{}/health", host, port);
    println!("   API:       http://{}:{}/api/", host, port);

    axum::serve(listener, app).await?;
    Ok(())
}

/// Authentication Middleware for API endpoints (CVE-1 Fix)
async fn api_key_auth(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = req.headers().get("Authorization").and_then(|h| h.to_str().ok());
    let api_key = req.headers().get("X-API-Key").and_then(|h| h.to_str().ok());
    
    let provided_key = api_key.or_else(|| {
        auth_header.and_then(|h| h.strip_prefix("Bearer "))
    });

    if let Some(key) = provided_key {
        if key == state.config.server.api_key {
            return Ok(next.run(req).await);
        }
    }
    
    tracing::warn!("Blocked unauthorized API request to {}", req.uri().path());
    Err(StatusCode::UNAUTHORIZED)
}

// ── Request/Response types ──────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
struct RegisterAgentRequest {
    agent_id: String,
    owner: String,
    description: Option<String>,
    metadata: Option<HashMap<String, String>>,
}

#[derive(Deserialize)]
struct IssueTokenRequest {
    agent_id: String,
    scope: Option<Vec<Permission>>,
    ttl_seconds: Option<u64>,
    binary_hash: Option<String>,
}

#[derive(Deserialize)]
struct VerifyChainRequest {
    from: u64,
    to: u64,
}

#[derive(Deserialize)]
struct SanitizeToolsRequest {
    tools: Vec<McpToolDefinition>,
}

#[derive(Deserialize)]
struct ValidateToolArgsRequest {
    tool_name: String,
    arguments: serde_json::Value,
}

#[derive(Serialize)]
struct ApiResponse<T: Serialize> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    fn ok(data: T) -> Json<Self> {
        Json(Self {
            success: true,
            data: Some(data),
            error: None,
        })
    }

    fn err(msg: impl Into<String>) -> (StatusCode, Json<Self>) {
        (
            StatusCode::BAD_REQUEST,
            Json(Self {
                success: false,
                data: None,
                error: Some(msg.into()),
            }),
        )
    }
}

// ── Handlers ────────────────────────────────────────────────────────────

async fn serve_ui() -> impl IntoResponse {
    // Build a list of candidate paths for ui/index.html
    let mut paths: Vec<std::path::PathBuf> = vec![
        "ui/index.html".into(),
        "../../ui/index.html".into(),
    ];

    // Log CWD and exe for debugging
    eprintln!("  [serve_ui] CWD: {:?}", std::env::current_dir().ok());
    eprintln!("  [serve_ui] EXE: {:?}", std::env::current_exe().ok());

    // Also check relative to the binary location (for .app bundles)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            // .app bundle: Contents/MacOS/binary → Contents/Resources/index.html
            paths.push(exe_dir.join("../Resources/index.html"));
            // Sibling directory
            paths.push(exe_dir.join("index.html"));
            // Next to the binary in a flat dist
            paths.push(exe_dir.join("ui/index.html"));
        }
    }

    for path in &paths {
        let exists = path.exists();
        eprintln!("  [serve_ui] try {:?} → exists={}", path, exists);
        if let Ok(content) = tokio::fs::read_to_string(path).await {
            eprintln!("  [serve_ui] ✅ Serving from {:?} ({} bytes)", path, content.len());
            return Html(content).into_response();
        }
    }
    eprintln!("  [serve_ui] ❌ No index.html found!");
    // Fallback: embed a redirect message
    Html("<html><body style='background:#0a0e1a;color:#f1f5f9;font-family:Inter,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh'><div style='text-align:center'><h1>🛡️ AI-SPM</h1><p>Dashboard UI not found. Place <code>ui/index.html</code> in the working directory.</p><p><a href='/health' style='color:#818cf8'>Health Check</a></p></div></body></html>".to_string()).into_response()
}

async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "ai-spm",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

async fn register_agent(
    State(state): State<SharedState>,
    Json(req): Json<RegisterAgentRequest>,
) -> impl IntoResponse {
    let agent_id = AgentId::new(&req.agent_id);
    match state.registry.register_agent(
        &agent_id,
        &req.owner,
        req.description.as_deref().unwrap_or(""),
        req.metadata.unwrap_or_default(),
    ) {
        Ok(record) => {
            let _ = state.audit_log.append(
                &agent_id,
                AuditAction::AgentRegistered { owner: req.owner },
                None,
            );
            (StatusCode::CREATED, ApiResponse::ok(record)).into_response()
        }
        Err(e) => ApiResponse::<AgentRecord>::err(e.to_string()).into_response(),
    }
}

async fn list_agents(State(state): State<SharedState>) -> impl IntoResponse {
    match state.registry.list_agents(None) {
        Ok(agents) => ApiResponse::ok(agents).into_response(),
        Err(e) => ApiResponse::<Vec<AgentRecord>>::err(e.to_string()).into_response(),
    }
}

async fn get_agent(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let agent_id = AgentId::new(&id);
    match state.registry.lookup_agent(&agent_id) {
        Ok(record) => ApiResponse::ok(record).into_response(),
        Err(e) => ApiResponse::<AgentRecord>::err(e.to_string()).into_response(),
    }
}

async fn revoke_agent(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let agent_id = AgentId::new(&id);
    match state.registry.revoke_agent(&agent_id) {
        Ok(()) => {
            let _ = state.audit_log.append(
                &agent_id,
                AuditAction::AgentRevoked,
                None,
            );
            ApiResponse::ok("Agent revoked").into_response()
        }
        Err(e) => ApiResponse::<String>::err(e.to_string()).into_response(),
    }
}

async fn issue_token(
    State(state): State<SharedState>,
    Json(req): Json<IssueTokenRequest>,
) -> impl IntoResponse {
    let agent_id = AgentId::new(&req.agent_id);
    match state.token_manager.issue_token(
        &agent_id,
        req.scope.unwrap_or_default(),
        req.ttl_seconds,
        req.binary_hash,
    ) {
        Ok(token) => {
            let _ = state.audit_log.append(
                &agent_id,
                AuditAction::TokenIssued {
                    scope_summary: "API issued".into(),
                    ttl_seconds: req.ttl_seconds.unwrap_or(300),
                },
                None,
            );
            (StatusCode::CREATED, ApiResponse::ok(token)).into_response()
        }
        Err(e) => ApiResponse::<ScopedToken>::err(e.to_string()).into_response(),
    }
}

async fn evaluate_envelope(
    State(state): State<SharedState>,
    Json(envelope): Json<IntentEnvelope>,
) -> impl IntoResponse {
    let _ = state.audit_log.append(
        &envelope.request.agent_id,
        AuditAction::ToolCallRequested {
            tool_name: envelope.request.tool_name.clone(),
        },
        None,
    );

    ApiResponse::ok(serde_json::json!({
        "status": "received",
        "request_id": envelope.request.request_id,
        "tool": envelope.request.tool_name,
        "note": "Full OPA evaluation requires OPA server running"
    }))
    .into_response()
}

async fn sanitize_tools(
    State(state): State<SharedState>,
    Json(req): Json<SanitizeToolsRequest>,
) -> impl IntoResponse {
    let mcp = state.mcp_middleware.read().await;
    let sanitized = mcp.sanitize_tool_descriptions(req.tools);
    ApiResponse::ok(sanitized).into_response()
}

async fn validate_tool_args(
    State(state): State<SharedState>,
    Json(req): Json<ValidateToolArgsRequest>,
) -> impl IntoResponse {
    let mcp = state.mcp_middleware.read().await;
    match mcp.validate_tool_arguments(&req.tool_name, &req.arguments) {
        Ok(()) => ApiResponse::ok("Arguments valid").into_response(),
        Err(e) => ApiResponse::<String>::err(e.to_string()).into_response(),
    }
}

async fn list_traces(State(state): State<SharedState>) -> impl IntoResponse {
    match state.trace_collector.list_traces(None) {
        Ok(traces) => ApiResponse::ok(traces).into_response(),
        Err(e) => ApiResponse::<Vec<ReasoningTrace>>::err(e.to_string()).into_response(),
    }
}

async fn get_provenance(
    State(state): State<SharedState>,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    let agent_id = AgentId::new(&agent_id);
    let provenance = ProvenanceService::new(&state.audit_log);
    match provenance.trace_provenance(&agent_id) {
        Ok(chain) => ApiResponse::ok(chain).into_response(),
        Err(e) => ApiResponse::<String>::err(e.to_string()).into_response(),
    }
}

async fn verify_chain(
    State(state): State<SharedState>,
    Json(req): Json<VerifyChainRequest>,
) -> impl IntoResponse {
    match state.audit_log.verify_chain(req.from, req.to) {
        Ok(valid) => ApiResponse::ok(serde_json::json!({
            "valid": valid,
            "from": req.from,
            "to": req.to
        }))
        .into_response(),
        Err(e) => ApiResponse::<String>::err(e.to_string()).into_response(),
    }
}

async fn list_audit_entries(State(state): State<SharedState>) -> impl IntoResponse {
    match state.audit_log.query_entries(None, Some(100)) {
        Ok(entries) => ApiResponse::ok(entries).into_response(),
        Err(e) => ApiResponse::<Vec<AuditEntry>>::err(e.to_string()).into_response(),
    }
}

async fn compliance_summary(State(state): State<SharedState>) -> impl IntoResponse {
    let provenance = ProvenanceService::new(&state.audit_log);
    match provenance.compliance_summary() {
        Ok(summary) => ApiResponse::ok(summary).into_response(),
        Err(e) => ApiResponse::<ComplianceSummary>::err(e.to_string()).into_response(),
    }
}

async fn list_discovered_agents(State(state): State<SharedState>) -> impl IntoResponse {
    let sessions = state.monitor_sessions.read().await;
    
    // Find the latest discovery event across all sessions
    let mut latest_discovery: Option<serde_json::Value> = None;
    let mut latest_ts = 0;

    for events in sessions.values().map(|(_, evts)| evts) {
        for evt in events {
            if evt.get("event_type").and_then(|v| v.as_str()) == Some("agent_discovery") {
                let ts_str = evt.get("timestamp").and_then(|t| t.as_str()).unwrap_or("");
                let ts = chrono::DateTime::parse_from_rfc3339(ts_str)
                    .map(|d| d.timestamp())
                    .unwrap_or(0);
                
                // Allow equal so we pick up the latest event if all parsing fails
                if ts >= latest_ts {
                    latest_ts = ts;
                    if let Some(details) = evt.get("details") {
                        latest_discovery = Some(details.clone());
                    }
                }
            }
        }
    }

    if let Some(discovery) = latest_discovery {
        ApiResponse::ok(discovery).into_response()
    } else {
        // Return empty structure if none found
        ApiResponse::ok(serde_json::json!({
            "agents": [],
            "mcp_servers": [],
            "extensions": []
        })).into_response()
    }
}

/// Build a dependency graph from discovered agents, MCP servers, and extensions.
async fn dependency_graph(State(state): State<SharedState>) -> impl IntoResponse {
    let sessions = state.monitor_sessions.read().await;

    // Find the latest discovery event
    let mut agents: Vec<serde_json::Value> = vec![];
    let mut mcp_servers: Vec<serde_json::Value> = vec![];
    let mut extensions: Vec<serde_json::Value> = vec![];
    let mut latest_ts: i64 = 0;

    for events in sessions.values().map(|(_, evts)| evts) {
        for evt in events {
            if evt.get("event_type").and_then(|v| v.as_str()) == Some("agent_discovery") {
                let ts = evt.get("timestamp")
                    .and_then(|t| t.as_str())
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|d| d.timestamp())
                    .unwrap_or(0);
                if ts >= latest_ts {
                    latest_ts = ts;
                    if let Some(details) = evt.get("details") {
                        agents = details.get("agents").and_then(|a| a.as_array()).cloned().unwrap_or_default();
                        mcp_servers = details.get("mcp_servers").and_then(|a| a.as_array()).cloned().unwrap_or_default();
                        extensions = details.get("extensions").and_then(|a| a.as_array()).cloned().unwrap_or_default();
                    }
                }
            }
        }
    }

    // ── Build Nodes ──────────────────────────────
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    for (i, agent) in agents.iter().enumerate() {
        let name = agent.get("name").and_then(|n| n.as_str()).unwrap_or("Unknown");
        let agent_type = agent.get("agent_type").and_then(|t| t.as_str()).unwrap_or("agent");
        let status = agent.get("status").and_then(|s| s.as_str()).unwrap_or("unknown");
        let version = agent.get("version").and_then(|v| v.as_str()).unwrap_or("");
        let pid = agent.get("pid").and_then(|p| p.as_u64()).unwrap_or(0);

        nodes.push(serde_json::json!({
            "id": format!("agent-{}", i),
            "label": name,
            "type": "agent",
            "subtype": agent_type,
            "status": status,
            "version": version,
            "pid": pid
        }));
    }

    for (i, mcp) in mcp_servers.iter().enumerate() {
        let name = mcp.get("name").and_then(|n| n.as_str()).unwrap_or("Unknown");
        let command = mcp.get("command").and_then(|c| c.as_str()).unwrap_or("");
        let transport = mcp.get("transport").and_then(|t| t.as_str()).unwrap_or("stdio");
        let source_file = mcp.get("source_file").and_then(|s| s.as_str()).unwrap_or("");

        nodes.push(serde_json::json!({
            "id": format!("mcp-{}", i),
            "label": name,
            "type": "mcp_server",
            "command": command,
            "transport": transport,
            "source_file": source_file
        }));
    }

    for (i, ext) in extensions.iter().enumerate() {
        let name = ext.get("name").and_then(|n| n.as_str()).unwrap_or("Unknown");
        let ide = ext.get("ide").and_then(|i| i.as_str()).unwrap_or("");
        let version = ext.get("version").and_then(|v| v.as_str()).unwrap_or("");

        nodes.push(serde_json::json!({
            "id": format!("ext-{}", i),
            "label": name,
            "type": "extension",
            "ide": ide,
            "version": version
        }));
    }

    // ── Infer Edges ─────────────────────────────
    let ide_map: std::collections::HashMap<&str, Vec<&str>> = [
        ("cursor",       vec!["cursor", "Cursor"]),
        ("vscode",       vec!["code", "VS Code", "vscode"]),
        ("antigravity",  vec!["antigravity", "Antigravity"]),
    ].into_iter().collect();

    // Agent → Extension edges
    for (ai, agent) in agents.iter().enumerate() {
        let agent_name = agent.get("name").and_then(|n| n.as_str()).unwrap_or("").to_lowercase();

        for (ei, ext) in extensions.iter().enumerate() {
            let ext_ide = ext.get("ide").and_then(|i| i.as_str()).unwrap_or("");

            let connected = ide_map.iter().any(|(ide_key, patterns)| {
                *ide_key == ext_ide && patterns.iter().any(|p| agent_name.contains(&p.to_lowercase()))
            });

            let vscode_fallback = ext_ide == "vscode"
                && agent.get("agent_type").and_then(|t| t.as_str()) == Some("cli");

            if connected || vscode_fallback {
                edges.push(serde_json::json!({
                    "source": format!("agent-{}", ai),
                    "target": format!("ext-{}", ei),
                    "relationship": "has_extension",
                    "label": "Extension"
                }));
            }
        }
    }

    // Agent → MCP Server edges
    for (ai, agent) in agents.iter().enumerate() {
        let agent_name = agent.get("name").and_then(|n| n.as_str()).unwrap_or("").to_lowercase();

        for (mi, mcp) in mcp_servers.iter().enumerate() {
            let source_file = mcp.get("source_file").and_then(|s| s.as_str()).unwrap_or("").to_lowercase();

            let connected = ide_map.iter().any(|(_ide_key, patterns)| {
                patterns.iter().any(|p| {
                    let p_lower = p.to_lowercase();
                    agent_name.contains(&p_lower) && source_file.contains(&p_lower)
                })
            });

            let cli_connection = agent.get("agent_type").and_then(|t| t.as_str()) == Some("cli")
                && (source_file.contains(&agent_name) || source_file.contains("claude"));

            if connected || cli_connection {
                edges.push(serde_json::json!({
                    "source": format!("agent-{}", ai),
                    "target": format!("mcp-{}", mi),
                    "relationship": "uses_mcp",
                    "label": "MCP"
                }));
            }
        }
    }

    // Agent → Agent edges (IDE ↔ LSP)
    for (i, a1) in agents.iter().enumerate() {
        for (j, _a2) in agents.iter().enumerate() {
            if i >= j { continue; }
            let t1 = a1.get("agent_type").and_then(|t| t.as_str()).unwrap_or("");
            let t2 = _a2.get("agent_type").and_then(|t| t.as_str()).unwrap_or("");
            if (t1 == "lsp" && t2 == "ide") || (t1 == "ide" && t2 == "lsp") {
                edges.push(serde_json::json!({
                    "source": format!("agent-{}", i),
                    "target": format!("agent-{}", j),
                    "relationship": "communicates_with",
                    "label": "LSP"
                }));
            }
        }
    }

    // ── Blast Radii ─────────────────────────────
    let mut blast_radii = Vec::new();
    for node in &nodes {
        let node_id = node.get("id").and_then(|i| i.as_str()).unwrap_or("");
        let affected: Vec<String> = edges.iter()
            .filter_map(|e| {
                let src = e.get("source").and_then(|s| s.as_str()).unwrap_or("");
                let tgt = e.get("target").and_then(|t| t.as_str()).unwrap_or("");
                if src == node_id { Some(tgt.to_string()) }
                else if tgt == node_id { Some(src.to_string()) }
                else { None }
            })
            .collect();

        let impact = match affected.len() {
            0 => "none",
            1..=2 => "low",
            3..=5 => "medium",
            _ => "high",
        };

        blast_radii.push(serde_json::json!({
            "node_id": node_id,
            "affected_nodes": affected,
            "impact": impact
        }));
    }

    ApiResponse::ok(serde_json::json!({
        "nodes": nodes,
        "edges": edges,
        "blast_radii": blast_radii
    }))
}

async fn dashboard_metrics(State(state): State<SharedState>) -> impl IntoResponse {
    let agent_count = state
        .registry
        .list_agents(None)
        .map(|a| a.len())
        .unwrap_or(0);
    let audit_count = state.audit_log.entry_count().unwrap_or(0);
    let trace_count = state
        .trace_collector
        .list_traces(None)
        .map(|t| t.len())
        .unwrap_or(0);

    // Monitor session metrics
    let sessions = state.monitor_sessions.read().await;
    let session_count = sessions.len();
    let mut total_events = 0usize;
    let mut total_commands = 0usize;
    let mut total_files = 0usize;
    let mut total_processes = 0usize;
    let mut total_network = 0usize;
    let mut total_flagged = 0usize;
    let mut total_blocked = 0usize;
    let mut total_discovered_agents = 0usize;

    for (session, events) in sessions.values() {
        total_events += session.total_events;
        for evt in events {
            if let Some(et) = evt.get("event_type").and_then(|v| v.as_str()) {
                match et {
                    "shell_command" => total_commands += 1,
                    "file_change" => total_files += 1,
                    "process_spawn" => total_processes += 1,
                    "network_connection" => total_network += 1,
                    "agent_discovery" => {
                        // just use the latest block of agent_discovery to determine count,
                        // or max count seen. Let's just track the max count seen in any event.
                        if let Some(details) = evt.get("details") {
                            if let Some(agents) = details.get("agents").and_then(|a| a.as_array()) {
                                total_discovered_agents = total_discovered_agents.max(agents.len());
                            }
                        }
                    }
                    _ => {}
                }
            }
            if let Some(sev) = evt.get("severity").and_then(|v| v.as_str()) {
                match sev {
                    "warning" => total_flagged += 1,
                    "critical" => total_blocked += 1,
                    _ => {}
                }
            }
        }
    }
    drop(sessions);

    ApiResponse::ok(serde_json::json!({
        "agents_registered": agent_count,
        "audit_entries": audit_count,
        "reasoning_traces": trace_count,
        "server_uptime": "running",
        "monitor_sessions": session_count,
        "monitor_events": total_events,
        "monitor_commands": total_commands,
        "monitor_files": total_files,
        "monitor_processes": total_processes,
        "monitor_network": total_network,
        "monitor_flagged": total_flagged,
        "monitor_blocked": total_blocked,
        "discovered_agents": total_discovered_agents,
    }))
    .into_response()
}

// ── Vibe Coding: Shell & Filesystem Handlers ────────────────────────────

#[derive(Deserialize)]
struct ShellEvalRequest {
    command: String,
    agent_id: Option<String>,
}

#[derive(Deserialize)]
struct FileCheckRequest {
    path: String,
    operation: FileOp,
    agent_id: Option<String>,
}

#[derive(Deserialize)]
struct NetworkEvaluateRequest {
    agent_id: Option<String>,
    domain: String,
    port: u16,
}

async fn evaluate_shell_command(
    State(state): State<SharedState>,
    Json(req): Json<ShellEvalRequest>,
) -> impl IntoResponse {
    let result = state.shell_guard.evaluate(&req.command);

    // Audit log the result
    let agent_id = AgentId::new(req.agent_id.as_deref().unwrap_or("anonymous-agent"));
    match &result.verdict {
        ShellVerdict::Deny { reason, .. } => {
            let _ = state.audit_log.append(
                &agent_id,
                AuditAction::ShellCommandBlocked {
                    command: req.command.clone(),
                    reason: reason.clone(),
                },
                None,
            );
        }
        ShellVerdict::RequiresApproval { reason, .. } => {
            let _ = state.audit_log.append(
                &agent_id,
                AuditAction::ShellCommandPendingApproval {
                    command: req.command.clone(),
                    reason: reason.clone(),
                },
                None,
            );
        }
        ShellVerdict::Allow => {
            let _ = state.audit_log.append(
                &agent_id,
                AuditAction::ShellCommandAllowed {
                    command: req.command.clone(),
                },
                None,
            );
        }
    }

    ApiResponse::ok(result).into_response()
}

async fn check_file_access(
    State(state): State<SharedState>,
    Json(req): Json<FileCheckRequest>,
) -> impl IntoResponse {
    let result = state.fs_sentinel.check_access(&req.path, req.operation);

    // Audit log sensitive access
    if !result.allowed {
        let agent_id = AgentId::new(req.agent_id.as_deref().unwrap_or("anonymous-agent"));
        let _ = state.audit_log.append(
            &agent_id,
            AuditAction::SensitiveFileAccess {
                path: req.path.clone(),
                operation: req.operation.to_string(),
                sensitivity: result.sensitivity.to_string(),
            },
            None,
        );
    }

    ApiResponse::ok(result).into_response()
}

async fn get_shell_policy() -> impl IntoResponse {
    ApiResponse::ok(serde_json::json!({
        "blocked_commands": [
            {"pattern": "rm -rf /", "risk": "destructive_operation"},
            {"pattern": "mkfs", "risk": "destructive_operation"},
            {"pattern": "dd if=", "risk": "destructive_operation"},
            {"pattern": "shutdown", "risk": "destructive_operation"},
            {"pattern": "curl|bash", "risk": "remote_code_exec"},
            {"pattern": "wget|sh", "risk": "remote_code_exec"},
            {"pattern": "base64 -d|bash", "risk": "obfuscation"},
            {"pattern": "chmod 777", "risk": "privilege_escalation"},
            {"pattern": "cat ~/.ssh/*", "risk": "credential_access"},
            {"pattern": "cat .env", "risk": "credential_access"},
            {"pattern": "nc -e /bin/sh", "risk": "data_exfiltration"},
        ],
        "approval_required": [
            {"pattern": "sudo *", "risk": "privilege_escalation"},
            {"pattern": "npm install *", "risk": "supply_chain"},
            {"pattern": "pip install *", "risk": "supply_chain"},
            {"pattern": "cargo install *", "risk": "supply_chain"},
            {"pattern": "brew install *", "risk": "supply_chain"},
            {"pattern": "scp * @*", "risk": "data_exfiltration"},
            {"pattern": "env / printenv", "risk": "credential_access"},
        ],
        "always_allowed": [
            "ls", "cat (project files)", "grep", "find",
            "git status/diff/log", "cargo build/test/run",
            "npm run/test", "echo", "pwd", "which"
        ]
    }))
    .into_response()
}

async fn evaluate_network(
    State(state): State<SharedState>,
    Json(req): Json<NetworkEvaluateRequest>,
) -> impl IntoResponse {
    let agent_id = AgentId::new(req.agent_id.as_deref().unwrap_or("anonymous-agent"));
    
    // Simple blocklist logic for demonstration
    let blocklist = vec![
        "ngrok.io", "pastebin.com", "evil-exfil.com", "miner.pool",
    ];

    let mut is_blocked = false;
    let mut reason = String::new();

    if blocklist.iter().any(|&b| req.domain.ends_with(b)) {
        is_blocked = true;
        reason = format!("Domain '{}' is on the exfiltration blocklist", req.domain);
    }

    if is_blocked {
        let _ = state.audit_log.append(
            &agent_id,
            AuditAction::NetworkRequestBlocked {
                domain: req.domain.clone(),
                port: req.port,
                reason: reason.clone(),
            },
            None,
        );
        
        ApiResponse::ok(serde_json::json!({
            "verdict": "deny",
            "reason": reason
        }))
        .into_response()
    } else {
        let _ = state.audit_log.append(
            &agent_id,
            AuditAction::NetworkRequestAllowed {
                domain: req.domain.clone(),
                port: req.port,
            },
            None,
        );
        
        ApiResponse::ok(serde_json::json!({
            "verdict": "allow"
        }))
        .into_response()
    }
}

// ── Monitor Events ─────────────────────────────────────────────

async fn receive_monitor_events(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let session_id = payload.get("session_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let events: Vec<serde_json::Value> = payload.get("events")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let event_count = events.len();
    let now = chrono::Utc::now().to_rfc3339();

    // Store events in memory
    {
        let mut sessions = state.monitor_sessions.write().await;
        
        // CVE-2 Fix: Enforce bounds on the memory cache to prevent DoS
        if sessions.len() >= 100 && !sessions.contains_key(&session_id) {
            if let Some(oldest) = sessions.iter()
                .min_by_key(|(_, (s, _))| &s.last_updated)
                .map(|(k, _)| k.clone())
            {
                tracing::warn!("Evicting oldest monitor session: {}", oldest);
                sessions.remove(&oldest);
            }
        }

        let entry = sessions.entry(session_id.clone()).or_insert_with(|| {
            (MonitorSession {
                session_id: session_id.clone(),
                started_at: now.clone(),
                last_updated: now.clone(),
                total_events: 0,
                summary: serde_json::json!({}),
            }, Vec::new())
        });
        entry.0.last_updated = now;
        entry.0.total_events += event_count;
        entry.1.extend(events);

        // Keep max 2000 events per session
        if entry.1.len() > 2000 {
            let drain_count = entry.1.len() - 2000;
            entry.1.drain(..drain_count);
        }
    }

    tracing::info!("Monitor events stored: session={}, count={}", session_id, event_count);

    Json(serde_json::json!({
        "success": true,
        "data": {
            "session_id": session_id,
            "events_received": event_count
        }
    }))
    .into_response()
}

async fn list_monitor_sessions(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let sessions = state.monitor_sessions.read().await;
    let list: Vec<&MonitorSession> = sessions.values().map(|(s, _)| s).collect();

    Json(serde_json::json!({
        "success": true,
        "data": list
    }))
    .into_response()
}

async fn get_monitor_session(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(session_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let sessions = state.monitor_sessions.read().await;
    if let Some((session, events)) = sessions.get(&session_id) {
        Json(serde_json::json!({
            "success": true,
            "data": {
                "session": session,
                "events": events
            }
        }))
        .into_response()
    } else {
        Json(serde_json::json!({
            "success": false,
            "error": "Session not found"
        }))
        .into_response()
    }
}

// ── System Info ──────────────────────────────────────────────────
async fn system_info() -> impl IntoResponse {
    let platform = if cfg!(target_os = "macos") {
        "macOS"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else if cfg!(target_os = "windows") {
        "Windows"
    } else {
        "Unknown"
    };

    let arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "unknown"
    };

    ApiResponse::ok(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "build": "dev",
        "platform": platform,
        "arch": arch,
        "rust_version": "stable",
        "uptime": "running",
        "host": "127.0.0.1",
        "port": 8080
    }))
    .into_response()
}

// ── Configuration ────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConfigPayload {
    #[serde(default = "default_host")]
    host: String,
    #[serde(default = "default_port")]
    port: u16,
    #[serde(default = "default_data_dir")]
    data_dir: String,
    #[serde(default = "default_scan_interval")]
    scan_interval: u64,
    #[serde(default)]
    process_patterns: String,
    #[serde(default)]
    watch_paths: String,
    #[serde(default = "default_shell_action")]
    shell_default: String,
    #[serde(default = "default_fs_action")]
    fs_default: String,
    #[serde(default)]
    auto_register: bool,
    #[serde(default = "default_retention")]
    retention_days: u32,
}

fn default_host() -> String { "127.0.0.1".to_string() }
fn default_port() -> u16 { 8080 }
fn default_data_dir() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
    format!("{}/.ai-spm/data", home)
}
fn default_scan_interval() -> u64 { 30 }
fn default_shell_action() -> String { "flag".to_string() }
fn default_fs_action() -> String { "flag".to_string() }
fn default_retention() -> u32 { 90 }

fn config_file_path() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
    format!("{}/.ai-spm/config.json", home)
}

async fn get_config() -> impl IntoResponse {
    let path = config_file_path();
    if let Ok(content) = tokio::fs::read_to_string(&path).await {
        if let Ok(cfg) = serde_json::from_str::<ConfigPayload>(&content) {
            return ApiResponse::ok(cfg).into_response();
        }
    }
    // Return defaults
    ApiResponse::ok(ConfigPayload {
        host: default_host(),
        port: default_port(),
        data_dir: default_data_dir(),
        scan_interval: default_scan_interval(),
        process_patterns: "claude,copilot,cursor,windsurf,aider,cline".to_string(),
        watch_paths: String::new(),
        shell_default: default_shell_action(),
        fs_default: default_fs_action(),
        auto_register: false,
        retention_days: default_retention(),
    }).into_response()
}

async fn save_config(Json(payload): Json<ConfigPayload>) -> impl IntoResponse {
    let path = config_file_path();
    // Ensure directory exists
    if let Some(parent) = std::path::Path::new(&path).parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    match serde_json::to_string_pretty(&payload) {
        Ok(json) => {
            match tokio::fs::write(&path, &json).await {
                Ok(_) => {
                    info!("Configuration saved to {}", path);
                    ApiResponse::ok(serde_json::json!({ "saved": true, "path": path })).into_response()
                }
                Err(e) => ApiResponse::<serde_json::Value>::err(format!("Failed to write config: {}", e)).into_response(),
            }
        }
        Err(e) => ApiResponse::<serde_json::Value>::err(format!("Invalid config: {}", e)).into_response(),
    }
}

// ── Policy Management ──────────────────────────────────────────

fn policies_dir() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    format!("{}/.ai-spm/policies", home)
}

#[derive(Serialize)]
struct PolicyDoc {
    name: String,
    content: String,
}

#[derive(Deserialize)]
struct SavePolicyRequest {
    name: String,
    content: String,
}

async fn list_policies() -> impl IntoResponse {
    let dir = policies_dir();
    let mut policies = Vec::new();
    
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e: &std::ffi::OsStr| e.to_str()) == Some("rego") {
                if let Some(name) = path.file_stem().and_then(|n: &std::ffi::OsStr| n.to_str()) {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        policies.push(PolicyDoc {
                            name: name.to_string(),
                            content,
                        });
                    }
                }
            }
        }
    }
    
    ApiResponse::ok(serde_json::json!({ "policies": policies })).into_response()
}

async fn save_policy(Json(payload): Json<SavePolicyRequest>) -> impl IntoResponse {
    let dir = policies_dir();
    if !std::path::Path::new(&dir).exists() {
        if let Err(e) = std::fs::create_dir_all(&dir) {
            return ApiResponse::<serde_json::Value>::err(format!("Failed to create policies directory: {}", e)).into_response();
        }
    }
    
    // Sanitize name to prevent path traversal
    let safe_name: String = payload.name.chars().filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_').collect();
    if safe_name.is_empty() {
        return ApiResponse::<serde_json::Value>::err("Invalid policy name".to_string()).into_response();
    }
    
    let path = format!("{}/{}.rego", dir, safe_name);
    if let Err(e) = std::fs::write(&path, &payload.content) {
        return ApiResponse::<serde_json::Value>::err(format!("Failed to save policy: {}", e)).into_response();
    }
    
    ApiResponse::ok(serde_json::json!({ "message": "Policy saved", "name": safe_name })).into_response()
}

async fn delete_policy(axum::extract::Path(name): axum::extract::Path<String>) -> impl IntoResponse {
    let dir = policies_dir();
    let safe_name: String = name.chars().filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_').collect();
    if safe_name.is_empty() {
        return ApiResponse::<serde_json::Value>::err("Invalid policy name".to_string()).into_response();
    }
    
    let path = format!("{}/{}.rego", dir, safe_name);
    if std::path::Path::new(&path).exists() {
        if let Err(e) = std::fs::remove_file(&path) {
            return ApiResponse::<serde_json::Value>::err(format!("Failed to delete policy: {}", e)).into_response();
        }
    }
    
    ApiResponse::ok(serde_json::json!({ "message": "Policy deleted" })).into_response()
}

// ── Standards Coverage ──────────────────────────────────────────
async fn get_standards_coverage() -> impl IntoResponse {
    let matrix = serde_json::json!({
        "standards": [
            {
                "name": "OWASP Top 10 for LLM Applications (2025)",
                "short": "OWASP LLM",
                "total_controls": 10,
                "covered": 8,
                "partial": 1,
                "items": [
                    { "id": "LLM01", "name": "Prompt Injection", "status": "covered", "feature": "Shell Guard, Gateway Policy" },
                    { "id": "LLM02", "name": "Insecure Output Handling", "status": "covered", "feature": "Gateway Envelope Evaluation" },
                    { "id": "LLM03", "name": "Training Data Poisoning", "status": "partial", "feature": "Audit Provenance (monitoring only)" },
                    { "id": "LLM04", "name": "Model Denial of Service", "status": "covered", "feature": "Agent Monitor, Rate Detection" },
                    { "id": "LLM05", "name": "Supply Chain Vulnerabilities", "status": "covered", "feature": "MCP Tester, Extension Discovery" },
                    { "id": "LLM06", "name": "Sensitive Information Disclosure", "status": "covered", "feature": "File Sentinel, Shell Guard" },
                    { "id": "LLM07", "name": "Insecure Plugin Design", "status": "covered", "feature": "MCP Tool Validation" },
                    { "id": "LLM08", "name": "Excessive Agency", "status": "covered", "feature": "Gateway Policy Engine" },
                    { "id": "LLM09", "name": "Overreliance", "status": "not_covered", "feature": "—" },
                    { "id": "LLM10", "name": "Model Theft", "status": "covered", "feature": "Audit Trail, SPIFFE Identity" }
                ]
            },
            {
                "name": "NIST AI Risk Management Framework (AI RMF 1.0)",
                "short": "NIST AI RMF",
                "total_controls": 4,
                "covered": 4,
                "partial": 0,
                "items": [
                    { "id": "GOVERN", "name": "Governance", "status": "covered", "feature": "SPIFFE Identity, Audit Log, Compliance Dashboard" },
                    { "id": "MAP", "name": "Map", "status": "covered", "feature": "Auto Discovery, Agent Registry" },
                    { "id": "MEASURE", "name": "Measure", "status": "covered", "feature": "Agent Monitor, Compliance Scoring" },
                    { "id": "MANAGE", "name": "Manage", "status": "covered", "feature": "Gateway Policy, Shell Guard, File Sentinel" }
                ]
            },
            {
                "name": "MITRE ATLAS",
                "short": "MITRE ATLAS",
                "total_controls": 5,
                "covered": 4,
                "partial": 1,
                "items": [
                    { "id": "AML.T0015", "name": "Evade ML Model", "status": "covered", "feature": "Red Team Probing" },
                    { "id": "AML.T0043", "name": "Craft Adversarial Data", "status": "partial", "feature": "Shell Guard (detection)" },
                    { "id": "AML.T0040", "name": "ML Supply Chain Compromise", "status": "covered", "feature": "MCP Validation, Discovery" },
                    { "id": "AML.T0024", "name": "Exfiltration via ML API", "status": "covered", "feature": "Gateway Envelope, Audit" },
                    { "id": "AML.T0042", "name": "Verify ML Artifacts", "status": "covered", "feature": "Tamper-proof Audit Log" }
                ]
            },
            {
                "name": "ISO/IEC 42001 — AI Management System",
                "short": "ISO 42001",
                "total_controls": 4,
                "covered": 3,
                "partial": 1,
                "items": [
                    { "id": "A.5", "name": "AI Policies", "status": "covered", "feature": "Gateway Policy Engine, Configuration" },
                    { "id": "A.6", "name": "Planning (Risk Assessment)", "status": "covered", "feature": "Compliance Dashboard, Red Team" },
                    { "id": "A.8", "name": "Operations", "status": "covered", "feature": "Agent Monitor, Discovery, Audit" },
                    { "id": "A.9", "name": "Performance Evaluation", "status": "partial", "feature": "Compliance Scoring (partial metrics)" }
                ]
            },
            {
                "name": "EU AI Act (Regulation 2024/1689)",
                "short": "EU AI Act",
                "total_controls": 5,
                "covered": 4,
                "partial": 1,
                "items": [
                    { "id": "Art.9", "name": "Risk Management System", "status": "covered", "feature": "Full AI-SPM Platform" },
                    { "id": "Art.10", "name": "Data Governance", "status": "partial", "feature": "File Sentinel, Audit Log" },
                    { "id": "Art.11", "name": "Technical Documentation", "status": "covered", "feature": "Audit Trail, Provenance" },
                    { "id": "Art.12", "name": "Record Keeping", "status": "covered", "feature": "Tamper-proof Audit Log" },
                    { "id": "Art.13", "name": "Transparency", "status": "covered", "feature": "Agent Registry, Compliance Reports" }
                ]
            }
        ],
        "generated_at": chrono::Utc::now().to_rfc3339()
    });

    ApiResponse::ok(matrix).into_response()
}

// ── Batch Registration ──────────────────────────────────────────
#[derive(Debug, Deserialize)]
struct BatchRegisterRequest {
    agents: Vec<RegisterAgentRequest>,
}

async fn batch_register_agents(
    State(state): State<SharedState>,
    Json(req): Json<BatchRegisterRequest>,
) -> impl IntoResponse {
    let mut registered = 0u32;
    let mut errors: Vec<String> = Vec::new();

    for agent_req in &req.agents {
        let agent_id = AgentId::new(&agent_req.agent_id);
        match state.registry.register_agent(
            &agent_id,
            &agent_req.owner,
            agent_req.description.as_deref().unwrap_or(""),
            agent_req.metadata.clone().unwrap_or_default(),
        ) {
            Ok(_) => {
                let _ = state.audit_log.append(
                    &agent_id,
                    AuditAction::AgentRegistered { owner: agent_req.owner.clone() },
                    None,
                );
                registered += 1;
            }
            Err(e) => errors.push(format!("{}: {}", agent_req.agent_id, e)),
        }
    }

    ApiResponse::ok(serde_json::json!({
        "total": req.agents.len(),
        "registered": registered,
        "errors": errors
    })).into_response()
}

// ── Token Listing ───────────────────────────────────────────────
async fn list_tokens(State(state): State<SharedState>) -> impl IntoResponse {
    // List all agents and show their token status
    match state.registry.list_agents(None) {
        Ok(agents) => {
            let tokens: Vec<serde_json::Value> = agents.iter()
                .filter(|a| a.status == AgentStatus::Active)
                .map(|a| {
                    serde_json::json!({
                        "token_id": format!("tok-{}", &a.agent_id.to_string()[..8.min(a.agent_id.to_string().len())]),
                        "agent_id": a.agent_id.to_string(),
                        "issued_at": a.created_at,
                        "expires_at": "3600s from issue",
                        "status": "active"
                    })
                })
                .collect();
            ApiResponse::ok(tokens).into_response()
        }
        Err(e) => ApiResponse::<Vec<serde_json::Value>>::err(e.to_string()).into_response(),
    }
}
