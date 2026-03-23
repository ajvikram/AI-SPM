mod api;

use ai_spm_core::config::AppConfig;
use ai_spm_core::types::FileOp;
use ai_spm_gateway::shell_guard::ShellGuard;
use ai_spm_gateway::fs_sentinel::FsSentinel;
use clap::{Parser, Subcommand};
use tracing::info;

#[derive(Parser)]
#[command(
    name = "ai-spm",
    about = "AI Security Posture Management — Secure, audit, and test autonomous AI agents",
    version
)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "config/default.toml")]
    config: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the HTTP server
    Serve {
        /// Override host
        #[arg(long)]
        host: Option<String>,
        /// Override port
        #[arg(long)]
        port: Option<u16>,
    },
    /// Manage agent identities
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },
    /// Query and verify audit logs
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },
    /// Run adversarial security tests
    Redteam {
        #[command(subcommand)]
        action: RedteamAction,
    },
    /// Generate default configuration and golden dataset
    Init,
    /// Audit recent shell history through guardrails
    AuditSession {
        /// Number of recent commands to audit
        #[arg(long, default_value = "50")]
        last: usize,
        /// Path to shell history file
        #[arg(long)]
        history_file: Option<String>,
        /// Also check files referenced in commands
        #[arg(long, default_value = "true")]
        check_files: bool,
    },
}

#[derive(Subcommand)]
enum AgentAction {
    /// Register a new agent
    Register {
        /// Agent SPIFFE ID (e.g., spiffe://domain/finance-agent)
        #[arg(long)]
        id: String,
        /// Owner of the agent
        #[arg(long)]
        owner: String,
        /// Description
        #[arg(long, default_value = "")]
        description: String,
    },
    /// List all agents
    List {
        /// Filter by status (active, suspended, revoked)
        #[arg(long)]
        status: Option<String>,
    },
    /// Revoke an agent
    Revoke {
        /// Agent SPIFFE ID
        #[arg(long)]
        id: String,
    },
    /// Issue a JIT token for an agent
    Token {
        /// Agent SPIFFE ID
        #[arg(long)]
        id: String,
        /// TTL in seconds
        #[arg(long, default_value = "300")]
        ttl: u64,
    },
}

#[derive(Subcommand)]
enum AuditAction {
    /// Query audit log entries
    Query {
        /// Filter by agent ID
        #[arg(long)]
        agent_id: Option<String>,
        /// Maximum entries to return
        #[arg(long, default_value = "100")]
        limit: u32,
    },
    /// Verify audit chain integrity
    Verify {
        /// Start sequence number
        #[arg(long, default_value = "1")]
        from: u64,
        /// End sequence number
        #[arg(long)]
        to: Option<u64>,
    },
    /// Generate compliance report
    Report {
        /// Output format: json or markdown
        #[arg(long, default_value = "markdown")]
        format: String,
        /// Output file path
        #[arg(long)]
        output: Option<String>,
    },
}

#[derive(Subcommand)]
enum RedteamAction {
    /// Run an adversarial probe
    Probe {
        /// Target agent SPIFFE ID
        #[arg(long)]
        target: String,
        /// Target endpoint URL
        #[arg(long)]
        target_url: String,
        /// Target API key
        #[arg(long)]
        target_key: String,
        /// Target model
        #[arg(long, default_value = "gpt-4o-mini")]
        target_model: String,
        /// Probing strategy: crescendo, goat, persona, refusal, topic
        #[arg(long, default_value = "crescendo")]
        strategy: String,
    },
    /// Run golden dataset benchmark
    Benchmark {
        /// Path to golden dataset file
        #[arg(long)]
        dataset: Option<String>,
        /// Output report path
        #[arg(long)]
        output: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Load configuration
    let config = AppConfig::load(&cli.config).unwrap_or_else(|e| {
        eprintln!("⚠️  Failed to load config '{}': {}. Using defaults.", cli.config, e);
        AppConfig::development()
    });

    ai_spm_core::init_tracing(&config.server.log_level);

    match cli.command {
        Commands::Serve { host, port } => {
            let host = host.unwrap_or(config.server.host.clone());
            let port = port.unwrap_or(config.server.port);
            info!("Starting AI-SPM server on {}:{}", host, port);
            api::run_server(&config, &host, port).await?;
        }
        Commands::Agent { action } => match action {
            AgentAction::Register {
                id,
                owner,
                description,
            } => {
                let store =
                    ai_spm_identity::store::IdentityStore::open(&config.identity.database_path)?;
                let registry = ai_spm_identity::registry::NhiRegistry::new(store);
                let agent_id = ai_spm_core::types::AgentId::new(&id);
                let record = registry.register_agent(
                    &agent_id,
                    &owner,
                    &description,
                    std::collections::HashMap::new(),
                )?;
                println!("✅ Agent registered:");
                println!("   ID:      {}", record.agent_id);
                println!("   Owner:   {}", record.owner);
                println!("   Status:  {:?}", record.status);
                println!("   Created: {}", record.created_at);
            }
            AgentAction::List { status } => {
                let store =
                    ai_spm_identity::store::IdentityStore::open(&config.identity.database_path)?;
                let registry = ai_spm_identity::registry::NhiRegistry::new(store);
                let filter = status.map(|s| match s.as_str() {
                    "active" => ai_spm_core::types::AgentStatus::Active,
                    "suspended" => ai_spm_core::types::AgentStatus::Suspended,
                    "revoked" => ai_spm_core::types::AgentStatus::Revoked,
                    _ => ai_spm_core::types::AgentStatus::Active,
                });
                let agents = registry.list_agents(filter)?;
                println!("📋 Agents ({} total):", agents.len());
                for agent in agents {
                    println!(
                        "   {} | {:?} | Owner: {} | {}",
                        agent.agent_id, agent.status, agent.owner, agent.description
                    );
                }
            }
            AgentAction::Revoke { id } => {
                let store =
                    ai_spm_identity::store::IdentityStore::open(&config.identity.database_path)?;
                let registry = ai_spm_identity::registry::NhiRegistry::new(store);
                let agent_id = ai_spm_core::types::AgentId::new(&id);
                registry.revoke_agent(&agent_id)?;
                println!("🚫 Agent {} revoked.", id);
            }
            AgentAction::Token { id, ttl } => {
                let manager = ai_spm_identity::jit_tokens::JitTokenManager::new(
                    &config.identity.token_signing_key,
                    config.identity.default_token_ttl_seconds,
                )?;
                let agent_id = ai_spm_core::types::AgentId::new(&id);
                let token = manager.issue_token(&agent_id, vec![], Some(ttl), None)?;
                println!("🔑 JIT Token issued:");
                println!("   Token ID:  {}", token.token_id);
                println!("   Agent:     {}", token.agent_id);
                println!("   Expires:   {}", token.expires_at);
                println!("   Signature: {}...{}", &token.signature[..8], &token.signature[token.signature.len()-8..]);
            }
        },
        Commands::Audit { action } => match action {
            AuditAction::Query { agent_id, limit } => {
                let log = ai_spm_audit::tamper_log::AuditLog::open(
                    &config.audit.log_file_path,
                    &config.audit.index_database_path,
                    &config.audit.genesis_hash,
                )?;
                let filter = agent_id.map(|id| ai_spm_core::types::AgentId::new(id));
                let entries = log.query_entries(filter.as_ref(), Some(limit))?;
                println!("📜 Audit entries ({}):", entries.len());
                for entry in entries {
                    println!(
                        "   #{} | {} | {} | {}",
                        entry.sequence,
                        entry.agent_id,
                        entry.entry_hash[..12].to_string(),
                        entry.timestamp.format("%Y-%m-%d %H:%M:%S")
                    );
                }
            }
            AuditAction::Verify { from, to } => {
                let log = ai_spm_audit::tamper_log::AuditLog::open(
                    &config.audit.log_file_path,
                    &config.audit.index_database_path,
                    &config.audit.genesis_hash,
                )?;
                let to_seq = to.unwrap_or(log.entry_count()?);
                match log.verify_chain(from, to_seq) {
                    Ok(true) => println!("✅ Audit chain integrity verified (seq {} to {}).", from, to_seq),
                    Ok(false) => println!("⚠️  Audit chain verification returned false."),
                    Err(e) => println!("❌ Chain integrity violation: {}", e),
                }
            }
            AuditAction::Report { format: _, output } => {
                let log = ai_spm_audit::tamper_log::AuditLog::open(
                    &config.audit.log_file_path,
                    &config.audit.index_database_path,
                    &config.audit.genesis_hash,
                )?;
                let provenance = ai_spm_audit::provenance::ProvenanceService::new(&log);
                let summary = provenance.compliance_summary()?;
                let report = serde_json::to_string_pretty(&summary)?;

                if let Some(path) = output {
                    std::fs::write(&path, &report)?;
                    println!("📊 Compliance report saved to {}", path);
                } else {
                    println!("{}", report);
                }
            }
        },
        Commands::Redteam { action } => match action {
            RedteamAction::Probe {
                target,
                target_url,
                target_key,
                target_model,
                strategy,
            } => {
                let strategy = match strategy.as_str() {
                    "crescendo" => ai_spm_core::types::ProbingStrategy::Crescendo,
                    "goat" => ai_spm_core::types::ProbingStrategy::Goat,
                    "persona" => ai_spm_core::types::ProbingStrategy::PersonaModification,
                    "refusal" => ai_spm_core::types::ProbingStrategy::RefusalSuppression,
                    "topic" => ai_spm_core::types::ProbingStrategy::TopicSplitting,
                    _ => {
                        eprintln!("Unknown strategy: {}. Using crescendo.", strategy);
                        ai_spm_core::types::ProbingStrategy::Crescendo
                    }
                };

                let probe_config = ai_spm_redteam::probing::ProbeConfig {
                    base_url: config.openai.base_url.clone(),
                    api_key: config.openai.api_key.clone(),
                    attacker_model: config.openai.model.clone(),
                    max_turns: config.redteam.max_probe_turns,
                    turn_timeout_seconds: config.redteam.probe_timeout_seconds,
                    temperature: 0.7,
                };

                let prober = ai_spm_redteam::probing::Prober::new(probe_config);
                let agent_id = ai_spm_core::types::AgentId::new(&target);

                println!("🔴 Running {} probe against {} ...", strategy, target);
                let result = prober
                    .run_probe(
                        &agent_id,
                        &target_url,
                        &target_key,
                        &target_model,
                        "You are a helpful assistant.",
                        strategy,
                    )
                    .await?;

                if result.success {
                    println!("⚠️  Target COMPROMISED in {} turns!", result.turns_taken);
                } else {
                    println!("✅ Target remained RESILIENT ({} turns).", result.turns_taken);
                }
            }
            RedteamAction::Benchmark { dataset, output } => {
                let ds = match dataset {
                    Some(path) => ai_spm_redteam::benchmark::GoldenDataset::load(&path)?,
                    None => {
                        let ds = ai_spm_redteam::benchmark::GoldenDataset::default_dataset();
                        println!("ℹ️  Using default golden dataset ({} test cases)", ds.test_cases.len());
                        ds
                    }
                };

                println!("📋 Golden Dataset: {} v{}", ds.name, ds.version);
                println!("   {} test cases defined", ds.test_cases.len());

                if let Some(path) = output {
                    ds.save(&path)?;
                    println!("💾 Dataset saved to {}", path);
                }
            }
        },
        Commands::Init => {
            // Create default config
            let config = AppConfig::development();
            let toml = toml_string(&config);
            std::fs::create_dir_all("config")?;
            std::fs::write("config/default.toml", &toml)?;
            println!("✅ Created config/default.toml");

            // Create default golden dataset
            let dataset = ai_spm_redteam::benchmark::GoldenDataset::default_dataset();
            std::fs::create_dir_all("data/golden_datasets")?;
            dataset.save("data/golden_datasets/default.json")?;
            println!("✅ Created data/golden_datasets/default.json");

            // Create data directories
            std::fs::create_dir_all("data")?;
            std::fs::create_dir_all("policies")?;
            println!("✅ Created data/ and policies/ directories");
            println!("\n🚀 AI-SPM initialized! Run `ai-spm serve` to start the server.");
        }
        Commands::AuditSession { last, history_file, check_files } => {
            run_audit_session(last, history_file, check_files)?;
        }
    }

    Ok(())
}

/// Audit recent shell history through ShellGuard and FsSentinel.
fn run_audit_session(last: usize, history_file: Option<String>, check_files: bool) -> anyhow::Result<()> {
    // Determine history file path
    let hist_path = history_file.unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
        // Try zsh first, then bash
        let zsh = format!("{}/.zsh_history", home);
        let bash = format!("{}/.bash_history", home);
        if std::path::Path::new(&zsh).exists() { zsh } else { bash }
    });

    println!("\n🔍 AI-SPM Session Audit");
    println!("{}", "=".repeat(60));
    println!("   History: {}", hist_path);
    println!("   Checking last {} commands\n", last);

    // Read history file
    let content = match std::fs::read_to_string(&hist_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("❌ Cannot read history file '{}': {}", hist_path, e);
            eprintln!("   Try: ai-spm audit-session --history-file /path/to/history");
            return Ok(());
        }
    };

    // Parse commands (handle zsh extended history format: ": timestamp:0;command")
    let commands: Vec<String> = content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() { return None; }
            // zsh extended history format
            if line.starts_with(": ") {
                line.splitn(2, ';').nth(1).map(|s| s.to_string())
            } else {
                Some(line.to_string())
            }
        })
        .collect();

    let recent: Vec<&String> = commands.iter().rev().take(last).collect::<Vec<_>>().into_iter().rev().collect();

    let guard = ShellGuard::new();
    let sentinel = FsSentinel::new();

    let mut allowed = 0usize;
    let mut denied = 0usize;
    let mut flagged = 0usize;
    let mut files_blocked = 0usize;

    println!("┌─────────┬──────────────────────────────────────────────────────────┐");
    println!("│ VERDICT │ COMMAND                                                 │");
    println!("├─────────┼──────────────────────────────────────────────────────────┤");

    for cmd in &recent {
        let result = guard.evaluate(cmd);
        let cmd_display = if cmd.len() > 56 { format!("{}…", &cmd[..55]) } else { cmd.to_string() };

        match &result.verdict {
            ai_spm_core::types::ShellVerdict::Allow => {
                println!("│ ✅ ALLOW │ {:<56} │", cmd_display);
                allowed += 1;
            }
            ai_spm_core::types::ShellVerdict::Deny { reason, risk, .. } => {
                println!("│ 🚫 DENY  │ {:<56} │", cmd_display);
                println!("│         │  ⮑  {:?}: {:<44}│", risk, truncate_str(reason, 44));
                denied += 1;
            }
            ai_spm_core::types::ShellVerdict::RequiresApproval { reason, risk, .. } => {
                println!("│ ⚠️  FLAG  │ {:<56} │", cmd_display);
                println!("│         │  ⮑  {:?}: {:<44}│", risk, truncate_str(reason, 44));
                flagged += 1;
            }
        }

        // Check files referenced in commands
        if check_files {
            let words: Vec<&str> = cmd.split_whitespace().collect();
            for word in &words[1..] {
                // Skip flags
                if word.starts_with('-') { continue; }
                // Check if it looks like a file path
                if word.contains('/') || word.contains('.') || word.starts_with('~') {
                    let op = if words[0] == "cat" || words[0] == "less" || words[0] == "head" {
                        FileOp::Read
                    } else if words[0] == "rm" || words[0] == "rmdir" {
                        FileOp::Delete
                    } else {
                        FileOp::Write
                    };
                    let fs_result = sentinel.check_access(word, op);
                    if !fs_result.allowed {
                        println!("│    📁   │  ⮑  File blocked: {} ({:?}){}", 
                            truncate_str(word, 30), fs_result.sensitivity, 
                            " ".repeat(std::cmp::max(0, 16_i32 - word.len() as i32) as usize));
                        files_blocked += 1;
                    }
                }
            }
        }
    }

    println!("└─────────┴──────────────────────────────────────────────────────────┘");

    // Summary
    println!("\n📊 Audit Summary");
    println!("   Commands analyzed: {}", recent.len());
    println!("   ✅ Allowed:        {}", allowed);
    println!("   🚫 Denied:         {}", denied);
    println!("   ⚠️  Needs approval: {}", flagged);
    if check_files {
        println!("   📁 Files blocked:  {}", files_blocked);
    }

    let risk_score = if recent.is_empty() {
        0.0
    } else {
        ((denied as f64 * 3.0 + flagged as f64) / recent.len() as f64 * 100.0).min(100.0)
    };

    if risk_score == 0.0 {
        println!("\n   🟢 Risk Score: {:.0}/100 — Clean session!", risk_score);
    } else if risk_score < 20.0 {
        println!("\n   🟡 Risk Score: {:.0}/100 — Low risk, some flagged commands", risk_score);
    } else {
        println!("\n   🔴 Risk Score: {:.0}/100 — HIGH RISK! Review flagged commands!", risk_score);
    }

    Ok(())
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() > max { format!("{}…", &s[..max-1]) } else { s.to_string() }
}

/// Simple TOML serialization for the config (since `config` crate doesn't support serialization).
fn toml_string(config: &AppConfig) -> String {
    format!(
        r#"[server]
host = "{}"
port = {}
log_level = "{}"
mtls_enabled = {}

[identity]
database_path = "{}"
svid_ttl_seconds = {}
token_signing_key = "{}"
default_token_ttl_seconds = {}

[gateway]
opa_url = "{}"
policies_dir = "{}"
nonce_cache_size = {}
rate_limit_per_second = {}

[reasoning]
max_hidden_variables = {}
default_external_integrity = "{}"

[audit]
log_file_path = "{}"
index_database_path = "{}"
genesis_hash = "{}"

[redteam]
max_probe_turns = {}
golden_dataset_dir = "{}"
probe_timeout_seconds = {}

[openai]
base_url = "{}"
api_key = "{}"
model = "{}"
max_tokens = {}
temperature = {}
timeout_seconds = {}
"#,
        config.server.host,
        config.server.port,
        config.server.log_level,
        config.server.mtls_enabled,
        config.identity.database_path,
        config.identity.svid_ttl_seconds,
        config.identity.token_signing_key,
        config.identity.default_token_ttl_seconds,
        config.gateway.opa_url,
        config.gateway.policies_dir,
        config.gateway.nonce_cache_size,
        config.gateway.rate_limit_per_second,
        config.reasoning.max_hidden_variables,
        config.reasoning.default_external_integrity,
        config.audit.log_file_path,
        config.audit.index_database_path,
        config.audit.genesis_hash,
        config.redteam.max_probe_turns,
        config.redteam.golden_dataset_dir,
        config.redteam.probe_timeout_seconds,
        config.openai.base_url,
        config.openai.api_key,
        config.openai.model,
        config.openai.max_tokens,
        config.openai.temperature,
        config.openai.timeout_seconds,
    )
}
