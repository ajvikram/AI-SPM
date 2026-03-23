//! Reporter — syncs monitoring events to the AI-SPM server and generates reports.

use crate::types::{MonitorEvent, SessionSummary};

/// Sends a batch of events to the AI-SPM server.
pub async fn sync_events(
    server_url: &str,
    api_key: &str,
    session_id: &str,
    events: &[MonitorEvent],
) -> Result<(), String> {
    let client = reqwest::Client::new();
    let url = format!("{}/api/monitor/events", server_url);

    let payload = serde_json::json!({
        "session_id": session_id,
        "events": events,
    });

    match client
        .post(&url)
        .header("Authorization", format!("Bearer {}", api_key))
        .json(&payload)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(resp) => {
            if resp.status().is_success() {
                Ok(())
            } else {
                Err(format!("Server returned {}", resp.status()))
            }
        }
        Err(e) => Err(format!("Failed to sync: {}", e)),
    }
}

/// Print a formatted audit report to stdout.
pub fn print_report(summary: &SessionSummary, events: &[MonitorEvent]) {
    println!("\n🛡️  AI-SPM Agent Monitor — Session Report");
    println!("{}", "═".repeat(60));
    println!("   Session:  {}", summary.session_id);
    println!("   Started:  {}", summary.started_at.format("%Y-%m-%d %H:%M:%S"));
    println!();
    println!("   📊 Activity Summary");
    println!("   ├── Shell Commands:     {}", summary.total_commands);
    println!("   ├── File Changes:       {}", summary.total_file_changes);
    println!("   ├── Process Spawns:     {}", summary.total_processes);
    println!("   └── Network Connections: {}", summary.total_network);
    println!();
    println!("   🔍 Threat Assessment");
    println!("   ├── ✅ Allowed:  {}", summary.allowed);
    println!("   ├── ⚠️  Flagged:  {}", summary.flagged);
    println!("   └── 🚫 Blocked:  {}", summary.blocked);

    let total = summary.allowed + summary.flagged + summary.blocked;
    if total > 0 {
        let risk = ((summary.blocked as f64 * 3.0 + summary.flagged as f64) / total as f64 * 100.0).min(100.0);
        let indicator = if risk == 0.0 { "🟢" } else if risk < 20.0 { "🟡" } else { "🔴" };
        println!("\n   {} Risk Score: {:.0}/100", indicator, risk);
    }

    // Show critical events
    let critical: Vec<&MonitorEvent> = events.iter()
        .filter(|e| matches!(e.severity, crate::types::Severity::Critical | crate::types::Severity::Warning))
        .collect();

    if !critical.is_empty() {
        println!("\n   ⚠️  Notable Events ({}):", critical.len());
        for (i, evt) in critical.iter().take(20).enumerate() {
            let desc = match &evt.details {
                crate::types::EventDetails::ShellCommand { command, verdict, .. } => {
                    format!("CMD [{}] {}", verdict.to_uppercase(), truncate(command, 45))
                }
                crate::types::EventDetails::FileChange { path, operation, sensitivity, .. } => {
                    format!("FILE [{}] {} ({})", operation, truncate(path, 35), sensitivity)
                }
                crate::types::EventDetails::ProcessSpawn { name, pid, .. } => {
                    format!("PROC [{}] pid={}", name, pid)
                }
                crate::types::EventDetails::NetworkConnection { process, remote_addr, .. } => {
                    format!("NET [{}] → {}", process, truncate(remote_addr, 35))
                }
                crate::types::EventDetails::AgentDiscovery { agents, .. } => {
                    let names: Vec<&str> = agents.iter().map(|a| a.name.as_str()).collect();
                    format!("DISCOVERY [{}]", names.join(", "))
                }
            };
            println!("   {:>3}. {} {}", i + 1, evt.timestamp.format("%H:%M:%S"), desc);
        }
    }

    println!("\n{}", "═".repeat(60));
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max { format!("{}…", &s[..max-1]) } else { s.to_string() }
}
