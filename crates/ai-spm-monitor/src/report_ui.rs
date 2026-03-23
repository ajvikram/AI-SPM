//! HTML report renderer — generates beautiful standalone HTML reports
//! and opens them in a native webview window.

use crate::types::*;

/// Generate a complete standalone HTML report page.
pub fn render_html_report(summary: &SessionSummary, events: &[MonitorEvent], server_url: &str) -> String {
    let total = summary.allowed + summary.flagged + summary.blocked;
    let risk_score = if total > 0 {
        ((summary.blocked as f64 * 3.0 + summary.flagged as f64) / total as f64 * 100.0).min(100.0)
    } else {
        0.0
    };

    let risk_class = if risk_score == 0.0 { "clean" } else if risk_score < 20.0 { "low" } else { "high" };
    let risk_label = match risk_class {
        "clean" => "Clean Session",
        "low" => "Low Risk",
        _ => "HIGH RISK",
    };

    // Build event rows
    let mut event_rows = String::new();
    for evt in events.iter().rev().take(200) {
        let (icon, category, detail, severity_class) = match &evt.details {
            EventDetails::ShellCommand { command, verdict, reason, .. } => {
                let icon = match verdict.as_str() {
                    "allow" => "✅",
                    "deny" => "🚫",
                    _ => "⚠️",
                };
                let sev = match verdict.as_str() {
                    "allow" => "info",
                    "deny" => "critical",
                    _ => "warning",
                };
                (icon, "Shell", format!("{}<br><small class='reason'>{}</small>", 
                    html_escape(command), reason.as_deref().unwrap_or("")), sev)
            }
            EventDetails::FileChange { path, operation, sensitivity, allowed } => {
                let icon = if *allowed { "✅" } else { "🚫" };
                let sev = if *allowed { "info" } else { "critical" };
                (icon, "File", format!("<b>{}</b> {}<br><small>{}</small>", 
                    operation, html_escape(path), sensitivity), sev)
            }
            EventDetails::ProcessSpawn { name, pid, cmd_line, suspicious } => {
                let icon = if *suspicious { "⚠️" } else { "✅" };
                let sev = if *suspicious { "warning" } else { "info" };
                (icon, "Process", format!("<b>{}</b> (pid {})<br><small>{}</small>", 
                    name, pid, html_escape(&cmd_line.chars().take(80).collect::<String>())), sev)
            }
            EventDetails::NetworkConnection { process, remote_addr, direction, suspicious, .. } => {
                let icon = if *suspicious { "⚠️" } else { "✅" };
                let sev = if *suspicious { "warning" } else { "info" };
                (icon, "Network", format!("<b>{}</b> {} → {}", 
                    process, direction, html_escape(remote_addr)), sev)
            }
            EventDetails::AgentDiscovery { agents, mcp_servers, extensions } => {
                let summary = format!("{} agents, {} MCP servers, {} extensions", 
                    agents.len(), mcp_servers.len(), extensions.len());
                ("🔍", "Discovery", summary, "info")
            }
        };

        event_rows.push_str(&format!(
            r#"<tr class="event-row {sev}">
                <td class="time">{}</td>
                <td class="icon">{}</td>
                <td class="cat">{}</td>
                <td class="detail">{}</td>
            </tr>"#,
            evt.timestamp.format("%H:%M:%S"),
            icon,
            category,
            detail,
            sev = severity_class,
        ));
    }

    format!(r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI-SPM Agent Monitor — Report</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    background: #0a0e1a;
    color: #e1e5f0;
    min-height: 100vh;
  }}
  .header {{
    background: linear-gradient(135deg, #1a1f36 0%, #0d1226 100%);
    border-bottom: 1px solid rgba(99,132,255,0.2);
    padding: 20px 30px;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }}
  .header h1 {{
    font-size: 20px;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 10px;
  }}
  .header .shield {{ font-size: 28px; }}
  .header .session {{
    font-size: 12px;
    color: #8892b0;
    font-family: monospace;
  }}
  .server-badge {{
    background: rgba(99,132,255,0.15);
    border: 1px solid rgba(99,132,255,0.3);
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 11px;
    color: #6384ff;
  }}
  .metrics {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 16px;
    padding: 24px 30px;
  }}
  .metric-card {{
    background: linear-gradient(135deg, #151a30 0%, #0f1328 100%);
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 12px;
    padding: 18px;
    text-align: center;
  }}
  .metric-card .value {{
    font-size: 32px;
    font-weight: 700;
    margin: 6px 0;
  }}
  .metric-card .label {{
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: #8892b0;
  }}
  .metric-card.commands .value {{ color: #6384ff; }}
  .metric-card.files .value {{ color: #4cd964; }}
  .metric-card.processes .value {{ color: #ff9f43; }}
  .metric-card.network .value {{ color: #a78bfa; }}
  .metric-card.allowed .value {{ color: #4cd964; }}
  .metric-card.flagged .value {{ color: #ffcc00; }}
  .metric-card.blocked .value {{ color: #ff4757; }}

  .risk-banner {{
    margin: 0 30px 20px;
    padding: 18px 24px;
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }}
  .risk-banner.clean {{
    background: linear-gradient(135deg, rgba(76,217,100,0.1) 0%, rgba(76,217,100,0.03) 100%);
    border: 1px solid rgba(76,217,100,0.3);
  }}
  .risk-banner.low {{
    background: linear-gradient(135deg, rgba(255,204,0,0.1) 0%, rgba(255,204,0,0.03) 100%);
    border: 1px solid rgba(255,204,0,0.3);
  }}
  .risk-banner.high {{
    background: linear-gradient(135deg, rgba(255,71,87,0.1) 0%, rgba(255,71,87,0.03) 100%);
    border: 1px solid rgba(255,71,87,0.3);
  }}
  .risk-score {{
    font-size: 36px;
    font-weight: 800;
  }}
  .risk-banner.clean .risk-score {{ color: #4cd964; }}
  .risk-banner.low .risk-score {{ color: #ffcc00; }}
  .risk-banner.high .risk-score {{ color: #ff4757; }}
  .risk-label {{
    font-size: 14px;
    color: #8892b0;
  }}

  .events-section {{
    padding: 0 30px 30px;
  }}
  .events-section h2 {{
    font-size: 16px;
    margin-bottom: 12px;
    color: #c0c8e0;
  }}
  .events-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }}
  .events-table th {{
    text-align: left;
    padding: 10px 12px;
    background: rgba(99,132,255,0.08);
    border-bottom: 1px solid rgba(255,255,255,0.06);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: #8892b0;
  }}
  .events-table td {{
    padding: 8px 12px;
    border-bottom: 1px solid rgba(255,255,255,0.03);
    vertical-align: top;
  }}
  .event-row:hover {{ background: rgba(99,132,255,0.05); }}
  .event-row.critical {{ border-left: 3px solid #ff4757; }}
  .event-row.warning {{ border-left: 3px solid #ffcc00; }}
  .event-row.info {{ border-left: 3px solid transparent; }}
  .time {{ color: #6a7394; font-family: monospace; white-space: nowrap; }}
  .icon {{ font-size: 16px; text-align: center; width: 36px; }}
  .cat {{
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: #8892b0;
    width: 65px;
  }}
  .detail {{ color: #c0c8e0; word-break: break-word; }}
  .detail small {{ color: #6a7394; }}
  .reason {{ color: #ff9f43; }}
  .empty-state {{
    text-align: center;
    padding: 60px;
    color: #6a7394;
    font-size: 16px;
  }}
  .filter-bar {{
    display: flex;
    gap: 8px;
    margin-bottom: 12px;
  }}
  .filter-btn {{
    padding: 6px 14px;
    border-radius: 20px;
    border: 1px solid rgba(255,255,255,0.1);
    background: transparent;
    color: #8892b0;
    cursor: pointer;
    font-size: 12px;
    transition: all 0.2s;
  }}
  .filter-btn:hover, .filter-btn.active {{
    background: rgba(99,132,255,0.15);
    border-color: rgba(99,132,255,0.4);
    color: #6384ff;
  }}
</style>
</head>
<body>

<div class="header">
  <div>
    <h1><span class="shield">🛡️</span> AI-SPM Agent Monitor</h1>
    <div class="session">Session {session_id} • Started {started}</div>
  </div>
  <div class="server-badge">🌐 {server}</div>
</div>

<div class="metrics">
  <div class="metric-card commands">
    <div class="label">Shell Commands</div>
    <div class="value">{commands}</div>
  </div>
  <div class="metric-card files">
    <div class="label">File Changes</div>
    <div class="value">{files}</div>
  </div>
  <div class="metric-card processes">
    <div class="label">Processes</div>
    <div class="value">{processes}</div>
  </div>
  <div class="metric-card network">
    <div class="label">Network</div>
    <div class="value">{network}</div>
  </div>
  <div class="metric-card allowed">
    <div class="label">✅ Allowed</div>
    <div class="value">{allowed}</div>
  </div>
  <div class="metric-card flagged">
    <div class="label">⚠️ Flagged</div>
    <div class="value">{flagged}</div>
  </div>
  <div class="metric-card blocked">
    <div class="label">🚫 Blocked</div>
    <div class="value">{blocked}</div>
  </div>
</div>

<div class="risk-banner {risk_class}">
  <div>
    <div class="risk-label">Risk Score</div>
    <div class="risk-score">{risk_score:.0}/100</div>
  </div>
  <div style="font-size:18px; font-weight:600;">{risk_label}</div>
</div>

<div class="events-section">
  <h2>Event Log ({total} events)</h2>
  <div class="filter-bar">
    <button class="filter-btn active" onclick="filterEvents('all')">All</button>
    <button class="filter-btn" onclick="filterEvents('critical')">🚫 Blocked</button>
    <button class="filter-btn" onclick="filterEvents('warning')">⚠️ Flagged</button>
    <button class="filter-btn" onclick="filterEvents('info')">✅ Allowed</button>
  </div>
  {events_content}
</div>

<script>
function filterEvents(type) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.event-row').forEach(row => {{
    if (type === 'all' || row.classList.contains(type)) {{
      row.style.display = '';
    }} else {{
      row.style.display = 'none';
    }}
  }});
}}
</script>

</body>
</html>"##,
        session_id = summary.session_id,
        started = summary.started_at.format("%Y-%m-%d %H:%M:%S"),
        server = html_escape(server_url),
        commands = summary.total_commands,
        files = summary.total_file_changes,
        processes = summary.total_processes,
        network = summary.total_network,
        allowed = summary.allowed,
        flagged = summary.flagged,
        blocked = summary.blocked,
        risk_score = risk_score,
        risk_class = risk_class,
        risk_label = risk_label,
        total = total,
        events_content = if events.is_empty() {
            r#"<div class="empty-state">No events captured yet. Start monitoring to see activity.</div>"#.to_string()
        } else {
            format!(r#"<table class="events-table">
                <thead><tr><th>Time</th><th></th><th>Type</th><th>Details</th></tr></thead>
                <tbody>{}</tbody>
            </table>"#, event_rows)
        },
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
