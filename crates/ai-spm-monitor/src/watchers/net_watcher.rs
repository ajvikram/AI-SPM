//! Network watcher — detects active network connections by polling `lsof -i`
//! and flags new outbound connections.

use std::collections::HashSet;
use std::process::Command;
use std::sync::mpsc;
use crate::types::*;

/// Polls for new network connections every `interval`.
pub fn start_net_watcher(
    tx: mpsc::Sender<MonitorEvent>,
    interval: std::time::Duration,
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    std::thread::spawn(move || {
        let mut known_connections: HashSet<String> = HashSet::new();

        // Seed with current connections
        if let Some(conns) = get_connections() {
            for conn in &conns {
                known_connections.insert(conn_key(conn));
            }
        }

        while running.load(std::sync::atomic::Ordering::Relaxed) {
            std::thread::sleep(interval);

            if let Some(conns) = get_connections() {
                for conn in conns {
                    let key = conn_key(&conn);
                    if known_connections.contains(&key) {
                        continue;
                    }
                    known_connections.insert(key);

                    let suspicious = is_suspicious_connection(&conn);
                    let severity = if suspicious { Severity::Warning } else { Severity::Info };

                    let event = MonitorEvent::new(
                        EventType::NetworkConnection,
                        severity,
                        EventDetails::NetworkConnection {
                            pid: conn.pid,
                            process: conn.process.clone(),
                            remote_addr: conn.remote.clone(),
                            direction: conn.direction.clone(),
                            suspicious,
                        },
                    );

                    // Only report outbound or suspicious connections
                    if conn.direction == "outbound" || suspicious {
                        let _ = tx.send(event);
                    }
                }
            }

            // Prune old connections periodically (keep last 1000)
            if known_connections.len() > 1000 {
                known_connections.clear();
            }
        }
    });
}

#[derive(Debug)]
struct NetConnection {
    pid: u32,
    process: String,
    remote: String,
    direction: String,
}

fn conn_key(conn: &NetConnection) -> String {
    format!("{}:{}:{}", conn.pid, conn.process, conn.remote)
}

/// Get active network connections via `lsof -i -n -P`.
fn get_connections() -> Option<Vec<NetConnection>> {
    let output = Command::new("lsof")
        .args(["-i", "-n", "-P", "-F", "pcn"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut connections = Vec::new();
    let mut current_pid: u32 = 0;
    let mut current_process = String::new();

    for line in stdout.lines() {
        if line.starts_with('p') {
            current_pid = line[1..].parse().unwrap_or(0);
        } else if line.starts_with('c') {
            current_process = line[1..].to_string();
        } else if line.starts_with('n') {
            let addr = &line[1..];
            // Only care about TCP connections with remote addresses
            if addr.contains("->") {
                let parts: Vec<&str> = addr.split("->").collect();
                if parts.len() == 2 {
                    connections.push(NetConnection {
                        pid: current_pid,
                        process: current_process.clone(),
                        remote: parts[1].trim().to_string(),
                        direction: "outbound".to_string(),
                    });
                }
            } else if addr.contains("*:") || addr.contains("(LISTEN)") {
                // Listening socket — inbound
                connections.push(NetConnection {
                    pid: current_pid,
                    process: current_process.clone(),
                    remote: addr.to_string(),
                    direction: "inbound".to_string(),
                });
            }
        }
    }

    Some(connections)
}

fn is_suspicious_connection(conn: &NetConnection) -> bool {
    let proc_lower = conn.process.to_lowercase();
    // Common data exfiltration tools
    if proc_lower == "curl" || proc_lower == "wget" || proc_lower == "nc" || proc_lower == "ncat" {
        return true;
    }
    // Connections on unusual ports
    if let Some(port_str) = conn.remote.rsplit(':').next() {
        if let Ok(port) = port_str.parse::<u16>() {
            // Suspicious ports: reverse shells, C2 servers, etc.
            if matches!(port, 4444 | 5555 | 6666 | 8888 | 9999 | 1337 | 31337) {
                return true;
            }
        }
    }
    false
}
