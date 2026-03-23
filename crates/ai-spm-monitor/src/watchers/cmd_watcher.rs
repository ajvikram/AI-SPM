//! Shell command watcher — polls the shell history file for new commands
//! and evaluates each through ShellGuard.

use std::sync::mpsc;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use ai_spm_gateway::shell_guard::ShellGuard;
use ai_spm_core::types::ShellVerdict;
use crate::types::*;

/// Polls the shell history file for new commands every `interval`.
/// Runs in a loop until `running` flag is cleared.
pub fn start_cmd_watcher(
    history_path: &str,
    tx: mpsc::Sender<MonitorEvent>,
    interval: std::time::Duration,
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    let guard = ShellGuard::new();
    let hist = history_path.to_string();

    std::thread::spawn(move || {
        let mut last_size = match std::fs::metadata(&hist) {
            Ok(m) => m.len(),
            Err(e) => {
                tracing::error!("Cannot read history file metadata '{}': {}", hist, e);
                return;
            }
        };

        while running.load(std::sync::atomic::Ordering::Relaxed) {
            std::thread::sleep(interval);

            let current_size = match std::fs::metadata(&hist) {
                Ok(m) => m.len(),
                Err(_) => continue,
            };

            if current_size > last_size {
                if let Ok(mut file) = std::fs::File::open(&hist) {
                    if file.seek(SeekFrom::Start(last_size)).is_ok() {
                        let mut reader = BufReader::new(file);
                        let mut line = String::new();
                        while reader.read_line(&mut line).unwrap_or(0) > 0 {
                            if let Some(cmd) = parse_history_line(line.trim()) {
                                if !cmd.is_empty() {
                                    println!("🔍 CMD WATCHER READ: {}", cmd);
                                    let result = guard.evaluate(&cmd);
                                    let (verdict_str, risk, reason, severity) = match &result.verdict {
                                        ShellVerdict::Allow => ("allow".to_string(), None, None, Severity::Info),
                                        ShellVerdict::Deny { reason, risk, .. } => ("deny".to_string(), Some(format!("{:?}", risk)), Some(reason.clone()), Severity::Critical),
                                        ShellVerdict::RequiresApproval { reason, risk, .. } => ("requires_approval".to_string(), Some(format!("{:?}", risk)), Some(reason.clone()), Severity::Warning),
                                    };

                                    let event = MonitorEvent::new(
                                        EventType::ShellCommand,
                                        severity,
                                        EventDetails::ShellCommand {
                                            command: cmd,
                                            verdict: verdict_str,
                                            risk,
                                            reason,
                                        },
                                    );
                                    let _ = tx.send(event);
                                }
                            }
                            line.clear();
                        }
                    }
                }
                last_size = current_size;
            }
        }
    });
}

/// Parse a history line, handling both plain and zsh extended format.
fn parse_history_line(line: &str) -> Option<String> {
    if line.is_empty() { return None; }
    // zsh extended history: ": 1234567890:0;actual command"
    if line.starts_with(": ") {
        line.splitn(2, ';').nth(1).map(|s| s.trim().to_string())
    } else {
        Some(line.to_string())
    }
}
