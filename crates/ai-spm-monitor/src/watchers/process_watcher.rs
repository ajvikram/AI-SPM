//! Process watcher — detects new process spawns using `sysinfo`
//! and flags suspicious ones (curl, wget, nc, python http.server, etc.)
//! Also captures shell commands by detecting shell child processes.

use std::collections::HashSet;
use std::sync::mpsc;
use sysinfo::System;
use crate::types::*;

/// Suspicious process names that might indicate agent misbehavior.
const SUSPICIOUS_NAMES: &[&str] = &[
    "curl", "wget", "nc", "ncat", "netcat", "socat",
    "ssh", "scp", "sftp", "rsync",
    "python", "python3", "ruby", "perl", "php",  // scripting runtimes
    "base64", "openssl",
    "nmap", "nikto",
];

/// Shell process names — children of these are captured as shell commands.
const SHELL_NAMES: &[&str] = &[
    "bash", "zsh", "sh", "fish", "dash", "tcsh", "csh",
    "powershell", "pwsh", "cmd",
];

/// Polls for new processes every `interval`.
pub fn start_process_watcher(
    tx: mpsc::Sender<MonitorEvent>,
    _interval: std::time::Duration,
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    std::thread::spawn(move || {
        let mut sys = System::new();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

        // Track known PIDs
        let mut known_pids: HashSet<u32> = sys
            .processes()
            .keys()
            .map(|pid| pid.as_u32())
            .collect();

        // 100ms fast-poll to catch short-lived shell commands
        let fast_interval = std::time::Duration::from_millis(100);

        while running.load(std::sync::atomic::Ordering::Relaxed) {
            std::thread::sleep(fast_interval);
            
            // Only refresh the process list, not full memory/cpu stats to save CPU
            sys.refresh_processes(sysinfo::ProcessesToUpdate::All, false);

            for (pid, process) in sys.processes() {
                let pid_u32 = pid.as_u32();
                if known_pids.contains(&pid_u32) {
                    continue;
                }
                known_pids.insert(pid_u32);

                let name = process.name().to_string_lossy().to_string();
                let cmd_line = process.cmd()
                    .iter()
                    .map(|s| s.to_string_lossy().to_string())
                    .collect::<Vec<_>>()
                    .join(" ");

                let suspicious = is_suspicious(&name, &cmd_line);

                // Detect if THIS is a shell execution (e.g., zsh -c, bash -c)
                let name_lower = name.to_lowercase();
                let is_shell_exec = SHELL_NAMES.iter().any(|s| name_lower == *s || name_lower.starts_with(s))
                    && (cmd_line.contains("-c") || cmd_line.contains("--login"));

                // Emit shell command event if this is a shell running a command
                if (is_shell_exec || suspicious) && !cmd_line.is_empty() {
                    let shell_event = MonitorEvent::new(
                        EventType::ShellCommand,
                        if suspicious { Severity::Warning } else { Severity::Info },
                        EventDetails::ShellCommand {
                            command: cmd_line.clone(),
                            verdict: if suspicious { "flagged".to_string() } else { "allow".to_string() },
                            risk: if suspicious { Some("detected via process".to_string()) } else { None },
                            reason: if suspicious {
                                Some(format!("Suspicious process '{}' spawned from shell", name))
                            } else {
                                None
                            },
                        },
                    );
                    let _ = tx.send(shell_event);
                }

                // Report suspicious processes
                if suspicious {
                    let event = MonitorEvent::new(
                        EventType::ProcessSpawn,
                        Severity::Warning,
                        EventDetails::ProcessSpawn {
                            pid: pid_u32,
                            name,
                            cmd_line,
                            suspicious,
                        },
                    );
                    let _ = tx.send(event);
                }
            }

            // Clean up dead PIDs
            let current_pids: HashSet<u32> = sys
                .processes()
                .keys()
                .map(|pid| pid.as_u32())
                .collect();
            known_pids.retain(|pid| current_pids.contains(pid));
        }
    });
}

fn is_suspicious(name: &str, cmd_line: &str) -> bool {
    let name_lower = name.to_lowercase();
    for &s in SUSPICIOUS_NAMES {
        if name_lower == s || name_lower.starts_with(s) {
            return true;
        }
    }
    // Check for suspicious patterns in command line
    let cl = cmd_line.to_lowercase();
    cl.contains("http.server")
        || cl.contains("reverse_tcp")
        || cl.contains("exfiltrat")
        || cl.contains("/dev/tcp")
        || cl.contains("| base64")
}
