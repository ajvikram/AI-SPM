//! File system watcher — uses `notify` (FSEvents on macOS) to detect file changes
//! and evaluates each through FsSentinel.

use std::path::Path;
use std::sync::mpsc;
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher, EventKind};
use ai_spm_core::types::FileOp;
use ai_spm_gateway::fs_sentinel::FsSentinel;
use crate::types::*;

/// Watch a directory for file changes and send events to the channel.
pub fn start_fs_watcher(
    watch_dir: &str,
    tx: mpsc::Sender<MonitorEvent>,
) -> notify::Result<RecommendedWatcher> {
    let sentinel = FsSentinel::new();
    let watch_dir_owned = watch_dir.to_string();

    let mut watcher = RecommendedWatcher::new(
        move |res: Result<notify::Event, notify::Error>| {
            if let Ok(event) = res {
                for path in &event.paths {
                    let path_str = path.to_string_lossy().to_string();

                    // Skip hidden/build dirs
                    if path_str.contains("/target/")
                        || path_str.contains("/.git/")
                        || path_str.contains("/node_modules/")
                    {
                        continue;
                    }

                    let (op_str, file_op) = match event.kind {
                        EventKind::Create(_) => ("create", FileOp::Write),
                        EventKind::Modify(_) => ("modify", FileOp::Write),
                        EventKind::Remove(_) => ("delete", FileOp::Delete),
                        _ => continue,
                    };

                    let result = sentinel.check_access(&path_str, file_op);

                    let severity = if !result.allowed {
                        Severity::Critical
                    } else {
                        match result.sensitivity {
                            ai_spm_core::types::FileSensitivity::Normal => Severity::Info,
                            ai_spm_core::types::FileSensitivity::Config => Severity::Warning,
                            _ => Severity::Critical,
                        }
                    };

                    let sensitivity_str = format!("{:?}", result.sensitivity).to_lowercase();

                    let event = MonitorEvent::new(
                        EventType::FileChange,
                        severity,
                        EventDetails::FileChange {
                            path: path_str,
                            operation: op_str.to_string(),
                            sensitivity: sensitivity_str,
                            allowed: result.allowed,
                        },
                    );

                    let _ = tx.send(event);
                }
            }
        },
        Config::default(),
    )?;

    watcher.watch(Path::new(&watch_dir_owned), RecursiveMode::Recursive)?;
    Ok(watcher)
}
