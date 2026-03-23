//! AI-SPM Agent Monitor — macOS menu bar daemon.
//!
//! A lightweight system tray app that monitors shell commands, file changes,
//! process spawns, and network traffic during AI agent coding sessions.
//!
//! Server Modes:
//!   - **Embedded**: Starts an in-process HTTP server (standalone)
//!   - **Remote**: Sends events to a remote AI-SPM server
//!   - **Auto**: Tries remote first, falls back to embedded
//!
//! Admin Override:
//!   Set `admin_force_remote = true` in ~/.ai-spm/monitor.toml
//!   Or: AI_SPM_FORCE_REMOTE=1 AI_SPM_SERVER_URL=https://spm.corp.com

use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc, Mutex,
};


use tao::event_loop::{ControlFlow, EventLoop};
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    TrayIconBuilder, TrayIconEvent,
};

use ai_spm_monitor::config::MonitorConfig;
use ai_spm_monitor::types::*;
use ai_spm_monitor::watchers::*;
use ai_spm_monitor::reporter;

fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter("ai_spm_monitor=info")
        .init();

    // Load config
    let config = Arc::new(Mutex::new(MonitorConfig::load()));

    {
        let cfg = config.lock().unwrap();
        println!("\u{1f6e1}\u{fe0f}  AI-SPM Agent Monitor starting...");
        println!("   Server: {}", cfg.mode_display());
        if cfg.is_admin_locked() {
            println!("   \u{26a0}\u{fe0f}  Admin override active \u{2014} server settings locked");
        }
        println!("   Config: ~/.ai-spm/monitor.toml");
    }

    let event_loop = EventLoop::new();

    // NOTE: Do NOT set activation_policy to Accessory here —
    // it prevents WKWebView from rendering (white screen).
    // The dock icon will appear when a window is open, which is acceptable.

    // ── Build tray menu ───────────────────────────────────
    let menu = Menu::new();

    let status_item = MenuItem::new("Status: Idle", false, None);
    let toggle_item = MenuItem::new("▶ Start Monitoring", true, None);

    let mode_label = {
        let cfg = config.lock().unwrap();
        format!("Server: {}", cfg.mode_display())
    };
    let server_mode_item = MenuItem::new(&mode_label, !config.lock().unwrap().is_admin_locked(), None);
    let server_url_item = {
        let cfg = config.lock().unwrap();
        MenuItem::new(&format!("   URL: {}", cfg.effective_url()), false, None)
    };
    let edit_config_item = MenuItem::new("   ✏️ Edit Config", true, None);
    let reload_config_item = MenuItem::new("   🔄 Reload", true, None);

    let report_item = MenuItem::new("📊 View Report", true, None);
    let dashboard_item = MenuItem::new("🌐 Open Dashboard", true, None);
    let quit_item = MenuItem::new("❌ Quit", true, None);

    let _ = menu.append(&status_item);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&toggle_item);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&server_mode_item);
    let _ = menu.append(&server_url_item);
    let _ = menu.append(&edit_config_item);
    let _ = menu.append(&reload_config_item);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&report_item);
    let _ = menu.append(&dashboard_item);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&quit_item);

    // ── Create tray icon ──────────────────────────────────
    let icon = create_shield_icon(false);

    let _tray_icon = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("AI-SPM Agent Monitor")
        .with_icon(icon)
        .build()
        .expect("Failed to create tray icon");

    // ── Shared state ──────────────────────────────────────
    let monitoring = Arc::new(AtomicBool::new(true)); // ACTIVATE BY DEFAULT for discovery
    let events: Arc<Mutex<Vec<MonitorEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let summary: Arc<Mutex<SessionSummary>> = Arc::new(Mutex::new(SessionSummary::new()));
    let embedded_server_running = Arc::new(AtomicBool::new(false));

    // ── Shared active webview ──────────────────────────────
    let mut active_window: Option<tao::window::Window> = None;
    let mut active_webview: Option<wry::WebView> = None;

    // Event channel
    let (tx, rx) = mpsc::channel::<MonitorEvent>();

    // ── Event collector thread ────────────────────────────
    let events_clone = events.clone();
    let summary_clone = summary.clone();
    std::thread::spawn(move || {
        for event in rx {
            let icon = match event.severity {
                Severity::Critical => "🚫",
                Severity::Warning => "⚠️",
                Severity::Info => "✅",
            };
            let desc = match &event.details {
                EventDetails::ShellCommand { command, .. } => {
                    format!("CMD: {}", truncate(command, 40))
                }
                EventDetails::FileChange { path, operation, .. } => {
                    format!("FILE: {} {}", operation, truncate(path, 35))
                }
                EventDetails::ProcessSpawn { name, .. } => {
                    format!("PROC: {}", name)
                }
                EventDetails::NetworkConnection { process, remote_addr, .. } => {
                    format!("NET: {} → {}", process, truncate(remote_addr, 30))
                }
                EventDetails::AgentDiscovery { agents, mcp_servers, extensions } => {
                    format!("DISCOVERY: {} agents, {} MCP, {} ext",
                        agents.len(), mcp_servers.len(), extensions.len())
                }
            };
            println!("  {} {}", icon, desc);

            summary_clone.lock().unwrap().record_event(&event);
            events_clone.lock().unwrap().push(event);
        }
    });

    // Menu item IDs
    let toggle_id = toggle_item.id().clone();
    let server_mode_id = server_mode_item.id().clone();
    let edit_config_id = edit_config_item.id().clone();
    let reload_config_id = reload_config_item.id().clone();
    let report_id = report_item.id().clone();
    let dashboard_id = dashboard_item.id().clone();
    let quit_id = quit_item.id().clone();

    // Watcher handle
    let watcher_handle: Arc<Mutex<Option<notify::RecommendedWatcher>>> =
        Arc::new(Mutex::new(None));

    println!("🛡️  AI-SPM Agent Monitor ready! Click the menu bar icon.");

    // ── Try to start embedded server if needed ────────────
    {
        let cfg = config.lock().unwrap();
        if cfg.server_mode == "embedded" || cfg.server_mode == "auto" {
            start_embedded_server(cfg.embedded_port, embedded_server_running.clone());
        }
    }

    if monitoring.load(Ordering::Relaxed) {
        let sync_events = events.clone();
        let sync_summary = summary.clone();
        let sync_monitoring = monitoring.clone();
        let sync_url = config.lock().unwrap().effective_url();
        let sync_api_key = config.lock().unwrap().api_key.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let mut last_synced = 0usize;
            while sync_monitoring.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_secs(5));
                if !sync_monitoring.load(Ordering::Relaxed) { break; }
                let evts = sync_events.lock().unwrap().clone();
                if evts.len() > last_synced {
                    let new_events: Vec<_> = evts[last_synced..].to_vec();
                    let session_id = sync_summary.lock().unwrap().session_id.clone();
                    last_synced = evts.len();
                    let _ = rt.block_on(
                        reporter::sync_events(&sync_url, &sync_api_key, &session_id, &new_events)
                    );
                }
            }
        });

        // Start watchers
        let _cfg = config.lock().unwrap();
        let _home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
        
        let tx_discovery = tx.clone();
        let mon_discovery = monitoring.clone();
        std::thread::spawn(move || {
            agent_discovery::start_agent_discovery(tx_discovery, std::time::Duration::from_secs(10), mon_discovery);
        });
    }

    // ── Event loop ────────────────────────────────────────
    event_loop.run(move |tao_event, event_loop_window_target, control_flow| {
        *control_flow = ControlFlow::WaitUntil(
            std::time::Instant::now() + std::time::Duration::from_millis(100),
        );

        if let tao::event::Event::WindowEvent {
            event: tao::event::WindowEvent::CloseRequested,
            window_id,
            ..
        } = &tao_event
        {
            if let Some(win) = &active_window {
                if win.id() == *window_id {
                    active_webview = None;
                    active_window = None;
                }
            }
        }

        if let Ok(event) = MenuEvent::receiver().try_recv() {
            // ── Toggle Monitoring ─────────────────────
            if event.id == toggle_id {
                if monitoring.load(Ordering::Relaxed) {
                    // Stop
                    monitoring.store(false, Ordering::Relaxed);
                    toggle_item.set_text("▶ Start Monitoring");
                    status_item.set_text("Status: Idle");
                    *watcher_handle.lock().unwrap() = None;

                    let s = summary.lock().unwrap();
                    println!("\n⏹️  Monitoring stopped.");
                    println!(
                        "   Captured: {} cmds, {} files, {} procs, {} net",
                        s.total_commands, s.total_file_changes,
                        s.total_processes, s.total_network
                    );

                    // Sync events to server
                    let cfg = config.lock().unwrap().clone();
                    let evts = events.lock().unwrap().clone();
                    let session_id = s.session_id.clone();
                    if !evts.is_empty() {
                        let url = cfg.effective_url();
                        let api_key = cfg.api_key.clone();
                        std::thread::spawn(move || {
                            let rt = tokio::runtime::Runtime::new().unwrap();
                            let _ = rt.block_on(reporter::sync_events(&url, &api_key, &session_id, &evts));
                            println!("   📤 Events synced to {}", url);
                        });
                    }
                } else {
                    // Start
                    monitoring.store(true, Ordering::Relaxed);
                    toggle_item.set_text("⏹ Stop Monitoring");
                    status_item.set_text("Status: 🟢 Monitoring Active");

                    *summary.lock().unwrap() = SessionSummary::new();
                    events.lock().unwrap().clear();

                    let cfg = config.lock().unwrap().clone();
                    println!("\n▶️  Monitoring started!");
                    println!("   Server: {}", cfg.mode_display());

                    // ── Start live sync thread ──────────
                    {
                        let sync_events = events.clone();
                        let sync_summary = summary.clone();
                        let sync_monitoring = monitoring.clone();
                        let sync_url = cfg.effective_url();
                        let sync_api_key = cfg.api_key.clone();
                        std::thread::spawn(move || {
                            let rt = tokio::runtime::Runtime::new().unwrap();
                            let mut last_synced = 0usize;
                            while sync_monitoring.load(Ordering::Relaxed) {
                                std::thread::sleep(std::time::Duration::from_secs(5));
                                if !sync_monitoring.load(Ordering::Relaxed) { break; }
                                let evts = sync_events.lock().unwrap().clone();
                                if evts.len() > last_synced {
                                    let new_events: Vec<_> = evts[last_synced..].to_vec();
                                    let session_id = sync_summary.lock().unwrap().session_id.clone();
                                    last_synced = evts.len();
                                    let _ = rt.block_on(
                                        reporter::sync_events(&sync_url, &sync_api_key, &session_id, &new_events)
                                    );
                                }
                            }
                        });
                    }

                    // File watcher
                    let cwd = cfg.watch_dir.clone().unwrap_or_else(|| {
                        std::env::current_dir()
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_else(|_| ".".to_string())
                    });
                    match fs_watcher::start_fs_watcher(&cwd, tx.clone()) {
                        Ok(w) => {
                            *watcher_handle.lock().unwrap() = Some(w);
                            println!("   📁 File watcher: {}", cwd);
                        }
                        Err(e) => eprintln!("   ⚠️  File watcher failed: {}", e),
                    }

                    // Command watcher
                    let home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
                    let hist = cfg.history_file.clone()
                        .unwrap_or_else(|| format!("{}/.zsh_history", home));
                    cmd_watcher::start_cmd_watcher(
                        &hist, tx.clone(),
                        std::time::Duration::from_secs(1),
                        monitoring.clone(),
                    );
                    println!("   🖥️  Command watcher: {}", hist);

                    // Process watcher (also detects shell processes)
                    process_watcher::start_process_watcher(
                        tx.clone(),
                        std::time::Duration::from_secs(2),
                        monitoring.clone(),
                    );
                    println!("   ⚙️  Process watcher: active");

                    // Network watcher
                    net_watcher::start_net_watcher(
                        tx.clone(),
                        std::time::Duration::from_secs(3),
                        monitoring.clone(),
                    );
                    println!("   🌐 Network watcher: active");

                    // Agent discovery watcher
                    agent_discovery::start_agent_discovery(
                        tx.clone(),
                        std::time::Duration::from_secs(10),
                        monitoring.clone(),
                    );
                    println!("   🔍 Agent discovery: active");
                }
            }
            // ── Toggle Server Mode ────────────────────
            else if event.id == server_mode_id {
                let mut cfg = config.lock().unwrap();
                if cfg.is_admin_locked() {
                    println!("🔒 Server mode locked by admin");
                } else {
                    cfg.next_mode();
                    let display = cfg.mode_display();
                    let url = cfg.effective_url();
                    server_mode_item.set_text(&format!("Server: {}", display));
                    server_url_item.set_text(&format!("   URL: {}", url));
                    println!("   Server mode → {}", display);

                    // Start embedded server if switching to embedded/auto
                    if (cfg.server_mode == "embedded" || cfg.server_mode == "auto")
                        && !embedded_server_running.load(Ordering::Relaxed)
                    {
                        start_embedded_server(cfg.embedded_port, embedded_server_running.clone());
                    }

                    // Save config
                    let _ = cfg.save();
                }
            }
            // ── Edit & Reload Config ──────────────────
            else if event.id == edit_config_id {
                let path = ai_spm_monitor::config::config_path();
                #[cfg(target_os = "macos")]
                let _ = std::process::Command::new("open").arg(&path).spawn();
                
                #[cfg(target_os = "windows")]
                let _ = std::process::Command::new("cmd").args(["/C", "start", "", path.to_str().unwrap()]).spawn();
                
                #[cfg(target_os = "linux")]
                let _ = std::process::Command::new("xdg-open").arg(&path).spawn();
                
                println!("\n✏️  Opened configuration file for editing: {:?}", path);
            }
            else if event.id == reload_config_id {
                let new_cfg = MonitorConfig::load();
                let mut cfg = config.lock().unwrap();
                *cfg = new_cfg;
                
                let display = cfg.mode_display();
                let url = cfg.effective_url();
                server_mode_item.set_text(&format!("Server: {}", display));
                server_url_item.set_text(&format!("   URL: {}", url));
                println!("\n🔄 Config reloaded! Server is now: {}", display);
            }
            // ── View Report ───────────────────────────
            else if event.id == report_id {
                let cfg = config.lock().unwrap();
                let url = cfg.effective_url();
                drop(cfg);

                let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                let dashboard_url = if url.ends_with('/') {
                    format!("{}?t={}#monitor", url, t)
                } else {
                    format!("{}/?t={}#monitor", url, t)
                };

                println!("\n📊 Opening dashboard report in window...");
                
                if active_window.is_none() {
                    let window = tao::window::WindowBuilder::new()
                        .with_title("AI-SPM Report")
                        .with_inner_size(tao::dpi::LogicalSize::new(1280.0, 850.0))
                        .build(event_loop_window_target)
                        .unwrap();

                    let builder = wry::WebViewBuilder::new().with_url(&dashboard_url);

                    #[cfg(any(
                        target_os = "windows",
                        target_os = "macos",
                        target_os = "ios",
                        target_os = "android"
                    ))]
                    let webview = builder.build(&window).unwrap();

                    #[cfg(not(any(
                        target_os = "windows",
                        target_os = "macos",
                        target_os = "ios",
                        target_os = "android"
                    )))]
                    let webview = {
                        use tao::platform::unix::WindowExtUnix;
                        use wry::WebViewBuilderExtUnix;
                        let vbox = window.default_vbox().unwrap();
                        builder.build_gtk(vbox).unwrap()
                    };

                    active_window = Some(window);
                    active_webview = Some(webview);
                } else {
                    if let Some(win) = &active_window {
                        win.set_focus();
                        // Note: To navigate existing webview, we'd need to send a message to it
                        // but focusing it is good enough for now.
                    }
                }
            }
            // ── Open Dashboard ────────────────────────
            else if event.id == dashboard_id {
                let cfg = config.lock().unwrap();
                let url = cfg.effective_url();
                drop(cfg);
                let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                let dashboard_url = if url.ends_with('/') {
                    format!("{}?t={}", url, t)
                } else {
                    format!("{}/?t={}", url, t)
                };

                if active_window.is_none() {
                    let window = tao::window::WindowBuilder::new()
                        .with_title("AI-SPM Dashboard")
                        .with_inner_size(tao::dpi::LogicalSize::new(1280.0, 850.0))
                        .build(event_loop_window_target)
                        .unwrap();

                    let builder = wry::WebViewBuilder::new().with_url(&dashboard_url);

                    #[cfg(any(
                        target_os = "windows",
                        target_os = "macos",
                        target_os = "ios",
                        target_os = "android"
                    ))]
                    let webview = builder.build(&window).unwrap();

                    #[cfg(not(any(
                        target_os = "windows",
                        target_os = "macos",
                        target_os = "ios",
                        target_os = "android"
                    )))]
                    let webview = {
                        use tao::platform::unix::WindowExtUnix;
                        use wry::WebViewBuilderExtUnix;
                        let vbox = window.default_vbox().unwrap();
                        builder.build_gtk(vbox).unwrap()
                    };

                    active_window = Some(window);
                    active_webview = Some(webview);
                } else {
                    if let Some(win) = &active_window {
                        win.set_focus();
                    }
                }
            }
            // ── Quit ──────────────────────────────────
            else if event.id == quit_id {
                monitoring.store(false, Ordering::Relaxed);
                let s = summary.lock().unwrap().clone();
                let e = events.lock().unwrap().clone();
                if s.total_commands + s.total_file_changes > 0 {
                    reporter::print_report(&s, &e);
                }
                println!("\n👋 AI-SPM Agent Monitor shutting down.");
                *control_flow = ControlFlow::Exit;
            }
        }

        if let Ok(_event) = TrayIconEvent::receiver().try_recv() {
            // Handled by menu
        }
    });
}

/// Start an embedded AI-SPM server in a background thread.
fn start_embedded_server(port: u16, running: Arc<AtomicBool>) {
    if running.load(Ordering::Relaxed) {
        println!("   📦 Embedded server already running on port {}", port);
        return;
    }

    println!("   📦 Starting embedded server on port {}...", port);
    running.store(true, Ordering::Relaxed);

    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
        rt.block_on(async {
            let mut config = ai_spm_core::config::AppConfig::development();
            
            // Fix relative paths so the .app bundle can create/open databases
            // regardless of its working directory.
            if let Some(mut home) = dirs::home_dir() {
                home.push(".ai-spm");
                std::fs::create_dir_all(home.join("data")).unwrap_or_default();
                std::fs::create_dir_all(home.join("data/golden_datasets")).unwrap_or_default();
                std::fs::create_dir_all(home.join("policies")).unwrap_or_default();

                config.identity.database_path = home.join(&config.identity.database_path).to_string_lossy().into();
                config.audit.log_file_path = home.join(&config.audit.log_file_path).to_string_lossy().into();
                config.audit.index_database_path = home.join(&config.audit.index_database_path).to_string_lossy().into();
                config.gateway.policies_dir = home.join(&config.gateway.policies_dir).to_string_lossy().into();
                config.redteam.golden_dataset_dir = home.join(&config.redteam.golden_dataset_dir).to_string_lossy().into();
            }

            match ai_spm_server::api::run_server(&config, "127.0.0.1", port).await {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("   ⚠️  Embedded server error: {}", e);
                    running.store(false, Ordering::Relaxed);
                }
            }
        });
    });
}

/// Create a simple shield-shaped icon (32×32 RGBA).
fn create_shield_icon(active: bool) -> tray_icon::Icon {
    let size = 32u32;
    let mut rgba = vec![0u8; (size * size * 4) as usize];

    for y in 0..size {
        for x in 0..size {
            let idx = ((y * size + x) * 4) as usize;
            let cx = size as f32 / 2.0;
            let cy = size as f32 / 2.0;
            let dx = (x as f32 - cx).abs();
            let dy = y as f32 - cy;

            let max_width = if y < size / 2 {
                cx * 0.85
            } else {
                cx * 0.85 * (1.0 - (dy / cy).powi(2)).max(0.0)
            };

            if dx < max_width && y > 2 && y < size - 2 {
                if active {
                    rgba[idx] = 76;
                    rgba[idx + 1] = 217;
                    rgba[idx + 2] = 100;
                } else {
                    rgba[idx] = 99;
                    rgba[idx + 1] = 132;
                    rgba[idx + 2] = 255;
                }
                rgba[idx + 3] = 255;
            }
        }
    }

    tray_icon::Icon::from_rgba(rgba, size, size).expect("Failed to create icon")
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}…", &s[..max - 1])
    } else {
        s.to_string()
    }
}

/// Open an HTML report in a native webview window (new thread).
#[allow(dead_code)]
fn open_report_window(html: String) {
    std::thread::spawn(move || {
        // Write HTML to temp file
        let tmp_dir = std::env::temp_dir();
        let report_path = tmp_dir.join("ai-spm-report.html");
        if let Err(e) = std::fs::write(&report_path, &html) {
            eprintln!("   ⚠️  Cannot write report: {}", e);
            return;
        }

        // Open in default browser (works cross-platform)
        let url = format!("file://{}", report_path.to_string_lossy());

        #[cfg(target_os = "macos")]
        let _ = std::process::Command::new("open").arg(&url).spawn();

        #[cfg(target_os = "windows")]
        let _ = std::process::Command::new("cmd").args(["/C", "start", &url]).spawn();

        #[cfg(target_os = "linux")]
        let _ = std::process::Command::new("xdg-open").arg(&url).spawn();

        println!("   📊 Report opened in browser");
    });
}
