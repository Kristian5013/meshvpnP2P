//! MeshVPN Desktop GUI Application
//!
//! Built with Tauri for cross-platform desktop support.

// Temporarily show console for debugging
// #![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod state;
mod config;
mod tray;

use std::sync::Arc;
use std::io::Write;
use tauri::Manager;
use tokio::sync::RwLock;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use state::AppState;

fn main() {
    // Set up panic hook to write to file
    std::panic::set_hook(Box::new(|panic_info| {
        let log_path = std::env::temp_dir().join("meshvpn_crash.log");
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
            let _ = writeln!(file, "=== PANIC at {} ===", chrono::Utc::now());
            let _ = writeln!(file, "{}", panic_info);
            if let Some(location) = panic_info.location() {
                let _ = writeln!(file, "Location: {}:{}:{}", location.file(), location.line(), location.column());
            }
            let _ = writeln!(file, "Backtrace:\n{:?}", std::backtrace::Backtrace::capture());
        }
        eprintln!("PANIC: {}", panic_info);
    }));

    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set tracing subscriber");

    info!("Starting MeshVPN GUI...");

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--minimized"]),
        ))
        .setup(|app| {
            info!("Setting up application...");

            // Initialize app state
            let state = Arc::new(RwLock::new(AppState::new()?));
            app.manage(state);

            // Setup system tray
            tray::setup_tray(app)?;

            info!("Application setup complete");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::connect,
            commands::disconnect,
            commands::get_status,
            commands::get_stats,
            commands::get_servers,
            commands::set_server,
            commands::get_settings,
            commands::update_settings,
            commands::get_subscription_status,
            commands::create_payment,
            commands::check_payment,
            commands::get_logs,
            commands::export_identity,
            commands::import_identity,
            commands::generate_identity,
            commands::get_public_ip,
            commands::open_vpn_config,
            // P2P commands
            commands::detect_nat,
            commands::discover_peers,
            commands::connect_peer,
            commands::register_p2p,
            commands::connect_via_relay,
            commands::check_dht_status,
            // Circuit/Onion routing commands
            commands::build_circuit,
            commands::destroy_circuit,
            commands::connect_via_circuit,
        ])
        .run(tauri::generate_context!())
        .expect("Failed to run application");
}
