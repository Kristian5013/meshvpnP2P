//! System tray functionality

use tauri::{
    AppHandle, Manager,
    tray::{TrayIcon, TrayIconBuilder, MouseButton, MouseButtonState},
    menu::{Menu, MenuItem, PredefinedMenuItem},
};
use tracing::info;

/// Setup system tray
pub fn setup_tray(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    info!("Setting up system tray...");

    // Create menu items
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let show = MenuItem::with_id(app, "show", "Show", true, None::<&str>)?;
    let connect = MenuItem::with_id(app, "connect", "Connect", true, None::<&str>)?;
    let disconnect = MenuItem::with_id(app, "disconnect", "Disconnect", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;

    // Build menu
    let menu = Menu::with_items(
        app,
        &[&show, &separator, &connect, &disconnect, &separator, &quit],
    )?;

    // Build tray icon
    let _tray = TrayIconBuilder::new()
        .menu(&menu)
        .tooltip("MeshVPN - Disconnected")
        .on_menu_event(|app, event| {
            match event.id.as_ref() {
                "quit" => {
                    info!("Quit requested from tray");
                    app.exit(0);
                }
                "show" => {
                    info!("Show requested from tray");
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                }
                "connect" => {
                    info!("Connect requested from tray");
                    // Would trigger connect command
                }
                "disconnect" => {
                    info!("Disconnect requested from tray");
                    // Would trigger disconnect command
                }
                _ => {}
            }
        })
        .on_tray_icon_event(|tray, event| {
            if let tauri::tray::TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                let app = tray.app_handle();
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
        })
        .build(app)?;

    info!("System tray setup complete");
    Ok(())
}

/// Update tray tooltip and icon based on connection state
pub fn update_tray_state(app: &AppHandle, connected: bool, server_name: Option<&str>) {
    // In production, this would update the tray icon and tooltip
    let tooltip = if connected {
        format!("MeshVPN - Connected to {}", server_name.unwrap_or("Unknown"))
    } else {
        "MeshVPN - Disconnected".to_string()
    };

    info!("Tray state updated: {}", tooltip);
}
