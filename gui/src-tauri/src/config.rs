//! Application configuration

use serde::{Deserialize, Serialize};

/// Application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Auto-connect on startup
    pub auto_connect: bool,
    /// Enable kill switch (block traffic when disconnected)
    pub kill_switch: bool,
    /// Start minimized to tray
    pub start_minimized: bool,
    /// Show notifications
    pub notifications: bool,
    /// Theme (light, dark, system)
    pub theme: String,
    /// VPN listen port
    pub listen_port: u16,
    /// Preferred server ID
    pub preferred_server: Option<String>,
    /// DNS servers to use
    pub dns_servers: Vec<String>,
    /// Enable split tunneling
    pub split_tunneling: bool,
    /// Excluded apps (for split tunneling)
    pub excluded_apps: Vec<String>,
    /// P2P peer ID
    pub peer_id: Option<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            auto_connect: false,
            kill_switch: false,
            start_minimized: false,
            notifications: true,
            theme: "system".to_string(),
            listen_port: 51820,
            preferred_server: None,
            dns_servers: vec![
                "1.1.1.1".to_string(),
                "8.8.8.8".to_string(),
            ],
            split_tunneling: false,
            excluded_apps: Vec::new(),
            peer_id: None,
        }
    }
}

/// Settings exposed to UI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub auto_connect: bool,
    pub kill_switch: bool,
    pub start_minimized: bool,
    pub notifications: bool,
    pub theme: String,
}

impl From<&AppConfig> for AppSettings {
    fn from(config: &AppConfig) -> Self {
        Self {
            auto_connect: config.auto_connect,
            kill_switch: config.kill_switch,
            start_minimized: config.start_minimized,
            notifications: config.notifications,
            theme: config.theme.clone(),
        }
    }
}
