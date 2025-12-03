//! Application state management

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use meshvpn_network::wireguard::WireGuardClient;

use crate::config::AppConfig;

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Error,
}

impl Default for ConnectionState {
    fn default() -> Self {
        ConnectionState::Disconnected
    }
}

/// Server information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub id: String,
    pub name: String,
    pub country: String,
    pub city: String,
    pub load: u8,
    pub latency_ms: Option<u32>,
    pub is_premium: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

/// Connection statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub connected_since: Option<i64>,
    pub uptime_secs: u64,
    pub current_server: Option<String>,
}

impl Default for ConnectionStats {
    fn default() -> Self {
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            connected_since: None,
            uptime_secs: 0,
            current_server: None,
        }
    }
}

/// Subscription status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionStatus {
    pub is_active: bool,
    pub tier: String,
    pub expires_at: Option<i64>,
    pub data_used: u64,
    pub data_limit: Option<u64>,
}

/// Application state
pub struct AppState {
    /// Configuration
    pub config: AppConfig,
    /// WireGuard client
    pub wg_client: Option<Arc<WireGuardClient>>,
    /// Current connection state
    pub connection_state: ConnectionState,
    /// Selected server
    pub selected_server: Option<ServerInfo>,
    /// Available servers
    pub servers: Vec<ServerInfo>,
    /// Connection start time
    pub connected_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Subscription status
    pub subscription: SubscriptionStatus,
    /// Config directory
    pub config_dir: PathBuf,
}

impl AppState {
    /// Create new app state
    pub fn new() -> Result<Self> {
        // Get config directory
        let config_dir = directories::ProjectDirs::from("com", "meshvpn", "MeshVPN")
            .context("Failed to get project directories")?
            .config_dir()
            .to_path_buf();

        // Create config dir if needed
        std::fs::create_dir_all(&config_dir)?;

        // Load or create config
        let config_path = config_dir.join("config.toml");
        let config = if config_path.exists() {
            let contents = std::fs::read_to_string(&config_path)?;
            toml::from_str(&contents)?
        } else {
            AppConfig::default()
        };

        // Real servers from AWS EC2
        let servers = vec![
            ServerInfo {
                id: "us-east-1-real".to_string(),
                name: "US East (Live)".to_string(),
                country: "United States".to_string(),
                city: "Virginia".to_string(),
                load: 5,
                latency_ms: None,
                is_premium: false,
                endpoint: Some("54.160.213.165:51820".to_string()),
            },
        ];

        Ok(Self {
            config,
            wg_client: None,
            connection_state: ConnectionState::Disconnected,
            selected_server: servers.first().cloned(),
            servers,
            connected_at: None,
            subscription: SubscriptionStatus {
                is_active: false,
                tier: "free".to_string(),
                expires_at: None,
                data_used: 0,
                data_limit: Some(5 * 1024 * 1024 * 1024), // 5GB free tier
            },
            config_dir,
        })
    }

    /// Save configuration
    pub fn save_config(&self) -> Result<()> {
        let config_path = self.config_dir.join("config.toml");
        let contents = toml::to_string_pretty(&self.config)?;
        std::fs::write(config_path, contents)?;
        Ok(())
    }

    /// Get current status
    pub fn get_status(&self) -> ConnectionState {
        self.connection_state
    }

    /// Get connection stats
    pub async fn get_stats(&self) -> ConnectionStats {
        let mut stats = ConnectionStats::default();

        if let Some(connected_at) = self.connected_at {
            stats.connected_since = Some(connected_at.timestamp());
            stats.uptime_secs = (chrono::Utc::now() - connected_at).num_seconds() as u64;
        }

        if let Some(server) = &self.selected_server {
            stats.current_server = Some(server.name.clone());
        }

        // Get real traffic stats from WireGuard client
        if let Some(wg_client) = &self.wg_client {
            let tun_stats = wg_client.get_stats();
            stats.bytes_received = tun_stats.bytes_rx;
            stats.bytes_sent = tun_stats.bytes_tx;
            stats.packets_received = tun_stats.packets_rx;
            stats.packets_sent = tun_stats.packets_tx;
        }

        stats
    }
}
