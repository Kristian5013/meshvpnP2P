//! Client configuration

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Main client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Network configuration
    pub network: NetworkConfig,
    /// Circuit configuration
    pub circuit: CircuitConfig,
    /// Relay configuration (if acting as relay)
    pub relay: RelayConfig,
    /// Bootstrap nodes
    pub bootstrap: BootstrapConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Local listen port
    pub listen_port: u16,
    /// TUN device name
    pub tun_name: String,
    /// TUN device IP
    pub tun_ip: String,
    /// TUN netmask
    pub tun_netmask: String,
    /// MTU
    pub mtu: u16,
    /// Enable IPv6
    pub enable_ipv6: bool,
    /// DNS servers to use
    pub dns_servers: Vec<String>,
}

/// Circuit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitConfig {
    /// Number of relay hops (1-5)
    pub hop_count: usize,
    /// Preferred exit region
    pub preferred_region: Option<String>,
    /// Circuit rotation interval (seconds)
    pub rotation_interval: u64,
    /// Use guard nodes
    pub use_guards: bool,
    /// Prefer geographic diversity
    pub geo_diversity: bool,
}

/// Relay configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    /// Enable relay mode
    pub enabled: bool,
    /// Maximum circuits to relay
    pub max_circuits: usize,
    /// Bandwidth limit (bytes/sec, 0 = unlimited)
    pub bandwidth_limit: u64,
    /// Advertise as relay in DHT
    pub advertise: bool,
}

/// Bootstrap configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapConfig {
    /// Bootstrap node addresses
    pub nodes: Vec<String>,
    /// Custom bootstrap nodes (added to default)
    pub custom_nodes: Vec<String>,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    pub level: String,
    /// Log to file
    pub file: Option<String>,
    /// Enable structured logging
    pub structured: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig {
                listen_port: 51820,
                tun_name: "meshvpn0".to_string(),
                tun_ip: "10.200.0.1".to_string(),
                tun_netmask: "255.255.0.0".to_string(),
                mtu: 1420,
                enable_ipv6: false,
                dns_servers: vec![
                    "1.1.1.1".to_string(),
                    "1.0.0.1".to_string(),
                ],
            },
            circuit: CircuitConfig {
                hop_count: 3,
                preferred_region: None,
                rotation_interval: 600,
                use_guards: true,
                geo_diversity: true,
            },
            relay: RelayConfig {
                enabled: true,
                max_circuits: 100,
                bandwidth_limit: 0,
                advertise: true,
            },
            bootstrap: BootstrapConfig {
                nodes: vec![
                    "bootstrap1.meshvpn.net:51820".to_string(),
                    "bootstrap2.meshvpn.net:51820".to_string(),
                    "bootstrap3.meshvpn.net:51820".to_string(),
                ],
                custom_nodes: vec![],
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                file: None,
                structured: false,
            },
        }
    }
}

impl ClientConfig {
    /// Load configuration from file
    pub async fn load(path: &Path) -> Result<Self> {
        let contents = tokio::fs::read_to_string(path)
            .await
            .context("Failed to read config file")?;

        toml::from_str(&contents).context("Failed to parse config file")
    }

    /// Load or create default configuration
    pub async fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            Self::load(path).await
        } else {
            let config = Self::default();
            config.save(path).await?;
            Ok(config)
        }
    }

    /// Save configuration to file
    pub async fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let contents = toml::to_string_pretty(self)?;
        tokio::fs::write(path, contents).await?;
        Ok(())
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        if self.circuit.hop_count == 0 || self.circuit.hop_count > 7 {
            anyhow::bail!("hop_count must be between 1 and 7");
        }

        if self.network.mtu < 576 || self.network.mtu > 1500 {
            anyhow::bail!("MTU must be between 576 and 1500");
        }

        Ok(())
    }
}
