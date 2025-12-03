//! Exit node configuration

use serde::{Deserialize, Serialize};

/// Exit node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitConfig {
    /// Network interface for outbound traffic
    pub outbound_interface: String,
    /// Region identifier
    pub region: String,
    /// Maximum concurrent connections
    pub max_connections: usize,
    /// Bandwidth limit (bytes/sec, 0 = unlimited)
    pub bandwidth_limit: u64,
    /// Logging configuration
    pub logging: LoggingConfig,
    /// Sync configuration
    pub sync: SyncConfig,
    /// Token verification public key
    pub issuer_pubkey: Option<String>,
}

/// Logging configuration for legal compliance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Enable logging
    pub enabled: bool,
    /// Log file path
    pub path: String,
    /// Encrypt logs
    pub encrypt: bool,
    /// Encryption key (hex)
    pub encryption_key: Option<String>,
    /// Retention days
    pub retention_days: u32,
    /// Log format (json, csv)
    pub format: String,
}

/// Region sync configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    /// Enable sync
    pub enabled: bool,
    /// DynamoDB table name
    pub dynamodb_table: Option<String>,
    /// S3 bucket for log backup
    pub s3_bucket: Option<String>,
    /// AWS region
    pub aws_region: String,
    /// Sync interval seconds
    pub interval_secs: u64,
}

impl Default for ExitConfig {
    fn default() -> Self {
        Self {
            outbound_interface: "eth0".to_string(),
            region: "us-east-1".to_string(),
            max_connections: 10000,
            bandwidth_limit: 0,
            logging: LoggingConfig {
                enabled: true,
                path: "/var/log/meshvpn/connections.log".to_string(),
                encrypt: true,
                encryption_key: None,
                retention_days: 90,
                format: "json".to_string(),
            },
            sync: SyncConfig {
                enabled: false,
                dynamodb_table: None,
                s3_bucket: None,
                aws_region: "us-east-1".to_string(),
                interval_secs: 60,
            },
            issuer_pubkey: None,
        }
    }
}
