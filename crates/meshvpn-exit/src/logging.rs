//! Legal compliance logging
//!
//! Logs connection metadata (NOT content) for legal compliance.
//! - Timestamp
//! - Exit IP used
//! - Destination IP/port
//! - Bytes transferred
//!
//! Does NOT log:
//! - Packet contents
//! - Full circuit path
//! - User identity

use std::net::IpAddr;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::config::LoggingConfig;
use crate::error::{ExitError, ExitResult};

/// Connection log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionLog {
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Exit node IP
    pub exit_ip: IpAddr,
    /// Destination IP
    pub destination_ip: IpAddr,
    /// Destination port
    pub destination_port: u16,
    /// Protocol (TCP=6, UDP=17)
    pub protocol: u8,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Connection duration (seconds)
    pub duration_secs: u64,
}

/// Compliance logger
pub struct ComplianceLogger {
    /// Log file path
    path: PathBuf,
    /// Log file handle
    file: Mutex<Option<File>>,
    /// Encryption enabled
    encrypt: bool,
    /// Encryption key
    encryption_key: Option<[u8; 32]>,
    /// Log format
    format: LogFormat,
    /// Is logging enabled
    enabled: bool,
}

/// Log format
#[derive(Debug, Clone, Copy)]
pub enum LogFormat {
    Json,
    Csv,
}

impl ComplianceLogger {
    /// Create a new logger
    pub fn new(config: &LoggingConfig) -> ExitResult<Self> {
        let format = match config.format.to_lowercase().as_str() {
            "csv" => LogFormat::Csv,
            _ => LogFormat::Json,
        };

        let encryption_key = config.encryption_key.as_ref().and_then(|key| {
            hex_decode(key).ok().and_then(|bytes| {
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    Some(arr)
                } else {
                    None
                }
            })
        });

        Ok(Self {
            path: PathBuf::from(&config.path),
            file: Mutex::new(None),
            encrypt: config.encrypt,
            encryption_key,
            format,
            enabled: config.enabled,
        })
    }

    /// Log a connection (minimal metadata only)
    pub async fn log_connection(
        &self,
        _circuit_id: u32, // Not logged for privacy
        destination: IpAddr,
    ) -> ExitResult<()> {
        if !self.enabled {
            return Ok(());
        }

        let entry = ConnectionLog {
            timestamp: Utc::now(),
            exit_ip: IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), // TODO: Get actual exit IP
            destination_ip: destination,
            destination_port: 0, // Would be extracted from packet
            protocol: 6,         // TCP
            bytes_sent: 0,
            bytes_received: 0,
            duration_secs: 0,
        };

        self.write_entry(&entry).await
    }

    /// Write a log entry
    async fn write_entry(&self, entry: &ConnectionLog) -> ExitResult<()> {
        let mut file_guard = self.file.lock().await;

        // Open file if not already open
        if file_guard.is_none() {
            // Ensure parent directory exists
            if let Some(parent) = self.path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }

            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
                .await?;

            *file_guard = Some(file);
        }

        let file = file_guard.as_mut().unwrap();

        // Format entry
        let mut line = match self.format {
            LogFormat::Json => {
                serde_json::to_string(entry)
                    .map_err(|e| ExitError::LoggingError(e.to_string()))?
            }
            LogFormat::Csv => {
                format!(
                    "{},{},{},{},{},{},{},{}",
                    entry.timestamp.to_rfc3339(),
                    entry.exit_ip,
                    entry.destination_ip,
                    entry.destination_port,
                    entry.protocol,
                    entry.bytes_sent,
                    entry.bytes_received,
                    entry.duration_secs
                )
            }
        };
        line.push('\n');

        // Encrypt if enabled
        let data = if self.encrypt {
            if let Some(key) = &self.encryption_key {
                self.encrypt_line(&line, key)?
            } else {
                warn!("Encryption enabled but no key provided");
                line.into_bytes()
            }
        } else {
            line.into_bytes()
        };

        file.write_all(&data).await?;
        file.flush().await?;

        Ok(())
    }

    /// Encrypt a log line
    fn encrypt_line(&self, line: &str, key: &[u8; 32]) -> ExitResult<Vec<u8>> {
        use meshvpn_crypto::{encrypt, Nonce, SymmetricKey};

        let sym_key = SymmetricKey::from_bytes(*key);
        let nonce = Nonce::generate();

        let ciphertext = encrypt(&sym_key, &nonce, line.as_bytes())
            .map_err(|e| ExitError::LoggingError(e.to_string()))?;

        // Format: [nonce (12 bytes)][ciphertext]
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(nonce.as_bytes());
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Rotate log files
    pub async fn rotate(&self) -> ExitResult<()> {
        let mut file_guard = self.file.lock().await;

        // Close current file
        *file_guard = None;

        // Rename current log
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let rotated_path = self.path.with_extension(format!("{}.log", timestamp));

        if self.path.exists() {
            tokio::fs::rename(&self.path, &rotated_path).await?;
            debug!("Rotated log to {:?}", rotated_path);
        }

        Ok(())
    }
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, ()> {
    if hex.len() % 2 != 0 {
        return Err(());
    }

    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| ()))
        .collect()
}
