//! macOS TUN device implementation

use async_trait::async_trait;
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info};

use super::{TunConfig, TunDevice};
use crate::error::{NetworkError, NetworkResult};

/// macOS TUN device
pub struct MacOsTun {
    device: tokio::sync::Mutex<tun::AsyncDevice>,
    name: String,
    mtu: u16,
}

impl MacOsTun {
    /// Create a new macOS TUN device
    pub async fn create(config: TunConfig) -> NetworkResult<Self> {
        let mut tun_config = tun::Configuration::default();

        tun_config
            .name(&config.name)
            .address(config.address)
            .netmask(config.netmask)
            .mtu(config.mtu as i32)
            .up();

        let device = tun::create_as_async(&tun_config).map_err(|e| {
            NetworkError::TunError(format!("Failed to create TUN device: {}", e))
        })?;

        let name = config.name.clone();
        info!("Created TUN device: {} with IP {}/{}", name, config.address, config.netmask);

        Ok(Self {
            device: tokio::sync::Mutex::new(device),
            name,
            mtu: config.mtu,
        })
    }

    /// Configure routing for the TUN device
    pub async fn setup_routing(&self, gateway: std::net::Ipv4Addr) -> NetworkResult<()> {
        use tokio::process::Command;

        // Add default route through TUN
        let output = Command::new("route")
            .args(["-n", "add", "-net", "0.0.0.0/1", &gateway.to_string()])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            debug!("Route add result: {}", stderr);
        }

        // Add second half of address space
        let output = Command::new("route")
            .args(["-n", "add", "-net", "128.0.0.0/1", &gateway.to_string()])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            debug!("Route add result: {}", stderr);
        }

        Ok(())
    }
}

#[async_trait]
impl TunDevice for MacOsTun {
    async fn read(&self) -> NetworkResult<Bytes> {
        let mut buf = vec![0u8; self.mtu as usize + 4];
        let mut device = self.device.lock().await;

        let n = device.read(&mut buf).await.map_err(|e| {
            NetworkError::TunError(format!("Failed to read from TUN: {}", e))
        })?;

        // macOS includes 4-byte header, skip it
        if n > 4 {
            Ok(Bytes::from(buf[4..n].to_vec()))
        } else {
            Ok(Bytes::new())
        }
    }

    async fn write(&self, packet: &[u8]) -> NetworkResult<()> {
        let mut device = self.device.lock().await;

        // Prepend 4-byte header for macOS (AF_INET = 2)
        let mut buf = vec![0u8; packet.len() + 4];
        buf[3] = 2; // AF_INET for IPv4
        buf[4..].copy_from_slice(packet);

        device.write_all(&buf).await.map_err(|e| {
            NetworkError::TunError(format!("Failed to write to TUN: {}", e))
        })?;

        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }

    async fn close(&self) -> NetworkResult<()> {
        debug!("Closing TUN device: {}", self.name);
        Ok(())
    }
}
