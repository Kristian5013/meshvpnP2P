//! Linux TUN device implementation

use async_trait::async_trait;
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info};

use super::{TunConfig, TunDevice};
use crate::error::{NetworkError, NetworkResult};

/// Linux TUN device
pub struct LinuxTun {
    device: tokio::sync::Mutex<tun::AsyncDevice>,
    name: String,
    mtu: u16,
}

impl LinuxTun {
    /// Create a new Linux TUN device
    pub async fn create(config: TunConfig) -> NetworkResult<Self> {
        let mut tun_config = tun::Configuration::default();

        tun_config
            .name(&config.name)
            .address(config.address)
            .netmask(config.netmask)
            .mtu(config.mtu as i32)
            .up();

        // Enable packet info header on Linux
        #[cfg(target_os = "linux")]
        tun_config.platform(|platform| {
            platform.packet_information(false);
        });

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
        let output = Command::new("ip")
            .args(["route", "add", "default", "via", &gateway.to_string(), "dev", &self.name])
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
impl TunDevice for LinuxTun {
    async fn read(&self) -> NetworkResult<Bytes> {
        let mut buf = vec![0u8; self.mtu as usize + 4];
        let mut device = self.device.lock().await;

        let n = device.read(&mut buf).await.map_err(|e| {
            NetworkError::TunError(format!("Failed to read from TUN: {}", e))
        })?;

        buf.truncate(n);
        Ok(Bytes::from(buf))
    }

    async fn write(&self, packet: &[u8]) -> NetworkResult<()> {
        let mut device = self.device.lock().await;

        device.write_all(packet).await.map_err(|e| {
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
        // Device will be closed when dropped
        debug!("Closing TUN device: {}", self.name);
        Ok(())
    }

    async fn set_default_route(&self, _server_endpoint: std::net::SocketAddr) -> NetworkResult<()> {
        // Linux routing handled externally or via ip command
        Ok(())
    }

    async fn remove_default_route(&self) -> NetworkResult<()> {
        // Linux routing handled externally
        Ok(())
    }

    fn get_stats(&self) -> super::TrafficStats {
        super::TrafficStats::default()
    }
}
