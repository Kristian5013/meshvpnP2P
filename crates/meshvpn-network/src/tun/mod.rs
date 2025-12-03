//! TUN Device Abstraction
//!
//! Platform-agnostic TUN device interface with implementations for:
//! - Linux (using tun crate)
//! - Windows (using wintun)
//! - macOS (using tun crate)

use async_trait::async_trait;
use bytes::Bytes;

use crate::error::NetworkResult;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::LinuxTun;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::WindowsTun;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::MacOsTun;

/// TUN device configuration
#[derive(Clone, Debug)]
pub struct TunConfig {
    /// Device name (e.g., "meshvpn0")
    pub name: String,

    /// Device IP address
    pub address: std::net::Ipv4Addr,

    /// Subnet mask
    pub netmask: std::net::Ipv4Addr,

    /// Maximum transmission unit
    pub mtu: u16,

    /// Enable packet queueing
    pub queued: bool,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "meshvpn0".to_string(),
            address: std::net::Ipv4Addr::new(10, 200, 0, 1),
            netmask: std::net::Ipv4Addr::new(255, 255, 0, 0),
            mtu: 1420,
            queued: true,
        }
    }
}

/// Traffic statistics
#[derive(Debug, Clone, Default)]
pub struct TrafficStats {
    pub bytes_rx: u64,
    pub bytes_tx: u64,
    pub packets_rx: u64,
    pub packets_tx: u64,
}

/// Platform-agnostic TUN device trait
#[async_trait]
pub trait TunDevice: Send + Sync {
    /// Read a packet from the TUN device
    async fn read(&self) -> NetworkResult<Bytes>;

    /// Write a packet to the TUN device
    async fn write(&self, packet: &[u8]) -> NetworkResult<()>;

    /// Get device name
    fn name(&self) -> &str;

    /// Get device MTU
    fn mtu(&self) -> u16;

    /// Close the device
    async fn close(&self) -> NetworkResult<()>;

    /// Set up default route through this adapter (route all traffic through VPN)
    async fn set_default_route(&self, server_endpoint: std::net::SocketAddr) -> NetworkResult<()>;

    /// Remove default route
    async fn remove_default_route(&self) -> NetworkResult<()>;

    /// Get traffic statistics
    fn get_stats(&self) -> TrafficStats;
}

/// Create a TUN device for the current platform
pub async fn create_tun(config: TunConfig) -> NetworkResult<Box<dyn TunDevice>> {
    #[cfg(target_os = "linux")]
    {
        let tun = LinuxTun::create(config).await?;
        Ok(Box::new(tun))
    }

    #[cfg(target_os = "windows")]
    {
        let tun = WindowsTun::create(config).await?;
        Ok(Box::new(tun))
    }

    #[cfg(target_os = "macos")]
    {
        let tun = MacOsTun::create(config).await?;
        Ok(Box::new(tun))
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        Err(crate::error::NetworkError::PlatformNotSupported)
    }
}

/// IP packet parser utilities
pub mod ip {
    use bytes::Bytes;

    /// IP version
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum IpVersion {
        V4,
        V6,
    }

    /// Get IP version from packet
    pub fn get_version(packet: &[u8]) -> Option<IpVersion> {
        if packet.is_empty() {
            return None;
        }

        match packet[0] >> 4 {
            4 => Some(IpVersion::V4),
            6 => Some(IpVersion::V6),
            _ => None,
        }
    }

    /// Get destination IP from IPv4 packet
    pub fn get_ipv4_dst(packet: &[u8]) -> Option<std::net::Ipv4Addr> {
        if packet.len() < 20 {
            return None;
        }

        Some(std::net::Ipv4Addr::new(
            packet[16],
            packet[17],
            packet[18],
            packet[19],
        ))
    }

    /// Get source IP from IPv4 packet
    pub fn get_ipv4_src(packet: &[u8]) -> Option<std::net::Ipv4Addr> {
        if packet.len() < 20 {
            return None;
        }

        Some(std::net::Ipv4Addr::new(
            packet[12],
            packet[13],
            packet[14],
            packet[15],
        ))
    }

    /// Check if this is a DNS packet (UDP port 53)
    pub fn is_dns_packet(packet: &[u8]) -> bool {
        if packet.len() < 28 {
            return false;
        }

        // Check if UDP (protocol 17)
        if packet[9] != 17 {
            return false;
        }

        // Get header length
        let ihl = ((packet[0] & 0x0F) * 4) as usize;
        if packet.len() < ihl + 4 {
            return false;
        }

        // Check UDP port
        let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
        dst_port == 53
    }
}
