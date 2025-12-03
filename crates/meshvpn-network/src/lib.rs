//! MeshVPN Network Layer
//!
//! Provides network primitives:
//! - TUN/TAP adapters for capturing traffic
//! - UDP transport for relay communication
//! - NAT traversal (STUN/hole punching)
//! - Connection management

pub mod error;
pub mod transport;
pub mod tun;
pub mod nat;
pub mod connection;
pub mod packet;
pub mod wireguard;
pub mod p2p;

pub use error::{NetworkError, NetworkResult};
pub use transport::{UdpTransport, TransportMessage};
pub use connection::{Connection, ConnectionPool, ConnectionState};
pub use packet::{Packet, PacketType};
pub use wireguard::{WireGuardClient, WireGuardConfig};
pub use tun::TrafficStats;
pub use p2p::{
    PeerId, PeerInfo, NatType, P2PMessage,
    StunClient, HolePuncher, DiscoveryClient,
};

/// Network configuration
#[derive(Clone, Debug)]
pub struct NetworkConfig {
    /// Local UDP port for listening
    pub listen_port: u16,

    /// TUN device name (e.g., "meshvpn0")
    pub tun_name: String,

    /// TUN device IP address
    pub tun_address: std::net::Ipv4Addr,

    /// TUN subnet mask
    pub tun_netmask: std::net::Ipv4Addr,

    /// MTU for TUN device
    pub mtu: u16,

    /// Enable NAT traversal
    pub enable_nat_traversal: bool,

    /// STUN servers for NAT discovery
    pub stun_servers: Vec<String>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_port: 51820,
            tun_name: "meshvpn0".to_string(),
            tun_address: std::net::Ipv4Addr::new(10, 200, 0, 1),
            tun_netmask: std::net::Ipv4Addr::new(255, 255, 0, 0),
            mtu: 1420,
            enable_nat_traversal: true,
            stun_servers: vec![
                "stun.l.google.com:19302".to_string(),
                "stun1.l.google.com:19302".to_string(),
            ],
        }
    }
}
