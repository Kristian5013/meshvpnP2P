//! P2P Networking Module
//!
//! Provides peer-to-peer connectivity with NAT traversal:
//! - STUN client for NAT type detection
//! - UDP hole punching for direct P2P connections
//! - Discovery service integration
//! - Relay node support for symmetric NAT
//! - Circuit-based onion routing for multi-hop connections

pub mod protocol;
pub mod stun;
pub mod hole_punch;
pub mod discovery;
pub mod relay;
pub mod circuit;

pub use protocol::{
    P2PMessage, PeerId, PeerInfo, NatType, PeerCapabilities,
    serialize_message, deserialize_message,
};
pub use stun::{StunClient, StunResult, DEFAULT_STUN_SERVERS};
pub use hole_punch::{HolePuncher, HolePunchResult};
pub use discovery::DiscoveryClient;
pub use relay::{RelayServer, RelayClient, RelayMessage, RelayStats};
pub use circuit::{CircuitBuilder, CircuitNode, CircuitMessage, CircuitInfo, CircuitId};
