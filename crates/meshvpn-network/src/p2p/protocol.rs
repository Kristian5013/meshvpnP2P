//! P2P Protocol Messages for NAT Traversal and Peer Discovery
//!
//! This module defines the wire protocol for peer-to-peer communication
//! in the MeshVPN network.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Unique peer identifier (derived from public key)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId(pub [u8; 32]);

impl PeerId {
    pub fn from_public_key(key: &[u8; 32]) -> Self {
        // Use BLAKE3 hash of public key
        let hash = blake3::hash(key);
        Self(*hash.as_bytes())
    }

    /// Short hex form for display (8 bytes = 16 chars)
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0[..8])
    }

    /// Full hex form for data transfer (32 bytes = 64 chars)
    pub fn to_full_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Parse from full hex string (64 chars)
    pub fn from_hex(hex_str: &str) -> Option<Self> {
        let bytes = hex::decode(hex_str).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(Self(arr))
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// NAT type as detected by STUN
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NatType {
    /// No NAT (public IP)
    None,
    /// Full Cone NAT - easiest to traverse
    FullCone,
    /// Address Restricted Cone NAT
    AddressRestricted,
    /// Port Restricted Cone NAT
    PortRestricted,
    /// Symmetric NAT - requires TURN
    Symmetric,
    /// Unknown/couldn't detect
    Unknown,
}

impl NatType {
    /// Can this NAT type do direct P2P with the other?
    pub fn can_direct_connect(&self, other: &NatType) -> bool {
        match (self, other) {
            // Symmetric NAT on either side usually needs TURN
            (NatType::Symmetric, _) | (_, NatType::Symmetric) => false,
            // All other combinations can use hole punching
            _ => true,
        }
    }
}

/// Peer's network information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Unique peer identifier
    pub peer_id: PeerId,
    /// Public endpoint (as seen by STUN server)
    pub public_addr: SocketAddr,
    /// Local/private address (for same-LAN detection)
    pub local_addr: Option<SocketAddr>,
    /// Detected NAT type
    pub nat_type: NatType,
    /// X25519 public key for encryption
    pub public_key: [u8; 32],
    /// Capabilities/flags
    pub capabilities: PeerCapabilities,
    /// Last seen timestamp (Unix epoch seconds)
    pub last_seen: u64,
}

impl PeerInfo {
    pub fn new(
        peer_id: PeerId,
        public_addr: SocketAddr,
        public_key: [u8; 32],
    ) -> Self {
        Self {
            peer_id,
            public_addr,
            local_addr: None,
            nat_type: NatType::Unknown,
            public_key,
            capabilities: PeerCapabilities::default(),
            last_seen: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

/// Peer capabilities bitflags
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct PeerCapabilities {
    /// Can act as a relay node
    pub can_relay: bool,
    /// Has high bandwidth (> 10 Mbps)
    pub high_bandwidth: bool,
    /// Long uptime (> 1 hour)
    pub stable: bool,
    /// Can provide TURN relay
    pub turn_server: bool,
}

/// Protocol message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum P2PMessage {
    // === Discovery Messages (to/from EC2) ===

    /// Register this peer with discovery service
    Register(RegisterRequest),
    /// Registration response
    RegisterAck(RegisterResponse),

    /// Request list of available peers
    GetPeers(GetPeersRequest),
    /// List of peers response
    PeerList(PeerListResponse),

    /// Heartbeat to keep registration alive
    Heartbeat(HeartbeatRequest),
    HeartbeatAck,

    // === NAT Traversal Messages ===

    /// Request to connect to a peer (via discovery server)
    ConnectRequest(ConnectRequest),
    /// Connection info forwarded to target peer
    ConnectOffer(ConnectOffer),
    /// Target peer's response
    ConnectAnswer(ConnectAnswer),

    // === Direct P2P Messages ===

    /// Hole punch packet (sent simultaneously by both peers)
    HolePunch(HolePunchPacket),
    /// Hole punch acknowledgment
    HolePunchAck(HolePunchAck),

    /// Ping for latency measurement and keepalive
    Ping(PingPacket),
    Pong(PongPacket),

    // === Data Messages ===

    /// Encrypted data packet
    Data(DataPacket),
    /// Relay packet (when acting as relay node)
    Relay(RelayPacket),

    // === Error ===
    Error(ErrorResponse),
}

// === Discovery Messages ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub peer_info: PeerInfo,
    /// Signed with peer's private key (Ed25519 signature)
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub success: bool,
    /// Server's view of our public address
    pub observed_addr: SocketAddr,
    /// Detected NAT type
    pub nat_type: NatType,
    /// Registration expiry (seconds)
    pub ttl: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetPeersRequest {
    pub requesting_peer: PeerId,
    /// Maximum number of peers to return
    pub limit: u32,
    /// Filter by capabilities
    pub require_relay: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerListResponse {
    pub peers: Vec<PeerInfo>,
    /// Total available peers
    pub total_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub peer_id: PeerId,
    /// Current stats
    pub bytes_relayed: u64,
    pub active_connections: u32,
}

// === NAT Traversal Messages ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectRequest {
    pub from_peer: PeerId,
    pub to_peer: PeerId,
    /// Our public key for this session
    pub session_pubkey: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectOffer {
    pub from_peer: PeerId,
    pub from_addr: SocketAddr,
    pub from_local_addr: Option<SocketAddr>,
    pub from_nat_type: NatType,
    pub session_pubkey: [u8; 32],
    /// Random nonce for hole punching
    pub nonce: [u8; 16],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectAnswer {
    pub from_peer: PeerId,
    pub to_peer: PeerId,
    pub accepted: bool,
    pub session_pubkey: [u8; 32],
    pub nonce: [u8; 16],
}

// === Hole Punch Messages ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HolePunchPacket {
    pub peer_id: PeerId,
    /// Nonce from ConnectOffer/Answer
    pub nonce: [u8; 16],
    /// Sequence number for retry tracking
    pub seq: u32,
    /// Timestamp (for RTT calculation)
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HolePunchAck {
    pub peer_id: PeerId,
    pub nonce: [u8; 16],
    pub ack_seq: u32,
    /// Echo back timestamp for RTT
    pub echo_timestamp: u64,
}

// === Keepalive Messages ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingPacket {
    pub seq: u32,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PongPacket {
    pub seq: u32,
    pub echo_timestamp: u64,
    pub local_timestamp: u64,
}

// === Data Messages ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPacket {
    /// Circuit ID (identifies the path)
    pub circuit_id: u32,
    /// Encrypted payload (ChaCha20-Poly1305)
    pub payload: Vec<u8>,
    /// Authentication tag
    pub tag: [u8; 16],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayPacket {
    /// Next hop peer ID
    pub next_hop: PeerId,
    /// Onion-encrypted data
    pub onion_data: Vec<u8>,
}

// === Error Response ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ErrorCode {
    PeerNotFound,
    PeerOffline,
    NatTraversalFailed,
    AuthenticationFailed,
    RateLimited,
    InternalError,
}

/// Serialize message to bytes
pub fn serialize_message(msg: &P2PMessage) -> Result<Vec<u8>, bincode::Error> {
    bincode::serialize(msg)
}

/// Deserialize message from bytes
pub fn deserialize_message(data: &[u8]) -> Result<P2PMessage, bincode::Error> {
    bincode::deserialize(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_id_display() {
        let key = [1u8; 32];
        let peer_id = PeerId::from_public_key(&key);
        assert_eq!(peer_id.to_hex().len(), 16); // 8 bytes = 16 hex chars
    }

    #[test]
    fn test_nat_compatibility() {
        assert!(NatType::FullCone.can_direct_connect(&NatType::PortRestricted));
        assert!(!NatType::Symmetric.can_direct_connect(&NatType::FullCone));
    }

    #[test]
    fn test_message_serialization() {
        let msg = P2PMessage::Ping(PingPacket {
            seq: 1,
            timestamp: 12345,
        });
        let bytes = serialize_message(&msg).unwrap();
        let decoded = deserialize_message(&bytes).unwrap();

        if let P2PMessage::Ping(ping) = decoded {
            assert_eq!(ping.seq, 1);
            assert_eq!(ping.timestamp, 12345);
        } else {
            panic!("Wrong message type");
        }
    }
}
