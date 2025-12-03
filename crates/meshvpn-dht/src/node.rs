//! DHT Node Information

use std::net::SocketAddr;
use std::time::Instant;

use meshvpn_crypto::{NodeId, PublicKey, Signature};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// Node status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeStatus {
    /// Node is available for relaying
    Active,
    /// Node is busy (high load)
    Busy,
    /// Node is leaving the network
    Leaving,
    /// Exit node (controlled by operator)
    Exit,
}

/// Information about a node in the network
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Node's unique identifier
    pub node_id: NodeId,

    /// Node's public key for encryption
    pub public_key: PublicKey,

    /// Node's signing public key
    pub signing_key: [u8; 32],

    /// Node's network addresses (may have multiple)
    pub addresses: Vec<SocketAddr>,

    /// Node's current status
    pub status: NodeStatus,

    /// Node's self-reported capacity (max circuits)
    pub capacity: u32,

    /// Current load (0-100)
    pub load: u8,

    /// Protocol version
    pub version: u8,

    /// Geographic region (optional)
    pub region: Option<String>,

    /// Country code (optional)
    pub country: Option<String>,

    /// Timestamp of this info
    pub timestamp: u64,

    /// Signature over the info (for authenticity)
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

impl NodeInfo {
    /// Create new node info (unsigned)
    pub fn new(
        node_id: NodeId,
        public_key: PublicKey,
        signing_key: [u8; 32],
        addresses: Vec<SocketAddr>,
    ) -> Self {
        Self {
            node_id,
            public_key,
            signing_key,
            addresses,
            status: NodeStatus::Active,
            capacity: 100,
            load: 0,
            version: 1, // Protocol version
            region: None,
            country: None,
            timestamp: current_timestamp(),
            signature: [0u8; 64],
        }
    }

    /// Get bytes to sign
    pub fn bytes_to_sign(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.node_id.as_bytes());
        bytes.extend_from_slice(self.public_key.as_bytes());
        bytes.extend_from_slice(&self.signing_key);
        for addr in &self.addresses {
            bytes.extend_from_slice(&addr.to_string().as_bytes());
        }
        bytes.push(self.status as u8);
        bytes.extend_from_slice(&self.capacity.to_le_bytes());
        bytes.push(self.load);
        bytes.push(self.version);
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes
    }

    /// Sign the node info
    pub fn sign(&mut self, identity: &meshvpn_crypto::NodeIdentity) {
        let bytes = self.bytes_to_sign();
        let sig = identity.sign(&bytes);
        self.signature = *sig.as_bytes();
    }

    /// Verify the signature
    pub fn verify_signature(&self) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let bytes = self.bytes_to_sign();

        let Ok(verifying_key) = VerifyingKey::from_bytes(&self.signing_key) else {
            return false;
        };

        let signature = Signature::from_bytes(&self.signature);

        verifying_key.verify(&bytes, &signature).is_ok()
    }

    /// Check if info is fresh
    pub fn is_fresh(&self, max_age_secs: u64) -> bool {
        let now = current_timestamp();
        self.timestamp + max_age_secs > now
    }

    /// Get primary address
    pub fn primary_address(&self) -> Option<SocketAddr> {
        self.addresses.first().copied()
    }
}

/// Node entry in routing table
#[derive(Clone, Debug)]
pub struct NodeEntry {
    /// Node information
    pub info: NodeInfo,

    /// Last seen timestamp
    pub last_seen: Instant,

    /// Number of failed pings
    pub failed_pings: u8,

    /// Round-trip time (microseconds)
    pub rtt_us: u64,

    /// Is this node verified (responded to ping)
    pub verified: bool,
}

impl NodeEntry {
    /// Create new entry
    pub fn new(info: NodeInfo) -> Self {
        Self {
            info,
            last_seen: Instant::now(),
            failed_pings: 0,
            rtt_us: 0,
            verified: false,
        }
    }

    /// Update last seen
    pub fn touch(&mut self) {
        self.last_seen = Instant::now();
        self.failed_pings = 0;
    }

    /// Record failed ping
    pub fn record_failure(&mut self) {
        self.failed_pings += 1;
    }

    /// Check if node is considered dead
    pub fn is_dead(&self) -> bool {
        self.failed_pings >= 3
    }

    /// Update RTT
    pub fn update_rtt(&mut self, rtt_us: u64) {
        if self.rtt_us == 0 {
            self.rtt_us = rtt_us;
        } else {
            // Exponential moving average
            self.rtt_us = (self.rtt_us * 7 + rtt_us) / 8;
        }
    }
}

/// The main DHT node
pub struct DhtNode {
    /// Our identity
    identity: meshvpn_crypto::NodeIdentity,

    /// Our node ID
    node_id: NodeId,

    /// Our addresses
    addresses: Vec<SocketAddr>,

    /// Routing table
    routing_table: super::routing::RoutingTable,

    /// Value storage
    storage: super::storage::DhtStorage,

    /// Is running?
    running: std::sync::atomic::AtomicBool,
}

impl DhtNode {
    /// Create a new DHT node
    pub fn new(identity: meshvpn_crypto::NodeIdentity, addresses: Vec<SocketAddr>) -> Self {
        let node_id = identity.node_id();

        Self {
            identity,
            node_id,
            addresses,
            routing_table: super::routing::RoutingTable::new(node_id),
            storage: super::storage::DhtStorage::new(),
            running: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Get our node ID
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Get our identity
    pub fn identity(&self) -> &meshvpn_crypto::NodeIdentity {
        &self.identity
    }

    /// Get routing table
    pub fn routing_table(&self) -> &super::routing::RoutingTable {
        &self.routing_table
    }

    /// Get routing table mutably
    pub fn routing_table_mut(&mut self) -> &mut super::routing::RoutingTable {
        &mut self.routing_table
    }

    /// Get storage
    pub fn storage(&self) -> &super::storage::DhtStorage {
        &self.storage
    }

    /// Get storage mutably
    pub fn storage_mut(&mut self) -> &mut super::storage::DhtStorage {
        &mut self.storage
    }

    /// Create our node info
    pub fn our_info(&self, status: NodeStatus, load: u8) -> NodeInfo {
        let mut info = NodeInfo::new(
            self.node_id,
            self.identity.public_key(),
            self.identity.verifying_key().to_bytes(),
            self.addresses.clone(),
        );
        info.status = status;
        info.load = load;
        info.sign(&self.identity);
        info
    }

    /// Add a node to the routing table
    pub fn add_node(&mut self, info: NodeInfo) -> bool {
        if info.node_id == self.node_id {
            return false; // Don't add ourselves
        }

        if !info.verify_signature() {
            return false; // Invalid signature
        }

        self.routing_table.add(NodeEntry::new(info))
    }

    /// Find closest nodes to a target
    pub fn find_closest(&self, target: &NodeId, count: usize) -> Vec<NodeEntry> {
        self.routing_table.find_closest(target, count)
    }

    /// Get node by ID
    pub fn get_node(&self, id: &NodeId) -> Option<NodeEntry> {
        self.routing_table.get(id)
    }

    /// Remove a node
    pub fn remove_node(&mut self, id: &NodeId) -> Option<NodeEntry> {
        self.routing_table.remove(id)
    }

    /// Get all known nodes
    pub fn all_nodes(&self) -> Vec<NodeEntry> {
        self.routing_table.all_nodes()
    }

    /// Get node count
    pub fn node_count(&self) -> usize {
        self.routing_table.len()
    }

    /// Check if running
    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::Relaxed)
    }
}

fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
