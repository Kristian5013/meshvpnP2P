//! Circuit Management
//!
//! A circuit is an encrypted tunnel through multiple relay nodes
//! ending at an exit node. Traffic is onion-encrypted so each
//! relay only knows the previous and next hop.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use meshvpn_crypto::prelude::*;
use meshvpn_network::{Packet, PacketType};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

use crate::error::{CoreError, CoreResult};

/// Circuit identifier (random 32-bit value)
pub type CircuitId = u32;

/// Circuit state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Circuit is being built (handshakes in progress)
    Building,
    /// Circuit is ready for traffic
    Ready,
    /// Circuit is being extended with additional hops
    Extending,
    /// Circuit is being torn down
    Closing,
    /// Circuit is closed
    Closed,
    /// Circuit failed
    Failed,
}

/// Information about a single hop in the circuit
#[derive(Clone)]
pub struct HopInfo {
    /// Node ID of this hop
    pub node_id: NodeId,
    /// Public key for this hop
    pub public_key: PublicKey,
    /// Session key for encrypting/decrypting at this hop
    pub session_key: SymmetricKey,
    /// Nonce seed for this hop
    pub nonce_seed: [u8; 12],
    /// Circuit ID used at this hop (may differ per hop)
    pub circuit_id: CircuitId,
}

/// A circuit through the MeshVPN network
pub struct Circuit {
    /// Our circuit ID (used in first hop)
    id: CircuitId,

    /// Circuit state
    state: CircuitState,

    /// Hops in order (first hop to exit)
    hops: Vec<HopInfo>,

    /// Is this circuit for a specific destination?
    destination: Option<std::net::IpAddr>,

    /// Creation time
    created_at: Instant,

    /// Last activity
    last_activity: Instant,

    /// Bytes sent through circuit
    bytes_sent: u64,

    /// Bytes received through circuit
    bytes_received: u64,

    /// Number of packets sent
    packets_sent: u64,

    /// Number of packets received
    packets_received: u64,
}

impl Circuit {
    /// Create a new circuit with the given ID
    pub fn new(id: CircuitId) -> Self {
        let now = Instant::now();
        Self {
            id,
            state: CircuitState::Building,
            hops: Vec::new(),
            destination: None,
            created_at: now,
            last_activity: now,
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
        }
    }

    /// Get circuit ID
    pub fn id(&self) -> CircuitId {
        self.id
    }

    /// Get circuit state
    pub fn state(&self) -> CircuitState {
        self.state
    }

    /// Set circuit state
    pub fn set_state(&mut self, state: CircuitState) {
        debug!("Circuit {} state: {:?} -> {:?}", self.id, self.state, state);
        self.state = state;
    }

    /// Check if circuit is ready for traffic
    pub fn is_ready(&self) -> bool {
        self.state == CircuitState::Ready
    }

    /// Get number of hops
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    /// Add a hop to the circuit
    pub fn add_hop(&mut self, hop: HopInfo) {
        self.hops.push(hop);
    }

    /// Get the first hop (entry node)
    pub fn entry_hop(&self) -> Option<&HopInfo> {
        self.hops.first()
    }

    /// Get the last hop (exit node)
    pub fn exit_hop(&self) -> Option<&HopInfo> {
        self.hops.last()
    }

    /// Get all hops
    pub fn hops(&self) -> &[HopInfo] {
        &self.hops
    }

    /// Encrypt data for sending through circuit (wrap in onion layers)
    pub fn encrypt_forward(&self, data: &[u8]) -> CoreResult<Vec<u8>> {
        if !self.is_ready() {
            return Err(CoreError::CircuitError("Circuit not ready".into()));
        }

        let mut encrypted = data.to_vec();

        // Encrypt in reverse order (exit first, entry last)
        for (i, hop) in self.hops.iter().enumerate().rev() {
            let nonce = Nonce::from_counter(&hop.nonce_seed, self.packets_sent + i as u64);
            encrypted = meshvpn_crypto::encrypt(&hop.session_key, &nonce, &encrypted)?;
        }

        Ok(encrypted)
    }

    /// Decrypt data received through circuit (unwrap onion layers)
    pub fn decrypt_backward(&self, data: &[u8]) -> CoreResult<Vec<u8>> {
        if !self.is_ready() {
            return Err(CoreError::CircuitError("Circuit not ready".into()));
        }

        let mut decrypted = data.to_vec();

        // Decrypt in forward order (entry first, exit last)
        for (i, hop) in self.hops.iter().enumerate() {
            let nonce = Nonce::from_counter(&hop.nonce_seed, self.packets_received + i as u64);
            decrypted = meshvpn_crypto::decrypt(&hop.session_key, &nonce, &decrypted)?;
        }

        Ok(decrypted)
    }

    /// Record sent data
    pub fn record_sent(&mut self, bytes: usize) {
        self.bytes_sent += bytes as u64;
        self.packets_sent += 1;
        self.last_activity = Instant::now();
    }

    /// Record received data
    pub fn record_received(&mut self, bytes: usize) {
        self.bytes_received += bytes as u64;
        self.packets_received += 1;
        self.last_activity = Instant::now();
    }

    /// Get circuit age
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Get time since last activity
    pub fn idle_time(&self) -> Duration {
        self.last_activity.elapsed()
    }

    /// Set destination for this circuit
    pub fn set_destination(&mut self, dest: std::net::IpAddr) {
        self.destination = Some(dest);
    }

    /// Get destination
    pub fn destination(&self) -> Option<std::net::IpAddr> {
        self.destination
    }

    /// Get statistics
    pub fn stats(&self) -> CircuitStats {
        CircuitStats {
            id: self.id,
            state: self.state,
            hop_count: self.hops.len(),
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
            packets_sent: self.packets_sent,
            packets_received: self.packets_received,
            age_secs: self.age().as_secs(),
            idle_secs: self.idle_time().as_secs(),
        }
    }
}

/// Circuit statistics
#[derive(Debug, Clone)]
pub struct CircuitStats {
    pub id: CircuitId,
    pub state: CircuitState,
    pub hop_count: usize,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub age_secs: u64,
    pub idle_secs: u64,
}

/// Builder for constructing circuits incrementally
pub struct CircuitBuilder {
    circuit: Circuit,
    pending_handshakes: Vec<NodeId>,
}

impl CircuitBuilder {
    /// Start building a new circuit
    pub fn new() -> Self {
        let id = rand::random();
        Self {
            circuit: Circuit::new(id),
            pending_handshakes: Vec::new(),
        }
    }

    /// Start building with a specific ID
    pub fn with_id(id: CircuitId) -> Self {
        Self {
            circuit: Circuit::new(id),
            pending_handshakes: Vec::new(),
        }
    }

    /// Plan the path (nodes to build through)
    pub fn plan_path(mut self, nodes: Vec<(NodeId, PublicKey)>) -> Self {
        self.pending_handshakes = nodes.iter().map(|(id, _)| *id).collect();
        self
    }

    /// Complete handshake for a hop
    pub fn complete_hop(
        &mut self,
        node_id: NodeId,
        public_key: PublicKey,
        shared_secret: SharedSecret,
    ) -> CoreResult<()> {
        // Derive session keys
        let keys = shared_secret.derive_keys(b"meshvpn:circuit:hop");

        let hop = HopInfo {
            node_id,
            public_key,
            session_key: SymmetricKey::from_bytes(keys.forward_key),
            nonce_seed: keys.nonce_seed,
            circuit_id: rand::random(),
        };

        self.circuit.add_hop(hop);

        // Remove from pending
        self.pending_handshakes.retain(|id| *id != node_id);

        Ok(())
    }

    /// Check if all handshakes are complete
    pub fn is_complete(&self) -> bool {
        self.pending_handshakes.is_empty() && !self.circuit.hops.is_empty()
    }

    /// Finalize and return the circuit
    pub fn build(mut self) -> CoreResult<Circuit> {
        if !self.is_complete() {
            return Err(CoreError::CircuitError(format!(
                "Circuit incomplete: {} handshakes pending",
                self.pending_handshakes.len()
            )));
        }

        self.circuit.set_state(CircuitState::Ready);
        Ok(self.circuit)
    }

    /// Get current circuit ID
    pub fn id(&self) -> CircuitId {
        self.circuit.id
    }

    /// Get number of completed hops
    pub fn completed_hops(&self) -> usize {
        self.circuit.hops.len()
    }
}

impl Default for CircuitBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Manager for multiple circuits
pub struct CircuitManager {
    /// Active circuits
    circuits: RwLock<HashMap<CircuitId, Arc<RwLock<Circuit>>>>,

    /// Maximum circuits
    max_circuits: usize,

    /// Default circuit for general traffic
    default_circuit: RwLock<Option<CircuitId>>,
}

impl CircuitManager {
    /// Create a new circuit manager
    pub fn new(max_circuits: usize) -> Self {
        Self {
            circuits: RwLock::new(HashMap::new()),
            max_circuits,
            default_circuit: RwLock::new(None),
        }
    }

    /// Add a circuit
    pub async fn add(&self, circuit: Circuit) -> CoreResult<Arc<RwLock<Circuit>>> {
        let id = circuit.id();

        let mut circuits = self.circuits.write().await;

        if circuits.len() >= self.max_circuits {
            return Err(CoreError::CircuitError("Maximum circuits reached".into()));
        }

        if circuits.contains_key(&id) {
            return Err(CoreError::CircuitExists(id));
        }

        let circuit = Arc::new(RwLock::new(circuit));
        circuits.insert(id, circuit.clone());

        info!("Added circuit {}", id);
        Ok(circuit)
    }

    /// Get a circuit by ID
    pub async fn get(&self, id: CircuitId) -> Option<Arc<RwLock<Circuit>>> {
        let circuits = self.circuits.read().await;
        circuits.get(&id).cloned()
    }

    /// Remove a circuit
    pub async fn remove(&self, id: CircuitId) -> Option<Arc<RwLock<Circuit>>> {
        let mut circuits = self.circuits.write().await;
        let removed = circuits.remove(&id);

        if removed.is_some() {
            info!("Removed circuit {}", id);

            // Clear default if this was it
            let mut default = self.default_circuit.write().await;
            if *default == Some(id) {
                *default = None;
            }
        }

        removed
    }

    /// Set the default circuit for general traffic
    pub async fn set_default(&self, id: CircuitId) -> CoreResult<()> {
        // Verify circuit exists and is ready
        let circuit = self.get(id).await.ok_or(CoreError::CircuitNotFound(id))?;

        {
            let circuit = circuit.read().await;
            if !circuit.is_ready() {
                return Err(CoreError::CircuitError("Circuit not ready".into()));
            }
        }

        let mut default = self.default_circuit.write().await;
        *default = Some(id);

        debug!("Set default circuit to {}", id);
        Ok(())
    }

    /// Get the default circuit
    pub async fn get_default(&self) -> Option<Arc<RwLock<Circuit>>> {
        let default = self.default_circuit.read().await;
        if let Some(id) = *default {
            self.get(id).await
        } else {
            None
        }
    }

    /// Get a ready circuit (default or any available)
    pub async fn get_ready(&self) -> Option<Arc<RwLock<Circuit>>> {
        // Try default first
        if let Some(circuit) = self.get_default().await {
            let c = circuit.read().await;
            if c.is_ready() {
                return Some(circuit.clone());
            }
        }

        // Find any ready circuit
        let circuits = self.circuits.read().await;
        for circuit in circuits.values() {
            let c = circuit.read().await;
            if c.is_ready() {
                return Some(circuit.clone());
            }
        }

        None
    }

    /// Get all circuit IDs
    pub async fn circuit_ids(&self) -> Vec<CircuitId> {
        let circuits = self.circuits.read().await;
        circuits.keys().copied().collect()
    }

    /// Get circuit count
    pub async fn count(&self) -> usize {
        let circuits = self.circuits.read().await;
        circuits.len()
    }

    /// Clean up old/failed circuits
    pub async fn cleanup(&self, max_age: Duration, max_idle: Duration) -> usize {
        let mut to_remove = Vec::new();

        {
            let circuits = self.circuits.read().await;
            for (id, circuit) in circuits.iter() {
                let c = circuit.read().await;
                if c.age() > max_age
                    || c.idle_time() > max_idle
                    || c.state() == CircuitState::Failed
                    || c.state() == CircuitState::Closed
                {
                    to_remove.push(*id);
                }
            }
        }

        let count = to_remove.len();
        for id in to_remove {
            self.remove(id).await;
        }

        if count > 0 {
            debug!("Cleaned up {} circuits", count);
        }
        count
    }

    /// Get statistics for all circuits
    pub async fn all_stats(&self) -> Vec<CircuitStats> {
        let circuits = self.circuits.read().await;
        let mut stats = Vec::new();

        for circuit in circuits.values() {
            let c = circuit.read().await;
            stats.push(c.stats());
        }

        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_hop() -> HopInfo {
        HopInfo {
            node_id: NodeId::from_bytes([1u8; 20]),
            public_key: PublicKey::from_bytes([2u8; 32]),
            session_key: SymmetricKey::generate(),
            nonce_seed: [3u8; 12],
            circuit_id: 12345,
        }
    }

    #[test]
    fn test_circuit_creation() {
        let circuit = Circuit::new(1);
        assert_eq!(circuit.id(), 1);
        assert_eq!(circuit.state(), CircuitState::Building);
        assert_eq!(circuit.hop_count(), 0);
    }

    #[test]
    fn test_circuit_add_hops() {
        let mut circuit = Circuit::new(1);
        circuit.add_hop(create_test_hop());
        circuit.add_hop(create_test_hop());
        circuit.add_hop(create_test_hop());

        assert_eq!(circuit.hop_count(), 3);
        assert!(circuit.entry_hop().is_some());
        assert!(circuit.exit_hop().is_some());
    }

    #[test]
    fn test_circuit_builder() {
        let mut builder = CircuitBuilder::new();

        // Simulate completing handshakes
        let shared = SharedSecret::from_bytes([0u8; 32]);

        for i in 0..3 {
            let node_id = NodeId::from_bytes([i as u8; 20]);
            let pubkey = PublicKey::from_bytes([i as u8; 32]);
            builder.complete_hop(node_id, pubkey, shared.clone()).unwrap();
        }

        assert!(builder.is_complete());

        let circuit = builder.build().unwrap();
        assert!(circuit.is_ready());
        assert_eq!(circuit.hop_count(), 3);
    }

    #[tokio::test]
    async fn test_circuit_manager() {
        let manager = CircuitManager::new(10);

        let mut circuit = Circuit::new(1);
        circuit.add_hop(create_test_hop());
        circuit.set_state(CircuitState::Ready);

        manager.add(circuit).await.unwrap();

        assert_eq!(manager.count().await, 1);
        assert!(manager.get(1).await.is_some());
        assert!(manager.get(999).await.is_none());

        manager.remove(1).await;
        assert_eq!(manager.count().await, 0);
    }

    // Mock SharedSecret for tests
    impl SharedSecret {
        fn from_bytes(bytes: [u8; 32]) -> Self {
            // This is a test-only constructor
            unsafe { std::mem::transmute(bytes) }
        }

        fn clone(&self) -> Self {
            Self::from_bytes(*self.as_bytes())
        }
    }
}
