//! Relay Node Operations
//!
//! Handles the relay functionality - receiving encrypted packets
//! and forwarding them to the next hop.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use meshvpn_crypto::prelude::*;
use tokio::sync::RwLock;
use tracing::{debug, trace, warn};

use crate::circuit::CircuitId;
use crate::error::{CoreError, CoreResult};

/// Relay circuit entry (maps incoming circuit ID to outgoing)
pub struct RelayCircuit {
    /// Incoming circuit ID (from previous hop)
    pub incoming_id: CircuitId,

    /// Outgoing circuit ID (to next hop)
    pub outgoing_id: CircuitId,

    /// Next hop's address (None if we're the exit)
    pub next_hop: Option<std::net::SocketAddr>,

    /// Previous hop's address
    pub prev_hop: std::net::SocketAddr,

    /// Session key for decrypting from previous hop
    pub decrypt_key: SymmetricKey,

    /// Session key for encrypting to previous hop (responses)
    pub encrypt_key: SymmetricKey,

    /// Nonce counter for forward direction
    pub forward_nonce: Arc<AtomicU64>,

    /// Nonce counter for backward direction
    pub backward_nonce: Arc<AtomicU64>,

    /// Creation time
    pub created_at: Instant,

    /// Last activity
    pub last_activity: Instant,

    /// Bytes forwarded
    pub bytes_forwarded: AtomicU64,
}

impl RelayCircuit {
    /// Create a new relay circuit
    pub fn new(
        incoming_id: CircuitId,
        outgoing_id: CircuitId,
        prev_hop: std::net::SocketAddr,
        next_hop: Option<std::net::SocketAddr>,
        decrypt_key: SymmetricKey,
        encrypt_key: SymmetricKey,
    ) -> Self {
        let now = Instant::now();
        Self {
            incoming_id,
            outgoing_id,
            next_hop,
            prev_hop,
            decrypt_key,
            encrypt_key,
            forward_nonce: Arc::new(AtomicU64::new(0)),
            backward_nonce: Arc::new(AtomicU64::new(0)),
            created_at: now,
            last_activity: now,
            bytes_forwarded: AtomicU64::new(0),
        }
    }

    /// Check if this is an exit circuit (no next hop)
    pub fn is_exit(&self) -> bool {
        self.next_hop.is_none()
    }

    /// Decrypt incoming data and get next nonce
    pub fn decrypt_forward(&self, data: &[u8], nonce_seed: &[u8; 12]) -> CoreResult<Vec<u8>> {
        let counter = self.forward_nonce.fetch_add(1, Ordering::SeqCst);
        let nonce = Nonce::from_counter(nonce_seed, counter);
        meshvpn_crypto::decrypt(&self.decrypt_key, &nonce, data).map_err(CoreError::from)
    }

    /// Encrypt response data for previous hop
    pub fn encrypt_backward(&self, data: &[u8], nonce_seed: &[u8; 12]) -> CoreResult<Vec<u8>> {
        let counter = self.backward_nonce.fetch_add(1, Ordering::SeqCst);
        let nonce = Nonce::from_counter(nonce_seed, counter);
        meshvpn_crypto::encrypt(&self.encrypt_key, &nonce, data).map_err(CoreError::from)
    }

    /// Record forwarded bytes
    pub fn record_forward(&self, bytes: usize) {
        self.bytes_forwarded.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Get bytes forwarded
    pub fn bytes_forwarded(&self) -> u64 {
        self.bytes_forwarded.load(Ordering::Relaxed)
    }

    /// Get circuit age
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }
}

/// Relay node that forwards traffic
pub struct RelayNode {
    /// Our identity
    identity: NodeIdentity,

    /// Active relay circuits (by incoming circuit ID)
    circuits: RwLock<HashMap<CircuitId, Arc<RelayCircuit>>>,

    /// Reverse mapping (outgoing ID -> incoming ID)
    reverse_map: RwLock<HashMap<CircuitId, CircuitId>>,

    /// Maximum circuits we'll relay
    max_circuits: usize,

    /// Bandwidth limit (bytes/sec, 0 = unlimited)
    bandwidth_limit: u64,

    /// Current bandwidth usage
    current_bandwidth: AtomicU64,

    /// Total bytes relayed
    total_bytes: AtomicU64,

    /// Is relay enabled?
    enabled: std::sync::atomic::AtomicBool,
}

impl RelayNode {
    /// Create a new relay node
    pub fn new(identity: NodeIdentity, max_circuits: usize, bandwidth_limit: u64) -> Self {
        Self {
            identity,
            circuits: RwLock::new(HashMap::new()),
            reverse_map: RwLock::new(HashMap::new()),
            max_circuits,
            bandwidth_limit,
            current_bandwidth: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            enabled: std::sync::atomic::AtomicBool::new(true),
        }
    }

    /// Get our identity
    pub fn identity(&self) -> &NodeIdentity {
        &self.identity
    }

    /// Check if relay is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Enable/disable relay
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    /// Register a new relay circuit
    pub async fn register_circuit(&self, circuit: RelayCircuit) -> CoreResult<()> {
        let mut circuits = self.circuits.write().await;

        if circuits.len() >= self.max_circuits {
            return Err(CoreError::RelayError("Maximum circuits reached".into()));
        }

        let incoming_id = circuit.incoming_id;
        let outgoing_id = circuit.outgoing_id;

        circuits.insert(incoming_id, Arc::new(circuit));

        let mut reverse = self.reverse_map.write().await;
        reverse.insert(outgoing_id, incoming_id);

        debug!(
            "Registered relay circuit: {} -> {}",
            incoming_id, outgoing_id
        );
        Ok(())
    }

    /// Remove a relay circuit
    pub async fn remove_circuit(&self, incoming_id: CircuitId) -> Option<Arc<RelayCircuit>> {
        let mut circuits = self.circuits.write().await;
        let circuit = circuits.remove(&incoming_id);

        if let Some(ref c) = circuit {
            let mut reverse = self.reverse_map.write().await;
            reverse.remove(&c.outgoing_id);
            debug!("Removed relay circuit: {}", incoming_id);
        }

        circuit
    }

    /// Get a circuit by incoming ID
    pub async fn get_circuit(&self, incoming_id: CircuitId) -> Option<Arc<RelayCircuit>> {
        let circuits = self.circuits.read().await;
        circuits.get(&incoming_id).cloned()
    }

    /// Get a circuit by outgoing ID (for responses)
    pub async fn get_circuit_by_outgoing(&self, outgoing_id: CircuitId) -> Option<Arc<RelayCircuit>> {
        let reverse = self.reverse_map.read().await;
        if let Some(&incoming_id) = reverse.get(&outgoing_id) {
            let circuits = self.circuits.read().await;
            circuits.get(&incoming_id).cloned()
        } else {
            None
        }
    }

    /// Process incoming data and prepare for forwarding
    pub async fn relay_forward(
        &self,
        incoming_id: CircuitId,
        data: &[u8],
    ) -> CoreResult<RelayResult> {
        if !self.is_enabled() {
            return Err(CoreError::RelayError("Relay is disabled".into()));
        }

        // Check bandwidth limit
        if self.bandwidth_limit > 0 {
            let current = self.current_bandwidth.load(Ordering::Relaxed);
            if current + data.len() as u64 > self.bandwidth_limit {
                return Err(CoreError::RelayError("Bandwidth limit exceeded".into()));
            }
        }

        let circuit = self
            .get_circuit(incoming_id)
            .await
            .ok_or_else(|| CoreError::CircuitNotFound(incoming_id))?;

        // Record statistics
        circuit.record_forward(data.len());
        self.total_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);

        if let Some(next_hop) = circuit.next_hop {
            // We're a relay - forward to next hop
            Ok(RelayResult::Forward {
                next_hop,
                circuit_id: circuit.outgoing_id,
                data: data.to_vec(), // Data stays encrypted for next hop
            })
        } else {
            // We're the exit - this shouldn't happen in relay_forward
            // Exit processing is separate
            Err(CoreError::RelayError(
                "Circuit is exit, use process_exit instead".into(),
            ))
        }
    }

    /// Process response coming back through the circuit
    pub async fn relay_backward(
        &self,
        outgoing_id: CircuitId,
        data: &[u8],
    ) -> CoreResult<RelayResult> {
        let circuit = self
            .get_circuit_by_outgoing(outgoing_id)
            .await
            .ok_or_else(|| CoreError::CircuitNotFound(outgoing_id))?;

        circuit.record_forward(data.len());

        Ok(RelayResult::Forward {
            next_hop: circuit.prev_hop,
            circuit_id: circuit.incoming_id,
            data: data.to_vec(),
        })
    }

    /// Get circuit count
    pub async fn circuit_count(&self) -> usize {
        let circuits = self.circuits.read().await;
        circuits.len()
    }

    /// Get relay statistics
    pub fn stats(&self) -> RelayStats {
        RelayStats {
            enabled: self.is_enabled(),
            max_circuits: self.max_circuits,
            bandwidth_limit: self.bandwidth_limit,
            total_bytes_relayed: self.total_bytes.load(Ordering::Relaxed),
        }
    }

    /// Clean up old circuits
    pub async fn cleanup(&self, max_age: Duration) -> usize {
        let mut to_remove = Vec::new();

        {
            let circuits = self.circuits.read().await;
            for (id, circuit) in circuits.iter() {
                if circuit.age() > max_age {
                    to_remove.push(*id);
                }
            }
        }

        let count = to_remove.len();
        for id in to_remove {
            self.remove_circuit(id).await;
        }

        if count > 0 {
            debug!("Cleaned up {} old relay circuits", count);
        }
        count
    }
}

/// Result of relay processing
pub enum RelayResult {
    /// Forward data to next hop
    Forward {
        next_hop: std::net::SocketAddr,
        circuit_id: CircuitId,
        data: Vec<u8>,
    },
}

/// Relay statistics
#[derive(Debug, Clone)]
pub struct RelayStats {
    pub enabled: bool,
    pub max_circuits: usize,
    pub bandwidth_limit: u64,
    pub total_bytes_relayed: u64,
}

/// Relay manager for handling multiple relay operations
pub struct RelayManager {
    node: Arc<RelayNode>,
}

impl RelayManager {
    /// Create a new relay manager
    pub fn new(node: Arc<RelayNode>) -> Self {
        Self { node }
    }

    /// Get the relay node
    pub fn node(&self) -> &Arc<RelayNode> {
        &self.node
    }

    /// Start background cleanup task
    pub fn spawn_cleanup(self: Arc<Self>, interval: Duration, max_age: Duration) {
        let manager = self.clone();
        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            loop {
                interval_timer.tick().await;
                manager.node.cleanup(max_age).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_relay_circuit_registration() {
        let identity = NodeIdentity::generate();
        let relay = RelayNode::new(identity, 100, 0);

        let circuit = RelayCircuit::new(
            1,
            2,
            "127.0.0.1:8080".parse().unwrap(),
            Some("127.0.0.1:8081".parse().unwrap()),
            SymmetricKey::generate(),
            SymmetricKey::generate(),
        );

        relay.register_circuit(circuit).await.unwrap();

        assert!(relay.get_circuit(1).await.is_some());
        assert!(relay.get_circuit_by_outgoing(2).await.is_some());
        assert_eq!(relay.circuit_count().await, 1);
    }

    #[tokio::test]
    async fn test_relay_circuit_limit() {
        let identity = NodeIdentity::generate();
        let relay = RelayNode::new(identity, 2, 0);

        // Add 2 circuits (at limit)
        for i in 0..2 {
            let circuit = RelayCircuit::new(
                i,
                i + 100,
                "127.0.0.1:8080".parse().unwrap(),
                None,
                SymmetricKey::generate(),
                SymmetricKey::generate(),
            );
            relay.register_circuit(circuit).await.unwrap();
        }

        // Third should fail
        let circuit = RelayCircuit::new(
            99,
            199,
            "127.0.0.1:8080".parse().unwrap(),
            None,
            SymmetricKey::generate(),
            SymmetricKey::generate(),
        );
        assert!(relay.register_circuit(circuit).await.is_err());
    }
}
