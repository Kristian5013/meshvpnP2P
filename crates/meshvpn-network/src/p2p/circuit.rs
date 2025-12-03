//! Circuit-based Onion Routing
//!
//! Implements multi-hop routing through peer nodes:
//! User A → Node B → Node C → Exit Node → Internet
//!
//! Each hop only knows the previous and next hop.
//! Data is encrypted in layers (onion encryption).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, error, info, trace, warn};
use x25519_dalek::{EphemeralSecret, PublicKey};

use super::protocol::PeerId;
use crate::{NetworkError, NetworkResult};

/// Maximum hops in a circuit
pub const MAX_CIRCUIT_HOPS: usize = 5;

/// Circuit ID (random 32-bit identifier)
pub type CircuitId = u32;

/// Circuit message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CircuitMessage {
    /// Create a new circuit hop
    Create {
        circuit_id: CircuitId,
        /// Ephemeral public key for key exchange
        client_pubkey: [u8; 32],
    },

    /// Response to Create
    Created {
        circuit_id: CircuitId,
        /// Node's ephemeral public key
        node_pubkey: [u8; 32],
        /// Hash of shared secret (for verification)
        key_hash: [u8; 32],
    },

    /// Extend circuit to next hop (encrypted)
    Extend {
        circuit_id: CircuitId,
        /// Next hop's peer ID
        next_hop: PeerId,
        /// Next hop's address
        next_addr: SocketAddr,
        /// Ephemeral public key for next hop
        client_pubkey: [u8; 32],
    },

    /// Extended confirmation (encrypted)
    Extended {
        circuit_id: CircuitId,
        /// Next hop's public key
        node_pubkey: [u8; 32],
        /// Key hash for verification
        key_hash: [u8; 32],
    },

    /// Relay data through circuit
    Relay {
        circuit_id: CircuitId,
        /// Encrypted payload (one layer for each hop)
        payload: Vec<u8>,
    },

    /// Destroy circuit
    Destroy {
        circuit_id: CircuitId,
        reason: DestroyReason,
    },

    /// Exit to internet (only processed by exit node)
    Exit {
        circuit_id: CircuitId,
        /// Target address (IP:port or domain:port)
        target: String,
        /// Payload data
        data: Vec<u8>,
    },

    /// Response from exit node
    ExitResponse {
        circuit_id: CircuitId,
        /// Response data
        data: Vec<u8>,
    },
}

/// Reason for circuit destruction
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum DestroyReason {
    /// Normal shutdown
    Normal,
    /// Protocol error
    ProtocolError,
    /// Timeout
    Timeout,
    /// Resource limit
    ResourceLimit,
    /// Requested by user
    UserRequested,
}

impl CircuitMessage {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> NetworkResult<Vec<u8>> {
        bincode::serialize(self).map_err(|e| NetworkError::SerializationError(e.to_string()))
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> NetworkResult<Self> {
        bincode::deserialize(data).map_err(|e| NetworkError::SerializationError(e.to_string()))
    }
}

/// A single hop in the circuit
#[derive(Clone)]
pub struct CircuitHop {
    /// Peer ID of this hop
    pub peer_id: PeerId,
    /// Address of this hop
    pub addr: SocketAddr,
    /// Shared secret for encryption
    pub shared_secret: [u8; 32],
    /// Encryption key derived from shared secret
    pub cipher_key: [u8; 32],
}

impl CircuitHop {
    /// Encrypt data for this hop
    pub fn encrypt(&self, data: &[u8]) -> NetworkResult<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.cipher_key)
            .map_err(|e| NetworkError::Protocol(format!("Crypto error: {}", e)))?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| NetworkError::Protocol(format!("Crypto error: {}", e)))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data from this hop
    pub fn decrypt(&self, data: &[u8]) -> NetworkResult<Vec<u8>> {
        if data.len() < 12 {
            return Err(NetworkError::InvalidPacket("Data too short".to_string()));
        }

        let cipher = ChaCha20Poly1305::new_from_slice(&self.cipher_key)
            .map_err(|e| NetworkError::Protocol(format!("Crypto error: {}", e)))?;

        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext = &data[12..];

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| NetworkError::Protocol(format!("Crypto error: {}", e)))
    }
}

/// Client-side circuit
pub struct Circuit {
    /// Circuit ID
    pub id: CircuitId,
    /// List of hops in order
    pub hops: Vec<CircuitHop>,
    /// When circuit was created
    pub created_at: Instant,
    /// Last activity
    pub last_activity: Instant,
    /// Whether circuit is established
    pub established: bool,
}

impl Circuit {
    /// Create a new circuit with given ID
    pub fn new(id: CircuitId) -> Self {
        Self {
            id,
            hops: Vec::new(),
            created_at: Instant::now(),
            last_activity: Instant::now(),
            established: false,
        }
    }

    /// Add a hop to the circuit
    pub fn add_hop(&mut self, hop: CircuitHop) {
        self.hops.push(hop);
    }

    /// Encrypt data through all hops (onion layers)
    /// Encrypts from last hop to first (so first hop decrypts outer layer)
    pub fn encrypt_onion(&self, data: &[u8]) -> NetworkResult<Vec<u8>> {
        let mut encrypted = data.to_vec();

        // Encrypt in reverse order (last hop first, so outer layer is for first hop)
        for hop in self.hops.iter().rev() {
            encrypted = hop.encrypt(&encrypted)?;
        }

        Ok(encrypted)
    }

    /// Decrypt one layer of the onion
    pub fn decrypt_layer(&self, hop_index: usize, data: &[u8]) -> NetworkResult<Vec<u8>> {
        if hop_index >= self.hops.len() {
            return Err(NetworkError::InvalidPacket("Invalid hop index".to_string()));
        }

        self.hops[hop_index].decrypt(data)
    }

    /// Get the entry node address
    pub fn entry_addr(&self) -> Option<SocketAddr> {
        self.hops.first().map(|h| h.addr)
    }

    /// Get the exit node (last hop)
    pub fn exit_hop(&self) -> Option<&CircuitHop> {
        self.hops.last()
    }

    /// Number of hops
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }
}

/// Circuit builder for creating multi-hop circuits
pub struct CircuitBuilder {
    /// UDP socket for communication
    socket: Arc<UdpSocket>,
    /// Our peer ID
    our_peer_id: PeerId,
    /// Active circuits
    circuits: Arc<RwLock<HashMap<CircuitId, Circuit>>>,
    /// Timeout for circuit operations
    timeout: Duration,
}

impl CircuitBuilder {
    /// Create a new circuit builder
    pub async fn new(our_peer_id: PeerId, bind_addr: &str) -> NetworkResult<Self> {
        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| NetworkError::BindError(e.to_string()))?;

        Ok(Self {
            socket: Arc::new(socket),
            our_peer_id,
            circuits: Arc::new(RwLock::new(HashMap::new())),
            timeout: Duration::from_secs(10),
        })
    }

    /// Generate a new random circuit ID
    fn generate_circuit_id(&self) -> CircuitId {
        rand::random()
    }

    /// Build a circuit through the given nodes
    /// Returns the circuit ID on success
    pub async fn build_circuit(&self, nodes: Vec<(PeerId, SocketAddr)>) -> NetworkResult<CircuitId> {
        if nodes.is_empty() {
            return Err(NetworkError::ConfigError("No nodes provided".to_string()));
        }

        if nodes.len() > MAX_CIRCUIT_HOPS {
            return Err(NetworkError::ConfigError(format!(
                "Too many hops: {} > {}",
                nodes.len(),
                MAX_CIRCUIT_HOPS
            )));
        }

        let circuit_id = self.generate_circuit_id();
        let mut circuit = Circuit::new(circuit_id);

        info!(
            "Building circuit {} with {} hops",
            circuit_id,
            nodes.len()
        );

        // Create first hop
        let (first_peer, first_addr) = nodes[0];
        let first_hop = self.create_hop(circuit_id, first_peer, first_addr).await?;
        circuit.add_hop(first_hop);

        // Extend to remaining hops
        for (peer_id, addr) in nodes.iter().skip(1) {
            let hop = self
                .extend_circuit(circuit_id, &circuit, *peer_id, *addr)
                .await?;
            circuit.add_hop(hop);
        }

        circuit.established = true;
        info!("Circuit {} established with {} hops", circuit_id, circuit.hop_count());

        // Store circuit
        let mut circuits = self.circuits.write().await;
        circuits.insert(circuit_id, circuit);

        Ok(circuit_id)
    }

    /// Create first hop of circuit
    async fn create_hop(
        &self,
        circuit_id: CircuitId,
        peer_id: PeerId,
        addr: SocketAddr,
    ) -> NetworkResult<CircuitHop> {
        // Generate ephemeral key pair
        let secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&secret);

        // Send Create message
        let create_msg = CircuitMessage::Create {
            circuit_id,
            client_pubkey: *public.as_bytes(),
        };

        let data = create_msg.to_bytes()?;
        self.socket
            .send_to(&data, addr)
            .await
            .map_err(|e| NetworkError::SendError(e.to_string()))?;

        debug!("Sent Create to {} for circuit {}", addr, circuit_id);

        // Wait for Created response
        let mut buf = [0u8; 1024];
        let response = tokio::time::timeout(self.timeout, self.socket.recv_from(&mut buf)).await;

        match response {
            Ok(Ok((len, _))) => {
                let msg = CircuitMessage::from_bytes(&buf[..len])?;

                match msg {
                    CircuitMessage::Created {
                        circuit_id: cid,
                        node_pubkey,
                        key_hash,
                    } if cid == circuit_id => {
                        // Compute shared secret
                        let node_pk = PublicKey::from(node_pubkey);
                        let shared = secret.diffie_hellman(&node_pk);

                        // Derive cipher key
                        let cipher_key = derive_cipher_key(shared.as_bytes());

                        // Verify key hash
                        let expected_hash = blake3::hash(&cipher_key);
                        if expected_hash.as_bytes() != &key_hash {
                            return Err(NetworkError::Protocol(
                                "Key verification failed".to_string(),
                            ));
                        }

                        info!("Created hop to {} for circuit {}", addr, circuit_id);

                        Ok(CircuitHop {
                            peer_id,
                            addr,
                            shared_secret: *shared.as_bytes(),
                            cipher_key,
                        })
                    }
                    CircuitMessage::Destroy { reason, .. } => {
                        Err(NetworkError::ConnectionFailed(format!(
                            "Circuit creation rejected: {:?}",
                            reason
                        )))
                    }
                    _ => Err(NetworkError::InvalidPacket("Unexpected response".to_string())),
                }
            }
            Ok(Err(e)) => Err(NetworkError::ReceiveError(e.to_string())),
            Err(_) => Err(NetworkError::Timeout),
        }
    }

    /// Extend circuit to next hop (through existing circuit)
    async fn extend_circuit(
        &self,
        circuit_id: CircuitId,
        circuit: &Circuit,
        next_peer: PeerId,
        next_addr: SocketAddr,
    ) -> NetworkResult<CircuitHop> {
        // Generate ephemeral key pair for new hop
        let secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&secret);

        // Build Extend message
        let extend_msg = CircuitMessage::Extend {
            circuit_id,
            next_hop: next_peer,
            next_addr,
            client_pubkey: *public.as_bytes(),
        };

        // Serialize and encrypt through existing circuit
        let extend_data = extend_msg.to_bytes()?;
        let encrypted = circuit.encrypt_onion(&extend_data)?;

        // Wrap in Relay message
        let relay_msg = CircuitMessage::Relay {
            circuit_id,
            payload: encrypted,
        };

        // Send to entry node
        let entry_addr = circuit
            .entry_addr()
            .ok_or(NetworkError::NotConnected)?;

        let data = relay_msg.to_bytes()?;
        self.socket
            .send_to(&data, entry_addr)
            .await
            .map_err(|e| NetworkError::SendError(e.to_string()))?;

        debug!(
            "Sent Extend to {} via circuit {}",
            next_addr, circuit_id
        );

        // Wait for Extended response (will come through circuit)
        let mut buf = [0u8; 1024];
        let response = tokio::time::timeout(self.timeout, self.socket.recv_from(&mut buf)).await;

        match response {
            Ok(Ok((len, _))) => {
                let msg = CircuitMessage::from_bytes(&buf[..len])?;

                match msg {
                    CircuitMessage::Relay { circuit_id: cid, payload } if cid == circuit_id => {
                        // Decrypt through circuit to get Extended message
                        let mut decrypted = payload;
                        for i in 0..circuit.hop_count() {
                            decrypted = circuit.decrypt_layer(i, &decrypted)?;
                        }

                        let inner_msg = CircuitMessage::from_bytes(&decrypted)?;

                        match inner_msg {
                            CircuitMessage::Extended {
                                node_pubkey,
                                key_hash,
                                ..
                            } => {
                                // Compute shared secret with new hop
                                let node_pk = PublicKey::from(node_pubkey);
                                let shared = secret.diffie_hellman(&node_pk);
                                let cipher_key = derive_cipher_key(shared.as_bytes());

                                // Verify key hash
                                let expected_hash = blake3::hash(&cipher_key);
                                if expected_hash.as_bytes() != &key_hash {
                                    return Err(NetworkError::Protocol(
                                        "Key verification failed".to_string(),
                                    ));
                                }

                                info!("Extended circuit {} to {}", circuit_id, next_addr);

                                Ok(CircuitHop {
                                    peer_id: next_peer,
                                    addr: next_addr,
                                    shared_secret: *shared.as_bytes(),
                                    cipher_key,
                                })
                            }
                            _ => Err(NetworkError::InvalidPacket(
                                "Expected Extended message".to_string(),
                            )),
                        }
                    }
                    CircuitMessage::Destroy { reason, .. } => {
                        Err(NetworkError::ConnectionFailed(format!(
                            "Circuit extend rejected: {:?}",
                            reason
                        )))
                    }
                    _ => Err(NetworkError::InvalidPacket("Unexpected response".to_string())),
                }
            }
            Ok(Err(e)) => Err(NetworkError::ReceiveError(e.to_string())),
            Err(_) => Err(NetworkError::Timeout),
        }
    }

    /// Send data through circuit (with onion encryption)
    pub async fn send_data(&self, circuit_id: CircuitId, data: &[u8]) -> NetworkResult<()> {
        let circuits = self.circuits.read().await;
        let circuit = circuits
            .get(&circuit_id)
            .ok_or(NetworkError::NotConnected)?;

        if !circuit.established {
            return Err(NetworkError::NotConnected);
        }

        // Encrypt through all hops
        let encrypted = circuit.encrypt_onion(data)?;

        // Wrap in Relay message
        let relay_msg = CircuitMessage::Relay {
            circuit_id,
            payload: encrypted,
        };

        // Send to entry node
        let entry_addr = circuit.entry_addr().ok_or(NetworkError::NotConnected)?;

        let msg_data = relay_msg.to_bytes()?;
        self.socket
            .send_to(&msg_data, entry_addr)
            .await
            .map_err(|e| NetworkError::SendError(e.to_string()))?;

        trace!("Sent {} bytes through circuit {}", data.len(), circuit_id);

        Ok(())
    }

    /// Send exit request (to reach internet via exit node)
    pub async fn send_exit_request(
        &self,
        circuit_id: CircuitId,
        target: &str,
        data: &[u8],
    ) -> NetworkResult<()> {
        let circuits = self.circuits.read().await;
        let circuit = circuits
            .get(&circuit_id)
            .ok_or(NetworkError::NotConnected)?;

        if !circuit.established {
            return Err(NetworkError::NotConnected);
        }

        // Build Exit message
        let exit_msg = CircuitMessage::Exit {
            circuit_id,
            target: target.to_string(),
            data: data.to_vec(),
        };

        let exit_data = exit_msg.to_bytes()?;

        // Encrypt through all hops
        let encrypted = circuit.encrypt_onion(&exit_data)?;

        // Wrap in Relay message
        let relay_msg = CircuitMessage::Relay {
            circuit_id,
            payload: encrypted,
        };

        // Send to entry node
        let entry_addr = circuit.entry_addr().ok_or(NetworkError::NotConnected)?;

        let msg_data = relay_msg.to_bytes()?;
        self.socket
            .send_to(&msg_data, entry_addr)
            .await
            .map_err(|e| NetworkError::SendError(e.to_string()))?;

        debug!(
            "Sent exit request to {} through circuit {}",
            target, circuit_id
        );

        Ok(())
    }

    /// Receive data from circuit
    pub async fn recv_data(&self, circuit_id: CircuitId) -> NetworkResult<Vec<u8>> {
        let mut buf = [0u8; 65536];

        loop {
            let (len, _) = self
                .socket
                .recv_from(&mut buf)
                .await
                .map_err(|e| NetworkError::ReceiveError(e.to_string()))?;

            let msg = CircuitMessage::from_bytes(&buf[..len])?;

            match msg {
                CircuitMessage::Relay {
                    circuit_id: cid,
                    payload,
                } if cid == circuit_id => {
                    // Decrypt through circuit
                    let circuits = self.circuits.read().await;
                    let circuit = circuits
                        .get(&circuit_id)
                        .ok_or(NetworkError::NotConnected)?;

                    let mut decrypted = payload;
                    for i in 0..circuit.hop_count() {
                        decrypted = circuit.decrypt_layer(i, &decrypted)?;
                    }

                    return Ok(decrypted);
                }
                CircuitMessage::Destroy {
                    circuit_id: cid,
                    reason,
                } if cid == circuit_id => {
                    // Circuit was destroyed
                    let mut circuits = self.circuits.write().await;
                    circuits.remove(&circuit_id);

                    return Err(NetworkError::ConnectionFailed(format!(
                        "Circuit destroyed: {:?}",
                        reason
                    )));
                }
                _ => {
                    // Ignore messages for other circuits
                    continue;
                }
            }
        }
    }

    /// Destroy a circuit
    pub async fn destroy_circuit(&self, circuit_id: CircuitId) -> NetworkResult<()> {
        let circuits = self.circuits.read().await;
        let circuit = match circuits.get(&circuit_id) {
            Some(c) => c,
            None => return Ok(()), // Already destroyed
        };

        let entry_addr = match circuit.entry_addr() {
            Some(a) => a,
            None => return Ok(()),
        };

        drop(circuits);

        // Send Destroy message
        let destroy_msg = CircuitMessage::Destroy {
            circuit_id,
            reason: DestroyReason::UserRequested,
        };

        let data = destroy_msg.to_bytes()?;
        let _ = self.socket.send_to(&data, entry_addr).await;

        // Remove from our circuits
        let mut circuits = self.circuits.write().await;
        circuits.remove(&circuit_id);

        info!("Destroyed circuit {}", circuit_id);

        Ok(())
    }

    /// Get circuit info
    pub async fn get_circuit(&self, circuit_id: CircuitId) -> Option<CircuitInfo> {
        let circuits = self.circuits.read().await;
        circuits.get(&circuit_id).map(|c| CircuitInfo {
            id: c.id,
            hop_count: c.hops.len(),
            established: c.established,
            age_secs: c.created_at.elapsed().as_secs(),
        })
    }

    /// List all circuits
    pub async fn list_circuits(&self) -> Vec<CircuitInfo> {
        let circuits = self.circuits.read().await;
        circuits
            .values()
            .map(|c| CircuitInfo {
                id: c.id,
                hop_count: c.hops.len(),
                established: c.established,
                age_secs: c.created_at.elapsed().as_secs(),
            })
            .collect()
    }
}

/// Public circuit info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitInfo {
    pub id: CircuitId,
    pub hop_count: usize,
    pub established: bool,
    pub age_secs: u64,
}

/// Derive cipher key from shared secret using BLAKE3
fn derive_cipher_key(shared_secret: &[u8]) -> [u8; 32] {
    let hash = blake3::keyed_hash(&[0u8; 32], shared_secret);
    *hash.as_bytes()
}

/// Circuit relay node - handles incoming circuit messages
pub struct CircuitNode {
    /// UDP socket
    socket: Arc<UdpSocket>,
    /// Our peer ID
    peer_id: PeerId,
    /// Active circuits (we are a hop in)
    circuits: Arc<RwLock<HashMap<CircuitId, NodeCircuit>>>,
    /// Our key pairs for circuits
    keypairs: Arc<RwLock<HashMap<CircuitId, ([u8; 32], [u8; 32])>>>,
    /// Running flag
    running: Arc<std::sync::atomic::AtomicBool>,
    /// Is exit node
    is_exit: bool,
}

/// Node's view of a circuit (single hop)
struct NodeCircuit {
    /// Previous hop address
    prev_addr: SocketAddr,
    /// Next hop address (None if we are exit)
    next_addr: Option<SocketAddr>,
    /// Key for decrypting from previous hop
    prev_key: [u8; 32],
    /// Key for encrypting to previous hop
    next_key: Option<[u8; 32]>,
    /// Created at
    created_at: Instant,
}

impl CircuitNode {
    /// Create a new circuit node
    pub async fn new(peer_id: PeerId, bind_addr: &str, is_exit: bool) -> NetworkResult<Self> {
        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| NetworkError::BindError(e.to_string()))?;

        info!(
            "Circuit node listening on {}, exit={}",
            socket.local_addr().unwrap(),
            is_exit
        );

        Ok(Self {
            socket: Arc::new(socket),
            peer_id,
            circuits: Arc::new(RwLock::new(HashMap::new())),
            keypairs: Arc::new(RwLock::new(HashMap::new())),
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            is_exit,
        })
    }

    /// Get local address
    pub fn local_addr(&self) -> NetworkResult<SocketAddr> {
        self.socket
            .local_addr()
            .map_err(|e| NetworkError::ConfigError(e.to_string()))
    }

    /// Start handling circuit messages
    pub async fn run(&self) -> NetworkResult<()> {
        self.running
            .store(true, std::sync::atomic::Ordering::Relaxed);

        let mut buf = [0u8; 65536];

        while self.running.load(std::sync::atomic::Ordering::Relaxed) {
            let (len, from) = self
                .socket
                .recv_from(&mut buf)
                .await
                .map_err(|e| NetworkError::ReceiveError(e.to_string()))?;

            if let Err(e) = self.handle_message(&buf[..len], from).await {
                trace!("Error handling circuit message from {}: {}", from, e);
            }
        }

        Ok(())
    }

    /// Stop the node
    pub fn stop(&self) {
        self.running
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }

    /// Handle incoming circuit message
    async fn handle_message(&self, data: &[u8], from: SocketAddr) -> NetworkResult<()> {
        let msg = CircuitMessage::from_bytes(data)?;

        match msg {
            CircuitMessage::Create {
                circuit_id,
                client_pubkey,
            } => {
                self.handle_create(circuit_id, client_pubkey, from).await?;
            }

            CircuitMessage::Relay {
                circuit_id,
                payload,
            } => {
                self.handle_relay(circuit_id, payload, from).await?;
            }

            CircuitMessage::Destroy { circuit_id, .. } => {
                self.handle_destroy(circuit_id).await?;
            }

            _ => {
                // Ignore other message types at this level
            }
        }

        Ok(())
    }

    /// Handle Create message
    async fn handle_create(
        &self,
        circuit_id: CircuitId,
        client_pubkey: [u8; 32],
        from: SocketAddr,
    ) -> NetworkResult<()> {
        // Generate our ephemeral key pair
        let secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&secret);

        // Compute shared secret
        let client_pk = PublicKey::from(client_pubkey);
        let shared = secret.diffie_hellman(&client_pk);

        // Derive cipher key
        let cipher_key = derive_cipher_key(shared.as_bytes());

        // Compute key hash for verification
        let key_hash = blake3::hash(&cipher_key);

        // Store circuit
        let node_circuit = NodeCircuit {
            prev_addr: from,
            next_addr: None,
            prev_key: cipher_key,
            next_key: None,
            created_at: Instant::now(),
        };

        let mut circuits = self.circuits.write().await;
        circuits.insert(circuit_id, node_circuit);

        info!(
            "Created circuit {} from {} (we are first hop)",
            circuit_id, from
        );

        // Send Created response
        let response = CircuitMessage::Created {
            circuit_id,
            node_pubkey: *public.as_bytes(),
            key_hash: *key_hash.as_bytes(),
        };

        let response_data = response.to_bytes()?;
        self.socket
            .send_to(&response_data, from)
            .await
            .map_err(|e| NetworkError::SendError(e.to_string()))?;

        Ok(())
    }

    /// Handle Relay message
    async fn handle_relay(
        &self,
        circuit_id: CircuitId,
        payload: Vec<u8>,
        from: SocketAddr,
    ) -> NetworkResult<()> {
        let circuits = self.circuits.read().await;
        let circuit = match circuits.get(&circuit_id) {
            Some(c) => c,
            None => {
                warn!("Unknown circuit ID: {}", circuit_id);
                return Ok(());
            }
        };

        // Decrypt outer layer
        let cipher = ChaCha20Poly1305::new_from_slice(&circuit.prev_key)
            .map_err(|e| NetworkError::Protocol(e.to_string()))?;

        if payload.len() < 12 {
            return Err(NetworkError::InvalidPacket("Payload too short".to_string()));
        }

        let nonce = Nonce::from_slice(&payload[..12]);
        let ciphertext = &payload[12..];

        let decrypted = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| NetworkError::Protocol(e.to_string()))?;

        // Check if this is an Extend message
        if let Ok(inner_msg) = CircuitMessage::from_bytes(&decrypted) {
            match inner_msg {
                CircuitMessage::Extend {
                    next_hop,
                    next_addr,
                    client_pubkey,
                    ..
                } => {
                    drop(circuits);
                    self.handle_extend(circuit_id, from, next_hop, next_addr, client_pubkey)
                        .await?;
                    return Ok(());
                }

                CircuitMessage::Exit { target, data, .. } if self.is_exit => {
                    drop(circuits);
                    self.handle_exit(circuit_id, from, &target, &data).await?;
                    return Ok(());
                }

                _ => {}
            }
        }

        // If we have a next hop, forward the decrypted data
        if let Some(next_addr) = circuit.next_addr {
            let relay_msg = CircuitMessage::Relay {
                circuit_id,
                payload: decrypted,
            };

            let data = relay_msg.to_bytes()?;
            self.socket
                .send_to(&data, next_addr)
                .await
                .map_err(|e| NetworkError::SendError(e.to_string()))?;

            trace!(
                "Forwarded {} bytes on circuit {} to {}",
                data.len(),
                circuit_id,
                next_addr
            );
        }

        Ok(())
    }

    /// Handle Extend message
    async fn handle_extend(
        &self,
        circuit_id: CircuitId,
        from: SocketAddr,
        _next_hop: PeerId,
        next_addr: SocketAddr,
        client_pubkey: [u8; 32],
    ) -> NetworkResult<()> {
        // Forward Create to next hop
        let create_msg = CircuitMessage::Create {
            circuit_id,
            client_pubkey,
        };

        let data = create_msg.to_bytes()?;
        self.socket
            .send_to(&data, next_addr)
            .await
            .map_err(|e| NetworkError::SendError(e.to_string()))?;

        // Wait for Created response
        let mut buf = [0u8; 1024];
        let response = tokio::time::timeout(Duration::from_secs(10), self.socket.recv_from(&mut buf)).await;

        match response {
            Ok(Ok((len, _))) => {
                let msg = CircuitMessage::from_bytes(&buf[..len])?;

                match msg {
                    CircuitMessage::Created {
                        node_pubkey,
                        key_hash,
                        ..
                    } => {
                        // Update our circuit with next hop info
                        let mut circuits = self.circuits.write().await;
                        if let Some(circuit) = circuits.get_mut(&circuit_id) {
                            circuit.next_addr = Some(next_addr);
                        }

                        // Forward Extended back through circuit (encrypted)
                        let extended_msg = CircuitMessage::Extended {
                            circuit_id,
                            node_pubkey,
                            key_hash,
                        };

                        let inner_data = extended_msg.to_bytes()?;

                        // Encrypt for previous hop
                        let circuit = circuits.get(&circuit_id).unwrap();
                        let cipher = ChaCha20Poly1305::new_from_slice(&circuit.prev_key)
                            .map_err(|e| NetworkError::Protocol(e.to_string()))?;

                        let mut nonce_bytes = [0u8; 12];
                        rand::thread_rng().fill_bytes(&mut nonce_bytes);
                        let nonce = Nonce::from_slice(&nonce_bytes);

                        let encrypted = cipher
                            .encrypt(nonce, inner_data.as_slice())
                            .map_err(|e| NetworkError::Protocol(e.to_string()))?;

                        let mut encrypted_payload = Vec::with_capacity(12 + encrypted.len());
                        encrypted_payload.extend_from_slice(&nonce_bytes);
                        encrypted_payload.extend_from_slice(&encrypted);

                        let relay_msg = CircuitMessage::Relay {
                            circuit_id,
                            payload: encrypted_payload,
                        };

                        let relay_data = relay_msg.to_bytes()?;
                        self.socket
                            .send_to(&relay_data, from)
                            .await
                            .map_err(|e| NetworkError::SendError(e.to_string()))?;

                        info!(
                            "Extended circuit {} to {}",
                            circuit_id, next_addr
                        );
                    }
                    _ => {
                        warn!("Unexpected response to Create: {:?}", msg);
                    }
                }
            }
            Ok(Err(e)) => {
                error!("Error receiving Created: {}", e);
            }
            Err(_) => {
                warn!("Timeout waiting for Created from {}", next_addr);
            }
        }

        Ok(())
    }

    /// Handle Exit message (forward to internet)
    async fn handle_exit(
        &self,
        circuit_id: CircuitId,
        from: SocketAddr,
        target: &str,
        data: &[u8],
    ) -> NetworkResult<()> {
        info!(
            "Exit request on circuit {} to {} ({} bytes)",
            circuit_id,
            target,
            data.len()
        );

        // TODO: Actually forward to target and get response
        // For now, just echo back
        let response_data = format!("EXIT: would forward {} bytes to {}", data.len(), target);

        // Build response
        let response = CircuitMessage::ExitResponse {
            circuit_id,
            data: response_data.into_bytes(),
        };

        let inner_data = response.to_bytes()?;

        // Encrypt for previous hop
        let circuits = self.circuits.read().await;
        let circuit = match circuits.get(&circuit_id) {
            Some(c) => c,
            None => return Ok(()),
        };

        let cipher = ChaCha20Poly1305::new_from_slice(&circuit.prev_key)
            .map_err(|e| NetworkError::Protocol(e.to_string()))?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = cipher
            .encrypt(nonce, inner_data.as_slice())
            .map_err(|e| NetworkError::Protocol(e.to_string()))?;

        let mut encrypted_payload = Vec::with_capacity(12 + encrypted.len());
        encrypted_payload.extend_from_slice(&nonce_bytes);
        encrypted_payload.extend_from_slice(&encrypted);

        let relay_msg = CircuitMessage::Relay {
            circuit_id,
            payload: encrypted_payload,
        };

        let relay_data = relay_msg.to_bytes()?;
        self.socket
            .send_to(&relay_data, from)
            .await
            .map_err(|e| NetworkError::SendError(e.to_string()))?;

        Ok(())
    }

    /// Handle Destroy message
    async fn handle_destroy(&self, circuit_id: CircuitId) -> NetworkResult<()> {
        let mut circuits = self.circuits.write().await;

        if let Some(circuit) = circuits.remove(&circuit_id) {
            info!("Destroyed circuit {}", circuit_id);

            // Forward destroy to next hop if exists
            if let Some(next_addr) = circuit.next_addr {
                let destroy_msg = CircuitMessage::Destroy {
                    circuit_id,
                    reason: DestroyReason::Normal,
                };

                let data = destroy_msg.to_bytes()?;
                let _ = self.socket.send_to(&data, next_addr).await;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_cipher_key() {
        let secret = [1u8; 32];
        let key = derive_cipher_key(&secret);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_circuit_message_serialization() {
        let msg = CircuitMessage::Create {
            circuit_id: 12345,
            client_pubkey: [0u8; 32],
        };

        let bytes = msg.to_bytes().unwrap();
        let decoded = CircuitMessage::from_bytes(&bytes).unwrap();

        if let CircuitMessage::Create { circuit_id, .. } = decoded {
            assert_eq!(circuit_id, 12345);
        } else {
            panic!("Wrong message type");
        }
    }
}
