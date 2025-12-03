//! P2P Relay Protocol
//!
//! Implements packet relaying for peers behind Symmetric NAT.
//! A relay node forwards packets between peers that cannot establish direct connections.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, info, warn, error, trace};

use super::protocol::PeerId;
use crate::{NetworkError, NetworkResult};

/// Relay message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RelayMessage {
    /// Request to allocate a relay slot
    AllocateRequest {
        /// Client's peer ID
        peer_id: PeerId,
    },

    /// Response to allocation request
    AllocateResponse {
        /// Whether allocation succeeded
        success: bool,
        /// Allocated relay address (if success)
        relay_addr: Option<SocketAddr>,
        /// Error message (if failure)
        error: Option<String>,
        /// TTL in seconds
        ttl_secs: u32,
    },

    /// Request to connect to a peer via relay
    ConnectRequest {
        /// Source peer ID
        from_peer: PeerId,
        /// Target peer ID
        to_peer: PeerId,
        /// Connection nonce
        nonce: Vec<u8>,
    },

    /// Response to connect request
    ConnectResponse {
        /// Whether peer was found and notified
        success: bool,
        /// Error message if failed
        error: Option<String>,
    },

    /// Relayed data packet
    Data {
        /// Source peer ID
        from_peer: PeerId,
        /// Target peer ID
        to_peer: PeerId,
        /// Encrypted payload
        payload: Vec<u8>,
    },

    /// Keepalive to maintain relay allocation
    Keepalive {
        /// Peer ID
        peer_id: PeerId,
    },

    /// Disconnect from relay
    Disconnect {
        /// Peer ID
        peer_id: PeerId,
    },
}

impl RelayMessage {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> NetworkResult<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| NetworkError::SerializationError(e.to_string()))
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> NetworkResult<Self> {
        bincode::deserialize(data)
            .map_err(|e| NetworkError::SerializationError(e.to_string()))
    }
}

/// Relay allocation info
#[derive(Debug, Clone)]
pub struct RelayAllocation {
    /// Peer ID
    pub peer_id: PeerId,
    /// Client's actual address
    pub client_addr: SocketAddr,
    /// When allocation was created
    pub created_at: Instant,
    /// When allocation expires
    pub expires_at: Instant,
    /// Last activity
    pub last_activity: Instant,
    /// Bytes relayed
    pub bytes_relayed: u64,
}

impl RelayAllocation {
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }
}

/// Relay Server - forwards packets between peers
pub struct RelayServer {
    /// UDP socket
    socket: Arc<UdpSocket>,
    /// Allocations by peer ID
    allocations: Arc<RwLock<HashMap<PeerId, RelayAllocation>>>,
    /// Maximum allocations
    max_allocations: usize,
    /// Allocation TTL
    allocation_ttl: Duration,
    /// Running flag
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl RelayServer {
    /// Create a new relay server
    pub async fn new(bind_addr: &str) -> NetworkResult<Self> {
        let socket = UdpSocket::bind(bind_addr).await
            .map_err(|e| NetworkError::BindError(e.to_string()))?;

        info!("Relay server listening on {}", socket.local_addr().unwrap());

        Ok(Self {
            socket: Arc::new(socket),
            allocations: Arc::new(RwLock::new(HashMap::new())),
            max_allocations: 1000,
            allocation_ttl: Duration::from_secs(300), // 5 minutes
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Get local address
    pub fn local_addr(&self) -> NetworkResult<SocketAddr> {
        self.socket.local_addr()
            .map_err(|e| NetworkError::ConfigError(e.to_string()))
    }

    /// Start the relay server
    pub async fn run(&self) -> NetworkResult<()> {
        self.running.store(true, std::sync::atomic::Ordering::Relaxed);

        let mut buf = [0u8; 65536];

        // Spawn cleanup task
        let allocations = self.allocations.clone();
        let running = self.running.clone();
        tokio::spawn(async move {
            while running.load(std::sync::atomic::Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(60)).await;

                let mut allocs = allocations.write().await;
                let before = allocs.len();
                allocs.retain(|_, a| !a.is_expired());
                let removed = before - allocs.len();

                if removed > 0 {
                    info!("Cleaned up {} expired relay allocations", removed);
                }
            }
        });

        // Main receive loop
        while self.running.load(std::sync::atomic::Ordering::Relaxed) {
            let (len, from) = self.socket.recv_from(&mut buf).await
                .map_err(|e| NetworkError::ReceiveError(e.to_string()))?;

            if let Err(e) = self.handle_packet(&buf[..len], from).await {
                trace!("Error handling packet from {}: {}", from, e);
            }
        }

        Ok(())
    }

    /// Stop the server
    pub fn stop(&self) {
        self.running.store(false, std::sync::atomic::Ordering::Relaxed);
    }

    /// Handle incoming packet
    async fn handle_packet(&self, data: &[u8], from: SocketAddr) -> NetworkResult<()> {
        let msg = RelayMessage::from_bytes(data)?;

        match msg {
            RelayMessage::AllocateRequest { peer_id } => {
                self.handle_allocate(peer_id, from).await?;
            }

            RelayMessage::ConnectRequest { from_peer, to_peer, nonce: _ } => {
                self.handle_connect(from_peer, to_peer, from).await?;
            }

            RelayMessage::Data { from_peer, to_peer, payload } => {
                self.handle_data(from_peer, to_peer, payload, from).await?;
            }

            RelayMessage::Keepalive { peer_id } => {
                self.handle_keepalive(peer_id, from).await?;
            }

            RelayMessage::Disconnect { peer_id } => {
                self.handle_disconnect(peer_id).await?;
            }

            _ => {
                // Ignore unexpected messages
            }
        }

        Ok(())
    }

    /// Handle allocation request
    async fn handle_allocate(&self, peer_id: PeerId, from: SocketAddr) -> NetworkResult<()> {
        let mut allocations = self.allocations.write().await;

        // Check if already allocated
        if allocations.contains_key(&peer_id) {
            let response = RelayMessage::AllocateResponse {
                success: true,
                relay_addr: Some(self.local_addr()?),
                error: None,
                ttl_secs: self.allocation_ttl.as_secs() as u32,
            };
            self.send_to(&response, from).await?;
            return Ok(());
        }

        // Check capacity
        if allocations.len() >= self.max_allocations {
            let response = RelayMessage::AllocateResponse {
                success: false,
                relay_addr: None,
                error: Some("Relay at capacity".to_string()),
                ttl_secs: 0,
            };
            self.send_to(&response, from).await?;
            return Ok(());
        }

        // Create allocation
        let now = Instant::now();
        let allocation = RelayAllocation {
            peer_id,
            client_addr: from,
            created_at: now,
            expires_at: now + self.allocation_ttl,
            last_activity: now,
            bytes_relayed: 0,
        };

        allocations.insert(peer_id, allocation);
        info!("Allocated relay slot for {:?} at {}", peer_id, from);

        let response = RelayMessage::AllocateResponse {
            success: true,
            relay_addr: Some(self.local_addr()?),
            error: None,
            ttl_secs: self.allocation_ttl.as_secs() as u32,
        };
        self.send_to(&response, from).await?;

        Ok(())
    }

    /// Handle connect request (relay introduction)
    async fn handle_connect(
        &self,
        from_peer: PeerId,
        to_peer: PeerId,
        from: SocketAddr,
    ) -> NetworkResult<()> {
        let allocations = self.allocations.read().await;

        // Check if target peer has allocation
        let target_addr = match allocations.get(&to_peer) {
            Some(alloc) => alloc.client_addr,
            None => {
                let response = RelayMessage::ConnectResponse {
                    success: false,
                    error: Some("Target peer not registered with relay".to_string()),
                };
                self.send_to(&response, from).await?;
                return Ok(());
            }
        };

        drop(allocations);

        // Forward connect request to target
        let forward_msg = RelayMessage::ConnectRequest {
            from_peer,
            to_peer,
            nonce: Vec::new(),
        };
        self.send_to(&forward_msg, target_addr).await?;

        // Respond to sender
        let response = RelayMessage::ConnectResponse {
            success: true,
            error: None,
        };
        self.send_to(&response, from).await?;

        debug!("Relayed connect request from {:?} to {:?}", from_peer, to_peer);

        Ok(())
    }

    /// Handle data relay
    async fn handle_data(
        &self,
        from_peer: PeerId,
        to_peer: PeerId,
        payload: Vec<u8>,
        from: SocketAddr,
    ) -> NetworkResult<()> {
        let allocations = self.allocations.read().await;

        // Find target peer's address
        let target_addr = match allocations.get(&to_peer) {
            Some(alloc) => alloc.client_addr,
            None => {
                trace!("Target peer {:?} not registered with relay", to_peer);
                return Ok(());
            }
        };

        // Update sender's activity and address
        let sender_registered = allocations.contains_key(&from_peer);
        drop(allocations);

        if sender_registered {
            let mut allocations = self.allocations.write().await;
            if let Some(alloc) = allocations.get_mut(&from_peer) {
                alloc.client_addr = from;
                alloc.bytes_relayed += payload.len() as u64;
                alloc.touch();
            }
        }

        // Forward data to target peer
        let forward_msg = RelayMessage::Data {
            from_peer,
            to_peer,
            payload: payload.clone(),
        };
        self.send_to(&forward_msg, target_addr).await?;

        // Update target's stats
        let mut allocations = self.allocations.write().await;
        if let Some(alloc) = allocations.get_mut(&to_peer) {
            alloc.bytes_relayed += payload.len() as u64;
            alloc.touch();
        }

        trace!("Relayed {} bytes from {:?} to {:?}", payload.len(), from_peer, to_peer);

        Ok(())
    }

    /// Handle keepalive
    async fn handle_keepalive(&self, peer_id: PeerId, from: SocketAddr) -> NetworkResult<()> {
        let mut allocations = self.allocations.write().await;

        if let Some(alloc) = allocations.get_mut(&peer_id) {
            alloc.touch();
            alloc.expires_at = Instant::now() + self.allocation_ttl;
            alloc.client_addr = from; // Update in case of NAT rebinding
            trace!("Keepalive from {:?}", peer_id);
        }

        Ok(())
    }

    /// Handle disconnect
    async fn handle_disconnect(&self, peer_id: PeerId) -> NetworkResult<()> {
        let mut allocations = self.allocations.write().await;

        if allocations.remove(&peer_id).is_some() {
            info!("Peer {:?} disconnected from relay", peer_id);
        }

        Ok(())
    }

    /// Send message to address
    async fn send_to(&self, msg: &RelayMessage, addr: SocketAddr) -> NetworkResult<()> {
        let data = msg.to_bytes()?;
        self.socket.send_to(&data, addr).await
            .map_err(|e| NetworkError::SendError(e.to_string()))?;
        Ok(())
    }

    /// Get stats
    pub async fn stats(&self) -> RelayStats {
        let allocations = self.allocations.read().await;

        let mut total_bytes = 0u64;
        for alloc in allocations.values() {
            total_bytes += alloc.bytes_relayed;
        }

        RelayStats {
            active_allocations: allocations.len(),
            total_bytes_relayed: total_bytes,
        }
    }
}

/// Relay statistics
#[derive(Debug, Clone)]
pub struct RelayStats {
    pub active_allocations: usize,
    pub total_bytes_relayed: u64,
}

/// Relay Client - used by peers to connect via relay
pub struct RelayClient {
    /// UDP socket
    socket: Arc<UdpSocket>,
    /// Our peer ID
    peer_id: PeerId,
    /// Relay server address
    relay_addr: SocketAddr,
    /// Whether we have an allocation
    allocated: bool,
}

impl RelayClient {
    /// Create a new relay client
    pub async fn new(
        peer_id: PeerId,
        relay_addr: SocketAddr,
        bind_addr: &str,
    ) -> NetworkResult<Self> {
        let socket = UdpSocket::bind(bind_addr).await
            .map_err(|e| NetworkError::BindError(e.to_string()))?;

        Ok(Self {
            socket: Arc::new(socket),
            peer_id,
            relay_addr,
            allocated: false,
        })
    }

    /// Allocate a relay slot
    pub async fn allocate(&mut self) -> NetworkResult<SocketAddr> {
        let request = RelayMessage::AllocateRequest {
            peer_id: self.peer_id,
        };

        let data = request.to_bytes()?;
        self.socket.send_to(&data, self.relay_addr).await
            .map_err(|e| NetworkError::SendError(e.to_string()))?;

        // Wait for response
        let mut buf = [0u8; 1024];
        let timeout = tokio::time::timeout(
            Duration::from_secs(5),
            self.socket.recv_from(&mut buf),
        ).await;

        match timeout {
            Ok(Ok((len, _))) => {
                let response = RelayMessage::from_bytes(&buf[..len])?;

                match response {
                    RelayMessage::AllocateResponse { success: true, relay_addr: Some(addr), .. } => {
                        self.allocated = true;
                        info!("Got relay allocation at {}", addr);
                        Ok(addr)
                    }
                    RelayMessage::AllocateResponse { error: Some(e), .. } => {
                        Err(NetworkError::ConnectionFailed(e))
                    }
                    _ => Err(NetworkError::ConnectionFailed("Unexpected response".to_string())),
                }
            }
            Ok(Err(e)) => Err(NetworkError::ReceiveError(e.to_string())),
            Err(_) => Err(NetworkError::Timeout),
        }
    }

    /// Request connection to peer via relay
    pub async fn connect_via_relay(&self, target_peer: PeerId) -> NetworkResult<()> {
        if !self.allocated {
            return Err(NetworkError::NotConnected);
        }

        let nonce: Vec<u8> = (0..16).map(|_| rand::random::<u8>()).collect();

        let request = RelayMessage::ConnectRequest {
            from_peer: self.peer_id,
            to_peer: target_peer,
            nonce,
        };

        let data = request.to_bytes()?;
        self.socket.send_to(&data, self.relay_addr).await
            .map_err(|e| NetworkError::SendError(e.to_string()))?;

        // Wait for response
        let mut buf = [0u8; 1024];
        let timeout = tokio::time::timeout(
            Duration::from_secs(5),
            self.socket.recv_from(&mut buf),
        ).await;

        match timeout {
            Ok(Ok((len, _))) => {
                let response = RelayMessage::from_bytes(&buf[..len])?;

                match response {
                    RelayMessage::ConnectResponse { success: true, .. } => {
                        info!("Relay connect request sent to {:?}", target_peer);
                        Ok(())
                    }
                    RelayMessage::ConnectResponse { error: Some(e), .. } => {
                        Err(NetworkError::ConnectionFailed(e))
                    }
                    _ => Err(NetworkError::ConnectionFailed("Unexpected response".to_string())),
                }
            }
            Ok(Err(e)) => Err(NetworkError::ReceiveError(e.to_string())),
            Err(_) => Err(NetworkError::Timeout),
        }
    }

    /// Send data via relay to a specific peer
    pub async fn send_data(&self, to_peer: PeerId, payload: Vec<u8>) -> NetworkResult<()> {
        if !self.allocated {
            return Err(NetworkError::NotConnected);
        }

        let msg = RelayMessage::Data {
            from_peer: self.peer_id,
            to_peer,
            payload,
        };

        let data = msg.to_bytes()?;
        self.socket.send_to(&data, self.relay_addr).await
            .map_err(|e| NetworkError::SendError(e.to_string()))?;

        Ok(())
    }

    /// Receive data from relay
    pub async fn recv_data(&self) -> NetworkResult<(PeerId, Vec<u8>)> {
        let mut buf = [0u8; 65536];
        let timeout = tokio::time::timeout(
            Duration::from_secs(30),
            self.socket.recv_from(&mut buf),
        ).await;

        match timeout {
            Ok(Ok((len, _))) => {
                let msg = RelayMessage::from_bytes(&buf[..len])?;
                match msg {
                    RelayMessage::Data { from_peer, payload, .. } => {
                        Ok((from_peer, payload))
                    }
                    _ => Err(NetworkError::InvalidPacket("Expected Data message".to_string())),
                }
            }
            Ok(Err(e)) => Err(NetworkError::ReceiveError(e.to_string())),
            Err(_) => Err(NetworkError::Timeout),
        }
    }

    /// Send keepalive
    pub async fn keepalive(&self) -> NetworkResult<()> {
        let msg = RelayMessage::Keepalive {
            peer_id: self.peer_id,
        };

        let data = msg.to_bytes()?;
        self.socket.send_to(&data, self.relay_addr).await
            .map_err(|e| NetworkError::SendError(e.to_string()))?;

        Ok(())
    }

    /// Disconnect from relay
    pub async fn disconnect(&mut self) -> NetworkResult<()> {
        let msg = RelayMessage::Disconnect {
            peer_id: self.peer_id,
        };

        let data = msg.to_bytes()?;
        self.socket.send_to(&data, self.relay_addr).await
            .map_err(|e| NetworkError::SendError(e.to_string()))?;

        self.allocated = false;
        Ok(())
    }
}
