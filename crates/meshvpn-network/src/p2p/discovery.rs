//! Discovery Service Client
//!
//! Handles peer registration, discovery, and connection brokering
//! through the centralized discovery server (EC2).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::time::{interval, timeout};
use tracing::{debug, info, warn};

use super::protocol::{
    P2PMessage, PeerId, PeerInfo, NatType, PeerCapabilities,
    RegisterRequest, GetPeersRequest, HeartbeatRequest, ConnectRequest,
    serialize_message, deserialize_message,
};
use super::stun::{StunClient, DEFAULT_STUN_SERVERS};
use crate::error::{NetworkError, NetworkResult};

/// Discovery server configuration
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Discovery server address
    pub server_addr: SocketAddr,
    /// Heartbeat interval
    pub heartbeat_interval: Duration,
    /// Registration TTL
    pub registration_ttl: Duration,
    /// Request timeout
    pub request_timeout: Duration,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            // Default to our EC2 server
            server_addr: "54.160.213.165:51821".parse().unwrap(),
            heartbeat_interval: Duration::from_secs(30),
            registration_ttl: Duration::from_secs(120),
            request_timeout: Duration::from_secs(5),
        }
    }
}

/// Event from discovery service
#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    /// Registration successful
    Registered { nat_type: NatType, public_addr: SocketAddr },
    /// Connection request from peer
    ConnectionRequest { from_peer: PeerId, from_addr: SocketAddr, nonce: [u8; 16] },
    /// Peer list updated
    PeersUpdated { peers: Vec<PeerInfo> },
    /// Disconnected from server
    Disconnected,
    /// Error occurred
    Error(String),
}

/// Discovery service client
pub struct DiscoveryClient {
    /// Our peer ID
    peer_id: PeerId,
    /// Our public key
    public_key: [u8; 32],
    /// Private key for signing
    private_key: [u8; 32],
    /// UDP socket
    socket: Arc<UdpSocket>,
    /// Configuration
    config: DiscoveryConfig,
    /// Current registration state
    state: Arc<RwLock<DiscoveryState>>,
    /// Known peers
    peers: Arc<RwLock<Vec<PeerInfo>>>,
    /// Running flag
    running: Arc<std::sync::atomic::AtomicBool>,
}

/// Internal state
struct DiscoveryState {
    registered: bool,
    public_addr: Option<SocketAddr>,
    nat_type: NatType,
    last_heartbeat: Option<Instant>,
}

impl Default for DiscoveryState {
    fn default() -> Self {
        Self {
            registered: false,
            public_addr: None,
            nat_type: NatType::Unknown,
            last_heartbeat: None,
        }
    }
}

impl DiscoveryClient {
    /// Create new discovery client
    pub async fn new(
        public_key: [u8; 32],
        private_key: [u8; 32],
        bind_addr: &str,
    ) -> NetworkResult<Self> {
        let socket = UdpSocket::bind(bind_addr).await
            .map_err(|e| NetworkError::IoError(e.to_string()))?;

        let peer_id = PeerId::from_public_key(&public_key);

        info!("Discovery client created, peer ID: {}", peer_id);

        Ok(Self {
            peer_id,
            public_key,
            private_key,
            socket: Arc::new(socket),
            config: DiscoveryConfig::default(),
            state: Arc::new(RwLock::new(DiscoveryState::default())),
            peers: Arc::new(RwLock::new(Vec::new())),
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Set custom discovery server
    pub fn set_server(&mut self, addr: SocketAddr) {
        self.config.server_addr = addr;
    }

    /// Get local socket address
    pub fn local_addr(&self) -> NetworkResult<SocketAddr> {
        self.socket.local_addr()
            .map_err(|e| NetworkError::IoError(e.to_string()))
    }

    /// Get our peer ID
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Discover our NAT type using STUN
    pub async fn detect_nat(&self) -> NetworkResult<(SocketAddr, NatType)> {
        info!("Detecting NAT type via STUN...");

        // Create STUN client using our socket
        // Note: We need to use a separate socket for STUN or share carefully
        let stun = StunClient::new("0.0.0.0:0").await?;

        // Get mapped address from primary server
        let result = stun.get_mapped_address(DEFAULT_STUN_SERVERS[0]).await?;
        info!("STUN mapped address: {}", result.mapped_address);

        // Detect NAT type
        let nat_type = stun.detect_nat_type(DEFAULT_STUN_SERVERS[0]).await?;
        info!("Detected NAT type: {:?}", nat_type);

        Ok((result.mapped_address, nat_type))
    }

    /// Register with discovery server
    pub async fn register(&self) -> NetworkResult<(SocketAddr, NatType)> {
        info!("Registering with discovery server at {}", self.config.server_addr);

        // First detect our NAT situation
        let (public_addr, nat_type) = self.detect_nat().await?;

        // Build registration request
        let peer_info = PeerInfo {
            peer_id: self.peer_id,
            public_addr,
            local_addr: Some(self.local_addr()?),
            nat_type,
            public_key: self.public_key,
            capabilities: PeerCapabilities {
                can_relay: false, // TODO: detect
                high_bandwidth: false,
                stable: false,
                turn_server: false,
            },
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        // Sign the registration (simplified - should use proper Ed25519)
        let sign_data = format!("{}:{}", self.peer_id, public_addr);
        let hash = blake3::hash(sign_data.as_bytes());
        let mut signature = Vec::with_capacity(64);
        signature.extend_from_slice(hash.as_bytes());
        signature.extend_from_slice(&[0u8; 32]); // Pad to 64 bytes

        let request = P2PMessage::Register(RegisterRequest {
            peer_info,
            signature,
        });

        // Send registration
        let data = serialize_message(&request)
            .map_err(|e| NetworkError::Protocol(e.to_string()))?;

        self.socket.send_to(&data, self.config.server_addr).await
            .map_err(|e| NetworkError::IoError(e.to_string()))?;

        debug!("Sent registration request");

        // Wait for response
        let mut buf = [0u8; 4096];
        let (n, _from) = timeout(
            self.config.request_timeout,
            self.socket.recv_from(&mut buf),
        ).await
            .map_err(|_| NetworkError::TimeoutWithMessage("Registration timeout".into()))?
            .map_err(|e| NetworkError::IoError(e.to_string()))?;

        // Parse response
        let response = deserialize_message(&buf[..n])
            .map_err(|e| NetworkError::Protocol(e.to_string()))?;

        match response {
            P2PMessage::RegisterAck(ack) => {
                if ack.success {
                    info!(
                        "Registered successfully, public addr: {}, NAT: {:?}",
                        ack.observed_addr, ack.nat_type
                    );

                    // Update state
                    let mut state = self.state.write().await;
                    state.registered = true;
                    state.public_addr = Some(ack.observed_addr);
                    state.nat_type = ack.nat_type;
                    state.last_heartbeat = Some(Instant::now());

                    Ok((ack.observed_addr, ack.nat_type))
                } else {
                    Err(NetworkError::Protocol("Registration rejected".into()))
                }
            }
            P2PMessage::Error(e) => {
                Err(NetworkError::Protocol(format!("Registration error: {}", e.message)))
            }
            _ => {
                Err(NetworkError::Protocol("Unexpected response".into()))
            }
        }
    }

    /// Get list of available peers
    pub async fn get_peers(&self, limit: u32, require_relay: bool) -> NetworkResult<Vec<PeerInfo>> {
        let request = P2PMessage::GetPeers(GetPeersRequest {
            requesting_peer: self.peer_id,
            limit,
            require_relay,
        });

        let data = serialize_message(&request)
            .map_err(|e| NetworkError::Protocol(e.to_string()))?;

        self.socket.send_to(&data, self.config.server_addr).await
            .map_err(|e| NetworkError::IoError(e.to_string()))?;

        let mut buf = [0u8; 65536];
        let (n, _from) = timeout(
            self.config.request_timeout,
            self.socket.recv_from(&mut buf),
        ).await
            .map_err(|_| NetworkError::TimeoutWithMessage("GetPeers timeout".into()))?
            .map_err(|e| NetworkError::IoError(e.to_string()))?;

        let response = deserialize_message(&buf[..n])
            .map_err(|e| NetworkError::Protocol(e.to_string()))?;

        match response {
            P2PMessage::PeerList(list) => {
                info!("Received {} peers (total: {})", list.peers.len(), list.total_count);

                // Update local cache
                let mut peers = self.peers.write().await;
                *peers = list.peers.clone();

                Ok(list.peers)
            }
            P2PMessage::Error(e) => {
                Err(NetworkError::Protocol(format!("GetPeers error: {}", e.message)))
            }
            _ => {
                Err(NetworkError::Protocol("Unexpected response".into()))
            }
        }
    }

    /// Request connection to a peer
    pub async fn request_connection(
        &self,
        target_peer: PeerId,
        session_pubkey: [u8; 32],
    ) -> NetworkResult<()> {
        let request = P2PMessage::ConnectRequest(ConnectRequest {
            from_peer: self.peer_id,
            to_peer: target_peer,
            session_pubkey,
        });

        let data = serialize_message(&request)
            .map_err(|e| NetworkError::Protocol(e.to_string()))?;

        self.socket.send_to(&data, self.config.server_addr).await
            .map_err(|e| NetworkError::IoError(e.to_string()))?;

        info!("Sent connection request to peer {}", target_peer);
        Ok(())
    }

    /// Send heartbeat to keep registration alive
    pub async fn heartbeat(&self) -> NetworkResult<()> {
        let request = P2PMessage::Heartbeat(HeartbeatRequest {
            peer_id: self.peer_id,
            bytes_relayed: 0, // TODO: track
            active_connections: 0, // TODO: track
        });

        let data = serialize_message(&request)
            .map_err(|e| NetworkError::Protocol(e.to_string()))?;

        self.socket.send_to(&data, self.config.server_addr).await
            .map_err(|e| NetworkError::IoError(e.to_string()))?;

        // Wait for ack
        let mut buf = [0u8; 256];
        match timeout(Duration::from_secs(2), self.socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                if let Ok(P2PMessage::HeartbeatAck) = deserialize_message(&buf[..n]) {
                    debug!("Heartbeat acknowledged");
                    let mut state = self.state.write().await;
                    state.last_heartbeat = Some(Instant::now());
                }
            }
            _ => {
                warn!("Heartbeat timeout");
            }
        }

        Ok(())
    }

    /// Start background heartbeat task
    pub fn start_heartbeat(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        use std::sync::atomic::Ordering;

        let client = Arc::clone(self);
        client.running.store(true, Ordering::SeqCst);

        tokio::spawn(async move {
            let mut interval = interval(client.config.heartbeat_interval);

            while client.running.load(Ordering::SeqCst) {
                interval.tick().await;

                let state = client.state.read().await;
                if state.registered {
                    drop(state);
                    if let Err(e) = client.heartbeat().await {
                        warn!("Heartbeat failed: {}", e);
                    }
                }
            }
        })
    }

    /// Stop the client
    pub fn stop(&self) {
        use std::sync::atomic::Ordering;
        self.running.store(false, Ordering::SeqCst);
        info!("Discovery client stopped");
    }

    /// Get current registration state
    pub async fn is_registered(&self) -> bool {
        self.state.read().await.registered
    }

    /// Get detected NAT type
    pub async fn nat_type(&self) -> NatType {
        self.state.read().await.nat_type
    }

    /// Get our public address
    pub async fn public_addr(&self) -> Option<SocketAddr> {
        self.state.read().await.public_addr
    }

    /// Get cached peers
    pub async fn cached_peers(&self) -> Vec<PeerInfo> {
        self.peers.read().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = DiscoveryConfig::default();
        assert_eq!(config.heartbeat_interval, Duration::from_secs(30));
        assert_eq!(config.registration_ttl, Duration::from_secs(120));
    }
}
