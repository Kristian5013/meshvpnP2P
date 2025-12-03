//! MeshVPN Discovery Server
//!
//! Centralized service for P2P peer discovery and NAT traversal coordination.
//! Runs on EC2 to help peers find each other and establish direct connections.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::Parser;
use dashmap::DashMap;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use meshvpn_network::p2p::protocol::{
    P2PMessage, PeerId, PeerInfo, NatType,
    RegisterResponse, PeerListResponse, ConnectOffer,
    ErrorResponse, ErrorCode,
    serialize_message, deserialize_message,
};

/// MeshVPN Discovery Server
#[derive(Parser)]
#[command(name = "meshvpn-discovery")]
#[command(author, version, about)]
struct Cli {
    /// Listen address for UDP
    #[arg(short, long, default_value = "0.0.0.0:51821")]
    listen: String,

    /// Registration TTL (seconds)
    #[arg(long, default_value = "300")]
    ttl: u64,

    /// Cleanup interval (seconds)
    #[arg(long, default_value = "60")]
    cleanup_interval: u64,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,
}

/// Registered peer entry
struct PeerEntry {
    info: PeerInfo,
    observed_addr: SocketAddr,
    registered_at: Instant,
    last_heartbeat: Instant,
}

/// Discovery server state
struct DiscoveryServer {
    /// UDP socket
    socket: Arc<UdpSocket>,
    /// Registered peers
    peers: Arc<DashMap<PeerId, PeerEntry>>,
    /// Registration TTL
    ttl: Duration,
}

impl DiscoveryServer {
    async fn new(listen_addr: &str, ttl_secs: u64) -> Result<Self> {
        let socket = UdpSocket::bind(listen_addr).await?;
        info!("Discovery server listening on {}", listen_addr);

        Ok(Self {
            socket: Arc::new(socket),
            peers: Arc::new(DashMap::new()),
            ttl: Duration::from_secs(ttl_secs),
        })
    }

    async fn run(&self) -> Result<()> {
        let mut buf = [0u8; 65536];

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((n, from)) => {
                    if let Err(e) = self.handle_packet(&buf[..n], from).await {
                        warn!("Error handling packet from {}: {}", from, e);
                    }
                }
                Err(e) => {
                    error!("Receive error: {}", e);
                }
            }
        }
    }

    async fn handle_packet(&self, data: &[u8], from: SocketAddr) -> Result<()> {
        let msg = match deserialize_message(data) {
            Ok(m) => m,
            Err(e) => {
                debug!("Failed to deserialize message from {}: {}", from, e);
                return Ok(());
            }
        };

        match msg {
            P2PMessage::Register(req) => {
                self.handle_register(req.peer_info, from).await?;
            }
            P2PMessage::GetPeers(req) => {
                self.handle_get_peers(req, from).await?;
            }
            P2PMessage::Heartbeat(req) => {
                self.handle_heartbeat(req.peer_id, from).await?;
            }
            P2PMessage::ConnectRequest(req) => {
                self.handle_connect_request(req, from).await?;
            }
            _ => {
                debug!("Unexpected message type from {}", from);
            }
        }

        Ok(())
    }

    async fn handle_register(&self, mut peer_info: PeerInfo, observed_addr: SocketAddr) -> Result<()> {
        info!(
            "Register request from peer {} (observed: {}, claimed: {})",
            peer_info.peer_id, observed_addr, peer_info.public_addr
        );

        // Detect NAT type based on observed vs claimed address
        let nat_type = self.detect_nat_type(&peer_info, observed_addr);

        // Update peer info with server's observations
        peer_info.public_addr = observed_addr;
        peer_info.nat_type = nat_type;
        peer_info.last_seen = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let peer_id = peer_info.peer_id;

        // Store peer
        let entry = PeerEntry {
            info: peer_info,
            observed_addr,
            registered_at: Instant::now(),
            last_heartbeat: Instant::now(),
        };

        self.peers.insert(peer_id, entry);
        info!("Registered peer {} ({:?})", peer_id, nat_type);

        // Send response
        let response = P2PMessage::RegisterAck(RegisterResponse {
            success: true,
            observed_addr,
            nat_type,
            ttl: self.ttl.as_secs() as u32,
        });

        self.send_response(&response, observed_addr).await
    }

    fn detect_nat_type(&self, peer_info: &PeerInfo, observed_addr: SocketAddr) -> NatType {
        // Simple NAT detection based on claimed vs observed
        if let Some(local_addr) = peer_info.local_addr {
            if local_addr.ip() == observed_addr.ip() {
                // Public IP, no NAT
                return NatType::None;
            }
        }

        // If claimed public matches observed, peer correctly detected their public IP
        // This typically means they're behind some form of cone NAT
        if peer_info.public_addr == observed_addr {
            // For now, assume port restricted (most common)
            return NatType::PortRestricted;
        }

        // Port changed - might be symmetric
        if peer_info.public_addr.ip() == observed_addr.ip()
            && peer_info.public_addr.port() != observed_addr.port()
        {
            return NatType::Symmetric;
        }

        // Default to port restricted
        NatType::PortRestricted
    }

    async fn handle_get_peers(
        &self,
        req: meshvpn_network::p2p::protocol::GetPeersRequest,
        from: SocketAddr,
    ) -> Result<()> {
        debug!("GetPeers request from {:?}", req.requesting_peer);

        let mut peers: Vec<PeerInfo> = self.peers
            .iter()
            .filter(|entry| {
                // Don't return the requesting peer
                entry.key() != &req.requesting_peer
            })
            .filter(|entry| {
                // Filter by relay capability if requested
                if req.require_relay {
                    entry.value().info.capabilities.can_relay
                } else {
                    true
                }
            })
            .take(req.limit as usize)
            .map(|entry| entry.value().info.clone())
            .collect();

        let total_count = self.peers.len() as u32;

        // Sort by NAT type (easier to connect first)
        peers.sort_by_key(|p| match p.nat_type {
            NatType::None => 0,
            NatType::FullCone => 1,
            NatType::AddressRestricted => 2,
            NatType::PortRestricted => 3,
            NatType::Symmetric => 4,
            NatType::Unknown => 5,
        });

        info!("Returning {} peers to {:?}", peers.len(), req.requesting_peer);

        let response = P2PMessage::PeerList(PeerListResponse {
            peers,
            total_count,
        });

        self.send_response(&response, from).await
    }

    async fn handle_heartbeat(&self, peer_id: PeerId, from: SocketAddr) -> Result<()> {
        if let Some(mut entry) = self.peers.get_mut(&peer_id) {
            entry.last_heartbeat = Instant::now();
            entry.observed_addr = from;
            debug!("Heartbeat from peer {}", peer_id);
        } else {
            debug!("Heartbeat from unknown peer {}", peer_id);
        }

        let response = P2PMessage::HeartbeatAck;
        self.send_response(&response, from).await
    }

    async fn handle_connect_request(
        &self,
        req: meshvpn_network::p2p::protocol::ConnectRequest,
        from: SocketAddr,
    ) -> Result<()> {
        info!(
            "Connect request: {} -> {}",
            req.from_peer, req.to_peer
        );

        // Find target peer
        let target = match self.peers.get(&req.to_peer) {
            Some(entry) => entry,
            None => {
                let error = P2PMessage::Error(ErrorResponse {
                    code: ErrorCode::PeerNotFound,
                    message: "Target peer not registered".into(),
                });
                return self.send_response(&error, from).await;
            }
        };

        // Find source peer info
        let source = match self.peers.get(&req.from_peer) {
            Some(entry) => entry,
            None => {
                let error = P2PMessage::Error(ErrorResponse {
                    code: ErrorCode::AuthenticationFailed,
                    message: "Source peer not registered".into(),
                });
                return self.send_response(&error, from).await;
            }
        };

        // Generate nonce for hole punching
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).ok();

        // Forward connection offer to target
        let offer = P2PMessage::ConnectOffer(ConnectOffer {
            from_peer: req.from_peer,
            from_addr: from,
            from_local_addr: source.info.local_addr,
            from_nat_type: source.info.nat_type,
            session_pubkey: req.session_pubkey,
            nonce,
        });

        let target_addr = target.observed_addr;
        drop(target);
        drop(source);

        info!(
            "Forwarding connect offer to {} at {}",
            req.to_peer, target_addr
        );

        self.send_response(&offer, target_addr).await
    }

    async fn send_response(&self, msg: &P2PMessage, to: SocketAddr) -> Result<()> {
        let data = serialize_message(msg)?;
        self.socket.send_to(&data, to).await?;
        Ok(())
    }

    fn cleanup_expired(&self) {
        let now = Instant::now();
        let expired: Vec<PeerId> = self.peers
            .iter()
            .filter(|entry| now.duration_since(entry.value().last_heartbeat) > self.ttl)
            .map(|entry| *entry.key())
            .collect();

        for peer_id in expired {
            if let Some((_, entry)) = self.peers.remove(&peer_id) {
                info!(
                    "Removed expired peer {} (last seen: {:?} ago)",
                    peer_id,
                    now.duration_since(entry.last_heartbeat)
                );
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = match cli.log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting MeshVPN Discovery Server...");
    info!("Listen: {}", cli.listen);
    info!("TTL: {} seconds", cli.ttl);

    let server = DiscoveryServer::new(&cli.listen, cli.ttl).await?;
    let server = Arc::new(server);

    // Start cleanup task
    let server_cleanup = Arc::clone(&server);
    let cleanup_interval = Duration::from_secs(cli.cleanup_interval);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(cleanup_interval);
        loop {
            interval.tick().await;
            server_cleanup.cleanup_expired();
        }
    });

    // Start statistics reporter
    let server_stats = Arc::clone(&server);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let peer_count = server_stats.peers.len();
            let relay_count = server_stats.peers
                .iter()
                .filter(|e| e.value().info.capabilities.can_relay)
                .count();
            info!("Stats: {} peers registered, {} relays", peer_count, relay_count);
        }
    });

    // Handle shutdown
    let server_run = Arc::clone(&server);
    tokio::select! {
        result = server_run.run() => {
            if let Err(e) = result {
                error!("Server error: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal");
        }
    }

    info!("Discovery server stopped");
    Ok(())
}
