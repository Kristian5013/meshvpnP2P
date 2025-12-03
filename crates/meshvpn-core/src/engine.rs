//! VPN Engine - Core integration layer
//!
//! Connects TUN device, circuit management, DHT discovery,
//! and packet routing into a working VPN system.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use tokio::sync::{mpsc, oneshot, RwLock, Mutex, Notify};
use tokio::time::{interval, timeout};
use tracing::{debug, error, info, trace, warn};

use meshvpn_crypto::prelude::*;
use meshvpn_network::{
    tun::{create_tun, TunConfig, TunDevice},
    transport::UdpTransport,
    packet::{Packet, PacketType},
    connection::{Connection, ConnectionPool},
};

use crate::circuit::{Circuit, CircuitBuilder, CircuitId, CircuitManager, CircuitState, HopInfo};
use crate::config::CoreConfig;
use crate::error::{CoreError, CoreResult};
use crate::handshake::{InitiatorHandshake, ResponderHandshake, SessionKeys, HandshakeInit, HandshakeResponse};
use crate::path::{PathSelector, PathSelectionStrategy, RelayCandidate};
use crate::relay::{RelayNode, RelayCircuit, RelayResult};
use crate::router::{RouteDecision, Router, RoutingTable};

/// VPN Engine state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineState {
    Stopped,
    Starting,
    Running,
    Stopping,
    Error,
}

/// Engine statistics
#[derive(Debug, Clone, Default)]
pub struct EngineStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub active_circuits: usize,
    pub connected_peers: usize,
    pub uptime_secs: u64,
}

/// Peer information from DHT
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PeerInfo {
    pub node_id: NodeId,
    pub public_key: PublicKey,
    pub addresses: Vec<SocketAddr>,
    pub is_exit: bool,
    pub capacity: u32,
    pub load: u8,
    pub region: Option<String>,
}

/// Pending handshake info
struct PendingHandshake {
    handshake: InitiatorHandshake,
    response_tx: oneshot::Sender<HandshakeResponse>,
}

/// The main VPN engine
pub struct VpnEngine {
    /// Our identity
    identity: Arc<NodeIdentity>,
    /// Configuration
    config: CoreConfig,
    /// Engine state
    state: Arc<RwLock<EngineState>>,
    /// Start time for uptime calculation
    start_time: RwLock<Option<Instant>>,
    /// TUN device
    tun: Arc<RwLock<Option<Box<dyn TunDevice>>>>,
    /// UDP transport
    transport: Arc<RwLock<Option<Arc<UdpTransport>>>>,
    /// Circuit manager
    circuits: Arc<CircuitManager>,
    /// Relay node (for forwarding other's traffic)
    relay: Arc<RelayNode>,
    /// Connection pool
    connections: Arc<ConnectionPool>,
    /// Traffic router
    router: Arc<Router>,
    /// Known peers (from DHT)
    peers: Arc<RwLock<HashMap<NodeId, PeerInfo>>>,
    /// Exit nodes
    exit_nodes: Arc<RwLock<Vec<PeerInfo>>>,
    /// Bootstrap nodes
    bootstrap_nodes: Arc<RwLock<Vec<SocketAddr>>>,
    /// Pending handshakes waiting for responses
    pending_handshakes: Arc<RwLock<HashMap<CircuitId, PendingHandshake>>>,
    /// Statistics
    bytes_sent: Arc<AtomicU64>,
    bytes_received: Arc<AtomicU64>,
    packets_sent: Arc<AtomicU64>,
    packets_received: Arc<AtomicU64>,
    /// Shutdown signal
    shutdown: Arc<AtomicBool>,
    /// Shutdown notification
    shutdown_notify: Arc<Notify>,
}

impl VpnEngine {
    /// Create a new VPN engine
    pub async fn new(identity: NodeIdentity, config: CoreConfig) -> CoreResult<Arc<Self>> {
        let identity = Arc::new(identity);

        let circuits = Arc::new(CircuitManager::new(config.max_circuits));
        let relay = Arc::new(RelayNode::new(
            (*identity).clone(),
            config.max_relay_circuits,
            config.relay_bandwidth_limit,
        ));
        let connections = Arc::new(ConnectionPool::default_pool());
        let router = Arc::new(Router::new(circuits.clone()));

        Ok(Arc::new(Self {
            identity,
            config,
            state: Arc::new(RwLock::new(EngineState::Stopped)),
            start_time: RwLock::new(None),
            tun: Arc::new(RwLock::new(None)),
            transport: Arc::new(RwLock::new(None)),
            circuits,
            relay,
            connections,
            router,
            peers: Arc::new(RwLock::new(HashMap::new())),
            exit_nodes: Arc::new(RwLock::new(Vec::new())),
            bootstrap_nodes: Arc::new(RwLock::new(Vec::new())),
            pending_handshakes: Arc::new(RwLock::new(HashMap::new())),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
            packets_sent: Arc::new(AtomicU64::new(0)),
            packets_received: Arc::new(AtomicU64::new(0)),
            shutdown: Arc::new(AtomicBool::new(false)),
            shutdown_notify: Arc::new(Notify::new()),
        }))
    }

    /// Set bootstrap nodes
    pub async fn set_bootstrap_nodes(&self, nodes: Vec<SocketAddr>) {
        *self.bootstrap_nodes.write().await = nodes;
    }

    /// Get engine state
    pub async fn state(&self) -> EngineState {
        *self.state.read().await
    }

    /// Get our node ID
    pub fn node_id(&self) -> NodeId {
        self.identity.node_id()
    }

    /// Start the VPN engine
    pub async fn start(self: &Arc<Self>, tun_config: TunConfig, listen_port: u16) -> CoreResult<()> {
        info!("Starting VPN engine...");
        *self.state.write().await = EngineState::Starting;
        *self.start_time.write().await = Some(Instant::now());

        // Reset shutdown flag
        self.shutdown.store(false, Ordering::SeqCst);

        // Create TUN device
        info!("Creating TUN device: {}", tun_config.name);
        let tun = create_tun(tun_config.clone()).await?;
        info!("TUN device created successfully: {}", tun.name());
        *self.tun.write().await = Some(tun);

        // Create UDP transport
        let listen_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), listen_port);
        info!("Binding UDP transport to {}", listen_addr);
        let transport = Arc::new(UdpTransport::bind(listen_addr).await?);
        info!("UDP transport bound to {}", transport.local_addr());
        *self.transport.write().await = Some(transport.clone());

        // Initialize router
        self.router.init().await;

        // Bootstrap DHT
        let bootstrap_nodes = self.bootstrap_nodes.read().await.clone();
        if !bootstrap_nodes.is_empty() {
            info!("Bootstrapping from {} nodes", bootstrap_nodes.len());
            self.bootstrap(&bootstrap_nodes).await?;
        }

        // Build initial circuit
        info!("Building initial circuit with {} hops", self.config.circuit_length);
        match self.build_circuit().await {
            Ok(circuit_id) => {
                info!("Initial circuit {} built successfully", circuit_id);
            }
            Err(e) => {
                warn!("Failed to build initial circuit: {}. Continuing anyway...", e);
            }
        }

        // Start background tasks
        self.spawn_tun_reader_task();
        self.spawn_tun_writer_task();
        self.spawn_network_receiver_task(transport);
        self.spawn_keepalive_task();
        self.spawn_circuit_rotation_task();
        self.spawn_cleanup_task();

        *self.state.write().await = EngineState::Running;
        info!("VPN engine started successfully");

        Ok(())
    }

    /// Stop the VPN engine
    pub async fn stop(&self) -> CoreResult<()> {
        info!("Stopping VPN engine...");
        *self.state.write().await = EngineState::Stopping;

        // Signal shutdown
        self.shutdown.store(true, Ordering::SeqCst);
        self.shutdown_notify.notify_waiters();

        // Wait a moment for tasks to notice shutdown
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Close TUN device
        if let Some(tun) = self.tun.write().await.take() {
            if let Err(e) = tun.close().await {
                warn!("Error closing TUN device: {}", e);
            }
        }

        // Tear down circuits
        for circuit_id in self.circuits.circuit_ids().await {
            if let Err(e) = self.teardown_circuit(circuit_id).await {
                warn!("Error tearing down circuit {}: {}", circuit_id, e);
            }
        }

        *self.state.write().await = EngineState::Stopped;
        info!("VPN engine stopped");
        Ok(())
    }

    /// Bootstrap from known nodes
    async fn bootstrap(&self, bootstrap_nodes: &[SocketAddr]) -> CoreResult<()> {
        let transport = self.transport.read().await;
        let transport = transport.as_ref().ok_or_else(|| {
            CoreError::ProtocolError("Transport not initialized".into())
        })?;

        for addr in bootstrap_nodes {
            debug!("Contacting bootstrap node: {}", addr);

            // Send FIND_NODE request
            let find_node = self.create_find_node_request();
            let packet = Packet::new(
                PacketType::FindNodes,
                0,
                find_node,
            );

            if let Err(e) = transport.send_to(&packet, *addr).await {
                warn!("Failed to contact bootstrap node {}: {}", addr, e);
            }
        }

        // Wait for responses
        tokio::time::sleep(Duration::from_secs(2)).await;

        let peers = self.peers.read().await;
        info!("Bootstrap complete, discovered {} peers", peers.len());

        Ok(())
    }

    /// Build a new circuit
    pub async fn build_circuit(&self) -> CoreResult<CircuitId> {
        let exit_nodes = self.exit_nodes.read().await;
        let peers = self.peers.read().await;

        if exit_nodes.is_empty() {
            return Err(CoreError::NoPathAvailable);
        }

        // Convert to relay candidates
        let mut candidates: Vec<RelayCandidate> = peers
            .values()
            .filter(|p| !p.is_exit)
            .map(|p| RelayCandidate {
                node_id: p.node_id,
                public_key: p.public_key,
                address: p.addresses.first().copied().unwrap_or_else(|| {
                    "0.0.0.0:0".parse().unwrap()
                }),
                latency_ms: None,
                bandwidth: None,
                region: p.region.clone(),
                country: p.region.clone(),
                asn: None,
                is_exit: false,
                capacity: p.capacity,
                load: p.load,
                uptime: 0.99,
                last_seen: Instant::now(),
            })
            .collect();

        // Add exit nodes
        for exit in exit_nodes.iter() {
            candidates.push(RelayCandidate {
                node_id: exit.node_id,
                public_key: exit.public_key,
                address: exit.addresses.first().copied().unwrap_or_else(|| {
                    "0.0.0.0:0".parse().unwrap()
                }),
                latency_ms: None,
                bandwidth: None,
                region: exit.region.clone(),
                country: exit.region.clone(),
                asn: None,
                is_exit: true,
                capacity: exit.capacity,
                load: exit.load,
                uptime: 0.99,
                last_seen: Instant::now(),
            });
        }

        drop(peers);
        drop(exit_nodes);

        // Select path
        let strategy = if self.config.prefer_geo_diversity {
            PathSelectionStrategy::GeoDiverse
        } else {
            PathSelectionStrategy::Balanced
        };
        let selector = PathSelector::new(strategy);
        let path = selector.select_path(&candidates, self.config.circuit_length)?;

        info!(
            "Selected path: {:?}",
            path.iter().map(|p| format!("{:?}", p.node_id)).collect::<Vec<_>>()
        );

        // Build circuit through handshakes
        let circuit_id = self.build_circuit_through_path(&path).await?;

        // Set as default if we don't have one
        if self.circuits.get_default().await.is_none() {
            self.circuits.set_default(circuit_id).await?;
        }

        Ok(circuit_id)
    }

    /// Build circuit through a path of nodes
    async fn build_circuit_through_path(&self, path: &[RelayCandidate]) -> CoreResult<CircuitId> {
        let mut builder = CircuitBuilder::new();
        let circuit_id = builder.id();

        let transport = self.transport.read().await;
        let transport = transport.as_ref().ok_or_else(|| {
            CoreError::ProtocolError("Transport not initialized".into())
        })?;

        // Perform handshakes with each hop
        for (i, node) in path.iter().enumerate() {
            info!("Handshake with hop {}: {:?}", i + 1, node.node_id);

            // Create handshake
            let mut handshake = InitiatorHandshake::new(
                (*self.identity).clone(),
                node.public_key,
            );

            // Create response channel
            let (response_tx, response_rx) = oneshot::channel();

            // Store pending handshake
            {
                let mut pending = self.pending_handshakes.write().await;
                pending.insert(circuit_id, PendingHandshake {
                    handshake: handshake.clone(),
                    response_tx,
                });
            }

            // Send handshake init
            let init = handshake.create_init()?;
            let init_bytes = bincode::serialize(&init)
                .map_err(|e| CoreError::ProtocolError(e.to_string()))?;

            let packet = Packet::handshake_init(circuit_id, init_bytes);
            transport.send_to(&packet, node.address).await?;

            // Wait for response with timeout
            let response = match timeout(
                self.config.handshake_timeout,
                response_rx,
            ).await {
                Ok(Ok(resp)) => resp,
                Ok(Err(_)) => {
                    self.pending_handshakes.write().await.remove(&circuit_id);
                    return Err(CoreError::ProtocolError("Handshake channel closed".into()));
                }
                Err(_) => {
                    self.pending_handshakes.write().await.remove(&circuit_id);
                    return Err(CoreError::Timeout);
                }
            };

            // Get handshake back from pending
            let pending = self.pending_handshakes.write().await.remove(&circuit_id);

            // Process response
            let mut handshake = handshake;
            let session_keys = handshake.process_response(response)?;

            // Derive shared secret and complete hop
            let shared = derive_shared_secret(&session_keys);
            builder.complete_hop(node.node_id, node.public_key, shared)?;
        }

        // Build final circuit
        let circuit = builder.build()?;
        self.circuits.add(circuit).await?;

        // Register connection for first hop
        if let Some(first_hop) = path.first() {
            let conn = Connection::new(first_hop.address, first_hop.public_key, first_hop.node_id);
            self.connections.add(conn).await;
        }

        info!("Circuit {} built successfully with {} hops", circuit_id, path.len());
        Ok(circuit_id)
    }

    /// Teardown a circuit
    async fn teardown_circuit(&self, circuit_id: CircuitId) -> CoreResult<()> {
        if let Some(circuit) = self.circuits.get(circuit_id).await {
            let circuit = circuit.read().await;

            if let Some(hop) = circuit.entry_hop() {
                let transport = self.transport.read().await;
                if let Some(transport) = transport.as_ref() {
                    let packet = Packet::teardown(circuit_id);
                    if let Some(conn) = self.connections.get_by_node_id(&hop.node_id).await {
                        let conn = conn.read().await;
                        let _ = transport.send_to(&packet, conn.peer_addr).await;
                    }
                }
            }
        }

        self.circuits.remove(circuit_id).await;
        debug!("Circuit {} torn down", circuit_id);
        Ok(())
    }

    /// Send data through a circuit
    pub async fn send_through_circuit(&self, circuit_id: CircuitId, data: &[u8]) -> CoreResult<()> {
        let circuit = self.circuits.get(circuit_id).await
            .ok_or(CoreError::CircuitNotFound(circuit_id))?;

        let mut circuit = circuit.write().await;

        if !circuit.is_ready() {
            return Err(CoreError::CircuitError("Circuit not ready".into()));
        }

        // Encrypt data for circuit (onion encryption)
        let encrypted = circuit.encrypt_forward(data)?;
        circuit.record_sent(data.len());

        // Get first hop
        let hop = circuit.entry_hop()
            .ok_or_else(|| CoreError::CircuitError("No entry hop".into()))?;
        let node_id = hop.node_id;

        // Release circuit lock before transport operations
        drop(circuit);

        // Send through transport
        let transport = self.transport.read().await;
        let transport = transport.as_ref()
            .ok_or_else(|| CoreError::ProtocolError("Transport not initialized".into()))?;

        let packet = Packet::data(circuit_id, encrypted);

        // Get peer address
        if let Some(conn) = self.connections.get_by_node_id(&node_id).await {
            let conn = conn.read().await;
            transport.send_to(&packet, conn.peer_addr).await?;
        } else {
            return Err(CoreError::ProtocolError("No connection to entry node".into()));
        }

        self.bytes_sent.fetch_add(data.len() as u64, Ordering::Relaxed);
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Send IP packet through the VPN (called from TUN reader)
    async fn send_ip_packet(&self, packet_data: &[u8]) -> CoreResult<()> {
        // Get a ready circuit
        let circuit = self.circuits.get_ready().await
            .ok_or(CoreError::NoPathAvailable)?;

        let circuit_id = circuit.read().await.id();

        // Send through circuit
        self.send_through_circuit(circuit_id, packet_data).await
    }

    /// Write IP packet to TUN (called when receiving from circuit)
    async fn write_to_tun(&self, data: &[u8]) -> CoreResult<()> {
        let tun = self.tun.read().await;
        if let Some(tun) = tun.as_ref() {
            tun.write(data).await?;
        }
        Ok(())
    }

    // =====================
    // Background Tasks
    // =====================

    /// Spawn TUN reader task - reads packets from TUN and sends through circuit
    fn spawn_tun_reader_task(self: &Arc<Self>) {
        let engine = Arc::clone(self);

        tokio::spawn(async move {
            info!("TUN reader task started");

            loop {
                if engine.shutdown.load(Ordering::Relaxed) {
                    break;
                }

                // Get TUN device
                let tun_guard = engine.tun.read().await;
                let tun = match tun_guard.as_ref() {
                    Some(t) => t,
                    None => {
                        drop(tun_guard);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };

                // Read packet from TUN
                match tun.read().await {
                    Ok(packet) => {
                        trace!("TUN read: {} bytes", packet.len());

                        // Release TUN lock before sending
                        drop(tun_guard);

                        // Send through VPN circuit
                        if let Err(e) = engine.send_ip_packet(&packet).await {
                            debug!("Failed to send IP packet through circuit: {}", e);
                        }
                    }
                    Err(e) => {
                        if engine.shutdown.load(Ordering::Relaxed) {
                            break;
                        }
                        warn!("TUN read error: {}", e);
                        drop(tun_guard);
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
            }

            info!("TUN reader task stopped");
        });
    }

    /// Spawn TUN writer task - processes incoming data and writes to TUN
    fn spawn_tun_writer_task(self: &Arc<Self>) {
        // TUN writing is handled directly in handle_circuit_response
        // This task monitors and logs stats
        let engine = Arc::clone(self);

        tokio::spawn(async move {
            info!("TUN writer/stats task started");

            let mut stats_interval = interval(Duration::from_secs(30));

            loop {
                tokio::select! {
                    _ = stats_interval.tick() => {
                        let stats = engine.stats().await;
                        debug!(
                            "Engine stats: sent={} bytes, recv={} bytes, circuits={}",
                            stats.bytes_sent,
                            stats.bytes_received,
                            stats.active_circuits
                        );
                    }
                    _ = engine.shutdown_notify.notified() => {
                        break;
                    }
                }
            }

            info!("TUN writer/stats task stopped");
        });
    }

    /// Spawn network receiver task - receives UDP packets and processes them
    fn spawn_network_receiver_task(self: &Arc<Self>, transport: Arc<UdpTransport>) {
        let engine = Arc::clone(self);

        tokio::spawn(async move {
            info!("Network receiver task started");

            loop {
                if engine.shutdown.load(Ordering::Relaxed) {
                    break;
                }

                match transport.recv().await {
                    Ok(msg) => {
                        trace!("Received packet from {}: {} bytes", msg.from, msg.packet.payload.len());

                        if let Err(e) = engine.process_incoming_packet(msg.from, msg.packet).await {
                            debug!("Error processing packet from {}: {}", msg.from, e);
                        }
                    }
                    Err(e) => {
                        if engine.shutdown.load(Ordering::Relaxed) {
                            break;
                        }
                        warn!("Network receive error: {}", e);
                    }
                }
            }

            info!("Network receiver task stopped");
        });
    }

    /// Spawn keepalive task - sends periodic pings to keep circuits alive
    fn spawn_keepalive_task(self: &Arc<Self>) {
        let engine = Arc::clone(self);
        let keepalive_interval = engine.config.keepalive_interval;

        tokio::spawn(async move {
            info!("Keepalive task started");

            let mut interval = interval(keepalive_interval);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // Send pings to all circuit entry points
                        for circuit_id in engine.circuits.circuit_ids().await {
                            if let Some(circuit) = engine.circuits.get(circuit_id).await {
                                let circuit = circuit.read().await;
                                if circuit.is_ready() {
                                    if let Some(hop) = circuit.entry_hop() {
                                        let node_id = hop.node_id;
                                        drop(circuit);

                                        // Send ping
                                        if let Some(conn) = engine.connections.get_by_node_id(&node_id).await {
                                            let transport = engine.transport.read().await;
                                            if let Some(transport) = transport.as_ref() {
                                                let ping = Packet::ping(circuit_id);
                                                let conn = conn.read().await;
                                                let _ = transport.send_to(&ping, conn.peer_addr).await;
                                                trace!("Sent keepalive ping for circuit {}", circuit_id);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ = engine.shutdown_notify.notified() => {
                        break;
                    }
                }
            }

            info!("Keepalive task stopped");
        });
    }

    /// Spawn circuit rotation task - periodically builds new circuits
    fn spawn_circuit_rotation_task(self: &Arc<Self>) {
        let engine = Arc::clone(self);
        let rotation_interval = engine.config.circuit_rotation;

        tokio::spawn(async move {
            info!("Circuit rotation task started");

            let mut interval = interval(rotation_interval);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        info!("Rotating circuits...");

                        // Build new circuit
                        match engine.build_circuit().await {
                            Ok(new_id) => {
                                info!("Built new circuit {}", new_id);

                                // Set as default
                                if let Err(e) = engine.circuits.set_default(new_id).await {
                                    warn!("Failed to set new default circuit: {}", e);
                                }

                                // Clean up old circuits (keep last 2)
                                let all_ids = engine.circuits.circuit_ids().await;
                                if all_ids.len() > 2 {
                                    for id in all_ids.iter().take(all_ids.len() - 2) {
                                        let _ = engine.teardown_circuit(*id).await;
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to build new circuit during rotation: {}", e);
                            }
                        }
                    }
                    _ = engine.shutdown_notify.notified() => {
                        break;
                    }
                }
            }

            info!("Circuit rotation task stopped");
        });
    }

    /// Spawn cleanup task - removes stale connections and circuits
    fn spawn_cleanup_task(self: &Arc<Self>) {
        let engine = Arc::clone(self);

        tokio::spawn(async move {
            info!("Cleanup task started");

            let mut interval = interval(Duration::from_secs(60));

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // Clean up old circuits
                        let cleaned = engine.circuits.cleanup(
                            Duration::from_secs(600),  // max age: 10 minutes
                            Duration::from_secs(120),  // max idle: 2 minutes
                        ).await;

                        if cleaned > 0 {
                            debug!("Cleaned up {} stale circuits", cleaned);
                        }
                    }
                    _ = engine.shutdown_notify.notified() => {
                        break;
                    }
                }
            }

            info!("Cleanup task stopped");
        });
    }

    // =====================
    // Packet Processing
    // =====================

    /// Process incoming packet
    async fn process_incoming_packet(&self, from: SocketAddr, packet: Packet) -> CoreResult<()> {
        match packet.packet_type {
            PacketType::HandshakeInit => {
                self.handle_handshake_init(from, packet).await?;
            }
            PacketType::HandshakeResponse => {
                self.handle_handshake_response(from, packet).await?;
            }
            PacketType::Data => {
                self.handle_data_packet(from, packet).await?;
            }
            PacketType::DataResponse => {
                self.handle_data_response(from, packet).await?;
            }
            PacketType::Ping => {
                self.handle_ping(from, packet).await?;
            }
            PacketType::Pong => {
                self.handle_pong(from, packet).await?;
            }
            PacketType::CircuitTeardown => {
                self.handle_teardown(from, packet).await?;
            }
            PacketType::FindNodes => {
                self.handle_find_node(from, packet).await?;
            }
            PacketType::FoundNodes => {
                self.handle_found_nodes(from, packet).await?;
            }
            _ => {
                debug!("Unknown packet type: {:?}", packet.packet_type);
            }
        }

        Ok(())
    }

    /// Handle handshake init (we are being used as relay/exit)
    async fn handle_handshake_init(&self, from: SocketAddr, packet: Packet) -> CoreResult<()> {
        let init: HandshakeInit = bincode::deserialize(&packet.payload)
            .map_err(|e| CoreError::ProtocolError(e.to_string()))?;

        let mut handshake = ResponderHandshake::new((*self.identity).clone());
        handshake.process_init(init)?;

        let (response, session_keys) = handshake.create_response()?;

        // Register relay circuit
        let relay_circuit = RelayCircuit::new(
            packet.circuit_id,
            rand::random(),
            from,
            None, // Will be set on extend
            SymmetricKey::from_bytes(*session_keys.recv_key.as_bytes()),
            SymmetricKey::from_bytes(*session_keys.send_key.as_bytes()),
        );

        self.relay.register_circuit(relay_circuit).await?;

        // Send response
        let response_bytes = bincode::serialize(&response)
            .map_err(|e| CoreError::ProtocolError(e.to_string()))?;

        let transport = self.transport.read().await;
        if let Some(transport) = transport.as_ref() {
            let response_packet = Packet::handshake_response(packet.circuit_id, response_bytes);
            transport.send_to(&response_packet, from).await?;
        }

        debug!("Handled handshake init from {}, circuit {}", from, packet.circuit_id);
        Ok(())
    }

    /// Handle handshake response
    async fn handle_handshake_response(&self, from: SocketAddr, packet: Packet) -> CoreResult<()> {
        let response: HandshakeResponse = bincode::deserialize(&packet.payload)
            .map_err(|e| CoreError::ProtocolError(e.to_string()))?;

        // Find and complete pending handshake
        if let Some(pending) = self.pending_handshakes.write().await.remove(&packet.circuit_id) {
            let _ = pending.response_tx.send(response);
        }

        debug!("Received handshake response from {}, circuit {}", from, packet.circuit_id);
        Ok(())
    }

    /// Handle data packet (relay or process)
    async fn handle_data_packet(&self, from: SocketAddr, packet: Packet) -> CoreResult<()> {
        self.bytes_received.fetch_add(packet.payload.len() as u64, Ordering::Relaxed);
        self.packets_received.fetch_add(1, Ordering::Relaxed);

        // Check if we're relaying this circuit
        if self.relay.get_circuit(packet.circuit_id).await.is_some() {
            // Relay the packet
            match self.relay.relay_forward(packet.circuit_id, &packet.payload).await? {
                RelayResult::Forward { next_hop, circuit_id, data } => {
                    let transport = self.transport.read().await;
                    if let Some(transport) = transport.as_ref() {
                        let forward_packet = Packet::data(circuit_id, data);
                        transport.send_to(&forward_packet, next_hop).await?;
                    }
                }
            }
        } else {
            // This is our circuit - process response
            self.handle_circuit_response(packet.circuit_id, &packet.payload).await?;
        }

        Ok(())
    }

    /// Handle data response (from exit back through circuit)
    async fn handle_data_response(&self, from: SocketAddr, packet: Packet) -> CoreResult<()> {
        self.bytes_received.fetch_add(packet.payload.len() as u64, Ordering::Relaxed);
        self.packets_received.fetch_add(1, Ordering::Relaxed);

        self.handle_circuit_response(packet.circuit_id, &packet.payload).await
    }

    /// Handle circuit response - decrypt and write to TUN
    async fn handle_circuit_response(&self, circuit_id: CircuitId, data: &[u8]) -> CoreResult<()> {
        if let Some(circuit) = self.circuits.get(circuit_id).await {
            let mut circuit = circuit.write().await;

            // Decrypt response (unwrap onion layers)
            let decrypted = circuit.decrypt_backward(data)?;
            circuit.record_received(data.len());

            // Release circuit lock before TUN write
            drop(circuit);

            // Write decrypted IP packet to TUN
            self.write_to_tun(&decrypted).await?;
        }

        Ok(())
    }

    /// Handle ping
    async fn handle_ping(&self, from: SocketAddr, packet: Packet) -> CoreResult<()> {
        let transport = self.transport.read().await;
        if let Some(transport) = transport.as_ref() {
            let pong = Packet::pong(packet.circuit_id);
            transport.send_to(&pong, from).await?;
        }
        trace!("Handled ping from {}", from);
        Ok(())
    }

    /// Handle pong
    async fn handle_pong(&self, from: SocketAddr, _packet: Packet) -> CoreResult<()> {
        // Mark connection as active
        if let Some(conn) = self.connections.get_by_addr(&from).await {
            let mut conn = conn.write().await;
            conn.touch();
        }
        trace!("Received pong from {}", from);
        Ok(())
    }

    /// Handle teardown
    async fn handle_teardown(&self, from: SocketAddr, packet: Packet) -> CoreResult<()> {
        self.relay.remove_circuit(packet.circuit_id).await;
        debug!("Circuit {} torn down by {}", packet.circuit_id, from);
        Ok(())
    }

    /// Handle FIND_NODE request
    async fn handle_find_node(&self, from: SocketAddr, packet: Packet) -> CoreResult<()> {
        // Return list of known nodes
        let peers = self.peers.read().await;
        let node_list: Vec<_> = peers.values()
            .take(8) // Return up to 8 nodes
            .cloned()
            .collect();

        let response = bincode::serialize(&node_list)
            .map_err(|e| CoreError::ProtocolError(e.to_string()))?;

        let transport = self.transport.read().await;
        if let Some(transport) = transport.as_ref() {
            let response_packet = Packet::new(
                PacketType::FoundNodes,
                packet.circuit_id,
                Bytes::from(response),
            );
            transport.send_to(&response_packet, from).await?;
        }

        Ok(())
    }

    /// Handle FOUND_NODES response
    async fn handle_found_nodes(&self, from: SocketAddr, packet: Packet) -> CoreResult<()> {
        let nodes: Vec<PeerInfo> = bincode::deserialize(&packet.payload)
            .map_err(|e| CoreError::ProtocolError(e.to_string()))?;

        let mut peers = self.peers.write().await;
        let mut exits = self.exit_nodes.write().await;

        for node in nodes {
            if node.is_exit {
                if !exits.iter().any(|e| e.node_id == node.node_id) {
                    exits.push(node.clone());
                }
            }
            peers.insert(node.node_id, node);
        }

        debug!("Discovered {} nodes from {}", peers.len(), from);
        Ok(())
    }

    /// Create FIND_NODE request
    fn create_find_node_request(&self) -> Bytes {
        // Request nodes near our ID
        let request = self.identity.node_id().as_bytes().to_vec();
        Bytes::from(request)
    }

    /// Add a known peer
    pub async fn add_peer(&self, peer: PeerInfo) {
        let mut peers = self.peers.write().await;
        peers.insert(peer.node_id, peer.clone());

        if peer.is_exit {
            let mut exits = self.exit_nodes.write().await;
            if !exits.iter().any(|e| e.node_id == peer.node_id) {
                exits.push(peer);
            }
        }
    }

    /// Get statistics
    pub async fn stats(&self) -> EngineStats {
        let uptime = if let Some(start) = *self.start_time.read().await {
            start.elapsed().as_secs()
        } else {
            0
        };

        EngineStats {
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            active_circuits: self.circuits.count().await,
            connected_peers: self.peers.read().await.len(),
            uptime_secs: uptime,
        }
    }
}

/// Derive shared secret from session keys
fn derive_shared_secret(keys: &SessionKeys) -> SharedSecret {
    // Derive from the concatenated keys
    let mut key_material = [0u8; 32];
    key_material[..16].copy_from_slice(&keys.send_key.as_bytes()[..16]);
    key_material[16..].copy_from_slice(&keys.recv_key.as_bytes()[..16]);
    SharedSecret::from_bytes(key_material)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_engine_creation() {
        let identity = NodeIdentity::generate();
        let config = CoreConfig::default();

        let engine = VpnEngine::new(identity, config).await.unwrap();
        assert_eq!(engine.state().await, EngineState::Stopped);
    }
}
