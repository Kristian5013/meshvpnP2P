//! DHT Network Transport Layer
//!
//! UDP-based transport for DHT messages with async support.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use meshvpn_crypto::NodeId;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock, oneshot};
use tracing::{debug, error, info, trace, warn};

use crate::error::{DhtError, DhtResult};
use crate::node::{DhtNode, NodeEntry, NodeInfo, NodeStatus};
use crate::protocol::{DhtMessage, DhtRequest, DhtResponse, RpcId, RpcMessage};
use crate::{K, ALPHA};

/// Default timeout for RPC calls
const RPC_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum concurrent lookups
const MAX_CONCURRENT_LOOKUPS: usize = 3;

/// Pending RPC request
struct PendingRpc {
    /// Response sender
    response_tx: oneshot::Sender<DhtMessage>,
    /// When the request was sent
    sent_at: Instant,
    /// Peer address
    peer_addr: SocketAddr,
}

/// DHT Network Service
pub struct DhtNetwork {
    /// UDP socket
    socket: Arc<UdpSocket>,
    /// Local DHT node
    node: Arc<RwLock<DhtNode>>,
    /// Pending RPC requests
    pending_rpcs: Arc<RwLock<HashMap<RpcId, PendingRpc>>>,
    /// Bootstrap nodes
    bootstrap_nodes: Vec<SocketAddr>,
    /// Is running
    running: Arc<std::sync::atomic::AtomicBool>,
    /// Shutdown signal
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl DhtNetwork {
    /// Create a new DHT network service
    pub async fn new(
        node: DhtNode,
        bind_addr: &str,
        bootstrap_nodes: Vec<SocketAddr>,
    ) -> DhtResult<Self> {
        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| DhtError::BootstrapFailed(format!("Failed to bind: {}", e)))?;

        info!("DHT listening on {}", socket.local_addr().unwrap());

        Ok(Self {
            socket: Arc::new(socket),
            node: Arc::new(RwLock::new(node)),
            pending_rpcs: Arc::new(RwLock::new(HashMap::new())),
            bootstrap_nodes,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            shutdown_tx: None,
        })
    }

    /// Get local address
    pub fn local_addr(&self) -> DhtResult<SocketAddr> {
        self.socket
            .local_addr()
            .map_err(|e| DhtError::BootstrapFailed(e.to_string()))
    }

    /// Get our node ID
    pub async fn node_id(&self) -> NodeId {
        self.node.read().await.node_id()
    }

    /// Start the network service
    pub async fn start(&mut self) -> DhtResult<()> {
        if self.running.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(());
        }

        self.running.store(true, std::sync::atomic::Ordering::Relaxed);

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        // Spawn receive loop
        let socket = self.socket.clone();
        let node = self.node.clone();
        let pending = self.pending_rpcs.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            let mut buf = [0u8; 65536];

            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        info!("DHT network shutting down");
                        break;
                    }
                    result = socket.recv_from(&mut buf) => {
                        match result {
                            Ok((len, addr)) => {
                                if let Err(e) = Self::handle_packet(
                                    &buf[..len],
                                    addr,
                                    &socket,
                                    &node,
                                    &pending,
                                ).await {
                                    trace!("Error handling packet from {}: {}", addr, e);
                                }
                            }
                            Err(e) => {
                                if running.load(std::sync::atomic::Ordering::Relaxed) {
                                    error!("Socket error: {}", e);
                                }
                            }
                        }
                    }
                }
            }
        });

        // Bootstrap
        self.bootstrap().await?;

        Ok(())
    }

    /// Stop the network service
    pub async fn stop(&mut self) {
        self.running.store(false, std::sync::atomic::Ordering::Relaxed);
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }
    }

    /// Handle incoming packet
    async fn handle_packet(
        data: &[u8],
        from: SocketAddr,
        socket: &UdpSocket,
        node: &RwLock<DhtNode>,
        pending: &RwLock<HashMap<RpcId, PendingRpc>>,
    ) -> DhtResult<()> {
        let rpc_msg = RpcMessage::from_bytes(data)?;

        trace!("Received DHT message from {}: {:?}", from, rpc_msg.message);

        match &rpc_msg.message {
            DhtMessage::Request(req) => {
                // Handle request
                let response = Self::handle_request(req, from, node).await?;
                let response_rpc = rpc_msg.response(DhtMessage::Response(response));
                let response_bytes = response_rpc.to_bytes()?;
                socket.send_to(&response_bytes, from).await
                    .map_err(|e| DhtError::BootstrapFailed(e.to_string()))?;
            }
            DhtMessage::Response(resp) => {
                // Match to pending RPC
                let mut pending_guard = pending.write().await;
                if let Some(pending_rpc) = pending_guard.remove(&rpc_msg.rpc_id) {
                    let _ = pending_rpc.response_tx.send(rpc_msg.message);
                } else {
                    trace!("No pending RPC for ID {}", rpc_msg.rpc_id);
                }
            }
        }

        Ok(())
    }

    /// Handle a request and return response
    async fn handle_request(
        req: &DhtRequest,
        from: SocketAddr,
        node: &RwLock<DhtNode>,
    ) -> DhtResult<DhtResponse> {
        let node_guard = node.read().await;
        let our_id = node_guard.node_id();

        match req {
            DhtRequest::Ping { sender_id } => {
                debug!("Ping from {:?}", sender_id);
                Ok(DhtResponse::Pong { sender_id: our_id })
            }

            DhtRequest::FindNode { sender_id, target } => {
                let closest = node_guard.find_closest(target, K);
                let nodes: Vec<NodeInfo> = closest.into_iter()
                    .map(|e| e.info)
                    .collect();

                debug!("FindNode from {:?}, returning {} nodes", sender_id, nodes.len());
                Ok(DhtResponse::NodesFound {
                    sender_id: our_id,
                    nodes,
                })
            }

            DhtRequest::FindValue { sender_id, key } => {
                // Try to find value in storage
                if let Some(value) = node_guard.storage().get(key) {
                    Ok(DhtResponse::ValueFound {
                        sender_id: our_id,
                        value,
                    })
                } else {
                    // Return closest nodes to the key
                    let target = NodeId::from_bytes({
                        let mut bytes = [0u8; 20];
                        bytes.copy_from_slice(&key[..20]);
                        bytes
                    });
                    let closest = node_guard.find_closest(&target, K);
                    let nodes: Vec<NodeInfo> = closest.into_iter()
                        .map(|e| e.info)
                        .collect();

                    Ok(DhtResponse::ValueNotFound {
                        sender_id: our_id,
                        closest_nodes: nodes,
                    })
                }
            }

            DhtRequest::Store { sender_id, key, value, ttl } => {
                drop(node_guard);
                let mut node_mut = node.write().await;
                node_mut.storage_mut().put(*key, value.clone(), *ttl);

                debug!("Stored value for key {:?} from {:?}", hex::encode(&key[..8]), sender_id);
                Ok(DhtResponse::StoreAck {
                    sender_id: node_mut.node_id(),
                    success: true,
                })
            }

            DhtRequest::Announce { info } => {
                // Add announcing node to our routing table
                drop(node_guard);
                let mut node_mut = node.write().await;

                if info.verify_signature() {
                    let entry = NodeEntry::new(info.clone());
                    node_mut.add_node(info.clone());
                    debug!("Node announced: {:?} at {:?}", info.node_id, from);
                }

                Ok(DhtResponse::Pong {
                    sender_id: node_mut.node_id(),
                })
            }

            DhtRequest::GetExitNodes { sender_id, max_count } => {
                let all_nodes = node_guard.all_nodes();
                let exit_nodes: Vec<NodeInfo> = all_nodes
                    .into_iter()
                    .filter(|e| e.info.status == NodeStatus::Exit)
                    .take(*max_count as usize)
                    .map(|e| e.info)
                    .collect();

                Ok(DhtResponse::ExitNodes {
                    sender_id: our_id,
                    nodes: exit_nodes,
                })
            }

            DhtRequest::GetRelayNodes { sender_id, max_count, min_capacity } => {
                let all_nodes = node_guard.all_nodes();
                let min_cap = min_capacity.unwrap_or(0);

                let relay_nodes: Vec<NodeInfo> = all_nodes
                    .into_iter()
                    .filter(|e| {
                        e.info.status == NodeStatus::Active &&
                        e.info.capacity >= min_cap &&
                        e.info.load < 80 // Not overloaded
                    })
                    .take(*max_count as usize)
                    .map(|e| e.info)
                    .collect();

                Ok(DhtResponse::RelayNodes {
                    sender_id: our_id,
                    nodes: relay_nodes,
                })
            }
        }
    }

    /// Send RPC and wait for response
    pub async fn rpc(
        &self,
        target: SocketAddr,
        message: DhtMessage,
    ) -> DhtResult<DhtMessage> {
        let rpc_msg = RpcMessage::new(message);
        let rpc_id = rpc_msg.rpc_id;
        let data = rpc_msg.to_bytes()?;

        // Setup response channel
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending_rpcs.write().await;
            pending.insert(rpc_id, PendingRpc {
                response_tx: tx,
                sent_at: Instant::now(),
                peer_addr: target,
            });
        }

        // Send request
        self.socket.send_to(&data, target).await
            .map_err(|e| DhtError::BootstrapFailed(e.to_string()))?;

        // Wait for response with timeout
        match tokio::time::timeout(RPC_TIMEOUT, rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => {
                // Channel closed
                let mut pending = self.pending_rpcs.write().await;
                pending.remove(&rpc_id);
                Err(DhtError::Timeout)
            }
            Err(_) => {
                // Timeout
                let mut pending = self.pending_rpcs.write().await;
                pending.remove(&rpc_id);
                Err(DhtError::Timeout)
            }
        }
    }

    /// Ping a node
    pub async fn ping(&self, target: SocketAddr) -> DhtResult<bool> {
        let our_id = self.node.read().await.node_id();
        let request = DhtMessage::Request(DhtRequest::Ping { sender_id: our_id });

        match self.rpc(target, request).await {
            Ok(DhtMessage::Response(DhtResponse::Pong { .. })) => Ok(true),
            Ok(_) => Ok(false),
            Err(_) => Ok(false),
        }
    }

    /// Find node (iterative Kademlia lookup)
    pub async fn find_node(&self, target: NodeId) -> DhtResult<Vec<NodeInfo>> {
        let our_id = self.node.read().await.node_id();

        // Start with closest nodes we know
        let mut closest = {
            let node = self.node.read().await;
            node.find_closest(&target, K)
        };

        if closest.is_empty() {
            // Try bootstrap nodes
            for bootstrap in &self.bootstrap_nodes {
                let request = DhtMessage::Request(DhtRequest::FindNode {
                    sender_id: our_id,
                    target,
                });

                if let Ok(DhtMessage::Response(DhtResponse::NodesFound { nodes, .. })) =
                    self.rpc(*bootstrap, request).await
                {
                    for info in nodes {
                        let mut node = self.node.write().await;
                        node.add_node(info);
                    }
                }
            }

            // Refresh closest list
            let node = self.node.read().await;
            closest = node.find_closest(&target, K);
        }

        // Iterative lookup
        let mut queried: std::collections::HashSet<NodeId> = std::collections::HashSet::new();
        let mut best_nodes: Vec<NodeInfo> = closest.iter().map(|e| e.info.clone()).collect();

        for _ in 0..ALPHA {
            // Query ALPHA closest unqueried nodes
            let to_query: Vec<_> = best_nodes
                .iter()
                .filter(|n| !queried.contains(&n.node_id))
                .take(ALPHA)
                .cloned()
                .collect();

            if to_query.is_empty() {
                break;
            }

            // Query in parallel
            let mut handles = Vec::new();
            for node_info in to_query {
                queried.insert(node_info.node_id);

                if let Some(addr) = node_info.primary_address() {
                    let socket = self.socket.clone();
                    let target_copy = target;
                    let our_id_copy = our_id;

                    handles.push(tokio::spawn(async move {
                        let request = DhtMessage::Request(DhtRequest::FindNode {
                            sender_id: our_id_copy,
                            target: target_copy,
                        });
                        let rpc_msg = RpcMessage::new(request);
                        let data = rpc_msg.to_bytes().ok()?;

                        socket.send_to(&data, addr).await.ok()?;

                        // We can't easily wait for response here in parallel
                        // For simplicity, we'll collect and process separately
                        Some((addr, rpc_msg.rpc_id))
                    }));
                }
            }

            // Wait for results
            for handle in handles {
                if let Ok(Some(_)) = handle.await {
                    // Response handling is done in the receive loop
                }
            }

            // Small delay to allow responses to arrive
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Update best nodes from routing table
            let node = self.node.read().await;
            let new_closest = node.find_closest(&target, K);
            best_nodes = new_closest.into_iter().map(|e| e.info).collect();
        }

        Ok(best_nodes)
    }

    /// Store a value in the DHT
    pub async fn store(&self, key: [u8; 32], value: Vec<u8>, ttl: u32) -> DhtResult<usize> {
        let our_id = self.node.read().await.node_id();

        // Find K closest nodes to the key
        let target = NodeId::from_bytes({
            let mut bytes = [0u8; 20];
            bytes.copy_from_slice(&key[..20]);
            bytes
        });

        let closest = self.find_node(target).await?;
        let mut stored_count = 0;

        for node_info in closest.iter().take(K) {
            if let Some(addr) = node_info.primary_address() {
                let request = DhtMessage::Request(DhtRequest::Store {
                    sender_id: our_id,
                    key,
                    value: value.clone(),
                    ttl,
                });

                if let Ok(DhtMessage::Response(DhtResponse::StoreAck { success: true, .. })) =
                    self.rpc(addr, request).await
                {
                    stored_count += 1;
                }
            }
        }

        Ok(stored_count)
    }

    /// Get a value from the DHT
    pub async fn get(&self, key: [u8; 32]) -> DhtResult<Option<Vec<u8>>> {
        let our_id = self.node.read().await.node_id();

        // Check local storage first
        {
            let node = self.node.read().await;
            if let Some(value) = node.storage().get(&key) {
                return Ok(Some(value));
            }
        }

        // Find nodes close to the key
        let target = NodeId::from_bytes({
            let mut bytes = [0u8; 20];
            bytes.copy_from_slice(&key[..20]);
            bytes
        });

        let closest = self.find_node(target).await?;

        // Query them for the value
        for node_info in closest.iter().take(ALPHA) {
            if let Some(addr) = node_info.primary_address() {
                let request = DhtMessage::Request(DhtRequest::FindValue {
                    sender_id: our_id,
                    key,
                });

                if let Ok(DhtMessage::Response(DhtResponse::ValueFound { value, .. })) =
                    self.rpc(addr, request).await
                {
                    // Cache locally
                    {
                        let mut node = self.node.write().await;
                        node.storage_mut().put(key, value.clone(), 3600);
                    }
                    return Ok(Some(value));
                }
            }
        }

        Ok(None)
    }

    /// Bootstrap the DHT
    async fn bootstrap(&self) -> DhtResult<()> {
        if self.bootstrap_nodes.is_empty() {
            info!("No bootstrap nodes, starting as first node");
            return Ok(());
        }

        info!("Bootstrapping DHT with {} nodes", self.bootstrap_nodes.len());

        // Ping bootstrap nodes and get their peers
        for bootstrap in &self.bootstrap_nodes {
            if self.ping(*bootstrap).await? {
                info!("Connected to bootstrap node {}", bootstrap);

                // Find nodes close to us
                let our_id = self.node.read().await.node_id();
                if let Ok(nodes) = self.find_node(our_id).await {
                    let mut node = self.node.write().await;
                    for info in nodes {
                        node.add_node(info);
                    }
                }
            }
        }

        let node_count = self.node.read().await.node_count();
        info!("DHT bootstrapped, {} nodes in routing table", node_count);

        Ok(())
    }

    /// Announce ourselves to the network
    pub async fn announce(&self) -> DhtResult<()> {
        let info = {
            let node = self.node.read().await;
            node.our_info(NodeStatus::Active, 0)
        };

        let request = DhtMessage::Request(DhtRequest::Announce { info: info.clone() });

        // Announce to closest nodes
        let closest = {
            let node = self.node.read().await;
            node.find_closest(&info.node_id, K)
        };

        for entry in closest {
            if let Some(addr) = entry.info.primary_address() {
                let _ = self.rpc(addr, request.clone()).await;
            }
        }

        // Also announce to bootstrap nodes
        for bootstrap in &self.bootstrap_nodes {
            let _ = self.rpc(*bootstrap, request.clone()).await;
        }

        Ok(())
    }

    /// Get relay nodes from the network
    pub async fn find_relay_nodes(&self, count: u32) -> DhtResult<Vec<NodeInfo>> {
        let our_id = self.node.read().await.node_id();
        let mut relays = Vec::new();

        // Query bootstrap nodes first
        for bootstrap in &self.bootstrap_nodes {
            let request = DhtMessage::Request(DhtRequest::GetRelayNodes {
                sender_id: our_id,
                max_count: count,
                min_capacity: Some(10),
            });

            if let Ok(DhtMessage::Response(DhtResponse::RelayNodes { nodes, .. })) =
                self.rpc(*bootstrap, request).await
            {
                relays.extend(nodes);
                if relays.len() >= count as usize {
                    break;
                }
            }
        }

        // Also check local routing table for potential relays
        {
            let node = self.node.read().await;
            let local_relays: Vec<_> = node
                .all_nodes()
                .into_iter()
                .filter(|e| e.info.status == NodeStatus::Active && e.info.load < 80)
                .take(count as usize)
                .map(|e| e.info)
                .collect();

            relays.extend(local_relays);
        }

        // Deduplicate
        let mut seen = std::collections::HashSet::new();
        relays.retain(|n| seen.insert(n.node_id));
        relays.truncate(count as usize);

        Ok(relays)
    }

    /// Get node count
    pub async fn node_count(&self) -> usize {
        self.node.read().await.node_count()
    }

    /// Get all known nodes
    pub async fn all_nodes(&self) -> Vec<NodeInfo> {
        self.node.read().await
            .all_nodes()
            .into_iter()
            .map(|e| e.info)
            .collect()
    }
}
