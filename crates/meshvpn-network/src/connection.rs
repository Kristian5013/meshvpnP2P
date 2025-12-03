//! Connection Management
//!
//! Manages peer connections and circuit state.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use meshvpn_crypto::prelude::*;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::error::{NetworkError, NetworkResult};

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial state, handshake not started
    New,
    /// Handshake in progress
    Handshaking,
    /// Connection established
    Established,
    /// Connection is being torn down
    Closing,
    /// Connection closed
    Closed,
    /// Connection failed
    Failed,
}

/// A connection to a peer
pub struct Connection {
    /// Peer's address
    pub peer_addr: SocketAddr,

    /// Peer's public key
    pub peer_pubkey: PublicKey,

    /// Peer's node ID
    pub peer_node_id: NodeId,

    /// Connection state
    state: ConnectionState,

    /// Session keys (after handshake)
    session: Option<SessionKeys>,

    /// Circuit IDs using this connection
    circuits: Vec<u32>,

    /// Last activity timestamp
    last_activity: Instant,

    /// Bytes sent
    bytes_sent: u64,

    /// Bytes received
    bytes_received: u64,

    /// Round-trip time estimate (microseconds)
    rtt_us: u64,
}

/// Session keys for an established connection
pub struct SessionKeys {
    /// Key for encrypting outgoing messages
    pub send_key: SymmetricKey,
    /// Key for decrypting incoming messages
    pub recv_key: SymmetricKey,
    /// Nonce counter for sending
    pub send_nonce: std::sync::atomic::AtomicU64,
    /// Expected nonce for receiving (replay protection)
    pub recv_nonce: std::sync::atomic::AtomicU64,
}

impl Clone for SessionKeys {
    fn clone(&self) -> Self {
        use std::sync::atomic::Ordering;
        Self {
            send_key: self.send_key.clone(),
            recv_key: self.recv_key.clone(),
            send_nonce: std::sync::atomic::AtomicU64::new(self.send_nonce.load(Ordering::SeqCst)),
            recv_nonce: std::sync::atomic::AtomicU64::new(self.recv_nonce.load(Ordering::SeqCst)),
        }
    }
}

impl Connection {
    /// Create a new connection
    pub fn new(peer_addr: SocketAddr, peer_pubkey: PublicKey, peer_node_id: NodeId) -> Self {
        Self {
            peer_addr,
            peer_pubkey,
            peer_node_id,
            state: ConnectionState::New,
            session: None,
            circuits: Vec::new(),
            last_activity: Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            rtt_us: 0,
        }
    }

    /// Get connection state
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Set connection state
    pub fn set_state(&mut self, state: ConnectionState) {
        debug!(
            "Connection {} state: {:?} -> {:?}",
            self.peer_addr, self.state, state
        );
        self.state = state;
    }

    /// Set session keys after successful handshake
    pub fn establish(&mut self, send_key: SymmetricKey, recv_key: SymmetricKey) {
        self.session = Some(SessionKeys {
            send_key,
            recv_key,
            send_nonce: std::sync::atomic::AtomicU64::new(0),
            recv_nonce: std::sync::atomic::AtomicU64::new(0),
        });
        self.state = ConnectionState::Established;
    }

    /// Check if connection is established
    pub fn is_established(&self) -> bool {
        self.state == ConnectionState::Established && self.session.is_some()
    }

    /// Get session keys
    pub fn session(&self) -> Option<&SessionKeys> {
        self.session.as_ref()
    }

    /// Add a circuit using this connection
    pub fn add_circuit(&mut self, circuit_id: u32) {
        if !self.circuits.contains(&circuit_id) {
            self.circuits.push(circuit_id);
        }
    }

    /// Remove a circuit
    pub fn remove_circuit(&mut self, circuit_id: u32) {
        self.circuits.retain(|&id| id != circuit_id);
    }

    /// Get circuit count
    pub fn circuit_count(&self) -> usize {
        self.circuits.len()
    }

    /// Update activity timestamp
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Get time since last activity
    pub fn idle_time(&self) -> Duration {
        self.last_activity.elapsed()
    }

    /// Record sent bytes
    pub fn record_sent(&mut self, bytes: u64) {
        self.bytes_sent += bytes;
        self.touch();
    }

    /// Record received bytes
    pub fn record_received(&mut self, bytes: u64) {
        self.bytes_received += bytes;
        self.touch();
    }

    /// Update RTT estimate
    pub fn update_rtt(&mut self, rtt_us: u64) {
        // Exponential moving average
        if self.rtt_us == 0 {
            self.rtt_us = rtt_us;
        } else {
            self.rtt_us = (self.rtt_us * 7 + rtt_us) / 8;
        }
    }

    /// Get RTT estimate
    pub fn rtt(&self) -> Duration {
        Duration::from_micros(self.rtt_us)
    }
}

/// Pool of peer connections
pub struct ConnectionPool {
    /// Connections by peer address
    by_addr: RwLock<HashMap<SocketAddr, Arc<RwLock<Connection>>>>,
    /// Connections by node ID
    by_node_id: RwLock<HashMap<NodeId, SocketAddr>>,
    /// Maximum connections
    max_connections: usize,
    /// Idle timeout
    idle_timeout: Duration,
}

impl ConnectionPool {
    /// Create a new connection pool
    pub fn new(max_connections: usize, idle_timeout: Duration) -> Self {
        Self {
            by_addr: RwLock::new(HashMap::new()),
            by_node_id: RwLock::new(HashMap::new()),
            max_connections,
            idle_timeout,
        }
    }

    /// Create with default settings
    pub fn default_pool() -> Self {
        Self::new(1000, Duration::from_secs(300))
    }

    /// Get or create a connection
    pub async fn get_or_create(
        &self,
        addr: SocketAddr,
        pubkey: PublicKey,
        node_id: NodeId,
    ) -> NetworkResult<Arc<RwLock<Connection>>> {
        // Check if exists
        {
            let by_addr = self.by_addr.read().await;
            if let Some(conn) = by_addr.get(&addr) {
                return Ok(conn.clone());
            }
        }

        // Create new connection
        let conn = Connection::new(addr, pubkey, node_id);
        self.add(conn).await
    }

    /// Add a connection
    pub async fn add(&self, conn: Connection) -> NetworkResult<Arc<RwLock<Connection>>> {
        let addr = conn.peer_addr;
        let node_id = conn.peer_node_id;

        {
            let by_addr = self.by_addr.read().await;
            if by_addr.len() >= self.max_connections {
                return Err(NetworkError::ConnectionError(
                    "Connection pool full".into(),
                ));
            }
        }

        let conn = Arc::new(RwLock::new(conn));

        {
            let mut by_addr = self.by_addr.write().await;
            let mut by_node_id = self.by_node_id.write().await;

            by_addr.insert(addr, conn.clone());
            by_node_id.insert(node_id, addr);
        }

        debug!("Added connection to pool: {}", addr);
        Ok(conn)
    }

    /// Get connection by address
    pub async fn get_by_addr(&self, addr: &SocketAddr) -> Option<Arc<RwLock<Connection>>> {
        let by_addr = self.by_addr.read().await;
        by_addr.get(addr).cloned()
    }

    /// Get connection by node ID
    pub async fn get_by_node_id(&self, node_id: &NodeId) -> Option<Arc<RwLock<Connection>>> {
        let addr = {
            let by_node_id = self.by_node_id.read().await;
            by_node_id.get(node_id).copied()
        };

        if let Some(addr) = addr {
            self.get_by_addr(&addr).await
        } else {
            None
        }
    }

    /// Remove a connection
    pub async fn remove(&self, addr: &SocketAddr) -> Option<Arc<RwLock<Connection>>> {
        let mut by_addr = self.by_addr.write().await;
        let mut by_node_id = self.by_node_id.write().await;

        if let Some(conn) = by_addr.remove(addr) {
            let conn_read = conn.read().await;
            by_node_id.remove(&conn_read.peer_node_id);
            drop(conn_read);
            debug!("Removed connection from pool: {}", addr);
            Some(conn)
        } else {
            None
        }
    }

    /// Get all established connections
    pub async fn established_connections(&self) -> Vec<Arc<RwLock<Connection>>> {
        let by_addr = self.by_addr.read().await;
        let mut result = Vec::new();

        for conn in by_addr.values() {
            let conn_read = conn.read().await;
            if conn_read.is_established() {
                result.push(conn.clone());
            }
        }

        result
    }

    /// Clean up idle connections
    pub async fn cleanup_idle(&self) -> usize {
        let mut to_remove = Vec::new();

        {
            let by_addr = self.by_addr.read().await;
            for (addr, conn) in by_addr.iter() {
                let conn_read = conn.read().await;
                if conn_read.idle_time() > self.idle_timeout && conn_read.circuit_count() == 0 {
                    to_remove.push(*addr);
                }
            }
        }

        let count = to_remove.len();
        for addr in to_remove {
            self.remove(&addr).await;
        }

        if count > 0 {
            debug!("Cleaned up {} idle connections", count);
        }
        count
    }

    /// Get pool statistics
    pub async fn stats(&self) -> PoolStats {
        let by_addr = self.by_addr.read().await;

        let mut established = 0;
        let mut total_circuits = 0;
        let mut total_bytes_sent = 0;
        let mut total_bytes_received = 0;

        for conn in by_addr.values() {
            let conn_read = conn.read().await;
            if conn_read.is_established() {
                established += 1;
            }
            total_circuits += conn_read.circuit_count();
            total_bytes_sent += conn_read.bytes_sent;
            total_bytes_received += conn_read.bytes_received;
        }

        PoolStats {
            total_connections: by_addr.len(),
            established_connections: established,
            total_circuits,
            total_bytes_sent,
            total_bytes_received,
        }
    }
}

/// Connection pool statistics
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total_connections: usize,
    pub established_connections: usize,
    pub total_circuits: usize,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node_id() -> NodeId {
        NodeId::from_bytes([0u8; 20])
    }

    fn test_pubkey() -> PublicKey {
        PublicKey::from_bytes([1u8; 32])
    }

    #[tokio::test]
    async fn test_connection_lifecycle() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let mut conn = Connection::new(addr, test_pubkey(), test_node_id());

        assert_eq!(conn.state(), ConnectionState::New);

        conn.set_state(ConnectionState::Handshaking);
        assert_eq!(conn.state(), ConnectionState::Handshaking);

        let key = SymmetricKey::generate();
        conn.establish(key.clone(), key);
        assert!(conn.is_established());
    }

    #[tokio::test]
    async fn test_connection_pool() {
        let pool = ConnectionPool::new(10, Duration::from_secs(60));

        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let conn = pool
            .get_or_create(addr, test_pubkey(), test_node_id())
            .await
            .unwrap();

        // Should return same connection
        let conn2 = pool
            .get_or_create(addr, test_pubkey(), test_node_id())
            .await
            .unwrap();

        assert!(Arc::ptr_eq(&conn, &conn2));

        // Should find by address
        assert!(pool.get_by_addr(&addr).await.is_some());

        // Should find by node ID
        assert!(pool.get_by_node_id(&test_node_id()).await.is_some());

        // Remove and verify
        pool.remove(&addr).await;
        assert!(pool.get_by_addr(&addr).await.is_none());
    }
}
