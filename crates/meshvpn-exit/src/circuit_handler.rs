//! Circuit Handler for Exit Node
//!
//! Handles onion-encrypted circuit traffic and forwards to internet.

use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::RwLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, trace, warn};

use meshvpn_network::p2p::{CircuitNode, CircuitMessage, PeerId, CircuitId};

use crate::error::{ExitError, ExitResult};
use crate::logging::ComplianceLogger;

/// Circuit-based exit handler
pub struct CircuitExitHandler {
    /// The circuit node that handles encryption/decryption
    circuit_node: Arc<CircuitNode>,
    /// UDP socket for forwarding DNS and UDP traffic
    udp_socket: Arc<UdpSocket>,
    /// Active TCP connections (circuit_id -> connection)
    tcp_connections: Arc<RwLock<HashMap<CircuitId, TcpConnection>>>,
    /// Compliance logger
    logger: Arc<ComplianceLogger>,
    /// Running flag
    running: Arc<std::sync::atomic::AtomicBool>,
}

/// A TCP connection for a circuit
struct TcpConnection {
    stream: TcpStream,
    target: String,
}

impl CircuitExitHandler {
    /// Create a new circuit exit handler
    pub async fn new(
        peer_id: PeerId,
        listen_addr: &str,
        logger: Arc<ComplianceLogger>,
    ) -> ExitResult<Self> {
        // Create circuit node in exit mode
        let circuit_node = CircuitNode::new(peer_id, listen_addr, true)
            .await
            .map_err(|e| ExitError::Network(e.to_string()))?;

        // Create UDP socket for DNS/UDP forwarding
        let udp_socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| ExitError::Network(e.to_string()))?;

        info!(
            "Circuit exit handler listening on {}",
            circuit_node.local_addr().unwrap()
        );

        Ok(Self {
            circuit_node: Arc::new(circuit_node),
            udp_socket: Arc::new(udp_socket),
            tcp_connections: Arc::new(RwLock::new(HashMap::new())),
            logger,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Get listen address
    pub fn listen_addr(&self) -> SocketAddr {
        self.circuit_node.local_addr().unwrap()
    }

    /// Start handling circuit messages
    pub async fn run(&self) -> ExitResult<()> {
        self.running
            .store(true, std::sync::atomic::Ordering::Relaxed);

        info!("Circuit exit handler started");

        // Run the circuit node
        self.circuit_node
            .run()
            .await
            .map_err(|e| ExitError::Network(e.to_string()))?;

        Ok(())
    }

    /// Stop the handler
    pub fn stop(&self) {
        self.running
            .store(false, std::sync::atomic::Ordering::Relaxed);
        self.circuit_node.stop();
    }

    /// Forward traffic to target and return response
    pub async fn forward_to_internet(
        &self,
        circuit_id: CircuitId,
        target: &str,
        data: &[u8],
    ) -> ExitResult<Vec<u8>> {
        info!(
            "Forwarding {} bytes to {} for circuit {}",
            data.len(),
            target,
            circuit_id
        );

        // Log for compliance
        if let Err(e) = self.logger.log_connection(circuit_id, target.parse().ok().unwrap_or_else(|| "0.0.0.0".parse().unwrap())).await {
            warn!("Failed to log connection: {}", e);
        }

        // Parse target
        let (host, port) = parse_target(target)?;

        // Determine protocol based on port
        if port == 53 {
            // DNS - use UDP
            self.forward_udp(&host, port, data).await
        } else if is_http_port(port) {
            // HTTP/HTTPS - use TCP
            self.forward_tcp(circuit_id, &host, port, data).await
        } else {
            // Default to TCP for unknown ports
            self.forward_tcp(circuit_id, &host, port, data).await
        }
    }

    /// Forward via UDP (for DNS)
    async fn forward_udp(&self, host: &str, port: u16, data: &[u8]) -> ExitResult<Vec<u8>> {
        let target_addr = resolve_addr(host, port)?;

        self.udp_socket
            .send_to(data, target_addr)
            .await
            .map_err(|e| ExitError::Network(e.to_string()))?;

        // Wait for response
        let mut buf = [0u8; 65536];
        let timeout_result = tokio::time::timeout(
            Duration::from_secs(5),
            self.udp_socket.recv_from(&mut buf),
        )
        .await;

        match timeout_result {
            Ok(Ok((len, _))) => Ok(buf[..len].to_vec()),
            Ok(Err(e)) => Err(ExitError::Network(e.to_string())),
            Err(_) => Err(ExitError::Timeout),
        }
    }

    /// Forward via TCP
    async fn forward_tcp(
        &self,
        circuit_id: CircuitId,
        host: &str,
        port: u16,
        data: &[u8],
    ) -> ExitResult<Vec<u8>> {
        let target_addr = resolve_addr(host, port)?;

        // Check if we already have a connection for this circuit
        let mut connections = self.tcp_connections.write().await;

        let stream = if let Some(conn) = connections.get_mut(&circuit_id) {
            &mut conn.stream
        } else {
            // Create new connection
            let stream = TcpStream::connect(target_addr)
                .await
                .map_err(|e| ExitError::Network(e.to_string()))?;

            connections.insert(
                circuit_id,
                TcpConnection {
                    stream,
                    target: format!("{}:{}", host, port),
                },
            );

            &mut connections.get_mut(&circuit_id).unwrap().stream
        };

        // Send data
        stream
            .write_all(data)
            .await
            .map_err(|e| ExitError::Network(e.to_string()))?;

        // Read response (up to 64KB)
        let mut response = vec![0u8; 65536];
        let timeout_result = tokio::time::timeout(
            Duration::from_secs(30),
            stream.read(&mut response),
        )
        .await;

        match timeout_result {
            Ok(Ok(len)) => {
                response.truncate(len);
                Ok(response)
            }
            Ok(Err(e)) => Err(ExitError::Network(e.to_string())),
            Err(_) => Err(ExitError::Timeout),
        }
    }

    /// Close TCP connection for circuit
    pub async fn close_connection(&self, circuit_id: CircuitId) {
        let mut connections = self.tcp_connections.write().await;
        if connections.remove(&circuit_id).is_some() {
            debug!("Closed TCP connection for circuit {}", circuit_id);
        }
    }
}

/// Parse target string (host:port)
fn parse_target(target: &str) -> ExitResult<(String, u16)> {
    let parts: Vec<&str> = target.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(ExitError::InvalidTarget(target.to_string()));
    }

    let port: u16 = parts[0]
        .parse()
        .map_err(|_| ExitError::InvalidTarget(target.to_string()))?;
    let host = parts[1].to_string();

    Ok((host, port))
}

/// Resolve hostname to socket address
fn resolve_addr(host: &str, port: u16) -> ExitResult<SocketAddr> {
    let addr_str = format!("{}:{}", host, port);

    addr_str
        .to_socket_addrs()
        .map_err(|e| ExitError::DnsError(e.to_string()))?
        .next()
        .ok_or_else(|| ExitError::DnsError("No addresses found".to_string()))
}

/// Check if port is HTTP/HTTPS
fn is_http_port(port: u16) -> bool {
    matches!(port, 80 | 443 | 8080 | 8443)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_target() {
        let (host, port) = parse_target("example.com:443").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_is_http_port() {
        assert!(is_http_port(80));
        assert!(is_http_port(443));
        assert!(!is_http_port(22));
    }
}
