//! UDP Transport Layer
//!
//! Provides async UDP socket handling for MeshVPN communication.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, trace, warn};

use crate::error::{NetworkError, NetworkResult};
use crate::packet::{Packet, MAX_PACKET_SIZE};

/// A message received from the transport
#[derive(Debug, Clone)]
pub struct TransportMessage {
    /// Source address
    pub from: SocketAddr,

    /// The packet
    pub packet: Packet,
}

/// UDP transport for sending/receiving MeshVPN packets
pub struct UdpTransport {
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
}

impl UdpTransport {
    /// Create a new UDP transport bound to the specified address
    pub async fn bind(addr: SocketAddr) -> NetworkResult<Self> {
        let socket = UdpSocket::bind(addr).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::AddrInUse {
                NetworkError::AddressInUse(addr)
            } else {
                NetworkError::Io(e)
            }
        })?;

        let local_addr = socket.local_addr()?;
        debug!("UDP transport bound to {}", local_addr);

        Ok(Self {
            socket: Arc::new(socket),
            local_addr,
        })
    }

    /// Get local address
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Send a packet to the specified address
    pub async fn send_to(&self, packet: &Packet, addr: SocketAddr) -> NetworkResult<()> {
        let bytes = packet.to_bytes();

        if bytes.len() > MAX_PACKET_SIZE {
            return Err(NetworkError::InvalidPacket(format!(
                "Packet too large: {} bytes",
                bytes.len()
            )));
        }

        trace!("Sending {} bytes to {}", bytes.len(), addr);

        self.socket.send_to(&bytes, addr).await?;
        Ok(())
    }

    /// Receive a packet
    pub async fn recv(&self) -> NetworkResult<TransportMessage> {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];

        let (len, from) = self.socket.recv_from(&mut buf).await?;
        buf.truncate(len);

        trace!("Received {} bytes from {}", len, from);

        let packet = Packet::from_bytes(Bytes::from(buf))?;

        Ok(TransportMessage { from, packet })
    }

    /// Start receiving packets and forward to channel
    pub fn spawn_receiver(
        self: Arc<Self>,
        tx: mpsc::Sender<TransportMessage>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                match self.recv().await {
                    Ok(msg) => {
                        if tx.send(msg).await.is_err() {
                            debug!("Receiver channel closed, stopping");
                            break;
                        }
                    }
                    Err(NetworkError::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        continue;
                    }
                    Err(e) => {
                        warn!("Error receiving packet: {}", e);
                    }
                }
            }
        })
    }

    /// Clone the inner socket for sharing
    pub fn clone_socket(&self) -> Arc<UdpSocket> {
        self.socket.clone()
    }
}

/// Builder for UDP transport with custom options
pub struct UdpTransportBuilder {
    bind_addr: SocketAddr,
    recv_buffer_size: Option<usize>,
    send_buffer_size: Option<usize>,
}

impl UdpTransportBuilder {
    /// Create a new builder
    pub fn new(bind_addr: SocketAddr) -> Self {
        Self {
            bind_addr,
            recv_buffer_size: None,
            send_buffer_size: None,
        }
    }

    /// Set receive buffer size
    pub fn recv_buffer_size(mut self, size: usize) -> Self {
        self.recv_buffer_size = Some(size);
        self
    }

    /// Set send buffer size
    pub fn send_buffer_size(mut self, size: usize) -> Self {
        self.send_buffer_size = Some(size);
        self
    }

    /// Build the transport
    pub async fn build(self) -> NetworkResult<UdpTransport> {
        use socket2::{Domain, Protocol, Socket, Type};

        let domain = if self.bind_addr.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        };

        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

        // Set buffer sizes if specified
        if let Some(size) = self.recv_buffer_size {
            socket.set_recv_buffer_size(size)?;
        }
        if let Some(size) = self.send_buffer_size {
            socket.set_send_buffer_size(size)?;
        }

        // Allow address reuse
        socket.set_reuse_address(true)?;

        // Set non-blocking before converting to tokio
        socket.set_nonblocking(true)?;

        // Bind
        socket.bind(&self.bind_addr.into())?;

        // Convert to tokio UdpSocket
        let std_socket: std::net::UdpSocket = socket.into();
        let tokio_socket = UdpSocket::from_std(std_socket)?;

        let local_addr = tokio_socket.local_addr()?;
        debug!("UDP transport bound to {} with custom options", local_addr);

        Ok(UdpTransport {
            socket: Arc::new(tokio_socket),
            local_addr,
        })
    }
}

/// Rate limiter for transport (prevents DoS)
pub struct RateLimiter {
    /// Maximum packets per second per IP
    max_pps: u32,
    /// Tracking map (IP -> last packet timestamps)
    tracker: std::sync::RwLock<std::collections::HashMap<std::net::IpAddr, Vec<std::time::Instant>>>,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(max_pps: u32) -> Self {
        Self {
            max_pps,
            tracker: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Check if a packet from this IP should be allowed
    pub fn check(&self, ip: std::net::IpAddr) -> bool {
        let now = std::time::Instant::now();
        let window = std::time::Duration::from_secs(1);

        let mut tracker = self.tracker.write().unwrap();
        let timestamps = tracker.entry(ip).or_insert_with(Vec::new);

        // Remove old timestamps
        timestamps.retain(|&t| now.duration_since(t) < window);

        if timestamps.len() >= self.max_pps as usize {
            warn!("Rate limit exceeded for {}", ip);
            false
        } else {
            timestamps.push(now);
            true
        }
    }

    /// Clean up old entries periodically
    pub fn cleanup(&self) {
        let now = std::time::Instant::now();
        let window = std::time::Duration::from_secs(1);

        let mut tracker = self.tracker.write().unwrap();
        tracker.retain(|_, timestamps| {
            timestamps.retain(|&t| now.duration_since(t) < window);
            !timestamps.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_transport_bind() {
        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        assert!(transport.local_addr().port() > 0);
    }

    #[tokio::test]
    async fn test_transport_send_recv() {
        let transport1 = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let transport2 = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        let packet = Packet::ping(12345);

        // Send from t1 to t2
        transport1
            .send_to(&packet, transport2.local_addr())
            .await
            .unwrap();

        // Receive at t2
        let msg = transport2.recv().await.unwrap();

        assert_eq!(msg.from, transport1.local_addr());
        assert_eq!(msg.packet.circuit_id, 12345);
    }

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new(3);
        let ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();

        assert!(limiter.check(ip));
        assert!(limiter.check(ip));
        assert!(limiter.check(ip));
        assert!(!limiter.check(ip)); // 4th should be blocked
    }
}
