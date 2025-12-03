//! NAT Traversal
//!
//! Implements STUN-based NAT discovery and UDP hole punching
//! for peer-to-peer connectivity behind NATs.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::error::{NetworkError, NetworkResult};

/// NAT type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    /// No NAT - public IP
    None,
    /// Full cone NAT (easiest to traverse)
    FullCone,
    /// Restricted cone NAT
    RestrictedCone,
    /// Port restricted cone NAT
    PortRestrictedCone,
    /// Symmetric NAT (hardest to traverse)
    Symmetric,
    /// Unknown NAT type
    Unknown,
}

impl NatType {
    /// Check if this NAT type allows easy P2P connections
    pub fn is_traversable(&self) -> bool {
        matches!(
            self,
            NatType::None | NatType::FullCone | NatType::RestrictedCone | NatType::PortRestrictedCone
        )
    }
}

/// Result of NAT discovery
#[derive(Debug, Clone)]
pub struct NatInfo {
    /// Detected NAT type
    pub nat_type: NatType,

    /// Public IP:port as seen by STUN server
    pub public_addr: Option<SocketAddr>,

    /// Local IP:port
    pub local_addr: SocketAddr,

    /// Whether we're behind a NAT
    pub is_behind_nat: bool,
}

/// STUN client for NAT discovery
pub struct StunClient {
    servers: Vec<String>,
    timeout: Duration,
}

impl StunClient {
    /// Create a new STUN client
    pub fn new(servers: Vec<String>) -> Self {
        Self {
            servers,
            timeout: Duration::from_secs(3),
        }
    }

    /// Discover NAT type and public address
    pub async fn discover(&self, local_socket: &UdpSocket) -> NetworkResult<NatInfo> {
        let local_addr = local_socket.local_addr()?;

        // Try each STUN server until one works
        for server in &self.servers {
            match self.query_stun(local_socket, server).await {
                Ok(public_addr) => {
                    let is_behind_nat = public_addr.ip() != local_addr.ip();

                    // Determine NAT type (simplified - full detection requires multiple servers)
                    let nat_type = if !is_behind_nat {
                        NatType::None
                    } else if public_addr.port() == local_addr.port() {
                        // Port preserved - likely full cone or restricted
                        NatType::RestrictedCone
                    } else {
                        // Port changed - could be port restricted or symmetric
                        NatType::PortRestrictedCone
                    };

                    info!(
                        "NAT discovery: local={}, public={}, type={:?}",
                        local_addr, public_addr, nat_type
                    );

                    return Ok(NatInfo {
                        nat_type,
                        public_addr: Some(public_addr),
                        local_addr,
                        is_behind_nat,
                    });
                }
                Err(e) => {
                    debug!("STUN server {} failed: {}", server, e);
                    continue;
                }
            }
        }

        warn!("All STUN servers failed, NAT type unknown");
        Ok(NatInfo {
            nat_type: NatType::Unknown,
            public_addr: None,
            local_addr,
            is_behind_nat: true, // Assume worst case
        })
    }

    /// Query a single STUN server
    async fn query_stun(
        &self,
        socket: &UdpSocket,
        server: &str,
    ) -> NetworkResult<SocketAddr> {
        // Resolve STUN server address
        let server_addr: SocketAddr = tokio::net::lookup_host(server)
            .await?
            .next()
            .ok_or_else(|| NetworkError::NatTraversalFailed("Failed to resolve STUN server".into()))?;

        // Build STUN Binding Request
        let request = build_stun_binding_request();

        // Send request
        socket.send_to(&request, server_addr).await?;

        // Wait for response
        let mut buf = [0u8; 1024];
        let (len, _) = timeout(self.timeout, socket.recv_from(&mut buf))
            .await
            .map_err(|_| NetworkError::TimeoutWithMessage("STUN request timed out".into()))?
            ?;

        // Parse response
        parse_stun_response(&buf[..len])
    }
}

/// Build a STUN Binding Request message
fn build_stun_binding_request() -> Vec<u8> {
    let mut msg = Vec::with_capacity(20);

    // Message type: Binding Request (0x0001)
    msg.extend_from_slice(&0x0001u16.to_be_bytes());

    // Message length: 0 (no attributes)
    msg.extend_from_slice(&0x0000u16.to_be_bytes());

    // Magic cookie (RFC 5389)
    msg.extend_from_slice(&0x2112A442u32.to_be_bytes());

    // Transaction ID (12 random bytes)
    let mut tx_id = [0u8; 12];
    getrandom::getrandom(&mut tx_id).unwrap_or_else(|_| {
        // Fallback to pseudo-random
        for (i, byte) in tx_id.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(17).wrapping_add(42);
        }
    });
    msg.extend_from_slice(&tx_id);

    msg
}

/// Parse a STUN response and extract the mapped address
fn parse_stun_response(data: &[u8]) -> NetworkResult<SocketAddr> {
    if data.len() < 20 {
        return Err(NetworkError::NatTraversalFailed("Response too short".into()));
    }

    // Check message type (should be Binding Response: 0x0101)
    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    if msg_type != 0x0101 {
        return Err(NetworkError::NatTraversalFailed(format!(
            "Unexpected message type: 0x{:04x}",
            msg_type
        )));
    }

    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;

    // Parse attributes
    let mut offset = 20; // Skip header
    while offset + 4 <= 20 + msg_len && offset + 4 <= data.len() {
        let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;

        offset += 4;

        if offset + attr_len > data.len() {
            break;
        }

        // XOR-MAPPED-ADDRESS (0x0020) or MAPPED-ADDRESS (0x0001)
        if attr_type == 0x0020 || attr_type == 0x0001 {
            let is_xor = attr_type == 0x0020;
            let family = data[offset + 1];

            if family == 0x01 {
                // IPv4
                let mut port = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
                let mut ip_bytes = [
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ];

                if is_xor {
                    // XOR with magic cookie
                    port ^= 0x2112;
                    ip_bytes[0] ^= 0x21;
                    ip_bytes[1] ^= 0x12;
                    ip_bytes[2] ^= 0xA4;
                    ip_bytes[3] ^= 0x42;
                }

                let ip = std::net::Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
                return Ok(SocketAddr::new(ip.into(), port));
            }
        }

        // Align to 4 bytes
        offset += (attr_len + 3) & !3;
    }

    Err(NetworkError::NatTraversalFailed(
        "No mapped address found in response".into(),
    ))
}

/// UDP hole punching coordinator
pub struct HolePuncher {
    local_socket: std::sync::Arc<UdpSocket>,
}

impl HolePuncher {
    /// Create a new hole puncher
    pub fn new(socket: std::sync::Arc<UdpSocket>) -> Self {
        Self { local_socket: socket }
    }

    /// Attempt to punch a hole to a peer
    ///
    /// Both sides should call this simultaneously for best results.
    pub async fn punch(
        &self,
        peer_public_addr: SocketAddr,
        peer_local_addrs: &[SocketAddr],
    ) -> NetworkResult<SocketAddr> {
        let punch_packet = b"MESHVPN_PUNCH";
        let max_attempts = 10;
        let interval = Duration::from_millis(100);

        // Try both public and local addresses
        let mut targets = vec![peer_public_addr];
        targets.extend_from_slice(peer_local_addrs);

        for attempt in 0..max_attempts {
            // Send punch packets to all candidate addresses
            for target in &targets {
                let _ = self.local_socket.send_to(punch_packet, target).await;
                debug!("Sent punch packet to {} (attempt {})", target, attempt + 1);
            }

            // Wait for response
            let mut buf = [0u8; 64];
            match timeout(interval, self.local_socket.recv_from(&mut buf)).await {
                Ok(Ok((len, from))) => {
                    if len >= punch_packet.len() && &buf[..punch_packet.len()] == punch_packet {
                        info!("Hole punch successful to {}", from);
                        return Ok(from);
                    }
                }
                _ => continue,
            }
        }

        Err(NetworkError::NatTraversalFailed(
            "Hole punching failed after max attempts".into(),
        ))
    }
}

// Simple getrandom implementation
mod getrandom {
    pub fn getrandom(dest: &mut [u8]) -> Result<(), ()> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(12345) as u64;

        let mut state = seed;
        for byte in dest.iter_mut() {
            // Simple xorshift
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stun_request_format() {
        let request = build_stun_binding_request();

        // Should be 20 bytes
        assert_eq!(request.len(), 20);

        // Check message type
        assert_eq!(request[0], 0x00);
        assert_eq!(request[1], 0x01);

        // Check magic cookie
        assert_eq!(&request[4..8], &[0x21, 0x12, 0xA4, 0x42]);
    }

    #[test]
    fn test_nat_type_traversable() {
        assert!(NatType::None.is_traversable());
        assert!(NatType::FullCone.is_traversable());
        assert!(NatType::RestrictedCone.is_traversable());
        assert!(!NatType::Symmetric.is_traversable());
    }
}
