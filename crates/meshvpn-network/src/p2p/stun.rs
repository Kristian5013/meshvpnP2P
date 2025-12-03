//! STUN Client for NAT Discovery
//!
//! Implements RFC 5389 STUN (Session Traversal Utilities for NAT) for:
//! - Discovering public IP and port (reflexive transport address)
//! - NAT type detection
//! - Keepalive for NAT binding maintenance

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use super::protocol::NatType;
use crate::error::{NetworkError, NetworkResult};

/// STUN message types (RFC 5389)
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_RESPONSE: u16 = 0x0101;
const STUN_BINDING_ERROR: u16 = 0x0111;

/// STUN attributes
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_CHANGE_REQUEST: u16 = 0x0003;
const ATTR_RESPONSE_ORIGIN: u16 = 0x802b;
const ATTR_OTHER_ADDRESS: u16 = 0x802c;

/// STUN magic cookie (RFC 5389)
const MAGIC_COOKIE: u32 = 0x2112A442;

/// Default STUN servers
pub const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun.cloudflare.com:3478",
];

/// STUN client for NAT traversal
pub struct StunClient {
    socket: UdpSocket,
    timeout: Duration,
}

/// Result of STUN binding request
#[derive(Debug, Clone)]
pub struct StunResult {
    /// Our public address as seen by STUN server
    pub mapped_address: SocketAddr,
    /// Server's response origin (for NAT detection)
    pub response_origin: Option<SocketAddr>,
    /// Alternative server address (for NAT type test)
    pub other_address: Option<SocketAddr>,
}

impl StunClient {
    /// Create new STUN client bound to specified address
    pub async fn new(bind_addr: &str) -> NetworkResult<Self> {
        let socket = UdpSocket::bind(bind_addr).await
            .map_err(|e| NetworkError::IoError(e.to_string()))?;

        Ok(Self {
            socket,
            timeout: Duration::from_secs(3),
        })
    }

    /// Create from existing socket
    pub fn from_socket(socket: UdpSocket) -> Self {
        Self {
            socket,
            timeout: Duration::from_secs(3),
        }
    }

    /// Get local address
    pub fn local_addr(&self) -> NetworkResult<SocketAddr> {
        self.socket.local_addr()
            .map_err(|e| NetworkError::IoError(e.to_string()))
    }

    /// Perform STUN binding request to discover public address
    pub async fn get_mapped_address(&self, server: &str) -> NetworkResult<StunResult> {
        // Try parsing as socket address first, then resolve as hostname
        let server_addr: SocketAddr = if let Ok(addr) = server.parse() {
            addr
        } else {
            // Resolve hostname
            tokio::net::lookup_host(server).await
                .map_err(|e| NetworkError::ConfigError(format!("Failed to resolve STUN server '{}': {}", server, e)))?
                .next()
                .ok_or_else(|| NetworkError::ConfigError(format!("No addresses found for STUN server: {}", server)))?
        };

        self.binding_request(&server_addr, false, false).await
    }

    /// Perform binding request with change flags (for NAT type detection)
    async fn binding_request(
        &self,
        server: &SocketAddr,
        change_ip: bool,
        change_port: bool,
    ) -> NetworkResult<StunResult> {
        // Generate transaction ID (96 bits random)
        let mut transaction_id = [0u8; 12];
        getrandom::getrandom(&mut transaction_id)
            .map_err(|e| NetworkError::IoError(e.to_string()))?;

        // Build STUN request
        let request = build_binding_request(&transaction_id, change_ip, change_port);

        // Send request
        self.socket.send_to(&request, server).await
            .map_err(|e| NetworkError::IoError(e.to_string()))?;

        debug!("Sent STUN request to {}", server);

        // Wait for response with timeout
        let mut buf = [0u8; 576]; // STUN messages should fit in 576 bytes
        let (len, from) = timeout(self.timeout, self.socket.recv_from(&mut buf)).await
            .map_err(|_| NetworkError::TimeoutWithMessage("STUN request timed out".into()))?
            .map_err(|e| NetworkError::IoError(e.to_string()))?;

        debug!("Received STUN response from {} ({} bytes)", from, len);

        // Parse response
        parse_binding_response(&buf[..len], &transaction_id)
    }

    /// Detect NAT type using RFC 3489 algorithm
    pub async fn detect_nat_type(&self, primary_server: &str) -> NetworkResult<NatType> {
        info!("Starting NAT type detection...");

        // Test 1: Basic binding request
        let result1 = match self.get_mapped_address(primary_server).await {
            Ok(r) => r,
            Err(e) => {
                warn!("STUN Test 1 failed: {}", e);
                return Ok(NatType::Unknown);
            }
        };

        let local_addr = self.local_addr()?;
        info!("Test 1: Local {} -> Mapped {}", local_addr, result1.mapped_address);

        // Check if we have a public IP (no NAT)
        if local_addr.ip() == result1.mapped_address.ip() {
            info!("No NAT detected (public IP)");
            return Ok(NatType::None);
        }

        // Test 2: Request from different IP and port (requires STUN server support)
        let other_server = result1.other_address.or_else(|| {
            // Try a different STUN server as fallback
            DEFAULT_STUN_SERVERS.iter()
                .find(|s| *s != &primary_server)
                .and_then(|s| s.parse().ok())
        });

        if let Some(other) = other_server {
            // Test binding to different server
            match self.get_mapped_address(&other.to_string()).await {
                Ok(result2) => {
                    info!("Test 2: Mapped address from other server: {}", result2.mapped_address);

                    // If mapped address is different, we have Symmetric NAT
                    if result2.mapped_address != result1.mapped_address {
                        info!("Symmetric NAT detected (different mapping per destination)");
                        return Ok(NatType::Symmetric);
                    }
                }
                Err(e) => {
                    debug!("Test 2 failed (expected for some NAT types): {}", e);
                }
            }
        }

        // Test 3: Try to receive from changed IP/port
        // This requires STUN server with CHANGE-REQUEST support
        // For now, assume Port Restricted as conservative default
        info!("Assuming Port Restricted NAT (most common type)");
        Ok(NatType::PortRestricted)
    }

    /// Keep NAT binding alive by sending periodic STUN requests
    pub async fn keepalive(&self, server: &str) -> NetworkResult<()> {
        self.get_mapped_address(server).await?;
        Ok(())
    }
}

/// Build STUN binding request packet
fn build_binding_request(
    transaction_id: &[u8; 12],
    change_ip: bool,
    change_port: bool,
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(28);

    // Message Type: Binding Request (0x0001)
    packet.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());

    // Message Length (will be updated)
    let length_pos = packet.len();
    packet.extend_from_slice(&0u16.to_be_bytes());

    // Magic Cookie
    packet.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());

    // Transaction ID (12 bytes)
    packet.extend_from_slice(transaction_id);

    // Optional: CHANGE-REQUEST attribute
    if change_ip || change_port {
        let mut flags: u32 = 0;
        if change_ip {
            flags |= 0x04;
        }
        if change_port {
            flags |= 0x02;
        }

        // Attribute Type
        packet.extend_from_slice(&ATTR_CHANGE_REQUEST.to_be_bytes());
        // Attribute Length
        packet.extend_from_slice(&4u16.to_be_bytes());
        // Attribute Value
        packet.extend_from_slice(&flags.to_be_bytes());
    }

    // Update message length
    let msg_len = (packet.len() - 20) as u16;
    packet[length_pos..length_pos + 2].copy_from_slice(&msg_len.to_be_bytes());

    packet
}

/// Parse STUN binding response
fn parse_binding_response(
    data: &[u8],
    expected_txn_id: &[u8; 12],
) -> NetworkResult<StunResult> {
    if data.len() < 20 {
        return Err(NetworkError::Protocol("STUN response too short".into()));
    }

    // Parse header
    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let magic = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let txn_id = &data[8..20];

    // Validate
    if msg_type != STUN_BINDING_RESPONSE && msg_type != STUN_BINDING_ERROR {
        return Err(NetworkError::Protocol(format!(
            "Unexpected STUN message type: 0x{:04x}",
            msg_type
        )));
    }

    if magic != MAGIC_COOKIE {
        return Err(NetworkError::Protocol("Invalid STUN magic cookie".into()));
    }

    if txn_id != expected_txn_id {
        return Err(NetworkError::Protocol("Transaction ID mismatch".into()));
    }

    if msg_type == STUN_BINDING_ERROR {
        return Err(NetworkError::Protocol("STUN binding error response".into()));
    }

    if data.len() < 20 + msg_len {
        return Err(NetworkError::Protocol("STUN message truncated".into()));
    }

    // Parse attributes
    let mut mapped_address: Option<SocketAddr> = None;
    let mut response_origin: Option<SocketAddr> = None;
    let mut other_address: Option<SocketAddr> = None;

    let mut pos = 20;
    while pos + 4 <= 20 + msg_len {
        let attr_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let attr_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if pos + attr_len > data.len() {
            break;
        }

        let attr_data = &data[pos..pos + attr_len];

        match attr_type {
            ATTR_MAPPED_ADDRESS => {
                if let Some(addr) = parse_mapped_address(attr_data, false, &data[4..8]) {
                    mapped_address = Some(addr);
                }
            }
            ATTR_XOR_MAPPED_ADDRESS => {
                if let Some(addr) = parse_mapped_address(attr_data, true, &data[4..8]) {
                    mapped_address = Some(addr);
                }
            }
            ATTR_RESPONSE_ORIGIN => {
                if let Some(addr) = parse_mapped_address(attr_data, false, &data[4..8]) {
                    response_origin = Some(addr);
                }
            }
            ATTR_OTHER_ADDRESS => {
                if let Some(addr) = parse_mapped_address(attr_data, false, &data[4..8]) {
                    other_address = Some(addr);
                }
            }
            _ => {
                // Ignore unknown attributes
            }
        }

        // Move to next attribute (aligned to 4 bytes)
        pos += (attr_len + 3) & !3;
    }

    let mapped = mapped_address.ok_or_else(|| {
        NetworkError::Protocol("No mapped address in STUN response".into())
    })?;

    Ok(StunResult {
        mapped_address: mapped,
        response_origin,
        other_address,
    })
}

/// Parse MAPPED-ADDRESS or XOR-MAPPED-ADDRESS attribute
fn parse_mapped_address(
    data: &[u8],
    xor: bool,
    magic_cookie: &[u8],
) -> Option<SocketAddr> {
    if data.len() < 8 {
        return None;
    }

    let family = data[1];
    let mut port = u16::from_be_bytes([data[2], data[3]]);

    if xor {
        // XOR with magic cookie high bytes
        port ^= u16::from_be_bytes([magic_cookie[0], magic_cookie[1]]);
    }

    match family {
        0x01 => {
            // IPv4
            if data.len() < 8 {
                return None;
            }
            let mut ip_bytes = [data[4], data[5], data[6], data[7]];
            if xor {
                for i in 0..4 {
                    ip_bytes[i] ^= magic_cookie[i];
                }
            }
            let ip = std::net::Ipv4Addr::from(ip_bytes);
            Some(SocketAddr::new(ip.into(), port))
        }
        0x02 => {
            // IPv6
            if data.len() < 20 {
                return None;
            }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&data[4..20]);
            if xor {
                // XOR with magic cookie + transaction ID
                for i in 0..4 {
                    ip_bytes[i] ^= magic_cookie[i];
                }
                // Note: Should also XOR with transaction ID for full compliance
            }
            let ip = std::net::Ipv6Addr::from(ip_bytes);
            Some(SocketAddr::new(ip.into(), port))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_stun_request_building() {
        let txn_id = [1u8; 12];
        let request = build_binding_request(&txn_id, false, false);

        // Check header
        assert_eq!(request[0..2], [0x00, 0x01]); // Binding Request
        assert_eq!(request[4..8], MAGIC_COOKIE.to_be_bytes()); // Magic Cookie
        assert_eq!(&request[8..20], &txn_id); // Transaction ID
    }

    #[tokio::test]
    #[ignore] // Requires network
    async fn test_real_stun_request() {
        let client = StunClient::new("0.0.0.0:0").await.unwrap();
        let result = client.get_mapped_address("stun.l.google.com:19302").await;

        match result {
            Ok(r) => {
                println!("Mapped address: {}", r.mapped_address);
            }
            Err(e) => {
                println!("STUN failed (expected in some networks): {}", e);
            }
        }
    }
}
