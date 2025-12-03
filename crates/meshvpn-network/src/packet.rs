//! Packet definitions for MeshVPN protocol
//!
//! Wire format:
//! [Type: 1 byte][Circuit ID: 4 bytes][Payload: variable]

use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};

use crate::error::{NetworkError, NetworkResult};

/// Packet type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PacketType {
    /// Handshake initiation
    HandshakeInit = 0x01,

    /// Handshake response
    HandshakeResponse = 0x02,

    /// Onion-encrypted data packet
    Data = 0x10,

    /// Data response (from exit back through circuit)
    DataResponse = 0x11,

    /// Circuit extend request
    CircuitExtend = 0x20,

    /// Circuit extend acknowledgment
    CircuitExtendAck = 0x21,

    /// Circuit teardown
    CircuitTeardown = 0x22,

    /// Keep-alive ping
    Ping = 0x30,

    /// Keep-alive pong
    Pong = 0x31,

    /// DHT find nodes request
    FindNodes = 0x40,

    /// DHT found nodes response
    FoundNodes = 0x41,

    /// Error notification
    Error = 0xFF,
}

impl TryFrom<u8> for PacketType {
    type Error = NetworkError;

    fn try_from(value: u8) -> Result<Self, <Self as TryFrom<u8>>::Error> {
        match value {
            0x01 => Ok(Self::HandshakeInit),
            0x02 => Ok(Self::HandshakeResponse),
            0x10 => Ok(Self::Data),
            0x11 => Ok(Self::DataResponse),
            0x20 => Ok(Self::CircuitExtend),
            0x21 => Ok(Self::CircuitExtendAck),
            0x22 => Ok(Self::CircuitTeardown),
            0x30 => Ok(Self::Ping),
            0x31 => Ok(Self::Pong),
            0x40 => Ok(Self::FindNodes),
            0x41 => Ok(Self::FoundNodes),
            0xFF => Ok(Self::Error),
            _ => Err(NetworkError::InvalidPacket(format!(
                "Unknown packet type: 0x{:02x}",
                value
            ))),
        }
    }
}

/// A MeshVPN protocol packet
#[derive(Debug, Clone)]
pub struct Packet {
    /// Packet type
    pub packet_type: PacketType,

    /// Circuit identifier (for multiplexing)
    pub circuit_id: u32,

    /// Packet payload
    pub payload: Bytes,
}

/// Minimum packet size (type + circuit_id)
pub const MIN_PACKET_SIZE: usize = 5;

/// Maximum packet size (including overhead)
pub const MAX_PACKET_SIZE: usize = 65535;

impl Packet {
    /// Create a new packet
    pub fn new(packet_type: PacketType, circuit_id: u32, payload: impl Into<Bytes>) -> Self {
        Self {
            packet_type,
            circuit_id,
            payload: payload.into(),
        }
    }

    /// Create a handshake init packet
    pub fn handshake_init(circuit_id: u32, payload: impl Into<Bytes>) -> Self {
        Self::new(PacketType::HandshakeInit, circuit_id, payload)
    }

    /// Create a handshake response packet
    pub fn handshake_response(circuit_id: u32, payload: impl Into<Bytes>) -> Self {
        Self::new(PacketType::HandshakeResponse, circuit_id, payload)
    }

    /// Create a data packet
    pub fn data(circuit_id: u32, payload: impl Into<Bytes>) -> Self {
        Self::new(PacketType::Data, circuit_id, payload)
    }

    /// Create a data response packet
    pub fn data_response(circuit_id: u32, payload: impl Into<Bytes>) -> Self {
        Self::new(PacketType::DataResponse, circuit_id, payload)
    }

    /// Create a ping packet
    pub fn ping(circuit_id: u32) -> Self {
        Self::new(PacketType::Ping, circuit_id, Bytes::new())
    }

    /// Create a pong packet
    pub fn pong(circuit_id: u32) -> Self {
        Self::new(PacketType::Pong, circuit_id, Bytes::new())
    }

    /// Create a circuit teardown packet
    pub fn teardown(circuit_id: u32) -> Self {
        Self::new(PacketType::CircuitTeardown, circuit_id, Bytes::new())
    }

    /// Serialize packet to bytes
    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(MIN_PACKET_SIZE + self.payload.len());
        buf.put_u8(self.packet_type as u8);
        buf.put_u32(self.circuit_id);
        buf.put_slice(&self.payload);
        buf.freeze()
    }

    /// Deserialize packet from bytes
    pub fn from_bytes(mut bytes: Bytes) -> NetworkResult<Self> {
        if bytes.len() < MIN_PACKET_SIZE {
            return Err(NetworkError::InvalidPacket(format!(
                "Packet too short: {} bytes",
                bytes.len()
            )));
        }

        let packet_type = PacketType::try_from(bytes.get_u8())?;
        let circuit_id = bytes.get_u32();
        let payload = bytes;

        Ok(Self {
            packet_type,
            circuit_id,
            payload,
        })
    }

    /// Get total packet size
    pub fn size(&self) -> usize {
        MIN_PACKET_SIZE + self.payload.len()
    }

    /// Check if this is a control packet (not data)
    pub fn is_control(&self) -> bool {
        matches!(
            self.packet_type,
            PacketType::HandshakeInit
                | PacketType::HandshakeResponse
                | PacketType::CircuitExtend
                | PacketType::CircuitExtendAck
                | PacketType::CircuitTeardown
                | PacketType::Ping
                | PacketType::Pong
                | PacketType::Error
        )
    }
}

/// Handshake initiation payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeInit {
    /// Initiator's ephemeral public key
    pub ephemeral_pubkey: [u8; 32],

    /// Initiator's static public key (encrypted)
    pub static_pubkey: [u8; 32],

    /// Timestamp for replay protection
    pub timestamp: u64,

    /// Random nonce
    pub nonce: [u8; 12],
}

/// Handshake response payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResponse {
    /// Responder's ephemeral public key
    pub ephemeral_pubkey: [u8; 32],

    /// Encrypted payload (contains confirmation)
    pub encrypted_payload: Vec<u8>,
}

/// Circuit extend request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitExtendRequest {
    /// Next hop's public key
    pub next_hop_pubkey: [u8; 32],

    /// Encrypted handshake for next hop
    pub encrypted_handshake: Vec<u8>,
}

impl HandshakeInit {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> NetworkResult<Vec<u8>> {
        bincode::serialize(self).map_err(|e| NetworkError::InvalidPacket(e.to_string()))
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> NetworkResult<Self> {
        bincode::deserialize(bytes).map_err(|e| NetworkError::InvalidPacket(e.to_string()))
    }
}

impl HandshakeResponse {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> NetworkResult<Vec<u8>> {
        bincode::serialize(self).map_err(|e| NetworkError::InvalidPacket(e.to_string()))
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> NetworkResult<Self> {
        bincode::deserialize(bytes).map_err(|e| NetworkError::InvalidPacket(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_roundtrip() {
        let original = Packet::data(12345, vec![1, 2, 3, 4, 5]);
        let bytes = original.to_bytes();
        let decoded = Packet::from_bytes(bytes).unwrap();

        assert_eq!(original.packet_type, decoded.packet_type);
        assert_eq!(original.circuit_id, decoded.circuit_id);
        assert_eq!(original.payload, decoded.payload);
    }

    #[test]
    fn test_packet_types() {
        let types = [
            PacketType::HandshakeInit,
            PacketType::HandshakeResponse,
            PacketType::Data,
            PacketType::DataResponse,
            PacketType::Ping,
            PacketType::Pong,
        ];

        for pt in types {
            let packet = Packet::new(pt, 1, vec![]);
            let bytes = packet.to_bytes();
            let decoded = Packet::from_bytes(bytes).unwrap();
            assert_eq!(pt, decoded.packet_type);
        }
    }

    #[test]
    fn test_invalid_packet_type() {
        let mut bytes = BytesMut::new();
        bytes.put_u8(0xFE); // Invalid type
        bytes.put_u32(0);

        let result = Packet::from_bytes(bytes.freeze());
        assert!(result.is_err());
    }

    #[test]
    fn test_packet_too_short() {
        let bytes = Bytes::from_static(&[0x01, 0x00]); // Only 2 bytes
        let result = Packet::from_bytes(bytes);
        assert!(result.is_err());
    }
}
