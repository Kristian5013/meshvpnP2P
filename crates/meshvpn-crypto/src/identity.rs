//! Node Identity Management
//!
//! Provides Ed25519-based identity for nodes.
//! Each node has:
//! - A signing keypair (Ed25519) for authentication
//! - An encryption keypair (X25519) for key exchange
//! - A unique NodeId derived from the public key

use ed25519_dalek::{
    Signature as Ed25519Sig, Signer, SigningKey, Verifier, VerifyingKey,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use zeroize::ZeroizeOnDrop;

use crate::constants::{ED25519_PUBKEY_SIZE, NODE_ID_SIZE, SIGNATURE_SIZE};
use crate::error::{CryptoError, CryptoResult};
use crate::keys::{KeyPair, PublicKey, SecretKey};

/// A 160-bit node identifier (truncated BLAKE3 hash of public key)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId {
    bytes: [u8; NODE_ID_SIZE],
}

/// Ed25519 signature
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct Signature {
    #[serde(with = "BigArray")]
    bytes: [u8; SIGNATURE_SIZE],
}

/// A node's complete identity (signing + encryption keys)
#[derive(ZeroizeOnDrop)]
pub struct NodeIdentity {
    /// Ed25519 signing key
    #[zeroize(skip)]
    signing_key: SigningKey,

    /// X25519 encryption keypair
    #[zeroize(skip)]
    encryption_keypair: KeyPair,

    /// Cached node ID
    #[zeroize(skip)]
    node_id: NodeId,
}

/// Public identity information (shareable)
#[derive(Clone, Serialize, Deserialize)]
pub struct PublicNodeInfo {
    /// Node's unique identifier
    pub node_id: NodeId,

    /// Ed25519 public key for verifying signatures
    pub signing_pubkey: [u8; ED25519_PUBKEY_SIZE],

    /// X25519 public key for encryption
    pub encryption_pubkey: PublicKey,
}

impl NodeId {
    /// Create NodeId from raw bytes
    pub fn from_bytes(bytes: [u8; NODE_ID_SIZE]) -> Self {
        Self { bytes }
    }

    /// Derive NodeId from a public signing key
    pub fn from_pubkey(pubkey: &[u8; ED25519_PUBKEY_SIZE]) -> Self {
        let hash = blake3::hash(pubkey);
        let mut bytes = [0u8; NODE_ID_SIZE];
        bytes.copy_from_slice(&hash.as_bytes()[..NODE_ID_SIZE]);
        Self { bytes }
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; NODE_ID_SIZE] {
        &self.bytes
    }

    /// XOR distance between two NodeIds (for Kademlia DHT)
    pub fn distance(&self, other: &NodeId) -> [u8; NODE_ID_SIZE] {
        let mut result = [0u8; NODE_ID_SIZE];
        for i in 0..NODE_ID_SIZE {
            result[i] = self.bytes[i] ^ other.bytes[i];
        }
        result
    }

    /// Get the leading zeros in the XOR distance (for DHT bucket placement)
    pub fn leading_zeros(&self, other: &NodeId) -> u32 {
        let distance = self.distance(other);
        let mut zeros = 0u32;
        for byte in distance {
            if byte == 0 {
                zeros += 8;
            } else {
                zeros += byte.leading_zeros();
                break;
            }
        }
        zeros
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex_encode(&self.bytes)
    }

    /// Parse from hex string
    pub fn from_hex(hex: &str) -> CryptoResult<Self> {
        let bytes = hex_decode(hex)?;
        if bytes.len() != NODE_ID_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: NODE_ID_SIZE,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; NODE_ID_SIZE];
        arr.copy_from_slice(&bytes);
        Ok(Self { bytes: arr })
    }
}

impl std::fmt::Debug for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NodeId({})", &self.to_hex()[..8])
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Signature {
    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; SIGNATURE_SIZE]) -> Self {
        Self { bytes }
    }

    /// Try to create from slice
    pub fn try_from_slice(slice: &[u8]) -> CryptoResult<Self> {
        if slice.len() != SIGNATURE_SIZE {
            return Err(CryptoError::InvalidSignature);
        }
        let mut bytes = [0u8; SIGNATURE_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self { bytes })
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.bytes
    }
}

impl NodeIdentity {
    /// Generate a new random identity
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let encryption_keypair = KeyPair::generate();
        let node_id = NodeId::from_pubkey(&signing_key.verifying_key().to_bytes());

        Self {
            signing_key,
            encryption_keypair,
            node_id,
        }
    }

    /// Create from existing keys (for loading from storage)
    pub fn from_keys(
        signing_key_bytes: [u8; 32],
        encryption_key_bytes: [u8; 32],
    ) -> CryptoResult<Self> {
        let signing_key = SigningKey::from_bytes(&signing_key_bytes);
        let encryption_keypair = KeyPair::from_bytes(encryption_key_bytes);
        let node_id = NodeId::from_pubkey(&signing_key.verifying_key().to_bytes());

        Ok(Self {
            signing_key,
            encryption_keypair,
            node_id,
        })
    }

    /// Get the node's unique identifier
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Get the X25519 public key for encryption
    pub fn public_key(&self) -> PublicKey {
        self.encryption_keypair.public
    }

    /// Get the X25519 keypair for encryption
    pub fn encryption_keypair(&self) -> &KeyPair {
        &self.encryption_keypair
    }

    /// Get the Ed25519 verifying (public) key
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Signature {
        let sig = self.signing_key.sign(message);
        Signature {
            bytes: sig.to_bytes(),
        }
    }

    /// Export public information
    pub fn public_info(&self) -> PublicNodeInfo {
        PublicNodeInfo {
            node_id: self.node_id,
            signing_pubkey: self.signing_key.verifying_key().to_bytes(),
            encryption_pubkey: self.encryption_keypair.public,
        }
    }

    /// Export secret keys for secure storage
    pub fn export_secrets(&self) -> ([u8; 32], [u8; 32]) {
        (
            self.signing_key.to_bytes(),
            self.encryption_keypair.secret.to_bytes(),
        )
    }
}

impl Clone for NodeIdentity {
    fn clone(&self) -> Self {
        let (signing_bytes, encryption_bytes) = self.export_secrets();
        Self::from_keys(signing_bytes, encryption_bytes)
            .expect("Clone of valid identity should not fail")
    }
}

impl PublicNodeInfo {
    /// Verify a signature from this node
    pub fn verify(&self, message: &[u8], signature: &Signature) -> CryptoResult<()> {
        let verifying_key = VerifyingKey::from_bytes(&self.signing_pubkey)
            .map_err(|_| CryptoError::InvalidPublicKey)?;

        let sig = Ed25519Sig::from_bytes(&signature.bytes);

        verifying_key
            .verify(message, &sig)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }

    /// Get the encryption public key
    pub fn encryption_pubkey(&self) -> &PublicKey {
        &self.encryption_pubkey
    }
}

// Helper functions for hex encoding/decoding
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(hex: &str) -> CryptoResult<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return Err(CryptoError::SerializationError("Invalid hex length".into()));
    }

    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| CryptoError::SerializationError("Invalid hex character".into()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generation() {
        let identity = NodeIdentity::generate();
        let node_id = identity.node_id();

        // Node ID should be 20 bytes
        assert_eq!(node_id.as_bytes().len(), NODE_ID_SIZE);
    }

    #[test]
    fn test_sign_verify() {
        let identity = NodeIdentity::generate();
        let public_info = identity.public_info();

        let message = b"Hello, MeshVPN!";
        let signature = identity.sign(message);

        // Should verify correctly
        assert!(public_info.verify(message, &signature).is_ok());

        // Different message should fail
        let wrong_message = b"Hello, World!";
        assert!(public_info.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_export_import() {
        let identity = NodeIdentity::generate();
        let (signing_bytes, encryption_bytes) = identity.export_secrets();

        let restored = NodeIdentity::from_keys(signing_bytes, encryption_bytes).unwrap();

        assert_eq!(identity.node_id(), restored.node_id());
        assert_eq!(identity.public_key(), restored.public_key());
    }

    #[test]
    fn test_node_id_distance() {
        let id1 = NodeId::from_bytes([0xFF; NODE_ID_SIZE]);
        let id2 = NodeId::from_bytes([0x00; NODE_ID_SIZE]);

        let distance = id1.distance(&id2);
        assert_eq!(distance, [0xFF; NODE_ID_SIZE]);

        // Distance to self should be zero
        let self_distance = id1.distance(&id1);
        assert_eq!(self_distance, [0x00; NODE_ID_SIZE]);
    }

    #[test]
    fn test_node_id_leading_zeros() {
        let id1 = NodeId::from_bytes([0x00; NODE_ID_SIZE]);
        let mut id2_bytes = [0x00; NODE_ID_SIZE];
        id2_bytes[0] = 0x80; // First bit is 1
        let id2 = NodeId::from_bytes(id2_bytes);

        // XOR should give 0x80 in first byte = 0 leading zeros
        assert_eq!(id1.leading_zeros(&id2), 0);

        id2_bytes[0] = 0x01; // Last bit of first byte is 1
        let id3 = NodeId::from_bytes(id2_bytes);

        // XOR should give 0x01 in first byte = 7 leading zeros
        assert_eq!(id1.leading_zeros(&id3), 7);
    }

    #[test]
    fn test_node_id_hex() {
        let identity = NodeIdentity::generate();
        let node_id = identity.node_id();

        let hex = node_id.to_hex();
        let parsed = NodeId::from_hex(&hex).unwrap();

        assert_eq!(node_id, parsed);
    }
}
