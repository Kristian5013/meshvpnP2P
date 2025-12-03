//! MeshVPN Cryptographic Primitives
//!
//! This crate provides all cryptographic operations for the MeshVPN network:
//! - Key exchange (X25519)
//! - Symmetric encryption (ChaCha20-Poly1305)
//! - Digital signatures (Ed25519)
//! - Onion encryption for multi-hop routing
//! - Key derivation (HKDF-SHA256)

pub mod keys;
pub mod symmetric;
pub mod onion;
pub mod identity;
pub mod error;

pub use keys::{KeyPair, PublicKey, SecretKey, SharedSecret, EphemeralKeyPair};
pub use symmetric::{encrypt, decrypt, SymmetricKey, Nonce};
pub use onion::{OnionPacket, OnionLayer, OnionBuilder, OnionUnwrapper};
pub use identity::{NodeIdentity, NodeId, Signature};
pub use error::CryptoError;

/// Re-export commonly used types
pub mod prelude {
    pub use crate::keys::*;
    pub use crate::symmetric::*;
    pub use crate::onion::*;
    pub use crate::identity::*;
    pub use crate::error::*;
}

/// Protocol constants
pub mod constants {
    /// X25519 key size in bytes
    pub const X25519_KEY_SIZE: usize = 32;

    /// ChaCha20-Poly1305 key size
    pub const SYMMETRIC_KEY_SIZE: usize = 32;

    /// ChaCha20-Poly1305 nonce size
    pub const NONCE_SIZE: usize = 12;

    /// Poly1305 authentication tag size
    pub const AUTH_TAG_SIZE: usize = 16;

    /// Ed25519 signature size
    pub const SIGNATURE_SIZE: usize = 64;

    /// Ed25519 public key size
    pub const ED25519_PUBKEY_SIZE: usize = 32;

    /// Node ID size (truncated BLAKE3 hash)
    pub const NODE_ID_SIZE: usize = 20;

    /// Maximum onion layers (hops)
    pub const MAX_ONION_LAYERS: usize = 7;

    /// Onion packet header size per layer
    pub const ONION_HEADER_SIZE: usize = X25519_KEY_SIZE + AUTH_TAG_SIZE;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_crypto_flow() {
        // Generate identities for 3 relay nodes + 1 exit node
        let relay1 = NodeIdentity::generate();
        let relay2 = NodeIdentity::generate();
        let relay3 = NodeIdentity::generate();
        let exit = NodeIdentity::generate();

        // Original message
        let message = b"Hello, anonymous internet!";

        // Build onion packet
        let path = vec![
            relay1.public_key(),
            relay2.public_key(),
            relay3.public_key(),
            exit.public_key(),
        ];

        let onion = OnionBuilder::new()
            .set_payload(message.to_vec())
            .build_circuit(&path)
            .expect("Failed to build onion");

        // Simulate unwrapping at each hop
        let (layer1, packet1) = onion.unwrap_layer(&relay1.encryption_keypair().secret)
            .expect("Relay 1 failed to unwrap");
        assert!(layer1.next_hop.is_some());

        let (layer2, packet2) = packet1.unwrap_layer(&relay2.encryption_keypair().secret)
            .expect("Relay 2 failed to unwrap");
        assert!(layer2.next_hop.is_some());

        let (layer3, packet3) = packet2.unwrap_layer(&relay3.encryption_keypair().secret)
            .expect("Relay 3 failed to unwrap");
        assert!(layer3.next_hop.is_some());

        let (layer4, _) = packet3.unwrap_layer(&exit.encryption_keypair().secret)
            .expect("Exit failed to unwrap");

        // Exit node should see the original message
        assert!(layer4.is_exit);
        assert_eq!(layer4.payload.as_ref().unwrap(), message);
    }
}
