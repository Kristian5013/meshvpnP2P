//! Onion Encryption Layer
//!
//! Implements multi-layer encryption for anonymous routing.
//! Each layer can only be decrypted by its intended recipient,
//! revealing only the next hop (not the final destination or origin).
//!
//! Structure: [Ephemeral PubKey][Nonce][Encrypted Payload][Auth Tag]
//!
//! Similar to Tor's onion routing, but using modern cryptographic primitives:
//! - X25519 for key exchange (each layer)
//! - ChaCha20-Poly1305 for authenticated encryption
//! - HKDF-SHA256 for key derivation

use serde::{Deserialize, Serialize};

use crate::constants::{
    AUTH_TAG_SIZE, MAX_ONION_LAYERS, NONCE_SIZE, X25519_KEY_SIZE,
};
use crate::error::{CryptoError, CryptoResult};
use crate::keys::{EphemeralKeyPair, PublicKey, SecretKey, SharedSecret};
use crate::symmetric::{decrypt, encrypt, Nonce, SymmetricKey};

/// Header size per onion layer: pubkey + nonce + auth tag
pub const LAYER_OVERHEAD: usize = X25519_KEY_SIZE + NONCE_SIZE + AUTH_TAG_SIZE;

/// Maximum payload size (to prevent memory attacks)
pub const MAX_PAYLOAD_SIZE: usize = 65536; // 64KB

/// An encrypted onion packet
#[derive(Clone, Serialize, Deserialize)]
pub struct OnionPacket {
    /// Ephemeral public key for this layer
    pub ephemeral_pubkey: [u8; X25519_KEY_SIZE],

    /// Nonce for this layer's encryption
    pub nonce: [u8; NONCE_SIZE],

    /// Encrypted payload (contains next layer or final data)
    pub encrypted_payload: Vec<u8>,
}

/// Decrypted layer information
#[derive(Clone)]
pub struct OnionLayer {
    /// Next hop's public key (None if this is the exit layer)
    pub next_hop: Option<PublicKey>,

    /// The actual payload (only present at exit node)
    pub payload: Option<Vec<u8>>,

    /// Whether this is the final (exit) layer
    pub is_exit: bool,

    /// Circuit ID for this hop (for routing responses back)
    pub circuit_id: u32,
}

/// Internal structure for layer data before encryption
#[derive(Serialize, Deserialize)]
struct LayerData {
    /// Flag: 0 = relay, 1 = exit
    layer_type: u8,

    /// Circuit ID for response routing
    circuit_id: u32,

    /// Next hop's public key (for relay layers)
    next_hop_pubkey: Option<[u8; X25519_KEY_SIZE]>,

    /// Final payload (for exit layer)
    payload: Option<Vec<u8>>,

    /// The next encrypted layer (for relay)
    next_layer: Option<Vec<u8>>,
}

/// Builder for constructing onion packets
pub struct OnionBuilder {
    payload: Vec<u8>,
    circuit_ids: Vec<u32>,
}

impl OnionBuilder {
    /// Create a new onion builder
    pub fn new() -> Self {
        Self {
            payload: Vec::new(),
            circuit_ids: Vec::new(),
        }
    }

    /// Set the final payload to be delivered to the exit node
    pub fn set_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }

    /// Set circuit IDs for each hop (for response routing)
    pub fn set_circuit_ids(mut self, ids: Vec<u32>) -> Self {
        self.circuit_ids = ids;
        self
    }

    /// Build the onion packet for the given path
    ///
    /// Path should be ordered: [relay1, relay2, ..., exit_node]
    /// The packet will be encrypted in reverse order so relay1 can unwrap first.
    pub fn build_circuit(mut self, path: &[PublicKey]) -> CryptoResult<OnionPacket> {
        if path.is_empty() {
            return Err(CryptoError::EmptyCircuit);
        }

        if path.len() > MAX_ONION_LAYERS {
            return Err(CryptoError::TooManyLayers {
                max: MAX_ONION_LAYERS,
                actual: path.len(),
            });
        }

        if self.payload.len() > MAX_PAYLOAD_SIZE {
            return Err(CryptoError::MalformedOnionPacket(
                "Payload too large".into(),
            ));
        }

        // Generate circuit IDs if not provided
        if self.circuit_ids.is_empty() {
            self.circuit_ids = (0..path.len())
                .map(|_| rand::random::<u32>())
                .collect();
        }

        // Build layers from inside out (exit node first, then relays in reverse)
        let mut current_encrypted: Option<Vec<u8>> = None;

        // Process in reverse order
        for (i, pubkey) in path.iter().enumerate().rev() {
            let is_exit = i == path.len() - 1;
            let circuit_id = self.circuit_ids.get(i).copied().unwrap_or_else(rand::random);

            let layer_data = if is_exit {
                // Exit layer contains the actual payload
                LayerData {
                    layer_type: 1, // Exit
                    circuit_id,
                    next_hop_pubkey: None,
                    payload: Some(self.payload.clone()),
                    next_layer: None,
                }
            } else {
                // Relay layer contains next hop info and encrypted next layer
                let next_hop = path.get(i + 1).ok_or_else(|| {
                    CryptoError::MalformedOnionPacket("Missing next hop".into())
                })?;

                LayerData {
                    layer_type: 0, // Relay
                    circuit_id,
                    next_hop_pubkey: Some(next_hop.to_bytes()),
                    payload: None,
                    next_layer: current_encrypted.clone(),
                }
            };

            // Serialize layer data
            let layer_bytes = bincode::serialize(&layer_data)
                .map_err(|e| CryptoError::SerializationError(e.to_string()))?;

            // Encrypt for this hop
            let encrypted = encrypt_for_hop(pubkey, &layer_bytes)?;
            current_encrypted = Some(encrypted);
        }

        // Deserialize the final encrypted packet
        let final_bytes = current_encrypted.ok_or_else(|| {
            CryptoError::MalformedOnionPacket("Failed to build packet".into())
        })?;

        deserialize_onion_packet(&final_bytes)
    }
}

impl Default for OnionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl OnionPacket {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> CryptoResult<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        bincode::deserialize(bytes)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))
    }

    /// Unwrap one layer of the onion
    ///
    /// Returns the layer info and the next OnionPacket (if not exit)
    pub fn unwrap_layer(&self, secret_key: &SecretKey) -> CryptoResult<(OnionLayer, OnionPacket)> {
        // Reconstruct ephemeral public key
        let ephemeral_pubkey = PublicKey::from_bytes(self.ephemeral_pubkey);

        // Compute shared secret
        let shared_secret = secret_key.diffie_hellman(&ephemeral_pubkey);

        // Derive encryption key
        let sym_key = derive_layer_key(&shared_secret);
        let nonce = Nonce::from_bytes(self.nonce);

        // Decrypt the payload
        let decrypted = decrypt(&sym_key, &nonce, &self.encrypted_payload)?;

        // Deserialize layer data
        let layer_data: LayerData = bincode::deserialize(&decrypted)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))?;

        let is_exit = layer_data.layer_type == 1;

        let layer = OnionLayer {
            next_hop: layer_data.next_hop_pubkey.map(PublicKey::from_bytes),
            payload: layer_data.payload,
            is_exit,
            circuit_id: layer_data.circuit_id,
        };

        // If not exit, deserialize the next layer
        let next_packet = if let Some(next_bytes) = layer_data.next_layer {
            deserialize_onion_packet(&next_bytes)?
        } else {
            // Return a dummy packet for exit (won't be used)
            OnionPacket {
                ephemeral_pubkey: [0u8; X25519_KEY_SIZE],
                nonce: [0u8; NONCE_SIZE],
                encrypted_payload: Vec::new(),
            }
        };

        Ok((layer, next_packet))
    }

    /// Get the size of this packet
    pub fn size(&self) -> usize {
        X25519_KEY_SIZE + NONCE_SIZE + self.encrypted_payload.len()
    }
}

/// Unwrapper for processing onion packets as a relay/exit node
pub struct OnionUnwrapper {
    secret_key: SecretKey,
}

impl OnionUnwrapper {
    /// Create a new unwrapper with the node's secret key
    pub fn new(secret_key: SecretKey) -> Self {
        Self { secret_key }
    }

    /// Process an incoming onion packet
    pub fn process(&self, packet: &OnionPacket) -> CryptoResult<ProcessedOnion> {
        let (layer, next_packet) = packet.unwrap_layer(&self.secret_key)?;

        if layer.is_exit {
            Ok(ProcessedOnion::Exit {
                payload: layer.payload.unwrap_or_default(),
                circuit_id: layer.circuit_id,
            })
        } else {
            Ok(ProcessedOnion::Relay {
                next_hop: layer.next_hop.ok_or_else(|| {
                    CryptoError::MalformedOnionPacket("Missing next hop".into())
                })?,
                next_packet,
                circuit_id: layer.circuit_id,
            })
        }
    }
}

/// Result of processing an onion packet
pub enum ProcessedOnion {
    /// This is a relay layer - forward to next hop
    Relay {
        next_hop: PublicKey,
        next_packet: OnionPacket,
        circuit_id: u32,
    },

    /// This is the exit layer - process the payload
    Exit { payload: Vec<u8>, circuit_id: u32 },
}

// Helper functions

/// Encrypt data for a specific hop
fn encrypt_for_hop(pubkey: &PublicKey, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
    // Generate ephemeral keypair for this layer
    let ephemeral = EphemeralKeyPair::generate();
    let ephemeral_pubkey = ephemeral.public;

    // Compute shared secret
    let shared_secret = ephemeral.diffie_hellman(pubkey);

    // Derive symmetric key
    let sym_key = derive_layer_key(&shared_secret);

    // Generate random nonce
    let nonce = Nonce::generate();

    // Encrypt
    let ciphertext = encrypt(&sym_key, &nonce, plaintext)?;

    // Pack: [ephemeral_pubkey][nonce][ciphertext]
    let mut result = Vec::with_capacity(X25519_KEY_SIZE + NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(ephemeral_pubkey.as_bytes());
    result.extend_from_slice(nonce.as_bytes());
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Derive symmetric key from shared secret
fn derive_layer_key(shared: &SharedSecret) -> SymmetricKey {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hkdf = Hkdf::<Sha256>::new(Some(b"meshvpn-onion-layer"), shared.as_bytes());
    let mut key_bytes = [0u8; 32];
    hkdf.expand(b"layer-key", &mut key_bytes)
        .expect("HKDF expand failed");

    SymmetricKey::from_bytes(key_bytes)
}

/// Deserialize an onion packet from raw bytes
fn deserialize_onion_packet(bytes: &[u8]) -> CryptoResult<OnionPacket> {
    if bytes.len() < X25519_KEY_SIZE + NONCE_SIZE + AUTH_TAG_SIZE {
        return Err(CryptoError::MalformedOnionPacket("Packet too short".into()));
    }

    let mut ephemeral_pubkey = [0u8; X25519_KEY_SIZE];
    ephemeral_pubkey.copy_from_slice(&bytes[..X25519_KEY_SIZE]);

    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&bytes[X25519_KEY_SIZE..X25519_KEY_SIZE + NONCE_SIZE]);

    let encrypted_payload = bytes[X25519_KEY_SIZE + NONCE_SIZE..].to_vec();

    Ok(OnionPacket {
        ephemeral_pubkey,
        nonce,
        encrypted_payload,
    })
}

/// Create a response packet (for sending data back through the circuit)
pub struct ResponseBuilder {
    /// Symmetric keys for each hop (stored by client when building circuit)
    layer_keys: Vec<(SymmetricKey, [u8; NONCE_SIZE])>,
}

impl ResponseBuilder {
    /// Create with stored layer keys
    pub fn new(layer_keys: Vec<(SymmetricKey, [u8; NONCE_SIZE])>) -> Self {
        Self { layer_keys }
    }

    /// Encrypt response payload with all layer keys (for exit -> client)
    pub fn wrap_response(&self, payload: &[u8]) -> CryptoResult<Vec<u8>> {
        let mut data = payload.to_vec();

        // Encrypt in reverse order (from exit to client)
        for (i, (key, nonce_seed)) in self.layer_keys.iter().enumerate().rev() {
            let nonce = Nonce::from_counter(nonce_seed, i as u64);
            data = encrypt(key, &nonce, &data)?;
        }

        Ok(data)
    }

    /// Decrypt response payload (for client receiving from circuit)
    pub fn unwrap_response(&self, ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
        let mut data = ciphertext.to_vec();

        // Decrypt in forward order (from client to exit)
        for (i, (key, nonce_seed)) in self.layer_keys.iter().enumerate() {
            let nonce = Nonce::from_counter(nonce_seed, i as u64);
            data = decrypt(key, &nonce, &data)?;
        }

        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;

    #[test]
    fn test_single_hop_onion() {
        let exit = KeyPair::generate();
        let payload = b"Hello, Exit Node!";

        let onion = OnionBuilder::new()
            .set_payload(payload.to_vec())
            .build_circuit(&[exit.public])
            .expect("Failed to build onion");

        let (layer, _) = onion.unwrap_layer(&exit.secret).expect("Failed to unwrap");

        assert!(layer.is_exit);
        assert_eq!(layer.payload.as_ref().unwrap(), payload);
    }

    #[test]
    fn test_multi_hop_onion() {
        let relay1 = KeyPair::generate();
        let relay2 = KeyPair::generate();
        let relay3 = KeyPair::generate();
        let exit = KeyPair::generate();

        let payload = b"Secret message through 4 hops!";

        let path = vec![relay1.public, relay2.public, relay3.public, exit.public];

        let onion = OnionBuilder::new()
            .set_payload(payload.to_vec())
            .build_circuit(&path)
            .expect("Failed to build onion");

        // Relay 1 unwraps
        let (layer1, packet2) = onion.unwrap_layer(&relay1.secret).expect("Relay 1 failed");
        assert!(!layer1.is_exit);
        assert!(layer1.next_hop.is_some());
        assert_eq!(layer1.next_hop.unwrap(), relay2.public);

        // Relay 2 unwraps
        let (layer2, packet3) = packet2.unwrap_layer(&relay2.secret).expect("Relay 2 failed");
        assert!(!layer2.is_exit);
        assert_eq!(layer2.next_hop.unwrap(), relay3.public);

        // Relay 3 unwraps
        let (layer3, packet4) = packet3.unwrap_layer(&relay3.secret).expect("Relay 3 failed");
        assert!(!layer3.is_exit);
        assert_eq!(layer3.next_hop.unwrap(), exit.public);

        // Exit unwraps
        let (layer4, _) = packet4.unwrap_layer(&exit.secret).expect("Exit failed");
        assert!(layer4.is_exit);
        assert_eq!(layer4.payload.as_ref().unwrap(), payload);
    }

    #[test]
    fn test_wrong_key_fails() {
        let correct = KeyPair::generate();
        let wrong = KeyPair::generate();

        let onion = OnionBuilder::new()
            .set_payload(b"test".to_vec())
            .build_circuit(&[correct.public])
            .expect("Failed to build");

        let result = onion.unwrap_layer(&wrong.secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_max_hops() {
        let hops: Vec<KeyPair> = (0..MAX_ONION_LAYERS).map(|_| KeyPair::generate()).collect();
        let path: Vec<PublicKey> = hops.iter().map(|kp| kp.public).collect();

        let onion = OnionBuilder::new()
            .set_payload(b"max hops test".to_vec())
            .build_circuit(&path)
            .expect("Failed to build");

        // Unwrap all layers
        let mut current = onion;
        for (i, hop) in hops.iter().enumerate() {
            let (layer, next) = current.unwrap_layer(&hop.secret).expect("Unwrap failed");

            if i == hops.len() - 1 {
                assert!(layer.is_exit);
            } else {
                assert!(!layer.is_exit);
                current = next;
            }
        }
    }

    #[test]
    fn test_too_many_hops_rejected() {
        let hops: Vec<PublicKey> = (0..MAX_ONION_LAYERS + 1)
            .map(|_| KeyPair::generate().public)
            .collect();

        let result = OnionBuilder::new()
            .set_payload(b"test".to_vec())
            .build_circuit(&hops);

        assert!(matches!(result, Err(CryptoError::TooManyLayers { .. })));
    }

    #[test]
    fn test_empty_circuit_rejected() {
        let result = OnionBuilder::new()
            .set_payload(b"test".to_vec())
            .build_circuit(&[]);

        assert!(matches!(result, Err(CryptoError::EmptyCircuit)));
    }

    #[test]
    fn test_onion_unwrapper() {
        let relay = KeyPair::generate();
        let exit = KeyPair::generate();

        let onion = OnionBuilder::new()
            .set_payload(b"test".to_vec())
            .build_circuit(&[relay.public, exit.public])
            .expect("Failed to build");

        // Test relay unwrapper
        let relay_unwrapper = OnionUnwrapper::new(relay.secret);
        match relay_unwrapper.process(&onion).expect("Process failed") {
            ProcessedOnion::Relay { next_hop, .. } => {
                assert_eq!(next_hop, exit.public);
            }
            ProcessedOnion::Exit { .. } => panic!("Should be relay"),
        }
    }
}
