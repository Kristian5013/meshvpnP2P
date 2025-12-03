//! Cryptographic Handshake Protocol
//!
//! Implements the handshake protocol for establishing encrypted
//! connections between nodes. Based on Noise Protocol Framework
//! patterns with X25519-ChaCha20-BLAKE3.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use meshvpn_crypto::prelude::*;
use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};

/// Handshake state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Initial state
    Initial,
    /// Waiting for response (initiator)
    WaitingForResponse,
    /// Received initiation, sending response (responder)
    Responding,
    /// Handshake complete
    Complete,
    /// Handshake failed
    Failed,
}

/// Handshake initiation message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeInit {
    /// Protocol version
    pub version: u8,
    /// Initiator's ephemeral public key
    pub ephemeral_pubkey: [u8; 32],
    /// Timestamp (for replay protection)
    pub timestamp: u64,
    /// Random nonce
    pub nonce: [u8; 16],
    /// Encrypted static public key (under ephemeral shared secret)
    pub encrypted_static: Vec<u8>,
    /// MAC over the message
    pub mac: [u8; 16],
}

/// Handshake response message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResponse {
    /// Responder's ephemeral public key
    pub ephemeral_pubkey: [u8; 32],
    /// Encrypted payload (confirmation + optional data)
    pub encrypted_payload: Vec<u8>,
    /// MAC over the message
    pub mac: [u8; 16],
}

/// Session keys derived from handshake
#[derive(Clone)]
pub struct SessionKeys {
    /// Key for sending (initiator -> responder)
    pub send_key: SymmetricKey,
    /// Key for receiving (responder -> initiator)
    pub recv_key: SymmetricKey,
    /// Nonce seed for forward direction
    pub send_nonce_seed: [u8; 12],
    /// Nonce seed for backward direction
    pub recv_nonce_seed: [u8; 12],
}

/// Handshake as initiator
pub struct InitiatorHandshake {
    /// Our identity
    identity: NodeIdentity,
    /// Our ephemeral keypair
    ephemeral: KeyPair,
    /// Target node's static public key
    target_pubkey: PublicKey,
    /// Current state
    state: HandshakeState,
    /// Shared secret (computed after receiving response)
    shared_secret: Option<SharedSecret>,
    /// Timestamp used in initiation
    timestamp: u64,
}

impl InitiatorHandshake {
    /// Start a new handshake with target node
    pub fn new(identity: NodeIdentity, target_pubkey: PublicKey) -> Self {
        Self {
            identity,
            ephemeral: KeyPair::generate(),
            target_pubkey,
            state: HandshakeState::Initial,
            shared_secret: None,
            timestamp: current_timestamp(),
        }
    }

    /// Create the initiation message
    pub fn create_init(&mut self) -> CoreResult<HandshakeInit> {
        if self.state != HandshakeState::Initial {
            return Err(CoreError::InvalidStateTransition {
                from: format!("{:?}", self.state),
                to: "creating init".to_string(),
            });
        }

        // Generate random nonce
        let mut nonce = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);

        // Compute shared secret with target's static key
        let static_shared = self.ephemeral.secret.diffie_hellman(&self.target_pubkey);

        // Derive key for encrypting our static public key
        let derived = static_shared.derive_keys(b"meshvpn:handshake:init");
        let encrypt_key = SymmetricKey::from_bytes(derived.forward_key);
        let nonce_12: [u8; 12] = nonce[..12].try_into().unwrap();

        // Encrypt our static public key
        let static_pubkey = self.identity.verifying_key().to_bytes();
        let encrypted_static = meshvpn_crypto::encrypt(
            &encrypt_key,
            &Nonce::from_bytes(nonce_12),
            &static_pubkey,
        )?;

        // Compute MAC
        let mac = compute_mac(
            &derived.backward_key,
            &[
                &[super::PROTOCOL_VERSION],
                self.ephemeral.public.as_bytes(),
                &self.timestamp.to_le_bytes(),
                &nonce,
                &encrypted_static,
            ],
        );

        self.state = HandshakeState::WaitingForResponse;

        Ok(HandshakeInit {
            version: super::PROTOCOL_VERSION,
            ephemeral_pubkey: self.ephemeral.public.to_bytes(),
            timestamp: self.timestamp,
            nonce,
            encrypted_static,
            mac,
        })
    }

    /// Process the response and derive session keys
    pub fn process_response(&mut self, response: HandshakeResponse) -> CoreResult<SessionKeys> {
        if self.state != HandshakeState::WaitingForResponse {
            return Err(CoreError::InvalidStateTransition {
                from: format!("{:?}", self.state),
                to: "processing response".to_string(),
            });
        }

        // Compute shared secret with responder's ephemeral key
        let responder_ephemeral = PublicKey::from_bytes(response.ephemeral_pubkey);
        let ephemeral_shared = self.ephemeral.secret.diffie_hellman(&responder_ephemeral);

        // Also use static-static shared secret for key derivation
        // This provides identity hiding and forward secrecy
        let static_shared = self.identity.encryption_keypair().secret
            .diffie_hellman(&self.target_pubkey);

        // Combine shared secrets using HKDF
        let combined = combine_secrets(&ephemeral_shared, &static_shared);

        // Derive session keys
        let session_keys = derive_session_keys(&combined, true)?;

        // Verify MAC
        let expected_mac = compute_mac(
            session_keys.recv_key.as_bytes(),
            &[
                &response.ephemeral_pubkey,
                &response.encrypted_payload,
            ],
        );
        if expected_mac != response.mac {
            self.state = HandshakeState::Failed;
            return Err(CoreError::HandshakeFailed("MAC verification failed".into()));
        }

        // Decrypt and verify payload (optional)
        let _payload = meshvpn_crypto::decrypt(
            &session_keys.recv_key,
            &Nonce::from_bytes(session_keys.recv_nonce_seed),
            &response.encrypted_payload,
        )?;

        self.state = HandshakeState::Complete;
        self.shared_secret = Some(combined);

        Ok(session_keys)
    }

    /// Get current state
    pub fn state(&self) -> HandshakeState {
        self.state
    }
}

impl Clone for InitiatorHandshake {
    fn clone(&self) -> Self {
        Self {
            identity: self.identity.clone(),
            ephemeral: self.ephemeral.clone(),
            target_pubkey: self.target_pubkey,
            state: self.state,
            shared_secret: self.shared_secret.clone(),
            timestamp: self.timestamp,
        }
    }
}

/// Handshake as responder
pub struct ResponderHandshake {
    /// Our identity
    identity: NodeIdentity,
    /// Initiator's ephemeral public key
    initiator_ephemeral: Option<PublicKey>,
    /// Initiator's static public key (after decryption)
    initiator_static: Option<PublicKey>,
    /// Our ephemeral keypair
    ephemeral: KeyPair,
    /// Current state
    state: HandshakeState,
}

impl ResponderHandshake {
    /// Create a new responder handshake
    pub fn new(identity: NodeIdentity) -> Self {
        Self {
            identity,
            initiator_ephemeral: None,
            initiator_static: None,
            ephemeral: KeyPair::generate(),
            state: HandshakeState::Initial,
        }
    }

    /// Process the initiation message
    pub fn process_init(&mut self, init: HandshakeInit) -> CoreResult<()> {
        if self.state != HandshakeState::Initial {
            return Err(CoreError::InvalidStateTransition {
                from: format!("{:?}", self.state),
                to: "processing init".to_string(),
            });
        }

        // Version check
        if init.version != super::PROTOCOL_VERSION {
            return Err(CoreError::ProtocolError(format!(
                "Version mismatch: expected {}, got {}",
                super::PROTOCOL_VERSION,
                init.version
            )));
        }

        // Timestamp check (prevent replay)
        let now = current_timestamp();
        if init.timestamp > now + 60 || init.timestamp < now.saturating_sub(120) {
            return Err(CoreError::HandshakeFailed("Timestamp out of range".into()));
        }

        // Compute shared secret with initiator's ephemeral key
        let initiator_ephemeral = PublicKey::from_bytes(init.ephemeral_pubkey);
        let static_shared = self.identity.encryption_keypair().secret
            .diffie_hellman(&initiator_ephemeral);

        // Derive decryption key
        let derived = static_shared.derive_keys(b"meshvpn:handshake:init");
        let decrypt_key = SymmetricKey::from_bytes(derived.forward_key);
        let nonce_12: [u8; 12] = init.nonce[..12].try_into().unwrap();

        // Verify MAC
        let expected_mac = compute_mac(
            &derived.backward_key,
            &[
                &[init.version],
                &init.ephemeral_pubkey,
                &init.timestamp.to_le_bytes(),
                &init.nonce,
                &init.encrypted_static,
            ],
        );
        if expected_mac != init.mac {
            self.state = HandshakeState::Failed;
            return Err(CoreError::HandshakeFailed("MAC verification failed".into()));
        }

        // Decrypt initiator's static public key
        let static_bytes = meshvpn_crypto::decrypt(
            &decrypt_key,
            &Nonce::from_bytes(nonce_12),
            &init.encrypted_static,
        )?;

        if static_bytes.len() != 32 {
            return Err(CoreError::HandshakeFailed("Invalid static key length".into()));
        }

        let mut static_key = [0u8; 32];
        static_key.copy_from_slice(&static_bytes);

        self.initiator_ephemeral = Some(initiator_ephemeral);
        self.initiator_static = Some(PublicKey::from_bytes(static_key));
        self.state = HandshakeState::Responding;

        Ok(())
    }

    /// Create the response message
    pub fn create_response(&mut self) -> CoreResult<(HandshakeResponse, SessionKeys)> {
        if self.state != HandshakeState::Responding {
            return Err(CoreError::InvalidStateTransition {
                from: format!("{:?}", self.state),
                to: "creating response".to_string(),
            });
        }

        let initiator_ephemeral = self.initiator_ephemeral
            .ok_or_else(|| CoreError::HandshakeFailed("Missing initiator ephemeral".into()))?;
        let initiator_static = self.initiator_static
            .ok_or_else(|| CoreError::HandshakeFailed("Missing initiator static".into()))?;

        // Compute shared secrets
        let ephemeral_shared = self.ephemeral.secret.diffie_hellman(&initiator_ephemeral);
        let static_shared = self.identity.encryption_keypair().secret
            .diffie_hellman(&initiator_static);

        // Combine shared secrets
        let combined = combine_secrets(&ephemeral_shared, &static_shared);

        // Derive session keys (from responder's perspective)
        let session_keys = derive_session_keys(&combined, false)?;

        // Create encrypted payload (confirmation)
        let confirmation = b"meshvpn:confirmed";
        let encrypted_payload = meshvpn_crypto::encrypt(
            &session_keys.send_key,
            &Nonce::from_bytes(session_keys.send_nonce_seed),
            confirmation,
        )?;

        // Compute MAC
        let mac = compute_mac(
            session_keys.send_key.as_bytes(),
            &[
                self.ephemeral.public.as_bytes(),
                &encrypted_payload,
            ],
        );

        self.state = HandshakeState::Complete;

        let response = HandshakeResponse {
            ephemeral_pubkey: self.ephemeral.public.to_bytes(),
            encrypted_payload,
            mac,
        };

        Ok((response, session_keys))
    }

    /// Get current state
    pub fn state(&self) -> HandshakeState {
        self.state
    }

    /// Get initiator's static public key (after processing init)
    pub fn initiator_pubkey(&self) -> Option<&PublicKey> {
        self.initiator_static.as_ref()
    }
}

impl Clone for ResponderHandshake {
    fn clone(&self) -> Self {
        Self {
            identity: self.identity.clone(),
            initiator_ephemeral: self.initiator_ephemeral,
            initiator_static: self.initiator_static,
            ephemeral: self.ephemeral.clone(),
            state: self.state,
        }
    }
}

/// Combine two shared secrets using HKDF
fn combine_secrets(secret1: &SharedSecret, secret2: &SharedSecret) -> SharedSecret {
    use hkdf::Hkdf;
    use sha2::Sha256;

    // Concatenate secrets
    let mut combined_input = [0u8; 64];
    combined_input[..32].copy_from_slice(secret1.as_bytes());
    combined_input[32..].copy_from_slice(secret2.as_bytes());

    // Derive new secret
    let hkdf = Hkdf::<Sha256>::new(Some(b"meshvpn:combine"), &combined_input);
    let mut output = [0u8; 32];
    hkdf.expand(b"combined-secret", &mut output).expect("HKDF expand failed");

    SharedSecret::from_bytes(output)
}

/// Derive session keys from shared secret
fn derive_session_keys(shared: &SharedSecret, is_initiator: bool) -> CoreResult<SessionKeys> {
    let keys = shared.derive_keys(b"meshvpn:session");

    // Initiator sends with forward_key, responder sends with backward_key
    let (send_key, recv_key, send_nonce, recv_nonce) = if is_initiator {
        (
            keys.forward_key,
            keys.backward_key,
            keys.nonce_seed,
            derive_second_nonce(&keys.nonce_seed),
        )
    } else {
        (
            keys.backward_key,
            keys.forward_key,
            derive_second_nonce(&keys.nonce_seed),
            keys.nonce_seed,
        )
    };

    Ok(SessionKeys {
        send_key: SymmetricKey::from_bytes(send_key),
        recv_key: SymmetricKey::from_bytes(recv_key),
        send_nonce_seed: send_nonce,
        recv_nonce_seed: recv_nonce,
    })
}

/// Derive second nonce seed
fn derive_second_nonce(seed: &[u8; 12]) -> [u8; 12] {
    let hash = blake3::hash(seed);
    let mut result = [0u8; 12];
    result.copy_from_slice(&hash.as_bytes()[..12]);
    result
}

/// Compute MAC using BLAKE3
fn compute_mac(key: &[u8], data_parts: &[&[u8]]) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new_keyed(&pad_key(key));
    for part in data_parts {
        hasher.update(part);
    }
    let hash = hasher.finalize();
    let mut mac = [0u8; 16];
    mac.copy_from_slice(&hash.as_bytes()[..16]);
    mac
}

/// Pad key to 32 bytes for BLAKE3 keyed hashing
fn pad_key(key: &[u8]) -> [u8; 32] {
    let mut padded = [0u8; 32];
    let len = key.len().min(32);
    padded[..len].copy_from_slice(&key[..len]);
    padded
}

/// Get current timestamp
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Handshake wrapper for both roles
pub enum Handshake {
    Initiator(InitiatorHandshake),
    Responder(ResponderHandshake),
}

impl Handshake {
    /// Create as initiator
    pub fn initiator(identity: NodeIdentity, target: PublicKey) -> Self {
        Self::Initiator(InitiatorHandshake::new(identity, target))
    }

    /// Create as responder
    pub fn responder(identity: NodeIdentity) -> Self {
        Self::Responder(ResponderHandshake::new(identity))
    }

    /// Get current state
    pub fn state(&self) -> HandshakeState {
        match self {
            Self::Initiator(h) => h.state(),
            Self::Responder(h) => h.state(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_handshake() {
        // Create identities
        let alice_id = NodeIdentity::generate();
        let bob_id = NodeIdentity::generate();

        // Alice initiates
        let mut alice = InitiatorHandshake::new(alice_id.clone(), bob_id.public_key());
        let init = alice.create_init().unwrap();

        // Bob responds
        let mut bob = ResponderHandshake::new(bob_id);
        bob.process_init(init).unwrap();
        let (response, bob_keys) = bob.create_response().unwrap();

        // Alice processes response
        let alice_keys = alice.process_response(response).unwrap();

        // Both should be complete
        assert_eq!(alice.state(), HandshakeState::Complete);
        assert_eq!(bob.state(), HandshakeState::Complete);

        // Test that keys work (Alice sends to Bob)
        let message = b"Hello, Bob!";
        let nonce = Nonce::from_counter(&alice_keys.send_nonce_seed, 0);
        let ciphertext = meshvpn_crypto::encrypt(&alice_keys.send_key, &nonce, message).unwrap();

        let nonce = Nonce::from_counter(&bob_keys.recv_nonce_seed, 0);
        let decrypted = meshvpn_crypto::decrypt(&bob_keys.recv_key, &nonce, &ciphertext).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_replay_protection() {
        let alice_id = NodeIdentity::generate();
        let bob_id = NodeIdentity::generate();

        // Create an init with old timestamp
        let mut alice = InitiatorHandshake::new(alice_id, bob_id.public_key());
        alice.timestamp = current_timestamp() - 300; // 5 minutes ago

        let init = alice.create_init().unwrap();

        // Bob should reject
        let mut bob = ResponderHandshake::new(bob_id);
        let result = bob.process_init(init);
        assert!(result.is_err());
    }
}
