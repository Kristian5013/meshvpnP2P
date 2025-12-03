//! X25519 Key Exchange
//!
//! Provides Diffie-Hellman key exchange using Curve25519.
//! Used for establishing shared secrets between nodes in the circuit.

use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Deserialize, Serialize};

use crate::constants::{X25519_KEY_SIZE, SYMMETRIC_KEY_SIZE};
use crate::error::{CryptoError, CryptoResult};

/// A static X25519 secret key (for long-term node identity)
#[derive(ZeroizeOnDrop)]
pub struct SecretKey {
    inner: StaticSecret,
}

/// A X25519 public key
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicKey {
    bytes: [u8; X25519_KEY_SIZE],
}

/// A keypair containing both secret and public keys
pub struct KeyPair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

/// An ephemeral keypair for single-use key exchange
pub struct EphemeralKeyPair {
    secret: EphemeralSecret,
    pub public: PublicKey,
}

/// Shared secret derived from X25519 key exchange
#[derive(ZeroizeOnDrop)]
pub struct SharedSecret {
    bytes: [u8; SYMMETRIC_KEY_SIZE],
}

impl SecretKey {
    /// Generate a new random secret key
    pub fn generate() -> Self {
        Self {
            inner: StaticSecret::random_from_rng(OsRng),
        }
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; X25519_KEY_SIZE]) -> Self {
        Self {
            inner: StaticSecret::from(bytes),
        }
    }

    /// Perform Diffie-Hellman key exchange
    pub fn diffie_hellman(&self, their_public: &PublicKey) -> SharedSecret {
        let their_public = X25519Public::from(their_public.bytes);
        let shared = self.inner.diffie_hellman(&their_public);
        SharedSecret {
            bytes: shared.to_bytes(),
        }
    }

    /// Get the corresponding public key
    pub fn public_key(&self) -> PublicKey {
        let public = X25519Public::from(&self.inner);
        PublicKey {
            bytes: public.to_bytes(),
        }
    }

    /// Export raw bytes (use with caution!)
    pub fn to_bytes(&self) -> [u8; X25519_KEY_SIZE] {
        self.inner.to_bytes()
    }
}

impl Clone for SecretKey {
    fn clone(&self) -> Self {
        Self::from_bytes(self.to_bytes())
    }
}

impl PublicKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; X25519_KEY_SIZE]) -> Self {
        Self { bytes }
    }

    /// Try to create from a slice
    pub fn try_from_slice(slice: &[u8]) -> CryptoResult<Self> {
        if slice.len() != X25519_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: X25519_KEY_SIZE,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; X25519_KEY_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self { bytes })
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; X25519_KEY_SIZE] {
        &self.bytes
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; X25519_KEY_SIZE] {
        self.bytes
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({:?}...)", &self.bytes[..4])
    }
}

impl KeyPair {
    /// Generate a new random keypair
    pub fn generate() -> Self {
        let secret = SecretKey::generate();
        let public = secret.public_key();
        Self { secret, public }
    }

    /// Create from an existing secret key
    pub fn from_secret(secret: SecretKey) -> Self {
        let public = secret.public_key();
        Self { secret, public }
    }

    /// Create from raw secret bytes
    pub fn from_bytes(bytes: [u8; X25519_KEY_SIZE]) -> Self {
        let secret = SecretKey::from_bytes(bytes);
        Self::from_secret(secret)
    }
}

impl Clone for KeyPair {
    fn clone(&self) -> Self {
        Self {
            secret: self.secret.clone(),
            public: self.public,
        }
    }
}

impl EphemeralKeyPair {
    /// Generate a new ephemeral keypair (single use)
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = X25519Public::from(&secret);
        Self {
            secret,
            public: PublicKey {
                bytes: public.to_bytes(),
            },
        }
    }

    /// Perform Diffie-Hellman and consume the ephemeral secret
    pub fn diffie_hellman(self, their_public: &PublicKey) -> SharedSecret {
        let their_public = X25519Public::from(their_public.bytes);
        let shared = self.secret.diffie_hellman(&their_public);
        SharedSecret {
            bytes: shared.to_bytes(),
        }
    }
}

impl SharedSecret {
    /// Get the shared secret bytes
    pub fn as_bytes(&self) -> &[u8; SYMMETRIC_KEY_SIZE] {
        &self.bytes
    }

    /// Derive multiple keys from shared secret using HKDF
    pub fn derive_keys(&self, info: &[u8]) -> DerivedKeys {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hkdf = Hkdf::<Sha256>::new(None, &self.bytes);

        let mut forward_key = [0u8; SYMMETRIC_KEY_SIZE];
        let mut backward_key = [0u8; SYMMETRIC_KEY_SIZE];
        let mut nonce_seed = [0u8; 12];

        // Derive forward key
        let mut forward_info = info.to_vec();
        forward_info.extend_from_slice(b":forward");
        hkdf.expand(&forward_info, &mut forward_key)
            .expect("HKDF expand failed");

        // Derive backward key
        let mut backward_info = info.to_vec();
        backward_info.extend_from_slice(b":backward");
        hkdf.expand(&backward_info, &mut backward_key)
            .expect("HKDF expand failed");

        // Derive nonce seed
        let mut nonce_info = info.to_vec();
        nonce_info.extend_from_slice(b":nonce");
        hkdf.expand(&nonce_info, &mut nonce_seed)
            .expect("HKDF expand failed");

        DerivedKeys {
            forward_key,
            backward_key,
            nonce_seed,
        }
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; SYMMETRIC_KEY_SIZE]) -> Self {
        Self { bytes }
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; SYMMETRIC_KEY_SIZE] {
        self.bytes
    }
}

impl Clone for SharedSecret {
    fn clone(&self) -> Self {
        Self::from_bytes(self.to_bytes())
    }
}

/// Keys derived from a shared secret for bidirectional communication
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKeys {
    /// Key for encrypting messages going forward (toward exit)
    pub forward_key: [u8; SYMMETRIC_KEY_SIZE],
    /// Key for decrypting messages coming back
    pub backward_key: [u8; SYMMETRIC_KEY_SIZE],
    /// Seed for nonce generation
    pub nonce_seed: [u8; 12],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_exchange() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        let alice_shared = alice.secret.diffie_hellman(&bob.public);
        let bob_shared = bob.secret.diffie_hellman(&alice.public);

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_ephemeral_key_exchange() {
        let static_keypair = KeyPair::generate();
        let ephemeral = EphemeralKeyPair::generate();
        let ephemeral_public = ephemeral.public;

        // Ephemeral side computes shared secret
        let shared1 = ephemeral.diffie_hellman(&static_keypair.public);

        // Static side computes same shared secret
        let shared2 = static_keypair.secret.diffie_hellman(&ephemeral_public);

        assert_eq!(shared1.as_bytes(), shared2.as_bytes());
    }

    #[test]
    fn test_key_derivation() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        let shared = alice.secret.diffie_hellman(&bob.public);
        let keys = shared.derive_keys(b"meshvpn:circuit:1");

        // Keys should be different
        assert_ne!(keys.forward_key, keys.backward_key);
    }

    #[test]
    fn test_public_key_serialization() {
        let keypair = KeyPair::generate();
        let bytes = keypair.public.to_bytes();
        let restored = PublicKey::from_bytes(bytes);

        assert_eq!(keypair.public, restored);
    }
}
