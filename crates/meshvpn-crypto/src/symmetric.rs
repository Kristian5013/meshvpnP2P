//! Symmetric Encryption (ChaCha20-Poly1305)
//!
//! Provides authenticated encryption using ChaCha20-Poly1305 AEAD.
//! Used for encrypting data within each onion layer.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce as ChaNonce,
};
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::constants::{AUTH_TAG_SIZE, NONCE_SIZE, SYMMETRIC_KEY_SIZE};
use crate::error::{CryptoError, CryptoResult};

/// A 256-bit symmetric key for ChaCha20-Poly1305
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey {
    bytes: [u8; SYMMETRIC_KEY_SIZE],
}

/// A 96-bit nonce for ChaCha20-Poly1305
#[derive(Clone, Copy)]
pub struct Nonce {
    bytes: [u8; NONCE_SIZE],
}

impl SymmetricKey {
    /// Create a key from raw bytes
    pub fn from_bytes(bytes: [u8; SYMMETRIC_KEY_SIZE]) -> Self {
        Self { bytes }
    }

    /// Try to create from a slice
    pub fn try_from_slice(slice: &[u8]) -> CryptoResult<Self> {
        if slice.len() != SYMMETRIC_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: SYMMETRIC_KEY_SIZE,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; SYMMETRIC_KEY_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self { bytes })
    }

    /// Generate a random key
    pub fn generate() -> Self {
        let mut bytes = [0u8; SYMMETRIC_KEY_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; SYMMETRIC_KEY_SIZE] {
        &self.bytes
    }
}

impl Nonce {
    /// Create a nonce from raw bytes
    pub fn from_bytes(bytes: [u8; NONCE_SIZE]) -> Self {
        Self { bytes }
    }

    /// Try to create from a slice
    pub fn try_from_slice(slice: &[u8]) -> CryptoResult<Self> {
        if slice.len() != NONCE_SIZE {
            return Err(CryptoError::InvalidNonceLength {
                expected: NONCE_SIZE,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; NONCE_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self { bytes })
    }

    /// Generate a random nonce
    pub fn generate() -> Self {
        let mut bytes = [0u8; NONCE_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Create a nonce from a counter value
    /// Useful for deterministic nonce generation in streams
    pub fn from_counter(seed: &[u8; NONCE_SIZE], counter: u64) -> Self {
        let mut bytes = *seed;
        // XOR counter into the last 8 bytes
        let counter_bytes = counter.to_le_bytes();
        for i in 0..8 {
            bytes[i + 4] ^= counter_bytes[i];
        }
        Self { bytes }
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; NONCE_SIZE] {
        &self.bytes
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; NONCE_SIZE] {
        self.bytes
    }
}

/// Encrypt plaintext using ChaCha20-Poly1305
///
/// Returns ciphertext with authentication tag appended (16 bytes longer than input)
pub fn encrypt(key: &SymmetricKey, nonce: &Nonce, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(&key.bytes)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let cha_nonce = ChaNonce::from_slice(&nonce.bytes);

    cipher
        .encrypt(cha_nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed("ChaCha20-Poly1305 encryption failed".into()))
}

/// Encrypt with additional authenticated data (AAD)
pub fn encrypt_with_aad(
    key: &SymmetricKey,
    nonce: &Nonce,
    plaintext: &[u8],
    aad: &[u8],
) -> CryptoResult<Vec<u8>> {
    use chacha20poly1305::aead::Payload;

    let cipher = ChaCha20Poly1305::new_from_slice(&key.bytes)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let cha_nonce = ChaNonce::from_slice(&nonce.bytes);
    let payload = Payload { msg: plaintext, aad };

    cipher
        .encrypt(cha_nonce, payload)
        .map_err(|_| CryptoError::EncryptionFailed("ChaCha20-Poly1305 encryption failed".into()))
}

/// Decrypt ciphertext using ChaCha20-Poly1305
///
/// Input should include the 16-byte authentication tag at the end
pub fn decrypt(key: &SymmetricKey, nonce: &Nonce, ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
    if ciphertext.len() < AUTH_TAG_SIZE {
        return Err(CryptoError::DecryptionFailed);
    }

    let cipher = ChaCha20Poly1305::new_from_slice(&key.bytes)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    let cha_nonce = ChaNonce::from_slice(&nonce.bytes);

    cipher
        .decrypt(cha_nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Decrypt with additional authenticated data (AAD)
pub fn decrypt_with_aad(
    key: &SymmetricKey,
    nonce: &Nonce,
    ciphertext: &[u8],
    aad: &[u8],
) -> CryptoResult<Vec<u8>> {
    use chacha20poly1305::aead::Payload;

    if ciphertext.len() < AUTH_TAG_SIZE {
        return Err(CryptoError::DecryptionFailed);
    }

    let cipher = ChaCha20Poly1305::new_from_slice(&key.bytes)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    let cha_nonce = ChaNonce::from_slice(&nonce.bytes);
    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    cipher
        .decrypt(cha_nonce, payload)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Stream cipher for encrypting large amounts of data
pub struct EncryptionStream {
    key: SymmetricKey,
    nonce_seed: [u8; NONCE_SIZE],
    counter: u64,
}

impl EncryptionStream {
    /// Create a new encryption stream
    pub fn new(key: SymmetricKey, nonce_seed: [u8; NONCE_SIZE]) -> Self {
        Self {
            key,
            nonce_seed,
            counter: 0,
        }
    }

    /// Encrypt the next chunk of data
    pub fn encrypt_chunk(&mut self, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        let nonce = Nonce::from_counter(&self.nonce_seed, self.counter);
        self.counter += 1;
        encrypt(&self.key, &nonce, plaintext)
    }

    /// Get current counter value
    pub fn counter(&self) -> u64 {
        self.counter
    }
}

/// Stream decryption counterpart
pub struct DecryptionStream {
    key: SymmetricKey,
    nonce_seed: [u8; NONCE_SIZE],
    counter: u64,
}

impl DecryptionStream {
    /// Create a new decryption stream
    pub fn new(key: SymmetricKey, nonce_seed: [u8; NONCE_SIZE]) -> Self {
        Self {
            key,
            nonce_seed,
            counter: 0,
        }
    }

    /// Decrypt the next chunk of data
    pub fn decrypt_chunk(&mut self, ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
        let nonce = Nonce::from_counter(&self.nonce_seed, self.counter);
        self.counter += 1;
        decrypt(&self.key, &nonce, ciphertext)
    }

    /// Get current counter value
    pub fn counter(&self) -> u64 {
        self.counter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = SymmetricKey::generate();
        let nonce = Nonce::generate();
        let plaintext = b"Hello, MeshVPN!";

        let ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        assert_ne!(ciphertext.as_slice(), plaintext);
        assert_eq!(ciphertext.len(), plaintext.len() + AUTH_TAG_SIZE);

        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_with_aad() {
        let key = SymmetricKey::generate();
        let nonce = Nonce::generate();
        let plaintext = b"Secret data";
        let aad = b"circuit_id:12345";

        let ciphertext = encrypt_with_aad(&key, &nonce, plaintext, aad).unwrap();
        let decrypted = decrypt_with_aad(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);

        // Wrong AAD should fail
        let wrong_aad = b"circuit_id:99999";
        let result = decrypt_with_aad(&key, &nonce, &ciphertext, wrong_aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = SymmetricKey::generate();
        let key2 = SymmetricKey::generate();
        let nonce = Nonce::generate();
        let plaintext = b"Test message";

        let ciphertext = encrypt(&key1, &nonce, plaintext).unwrap();
        let result = decrypt(&key2, &nonce, &ciphertext);

        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = SymmetricKey::generate();
        let nonce = Nonce::generate();
        let plaintext = b"Test message";

        let mut ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        ciphertext[0] ^= 0xFF; // Flip bits

        let result = decrypt(&key, &nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_encryption_stream() {
        let key = SymmetricKey::generate();
        let nonce_seed = Nonce::generate().to_bytes();

        let mut enc_stream = EncryptionStream::new(key.clone(), nonce_seed);
        let mut dec_stream = DecryptionStream::new(key, nonce_seed);

        for i in 0..10 {
            let plaintext = format!("Message {}", i);
            let ciphertext = enc_stream.encrypt_chunk(plaintext.as_bytes()).unwrap();
            let decrypted = dec_stream.decrypt_chunk(&ciphertext).unwrap();
            assert_eq!(decrypted, plaintext.as_bytes());
        }
    }

    #[test]
    fn test_nonce_from_counter() {
        let seed = [0u8; NONCE_SIZE];

        let nonce1 = Nonce::from_counter(&seed, 0);
        let nonce2 = Nonce::from_counter(&seed, 1);
        let nonce3 = Nonce::from_counter(&seed, 2);

        // All nonces should be different
        assert_ne!(nonce1.as_bytes(), nonce2.as_bytes());
        assert_ne!(nonce2.as_bytes(), nonce3.as_bytes());
        assert_ne!(nonce1.as_bytes(), nonce3.as_bytes());
    }
}
