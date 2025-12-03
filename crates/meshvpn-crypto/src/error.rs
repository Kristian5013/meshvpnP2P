//! Cryptographic error types

use thiserror::Error;

/// Errors that can occur during cryptographic operations
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Invalid key length provided
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    /// Invalid nonce length
    #[error("Invalid nonce length: expected {expected}, got {actual}")]
    InvalidNonceLength { expected: usize, actual: usize },

    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption failed (authentication failed or corrupted data)
    #[error("Decryption failed: authentication or integrity check failed")]
    DecryptionFailed,

    /// Signature verification failed
    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    /// Invalid signature format
    #[error("Invalid signature format")]
    InvalidSignature,

    /// Key derivation failed
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// Invalid public key
    #[error("Invalid public key")]
    InvalidPublicKey,

    /// Onion packet is malformed
    #[error("Malformed onion packet: {0}")]
    MalformedOnionPacket(String),

    /// Too many onion layers
    #[error("Too many onion layers: maximum is {max}, got {actual}")]
    TooManyLayers { max: usize, actual: usize },

    /// No hops specified for circuit
    #[error("Circuit must have at least one hop")]
    EmptyCircuit,

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Random number generation failed
    #[error("Random number generation failed")]
    RngError,
}

/// Result type for cryptographic operations
pub type CryptoResult<T> = Result<T, CryptoError>;
