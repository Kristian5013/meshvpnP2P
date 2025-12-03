//! DHT error types

use thiserror::Error;

/// DHT errors
#[derive(Debug, Error)]
pub enum DhtError {
    /// Node not found
    #[error("Node not found: {0}")]
    NodeNotFound(String),

    /// Value not found
    #[error("Value not found for key")]
    ValueNotFound,

    /// Bucket full
    #[error("Bucket is full")]
    BucketFull,

    /// Invalid message
    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    /// Timeout
    #[error("Request timed out")]
    Timeout,

    /// Network error
    #[error("Network error: {0}")]
    NetworkError(#[from] meshvpn_network::NetworkError),

    /// Crypto error
    #[error("Crypto error: {0}")]
    CryptoError(#[from] meshvpn_crypto::CryptoError),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Bootstrap failed
    #[error("Bootstrap failed: {0}")]
    BootstrapFailed(String),

    /// Too many requests
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
}

/// Result type for DHT operations
pub type DhtResult<T> = Result<T, DhtError>;
