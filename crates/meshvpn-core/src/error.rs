//! Core protocol errors

use thiserror::Error;

/// Core protocol errors
#[derive(Debug, Error)]
pub enum CoreError {
    /// Circuit error
    #[error("Circuit error: {0}")]
    CircuitError(String),

    /// Circuit not found
    #[error("Circuit not found: {0}")]
    CircuitNotFound(u32),

    /// Circuit already exists
    #[error("Circuit already exists: {0}")]
    CircuitExists(u32),

    /// No path available
    #[error("No path available to destination")]
    NoPathAvailable,

    /// Path too long
    #[error("Path too long: {length} hops (max: {max})")]
    PathTooLong { length: usize, max: usize },

    /// Handshake failed
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    /// Relay error
    #[error("Relay error: {0}")]
    RelayError(String),

    /// Invalid state transition
    #[error("Invalid state transition: {from:?} -> {to:?}")]
    InvalidStateTransition {
        from: String,
        to: String,
    },

    /// Timeout
    #[error("Operation timed out")]
    Timeout,

    /// Peer error
    #[error("Peer error: {0}")]
    PeerError(String),

    /// Protocol error
    #[error("Protocol error: {0}")]
    ProtocolError(String),

    /// Crypto error
    #[error("Crypto error: {0}")]
    CryptoError(#[from] meshvpn_crypto::CryptoError),

    /// Network error
    #[error("Network error: {0}")]
    NetworkError(#[from] meshvpn_network::NetworkError),
}

/// Result type for core operations
pub type CoreResult<T> = Result<T, CoreError>;
