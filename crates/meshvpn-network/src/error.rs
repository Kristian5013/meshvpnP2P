//! Network error types

use thiserror::Error;

/// Network layer errors
#[derive(Debug, Error)]
pub enum NetworkError {
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// TUN device error
    #[error("TUN device error: {0}")]
    TunError(String),

    /// UDP transport error
    #[error("UDP transport error: {0}")]
    TransportError(String),

    /// Connection error
    #[error("Connection error: {0}")]
    ConnectionError(String),

    /// NAT traversal failed
    #[error("NAT traversal failed: {0}")]
    NatTraversalFailed(String),

    /// Invalid packet
    #[error("Invalid packet: {0}")]
    InvalidPacket(String),

    /// Connection timeout
    #[error("Connection timeout: {0}")]
    TimeoutWithMessage(String),

    /// Protocol error
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Address already in use
    #[error("Address already in use: {0}")]
    AddressInUse(std::net::SocketAddr),

    /// Peer not found
    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    /// Buffer too small
    #[error("Buffer too small: need {needed}, got {actual}")]
    BufferTooSmall { needed: usize, actual: usize },

    /// Crypto error (from meshvpn-crypto)
    #[error("Crypto error: {0}")]
    CryptoError(#[from] meshvpn_crypto::CryptoError),

    /// Platform not supported
    #[error("Platform not supported for this operation")]
    PlatformNotSupported,

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// WireGuard protocol error
    #[error("WireGuard error: {0}")]
    WireGuardError(String),

    /// IO error (string form)
    #[error("IO error: {0}")]
    IoError(String),

    /// Already running
    #[error("Already running")]
    AlreadyRunning,

    /// Bind error
    #[error("Bind error: {0}")]
    BindError(String),

    /// Send error
    #[error("Send error: {0}")]
    SendError(String),

    /// Receive error
    #[error("Receive error: {0}")]
    ReceiveError(String),

    /// Not connected
    #[error("Not connected")]
    NotConnected,

    /// Connection failed
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// General timeout (without message)
    #[error("Operation timed out")]
    Timeout,
}

/// Result type for network operations
pub type NetworkResult<T> = Result<T, NetworkError>;
