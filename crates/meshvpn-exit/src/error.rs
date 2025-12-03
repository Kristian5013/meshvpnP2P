//! Exit node errors

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExitError {
    #[error("NAT error: {0}")]
    NatError(String),

    #[error("Logging error: {0}")]
    LoggingError(String),

    #[error("Sync error: {0}")]
    SyncError(String),

    #[error("Config error: {0}")]
    ConfigError(String),

    #[error("AWS error: {0}")]
    AwsError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Network: {0}")]
    Network(String),

    #[error("Invalid target: {0}")]
    InvalidTarget(String),

    #[error("DNS error: {0}")]
    DnsError(String),

    #[error("Timeout")]
    Timeout,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("MeshVPN network error: {0}")]
    MeshNetworkError(#[from] meshvpn_network::NetworkError),
}

pub type ExitResult<T> = Result<T, ExitError>;
