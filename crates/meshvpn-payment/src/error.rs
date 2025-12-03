//! Payment error types

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PaymentError {
    #[error("Payment not found")]
    PaymentNotFound,

    #[error("Transaction not found")]
    TransactionNotFound,

    #[error("Insufficient confirmations: {current}/{required}")]
    InsufficientConfirmations { current: u64, required: u64 },

    #[error("Invalid amount: expected {expected}, got {actual}")]
    InvalidAmount { expected: u64, actual: u64 },

    #[error("Token expired")]
    TokenExpired,

    #[error("Invalid token signature")]
    InvalidSignature,

    #[error("Invalid token format")]
    InvalidToken,

    #[error("Blockchain API error: {0}")]
    ApiError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Crypto error: {0}")]
    CryptoError(#[from] meshvpn_crypto::CryptoError),
}

pub type PaymentResult<T> = Result<T, PaymentError>;
