//! MeshVPN Payment Verification
//!
//! Provides cryptocurrency payment verification for subscriptions.
//! Supports Monero (XMR) and potentially other privacy coins.
//!
//! The system works without a centralized server:
//! 1. User generates a unique payment address (subaddress)
//! 2. User sends payment to the address
//! 3. Payment verifier watches blockchain (view key only)
//! 4. After confirmations, issues a signed subscription token
//! 5. Token can be verified by any node (Ed25519 signature)

pub mod token;
pub mod monero;
pub mod verifier;
pub mod error;

pub use token::{SubscriptionToken, SubscriptionTier, TokenClaims};
pub use verifier::{PaymentVerifier, PaymentStatus};
pub use error::{PaymentError, PaymentResult};

/// Minimum confirmations for payment
pub const MIN_CONFIRMATIONS: u64 = 10;

/// Token validity period (30 days)
pub const TOKEN_VALIDITY_DAYS: i64 = 30;
