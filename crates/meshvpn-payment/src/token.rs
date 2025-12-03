//! Subscription tokens

use chrono::{Duration, Utc};
use meshvpn_crypto::{NodeIdentity, PublicKey};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::error::{PaymentError, PaymentResult};

/// Subscription tier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubscriptionTier {
    /// Free tier with daily limits
    Free,
    /// Basic paid tier
    Basic,
    /// Premium unlimited tier
    Premium,
}

impl SubscriptionTier {
    /// Get daily bandwidth limit in bytes (0 = unlimited)
    pub fn daily_limit(&self) -> u64 {
        match self {
            Self::Free => 500 * 1024 * 1024,      // 500 MB
            Self::Basic => 10 * 1024 * 1024 * 1024, // 10 GB
            Self::Premium => 0,                     // Unlimited
        }
    }

    /// Get price in atomic units (piconero for XMR)
    pub fn price_atomic(&self) -> u64 {
        match self {
            Self::Free => 0,
            Self::Basic => 5_000_000_000_000,    // 0.005 XMR
            Self::Premium => 20_000_000_000_000, // 0.02 XMR
        }
    }
}

/// Token claims (the signed payload)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    /// User's public key (NOT linked to payment address)
    pub user_pubkey: [u8; 32],
    /// Subscription tier
    pub tier: SubscriptionTier,
    /// Valid from timestamp
    pub valid_from: i64,
    /// Valid until timestamp
    pub valid_until: i64,
    /// Unique token ID (prevents replay)
    pub token_id: [u8; 16],
}

impl TokenClaims {
    /// Create new claims
    pub fn new(user_pubkey: PublicKey, tier: SubscriptionTier, validity_days: i64) -> Self {
        let now = Utc::now();
        let valid_until = now + Duration::days(validity_days);

        let mut token_id = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut token_id);

        Self {
            user_pubkey: user_pubkey.to_bytes(),
            tier,
            valid_from: now.timestamp(),
            valid_until: valid_until.timestamp(),
            token_id,
        }
    }

    /// Serialize to bytes for signing
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    /// Check if token is currently valid
    pub fn is_valid(&self) -> bool {
        let now = Utc::now().timestamp();
        now >= self.valid_from && now < self.valid_until
    }

    /// Get remaining validity duration
    pub fn remaining_validity(&self) -> Option<Duration> {
        let now = Utc::now().timestamp();
        if now < self.valid_until {
            Some(Duration::seconds(self.valid_until - now))
        } else {
            None
        }
    }
}

/// A signed subscription token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionToken {
    /// Token claims
    pub claims: TokenClaims,
    /// Signature over claims (Ed25519)
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

impl SubscriptionToken {
    /// Create and sign a new token
    pub fn create(
        user_pubkey: PublicKey,
        tier: SubscriptionTier,
        validity_days: i64,
        issuer: &NodeIdentity,
    ) -> Self {
        let claims = TokenClaims::new(user_pubkey, tier, validity_days);
        let signature = issuer.sign(&claims.to_bytes());

        Self {
            claims,
            signature: *signature.as_bytes(),
        }
    }

    /// Verify the token signature
    pub fn verify(&self, issuer_pubkey: &[u8; 32]) -> PaymentResult<()> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let verifying_key = VerifyingKey::from_bytes(issuer_pubkey)
            .map_err(|_| PaymentError::InvalidSignature)?;

        let signature = Signature::from_bytes(&self.signature);

        verifying_key
            .verify(&self.claims.to_bytes(), &signature)
            .map_err(|_| PaymentError::InvalidSignature)
    }

    /// Full validation (signature + expiry)
    pub fn validate(&self, issuer_pubkey: &[u8; 32]) -> PaymentResult<()> {
        self.verify(issuer_pubkey)?;

        if !self.claims.is_valid() {
            return Err(PaymentError::TokenExpired);
        }

        Ok(())
    }

    /// Serialize to base64 string
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        let bytes = bincode::serialize(self).unwrap();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes)
    }

    /// Deserialize from base64 string
    pub fn from_base64(s: &str) -> PaymentResult<Self> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|_| PaymentError::InvalidToken)?;

        bincode::deserialize(&bytes).map_err(|_| PaymentError::InvalidToken)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_creation_and_verification() {
        let issuer = NodeIdentity::generate();
        let user_pubkey = PublicKey::from_bytes([1u8; 32]);

        let token = SubscriptionToken::create(
            user_pubkey,
            SubscriptionTier::Basic,
            30,
            &issuer,
        );

        // Should verify with correct issuer
        let issuer_pubkey = issuer.verifying_key().to_bytes();
        assert!(token.verify(&issuer_pubkey).is_ok());
        assert!(token.validate(&issuer_pubkey).is_ok());

        // Should fail with wrong issuer
        let wrong_pubkey = [0u8; 32];
        assert!(token.verify(&wrong_pubkey).is_err());
    }

    #[test]
    fn test_token_serialization() {
        let issuer = NodeIdentity::generate();
        let user_pubkey = PublicKey::from_bytes([1u8; 32]);

        let token = SubscriptionToken::create(
            user_pubkey,
            SubscriptionTier::Premium,
            30,
            &issuer,
        );

        let base64 = token.to_base64();
        let restored = SubscriptionToken::from_base64(&base64).unwrap();

        assert_eq!(token.claims.tier, restored.claims.tier);
        assert_eq!(token.signature, restored.signature);
    }
}
