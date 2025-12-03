//! Payment verification service
//!
//! Manages payment requests and verifies payments using real Monero blockchain.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use meshvpn_crypto::{NodeIdentity, PublicKey};

use crate::error::{PaymentError, PaymentResult};
use crate::monero::{
    MoneroNetwork, MoneroPaymentChecker, MoneroWalletRpc, MoneroDaemonRpc,
    SubaddressInfo, PaymentInfo as MoneroPaymentInfo,
};
use crate::token::{SubscriptionTier, SubscriptionToken};
use crate::{MIN_CONFIRMATIONS, TOKEN_VALIDITY_DAYS};

/// Payment status
#[derive(Debug, Clone)]
pub enum PaymentStatus {
    /// Waiting for payment
    Pending,
    /// Payment detected, waiting for confirmations
    Confirming {
        txid: String,
        confirmations: u64,
        required: u64
    },
    /// Payment confirmed
    Confirmed {
        txid: String,
        amount: u64,
        confirmations: u64,
    },
    /// Payment expired (address no longer valid)
    Expired,
    /// Token already issued
    TokenIssued,
}

/// Pending payment record
#[derive(Debug, Clone)]
pub struct PendingPayment {
    /// Payment address (subaddress)
    pub address: String,
    /// Subaddress index (for querying)
    pub subaddr_index: u32,
    /// Expected amount in atomic units
    pub amount: u64,
    /// Subscription tier
    pub tier: SubscriptionTier,
    /// User's public key
    pub user_pubkey: PublicKey,
    /// Creation time
    pub created_at: DateTime<Utc>,
    /// Current status
    pub status: PaymentStatus,
    /// Expiry time (address valid until)
    pub expires_at: DateTime<Utc>,
    /// Transaction ID (if payment detected)
    pub tx_id: Option<String>,
}

/// Payment verifier configuration
#[derive(Debug, Clone)]
pub struct VerifierConfig {
    /// Monero network
    pub network: MoneroNetwork,
    /// Daemon host
    pub daemon_host: String,
    /// Daemon port
    pub daemon_port: u16,
    /// Wallet RPC host
    pub wallet_host: String,
    /// Wallet RPC port
    pub wallet_port: u16,
    /// Wallet RPC username (optional)
    pub wallet_username: Option<String>,
    /// Wallet RPC password (optional)
    pub wallet_password: Option<String>,
    /// Account index to use
    pub account_index: u32,
    /// Minimum confirmations
    pub min_confirmations: u64,
    /// Payment expiry hours
    pub payment_expiry_hours: i64,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            network: MoneroNetwork::Mainnet,
            daemon_host: "127.0.0.1".to_string(),
            daemon_port: 18081,
            wallet_host: "127.0.0.1".to_string(),
            wallet_port: 18083,
            wallet_username: None,
            wallet_password: None,
            account_index: 0,
            min_confirmations: MIN_CONFIRMATIONS,
            payment_expiry_hours: 24,
        }
    }
}

/// Payment verifier service
pub struct PaymentVerifier {
    /// Our identity for signing tokens
    identity: Arc<NodeIdentity>,
    /// Monero payment checker
    monero: Arc<MoneroPaymentChecker>,
    /// Wallet RPC (for creating addresses)
    wallet: Arc<MoneroWalletRpc>,
    /// Configuration
    config: VerifierConfig,
    /// Pending payments by address
    pending: RwLock<HashMap<String, PendingPayment>>,
    /// Address to subaddress index mapping
    address_indices: RwLock<HashMap<String, u32>>,
    /// Issued tokens (for preventing double-issuance)
    issued_tokens: RwLock<HashMap<[u8; 16], DateTime<Utc>>>,
}

impl PaymentVerifier {
    /// Create a new payment verifier
    pub fn new(identity: NodeIdentity, config: VerifierConfig) -> Self {
        let wallet = if let (Some(user), Some(pass)) = (&config.wallet_username, &config.wallet_password) {
            MoneroWalletRpc::with_auth(
                &config.wallet_host,
                config.wallet_port,
                config.network,
                user,
                pass,
            )
        } else {
            MoneroWalletRpc::new(&config.wallet_host, config.wallet_port, config.network)
        };

        let daemon = MoneroDaemonRpc::new(&config.daemon_host, config.daemon_port);

        let checker = MoneroPaymentChecker::new(
            MoneroWalletRpc::new(&config.wallet_host, config.wallet_port, config.network),
            daemon,
            config.account_index,
            config.min_confirmations,
        );

        Self {
            identity: Arc::new(identity),
            monero: Arc::new(checker),
            wallet: Arc::new(wallet),
            config,
            pending: RwLock::new(HashMap::new()),
            address_indices: RwLock::new(HashMap::new()),
            issued_tokens: RwLock::new(HashMap::new()),
        }
    }

    /// Create with localhost defaults
    pub fn localhost(identity: NodeIdentity, network: MoneroNetwork) -> Self {
        Self::new(identity, VerifierConfig {
            network,
            ..Default::default()
        })
    }

    /// Get issuer public key (for token verification by other nodes)
    pub fn issuer_pubkey(&self) -> [u8; 32] {
        self.identity.verifying_key().to_bytes()
    }

    /// Check system health
    pub async fn check_health(&self) -> PaymentResult<bool> {
        let health = self.monero.check_health().await?;
        Ok(health.synchronized)
    }

    /// Create a new payment request
    pub async fn create_payment(
        &self,
        user_pubkey: PublicKey,
        tier: SubscriptionTier,
    ) -> PaymentResult<PendingPayment> {
        // Generate unique subaddress
        let label = format!("meshvpn_{}_{}",
            hex::encode(&user_pubkey.as_bytes()[..8]),
            chrono::Utc::now().timestamp()
        );

        let subaddr = self.wallet.create_address(self.config.account_index, &label).await?;

        let now = Utc::now();
        let expires_at = now + chrono::Duration::hours(self.config.payment_expiry_hours);

        let payment = PendingPayment {
            address: subaddr.address.clone(),
            subaddr_index: subaddr.address_index,
            amount: tier.price_atomic(),
            tier,
            user_pubkey,
            created_at: now,
            status: PaymentStatus::Pending,
            expires_at,
            tx_id: None,
        };

        // Store payment
        {
            let mut pending = self.pending.write().await;
            pending.insert(subaddr.address.clone(), payment.clone());
        }

        // Store index mapping
        {
            let mut indices = self.address_indices.write().await;
            indices.insert(subaddr.address.clone(), subaddr.address_index);
        }

        info!("Created payment request: {} for {:?} ({})",
            subaddr.address, tier, crate::monero::format_xmr(tier.price_atomic()));

        Ok(payment)
    }

    /// Check payment status
    pub async fn check_payment(&self, address: &str) -> PaymentResult<PaymentStatus> {
        // Get payment info and release lock
        let (amount, expired, already_issued) = {
            let pending = self.pending.read().await;
            let payment = pending.get(address).ok_or(PaymentError::PaymentNotFound)?;
            (payment.amount, Utc::now() > payment.expires_at, matches!(payment.status, PaymentStatus::TokenIssued))
        };

        // Check if expired
        if expired {
            return Ok(PaymentStatus::Expired);
        }

        // If already issued, return that
        if already_issued {
            return Ok(PaymentStatus::TokenIssued);
        }

        // Get subaddress index
        let subaddr_index = {
            let indices = self.address_indices.read().await;
            indices.get(address).copied()
                .ok_or(PaymentError::PaymentNotFound)?
        };

        // Query blockchain
        match self.monero.check_payment(subaddr_index, amount).await? {
            crate::monero::PaymentStatus::Confirmed(info) => {
                // Update status
                let mut pending = self.pending.write().await;
                if let Some(p) = pending.get_mut(address) {
                    p.status = PaymentStatus::Confirmed {
                        txid: info.txid.clone(),
                        amount: info.amount,
                        confirmations: info.confirmations,
                    };
                    p.tx_id = Some(info.txid.clone());
                }

                Ok(PaymentStatus::Confirmed {
                    txid: info.txid,
                    amount: info.amount,
                    confirmations: info.confirmations,
                })
            }
            crate::monero::PaymentStatus::Confirming { txid, confirmations, required } => {
                // Update status
                let mut pending = self.pending.write().await;
                if let Some(p) = pending.get_mut(address) {
                    p.status = PaymentStatus::Confirming {
                        txid: txid.clone(),
                        confirmations,
                        required,
                    };
                    p.tx_id = Some(txid.clone());
                }

                Ok(PaymentStatus::Confirming { txid, confirmations, required })
            }
            crate::monero::PaymentStatus::Pending => {
                Ok(PaymentStatus::Pending)
            }
        }
    }

    /// Issue token after payment is confirmed
    pub async fn issue_token(&self, address: &str) -> PaymentResult<SubscriptionToken> {
        // First check current status
        let status = self.check_payment(address).await?;

        let mut pending = self.pending.write().await;
        let payment = pending.get_mut(address).ok_or(PaymentError::PaymentNotFound)?;

        // Verify payment is confirmed
        match &status {
            PaymentStatus::Confirmed { .. } => {}
            PaymentStatus::TokenIssued => {
                return Err(PaymentError::InvalidToken);
            }
            PaymentStatus::Confirming { confirmations, required, .. } => {
                return Err(PaymentError::InsufficientConfirmations {
                    current: *confirmations,
                    required: *required,
                });
            }
            PaymentStatus::Pending => {
                return Err(PaymentError::PaymentNotFound);
            }
            PaymentStatus::Expired => {
                return Err(PaymentError::TokenExpired);
            }
        }

        // Create token
        let token = SubscriptionToken::create(
            payment.user_pubkey,
            payment.tier,
            TOKEN_VALIDITY_DAYS,
            &self.identity,
        );

        // Mark as issued
        payment.status = PaymentStatus::TokenIssued;

        // Track issued token
        let mut issued = self.issued_tokens.write().await;
        issued.insert(token.claims.token_id, Utc::now());

        info!("Issued subscription token for address: {} (tier: {:?})",
            address, payment.tier);

        Ok(token)
    }

    /// Verify a token (can be called by any node)
    pub fn verify_token(&self, token: &SubscriptionToken) -> PaymentResult<()> {
        token.validate(&self.issuer_pubkey())
    }

    /// Get pending payment info
    pub async fn get_payment(&self, address: &str) -> Option<PendingPayment> {
        let pending = self.pending.read().await;
        pending.get(address).cloned()
    }

    /// Get all pending payments
    pub async fn get_all_pending(&self) -> Vec<PendingPayment> {
        let pending = self.pending.read().await;
        pending.values().cloned().collect()
    }

    /// Cleanup expired payments and old issued tokens
    pub async fn cleanup(&self) {
        let now = Utc::now();

        // Clean expired pending payments
        {
            let mut pending = self.pending.write().await;
            let before = pending.len();
            pending.retain(|_, p| p.expires_at > now);
            let removed = before - pending.len();
            if removed > 0 {
                debug!("Cleaned up {} expired payments", removed);
            }
        }

        // Clean address indices for removed payments
        {
            let pending = self.pending.read().await;
            let mut indices = self.address_indices.write().await;
            indices.retain(|addr, _| pending.contains_key(addr));
        }

        // Clean old issued tokens (keep for 60 days)
        {
            let mut issued = self.issued_tokens.write().await;
            let before = issued.len();
            issued.retain(|_, issued_at| {
                (*issued_at + chrono::Duration::days(60)) > now
            });
            let removed = before - issued.len();
            if removed > 0 {
                debug!("Cleaned up {} old token records", removed);
            }
        }
    }

    /// Background task to check and update all pending payments
    pub async fn poll_payments(&self) {
        let pending = self.pending.read().await;
        let addresses: Vec<String> = pending
            .iter()
            .filter(|(_, p)| matches!(p.status, PaymentStatus::Pending | PaymentStatus::Confirming { .. }))
            .map(|(addr, _)| addr.clone())
            .collect();
        drop(pending);

        for address in addresses {
            match self.check_payment(&address).await {
                Ok(PaymentStatus::Confirmed { txid, .. }) => {
                    info!("Payment confirmed for {}: tx {}", address, txid);
                }
                Ok(PaymentStatus::Confirming { confirmations, required, .. }) => {
                    debug!("Payment {} confirming: {}/{}", address, confirmations, required);
                }
                Ok(PaymentStatus::Pending) => {
                    debug!("Payment {} still pending", address);
                }
                Err(e) => {
                    warn!("Error checking payment {}: {}", address, e);
                }
                _ => {}
            }
        }
    }

    /// Start background polling task
    pub fn spawn_polling_task(self: Arc<Self>, interval: Duration) {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);

            loop {
                ticker.tick().await;
                self.poll_payments().await;
                self.cleanup().await;
            }
        });
    }
}

/// Hex encoding helper
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verifier_config_default() {
        let config = VerifierConfig::default();
        assert_eq!(config.network, MoneroNetwork::Mainnet);
        assert_eq!(config.daemon_port, 18081);
        assert_eq!(config.wallet_port, 18083);
    }
}
