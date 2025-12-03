//! Monero blockchain integration
//!
//! Provides real integration with Monero daemon (monerod) and wallet RPC (monero-wallet-rpc).
//! Only view key is required (no spend capability).
//!
//! ## Architecture
//! - monero-wallet-rpc: Used for subaddress generation and incoming transfer queries
//! - monerod: Used for network info and transaction verification
//!
//! ## Setup
//! 1. Run monerod: `monerod --rpc-bind-port 18081`
//! 2. Run wallet-rpc with view-only wallet: `monero-wallet-rpc --rpc-bind-port 18083 --wallet-file viewonly`

use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{debug, error, info, warn};

use crate::error::{PaymentError, PaymentResult};

/// Monero network
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MoneroNetwork {
    Mainnet,
    Testnet,
    Stagenet,
}

impl MoneroNetwork {
    /// Get default daemon port
    pub fn daemon_port(&self) -> u16 {
        match self {
            MoneroNetwork::Mainnet => 18081,
            MoneroNetwork::Testnet => 28081,
            MoneroNetwork::Stagenet => 38081,
        }
    }

    /// Get default wallet RPC port
    pub fn wallet_rpc_port(&self) -> u16 {
        match self {
            MoneroNetwork::Mainnet => 18083,
            MoneroNetwork::Testnet => 28083,
            MoneroNetwork::Stagenet => 38083,
        }
    }

    /// Get address prefix
    pub fn address_prefix(&self) -> &'static str {
        match self {
            MoneroNetwork::Mainnet => "4",
            MoneroNetwork::Testnet => "9",
            MoneroNetwork::Stagenet => "5",
        }
    }
}

/// Monero daemon RPC client
pub struct MoneroDaemonRpc {
    /// HTTP client
    client: Client,
    /// RPC endpoint URL
    endpoint: String,
    /// Request timeout
    timeout: Duration,
}

impl MoneroDaemonRpc {
    /// Create a new daemon RPC client
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            endpoint: format!("http://{}:{}/json_rpc", host, port),
            timeout: Duration::from_secs(30),
        }
    }

    /// Create client for localhost with default port
    pub fn localhost(network: MoneroNetwork) -> Self {
        Self::new("127.0.0.1", network.daemon_port())
    }

    /// Make a JSON-RPC call to the daemon
    async fn rpc_call(&self, method: &str, params: Value) -> PaymentResult<Value> {
        let request = json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": method,
            "params": params
        });

        debug!("Daemon RPC call: {} -> {:?}", method, params);

        let response = self.client
            .post(&self.endpoint)
            .json(&request)
            .send()
            .await
            .map_err(|e| PaymentError::NetworkError(format!("RPC request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(PaymentError::ApiError(format!(
                "Daemon returned status: {}",
                response.status()
            )));
        }

        let result: JsonRpcResponse = response
            .json()
            .await
            .map_err(|e| PaymentError::ApiError(format!("Failed to parse response: {}", e)))?;

        if let Some(error) = result.error {
            return Err(PaymentError::ApiError(format!(
                "RPC error {}: {}",
                error.code, error.message
            )));
        }

        result.result.ok_or_else(|| PaymentError::ApiError("Empty response".into()))
    }

    /// Get current blockchain height
    pub async fn get_block_count(&self) -> PaymentResult<u64> {
        let result = self.rpc_call("get_block_count", json!({})).await?;

        result["count"]
            .as_u64()
            .ok_or_else(|| PaymentError::ApiError("Invalid block count response".into()))
    }

    /// Get blockchain info
    pub async fn get_info(&self) -> PaymentResult<DaemonInfo> {
        let result = self.rpc_call("get_info", json!({})).await?;

        Ok(DaemonInfo {
            height: result["height"].as_u64().unwrap_or(0),
            target_height: result["target_height"].as_u64().unwrap_or(0),
            difficulty: result["difficulty"].as_u64().unwrap_or(0),
            tx_pool_size: result["tx_pool_size"].as_u64().unwrap_or(0),
            synchronized: result["synchronized"].as_bool().unwrap_or(false),
            version: result["version"].as_str().unwrap_or("").to_string(),
        })
    }

    /// Get transaction by hash
    pub async fn get_transaction(&self, tx_hash: &str) -> PaymentResult<TransactionInfo> {
        // Use /get_transactions endpoint (not JSON-RPC)
        let url = self.endpoint.replace("/json_rpc", "/get_transactions");

        let request = json!({
            "txs_hashes": [tx_hash],
            "decode_as_json": true
        });

        let response = self.client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| PaymentError::NetworkError(format!("Request failed: {}", e)))?;

        let result: Value = response
            .json()
            .await
            .map_err(|e| PaymentError::ApiError(format!("Failed to parse: {}", e)))?;

        if result["status"].as_str() != Some("OK") {
            return Err(PaymentError::ApiError(
                result["status"].as_str().unwrap_or("Unknown error").to_string()
            ));
        }

        let txs = result["txs"].as_array()
            .ok_or_else(|| PaymentError::ApiError("No transactions in response".into()))?;

        if txs.is_empty() {
            return Err(PaymentError::TransactionNotFound);
        }

        let tx = &txs[0];
        let block_height = tx["block_height"].as_u64();
        let in_pool = tx["in_pool"].as_bool().unwrap_or(false);

        // Calculate confirmations
        let confirmations = if let Some(height) = block_height {
            let current = self.get_block_count().await?;
            if current >= height {
                current - height + 1
            } else {
                0
            }
        } else {
            0
        };

        Ok(TransactionInfo {
            tx_hash: tx_hash.to_string(),
            block_height,
            in_pool,
            confirmations,
            double_spend_seen: tx["double_spend_seen"].as_bool().unwrap_or(false),
        })
    }

    /// Check if daemon is synchronized
    pub async fn is_synchronized(&self) -> PaymentResult<bool> {
        let info = self.get_info().await?;
        Ok(info.synchronized && info.height >= info.target_height)
    }
}

/// Monero wallet RPC client
pub struct MoneroWalletRpc {
    /// HTTP client
    client: Client,
    /// RPC endpoint URL
    endpoint: String,
    /// Network
    network: MoneroNetwork,
    /// Optional authentication credentials
    auth: Option<(String, String)>,
}

impl MoneroWalletRpc {
    /// Create a new wallet RPC client
    pub fn new(host: &str, port: u16, network: MoneroNetwork) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .expect("Failed to create HTTP client"),
            endpoint: format!("http://{}:{}/json_rpc", host, port),
            network,
            auth: None,
        }
    }

    /// Create with authentication
    pub fn with_auth(host: &str, port: u16, network: MoneroNetwork, username: &str, password: &str) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .expect("Failed to create HTTP client"),
            endpoint: format!("http://{}:{}/json_rpc", host, port),
            network,
            auth: Some((username.to_string(), password.to_string())),
        }
    }

    /// Create client for localhost with default port
    pub fn localhost(network: MoneroNetwork) -> Self {
        Self::new("127.0.0.1", network.wallet_rpc_port(), network)
    }

    /// Make a JSON-RPC call to the wallet
    async fn rpc_call(&self, method: &str, params: Value) -> PaymentResult<Value> {
        let request = json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": method,
            "params": params
        });

        debug!("Wallet RPC call: {} -> {:?}", method, params);

        let mut req = self.client.post(&self.endpoint).json(&request);
        if let Some((username, password)) = &self.auth {
            req = req.basic_auth(username, Some(password));
        }
        let response = req.send().await
            .map_err(|e| PaymentError::NetworkError(format!("Wallet RPC request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(PaymentError::ApiError(format!(
                "Wallet RPC returned status: {}",
                response.status()
            )));
        }

        let result: JsonRpcResponse = response
            .json()
            .await
            .map_err(|e| PaymentError::ApiError(format!("Failed to parse wallet response: {}", e)))?;

        if let Some(error) = result.error {
            return Err(PaymentError::ApiError(format!(
                "Wallet RPC error {}: {}",
                error.code, error.message
            )));
        }

        result.result.ok_or_else(|| PaymentError::ApiError("Empty wallet response".into()))
    }

    /// Get wallet balance
    pub async fn get_balance(&self, account_index: u32) -> PaymentResult<WalletBalance> {
        let result = self.rpc_call("get_balance", json!({
            "account_index": account_index,
            "all_accounts": false
        })).await?;

        Ok(WalletBalance {
            balance: result["balance"].as_u64().unwrap_or(0),
            unlocked_balance: result["unlocked_balance"].as_u64().unwrap_or(0),
            blocks_to_unlock: result["blocks_to_unlock"].as_u64().unwrap_or(0),
        })
    }

    /// Get primary wallet address
    pub async fn get_address(&self, account_index: u32) -> PaymentResult<String> {
        let result = self.rpc_call("get_address", json!({
            "account_index": account_index,
            "address_index": [0]
        })).await?;

        result["address"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| PaymentError::ApiError("No address in response".into()))
    }

    /// Create a new subaddress
    pub async fn create_address(&self, account_index: u32, label: &str) -> PaymentResult<SubaddressInfo> {
        let result = self.rpc_call("create_address", json!({
            "account_index": account_index,
            "label": label
        })).await?;

        Ok(SubaddressInfo {
            address: result["address"].as_str().unwrap_or("").to_string(),
            address_index: result["address_index"].as_u64().unwrap_or(0) as u32,
            label: label.to_string(),
            used: false,
        })
    }

    /// Get all subaddresses for an account
    pub async fn get_address_list(&self, account_index: u32) -> PaymentResult<Vec<SubaddressInfo>> {
        let result = self.rpc_call("get_address", json!({
            "account_index": account_index
        })).await?;

        let addresses = result["addresses"]
            .as_array()
            .ok_or_else(|| PaymentError::ApiError("No addresses in response".into()))?;

        let mut list = Vec::new();
        for addr in addresses {
            list.push(SubaddressInfo {
                address: addr["address"].as_str().unwrap_or("").to_string(),
                address_index: addr["address_index"].as_u64().unwrap_or(0) as u32,
                label: addr["label"].as_str().unwrap_or("").to_string(),
                used: addr["used"].as_bool().unwrap_or(false),
            });
        }

        Ok(list)
    }

    /// Get incoming transfers
    pub async fn get_transfers(&self, params: GetTransfersParams) -> PaymentResult<TransferList> {
        let result = self.rpc_call("get_transfers", json!({
            "in": params.incoming,
            "out": params.outgoing,
            "pending": params.pending,
            "failed": params.failed,
            "pool": params.pool,
            "account_index": params.account_index,
            "subaddr_indices": params.subaddr_indices,
            "filter_by_height": params.min_height.is_some() || params.max_height.is_some(),
            "min_height": params.min_height.unwrap_or(0),
            "max_height": params.max_height.unwrap_or(u64::MAX)
        })).await?;

        let parse_transfers = |key: &str| -> Vec<Transfer> {
            result[key]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .map(|t| Transfer {
                            txid: t["txid"].as_str().unwrap_or("").to_string(),
                            payment_id: t["payment_id"].as_str().unwrap_or("").to_string(),
                            height: t["height"].as_u64().unwrap_or(0),
                            timestamp: t["timestamp"].as_u64().unwrap_or(0),
                            amount: t["amount"].as_u64().unwrap_or(0),
                            fee: t["fee"].as_u64().unwrap_or(0),
                            confirmations: t["confirmations"].as_u64().unwrap_or(0),
                            address: t["address"].as_str().unwrap_or("").to_string(),
                            subaddr_index: SubaddrIndex {
                                major: t["subaddr_index"]["major"].as_u64().unwrap_or(0) as u32,
                                minor: t["subaddr_index"]["minor"].as_u64().unwrap_or(0) as u32,
                            },
                            double_spend_seen: t["double_spend_seen"].as_bool().unwrap_or(false),
                            locked: t["locked"].as_bool().unwrap_or(false),
                        })
                        .collect()
                })
                .unwrap_or_default()
        };

        Ok(TransferList {
            incoming: parse_transfers("in"),
            outgoing: parse_transfers("out"),
            pending: parse_transfers("pending"),
            pool: parse_transfers("pool"),
        })
    }

    /// Get incoming transfers for specific subaddresses
    pub async fn get_incoming_transfers(
        &self,
        account_index: u32,
        subaddr_indices: &[u32],
    ) -> PaymentResult<Vec<Transfer>> {
        let params = GetTransfersParams {
            incoming: true,
            outgoing: false,
            pending: true,
            failed: false,
            pool: true,
            account_index,
            subaddr_indices: subaddr_indices.to_vec(),
            min_height: None,
            max_height: None,
        };

        let transfers = self.get_transfers(params).await?;
        let mut all: Vec<Transfer> = Vec::new();
        all.extend(transfers.incoming);
        all.extend(transfers.pending);
        all.extend(transfers.pool);

        Ok(all)
    }

    /// Check for payments to a specific subaddress
    pub async fn check_payment(
        &self,
        account_index: u32,
        subaddr_index: u32,
        expected_amount: u64,
        min_confirmations: u64,
    ) -> PaymentResult<Option<PaymentInfo>> {
        let transfers = self.get_incoming_transfers(account_index, &[subaddr_index]).await?;

        for transfer in transfers {
            if transfer.amount >= expected_amount && transfer.confirmations >= min_confirmations {
                return Ok(Some(PaymentInfo {
                    txid: transfer.txid,
                    amount: transfer.amount,
                    confirmations: transfer.confirmations,
                    timestamp: transfer.timestamp,
                    address: transfer.address,
                }));
            }
        }

        // Check pending/unconfirmed
        for transfer in self.get_incoming_transfers(account_index, &[subaddr_index]).await? {
            if transfer.amount >= expected_amount && transfer.confirmations < min_confirmations {
                info!(
                    "Payment found but waiting for confirmations: {} (have {}, need {})",
                    transfer.txid, transfer.confirmations, min_confirmations
                );
            }
        }

        Ok(None)
    }

    /// Validate a Monero address
    pub async fn validate_address(&self, address: &str) -> PaymentResult<AddressValidation> {
        let result = self.rpc_call("validate_address", json!({
            "address": address
        })).await?;

        Ok(AddressValidation {
            valid: result["valid"].as_bool().unwrap_or(false),
            integrated: result["integrated"].as_bool().unwrap_or(false),
            subaddress: result["subaddress"].as_bool().unwrap_or(false),
            nettype: result["nettype"].as_str().unwrap_or("").to_string(),
        })
    }

    /// Get wallet height (last synced block)
    pub async fn get_height(&self) -> PaymentResult<u64> {
        let result = self.rpc_call("get_height", json!({})).await?;

        result["height"]
            .as_u64()
            .ok_or_else(|| PaymentError::ApiError("Invalid height response".into()))
    }

    /// Refresh wallet (sync with daemon)
    pub async fn refresh(&self, start_height: Option<u64>) -> PaymentResult<RefreshResult> {
        let params = if let Some(height) = start_height {
            json!({"start_height": height})
        } else {
            json!({})
        };

        let result = self.rpc_call("refresh", params).await?;

        Ok(RefreshResult {
            blocks_fetched: result["blocks_fetched"].as_u64().unwrap_or(0),
            received_money: result["received_money"].as_bool().unwrap_or(false),
        })
    }
}

// =====================
// Data Types
// =====================

#[derive(Debug, Deserialize)]
struct JsonRpcResponse {
    result: Option<Value>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

/// Daemon information
#[derive(Debug, Clone)]
pub struct DaemonInfo {
    pub height: u64,
    pub target_height: u64,
    pub difficulty: u64,
    pub tx_pool_size: u64,
    pub synchronized: bool,
    pub version: String,
}

/// Transaction information
#[derive(Debug, Clone)]
pub struct TransactionInfo {
    pub tx_hash: String,
    pub block_height: Option<u64>,
    pub in_pool: bool,
    pub confirmations: u64,
    pub double_spend_seen: bool,
}

/// Wallet balance
#[derive(Debug, Clone)]
pub struct WalletBalance {
    pub balance: u64,
    pub unlocked_balance: u64,
    pub blocks_to_unlock: u64,
}

/// Subaddress information
#[derive(Debug, Clone)]
pub struct SubaddressInfo {
    pub address: String,
    pub address_index: u32,
    pub label: String,
    pub used: bool,
}

/// Parameters for get_transfers
#[derive(Debug, Clone)]
pub struct GetTransfersParams {
    pub incoming: bool,
    pub outgoing: bool,
    pub pending: bool,
    pub failed: bool,
    pub pool: bool,
    pub account_index: u32,
    pub subaddr_indices: Vec<u32>,
    pub min_height: Option<u64>,
    pub max_height: Option<u64>,
}

impl Default for GetTransfersParams {
    fn default() -> Self {
        Self {
            incoming: true,
            outgoing: false,
            pending: false,
            failed: false,
            pool: false,
            account_index: 0,
            subaddr_indices: Vec::new(),
            min_height: None,
            max_height: None,
        }
    }
}

/// Transfer list result
#[derive(Debug, Clone)]
pub struct TransferList {
    pub incoming: Vec<Transfer>,
    pub outgoing: Vec<Transfer>,
    pub pending: Vec<Transfer>,
    pub pool: Vec<Transfer>,
}

/// Single transfer
#[derive(Debug, Clone)]
pub struct Transfer {
    pub txid: String,
    pub payment_id: String,
    pub height: u64,
    pub timestamp: u64,
    pub amount: u64,
    pub fee: u64,
    pub confirmations: u64,
    pub address: String,
    pub subaddr_index: SubaddrIndex,
    pub double_spend_seen: bool,
    pub locked: bool,
}

/// Subaddress index (account, subaddress)
#[derive(Debug, Clone, Copy)]
pub struct SubaddrIndex {
    pub major: u32,
    pub minor: u32,
}

/// Payment information
#[derive(Debug, Clone)]
pub struct PaymentInfo {
    pub txid: String,
    pub amount: u64,
    pub confirmations: u64,
    pub timestamp: u64,
    pub address: String,
}

/// Address validation result
#[derive(Debug, Clone)]
pub struct AddressValidation {
    pub valid: bool,
    pub integrated: bool,
    pub subaddress: bool,
    pub nettype: String,
}

/// Refresh result
#[derive(Debug, Clone)]
pub struct RefreshResult {
    pub blocks_fetched: u64,
    pub received_money: bool,
}

// =====================
// High-level Payment Checker
// =====================

/// High-level payment checking service
pub struct MoneroPaymentChecker {
    /// Wallet RPC client
    wallet: MoneroWalletRpc,
    /// Daemon RPC client
    daemon: MoneroDaemonRpc,
    /// Account index to use
    account_index: u32,
    /// Minimum confirmations required
    min_confirmations: u64,
}

impl MoneroPaymentChecker {
    /// Create a new payment checker
    pub fn new(
        wallet: MoneroWalletRpc,
        daemon: MoneroDaemonRpc,
        account_index: u32,
        min_confirmations: u64,
    ) -> Self {
        Self {
            wallet,
            daemon,
            account_index,
            min_confirmations,
        }
    }

    /// Create with default localhost configuration
    pub fn localhost(network: MoneroNetwork, min_confirmations: u64) -> Self {
        Self {
            wallet: MoneroWalletRpc::localhost(network),
            daemon: MoneroDaemonRpc::localhost(network),
            account_index: 0,
            min_confirmations,
        }
    }

    /// Check if the system is ready (daemon synced, wallet connected)
    pub async fn check_health(&self) -> PaymentResult<HealthStatus> {
        // Check daemon
        let daemon_info = self.daemon.get_info().await?;

        // Check wallet
        let wallet_height = self.wallet.get_height().await?;

        let synced = daemon_info.synchronized && wallet_height >= daemon_info.height.saturating_sub(1);

        Ok(HealthStatus {
            daemon_connected: true,
            wallet_connected: true,
            daemon_height: daemon_info.height,
            wallet_height,
            synchronized: synced,
        })
    }

    /// Create a new payment address for receiving
    pub async fn create_payment_address(&self, label: &str) -> PaymentResult<SubaddressInfo> {
        self.wallet.create_address(self.account_index, label).await
    }

    /// Check for payment to a specific address
    pub async fn check_payment(
        &self,
        subaddr_index: u32,
        expected_amount: u64,
    ) -> PaymentResult<PaymentStatus> {
        // First ensure wallet is refreshed
        self.wallet.refresh(None).await?;

        // Check for transfers
        let transfers = self.wallet
            .get_incoming_transfers(self.account_index, &[subaddr_index])
            .await?;

        for transfer in &transfers {
            if transfer.amount >= expected_amount {
                if transfer.confirmations >= self.min_confirmations {
                    return Ok(PaymentStatus::Confirmed(PaymentInfo {
                        txid: transfer.txid.clone(),
                        amount: transfer.amount,
                        confirmations: transfer.confirmations,
                        timestamp: transfer.timestamp,
                        address: transfer.address.clone(),
                    }));
                } else {
                    return Ok(PaymentStatus::Confirming {
                        txid: transfer.txid.clone(),
                        confirmations: transfer.confirmations,
                        required: self.min_confirmations,
                    });
                }
            }
        }

        Ok(PaymentStatus::Pending)
    }

    /// Verify a specific transaction
    pub async fn verify_transaction(&self, tx_hash: &str) -> PaymentResult<TransactionInfo> {
        self.daemon.get_transaction(tx_hash).await
    }
}

/// Health status for payment system
#[derive(Debug, Clone)]
pub struct HealthStatus {
    pub daemon_connected: bool,
    pub wallet_connected: bool,
    pub daemon_height: u64,
    pub wallet_height: u64,
    pub synchronized: bool,
}

/// Payment status for checker
#[derive(Debug, Clone)]
pub enum PaymentStatus {
    /// No payment detected yet
    Pending,
    /// Payment found, waiting for confirmations
    Confirming {
        txid: String,
        confirmations: u64,
        required: u64,
    },
    /// Payment confirmed
    Confirmed(PaymentInfo),
}

// =====================
// Amount Helpers
// =====================

/// Monero atomic unit conversion (1 XMR = 10^12 atomic units)
pub const ATOMIC_UNITS_PER_XMR: u64 = 1_000_000_000_000;

/// Convert XMR to atomic units
pub fn xmr_to_atomic(xmr: f64) -> u64 {
    (xmr * ATOMIC_UNITS_PER_XMR as f64) as u64
}

/// Convert atomic units to XMR
pub fn atomic_to_xmr(atomic: u64) -> f64 {
    atomic as f64 / ATOMIC_UNITS_PER_XMR as f64
}

/// Format atomic units as XMR string
pub fn format_xmr(atomic: u64) -> String {
    format!("{:.12} XMR", atomic_to_xmr(atomic))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xmr_conversion() {
        assert_eq!(xmr_to_atomic(1.0), ATOMIC_UNITS_PER_XMR);
        assert_eq!(xmr_to_atomic(0.5), ATOMIC_UNITS_PER_XMR / 2);
        assert!((atomic_to_xmr(ATOMIC_UNITS_PER_XMR) - 1.0).abs() < 0.0001);
    }

    #[test]
    fn test_network_ports() {
        assert_eq!(MoneroNetwork::Mainnet.daemon_port(), 18081);
        assert_eq!(MoneroNetwork::Testnet.daemon_port(), 28081);
        assert_eq!(MoneroNetwork::Stagenet.daemon_port(), 38081);
    }

    #[test]
    fn test_format_xmr() {
        let amount = xmr_to_atomic(1.5);
        let formatted = format_xmr(amount);
        assert!(formatted.contains("1.5"));
        assert!(formatted.contains("XMR"));
    }
}
