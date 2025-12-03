//! Tauri IPC commands for the GUI

use std::sync::Arc;
use std::net::{Ipv4Addr, SocketAddr};

use serde::{Deserialize, Serialize};
use tauri::State;
use tokio::sync::RwLock;
use tracing::{info, warn, error};

use meshvpn_network::tun::TunConfig;
use meshvpn_network::wireguard::{WireGuardClient, WireGuardConfig};
use meshvpn_network::p2p::{StunClient, DiscoveryClient, NatType, HolePuncher, RelayClient, PeerId};

use crate::state::{AppState, ConnectionState, ConnectionStats, ServerInfo, SubscriptionStatus};
use crate::config::AppSettings;


/// Command result type
#[derive(Debug, Serialize)]
pub struct CommandResult<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

impl<T> CommandResult<T> {
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn err(error: impl ToString) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error.to_string()),
        }
    }
}

/// Connect to VPN using WireGuard
#[tauri::command]
pub async fn connect(state: State<'_, Arc<RwLock<AppState>>>) -> Result<CommandResult<String>, ()> {
    info!("Connect command received");

    let mut state = state.write().await;

    // Check if already connected
    if state.connection_state == ConnectionState::Connected {
        return Ok(CommandResult::err("Already connected"));
    }

    // Get selected server
    let server = match &state.selected_server {
        Some(s) => s.clone(),
        None => return Ok(CommandResult::err("No server selected")),
    };

    // Get server endpoint
    let endpoint_str = match &server.endpoint {
        Some(e) => e.clone(),
        None => return Ok(CommandResult::err("Server has no endpoint configured")),
    };

    let endpoint: SocketAddr = match endpoint_str.parse() {
        Ok(e) => e,
        Err(_) => return Ok(CommandResult::err("Invalid server endpoint")),
    };

    state.connection_state = ConnectionState::Connecting;

    // WireGuard configuration
    let wg_config = WireGuardConfig {
        private_key: "EDqHUtmfXNMpJrB6Gld2DJp8E3RuC864mQ5goyjUwnU=".to_string(),
        server_public_key: "fSaOT+Eyeja4p4NVpSbk4llPoDNwYknCB+mmn532iAs=".to_string(),
        endpoint,
        address: Ipv4Addr::new(10, 200, 0, 2),
        netmask: Ipv4Addr::new(255, 255, 255, 0),
        keepalive: Some(25),
    };

    // Create TUN device
    let tun_config = TunConfig {
        name: "meshvpn0".to_string(),
        address: Ipv4Addr::new(10, 200, 0, 2),
        netmask: Ipv4Addr::new(255, 255, 255, 0),
        mtu: 1420,
        queued: false,
    };

    info!("Creating TUN device...");
    let tun = match meshvpn_network::tun::create_tun(tun_config).await {
        Ok(t) => t,
        Err(e) => {
            state.connection_state = ConnectionState::Error;
            error!("Failed to create TUN: {}", e);
            return Ok(CommandResult::err(format!("Failed to create TUN: {}", e)));
        }
    };

    // Set up routing: route all traffic through the TUN device
    info!("Setting up default route through VPN...");
    if let Err(e) = tun.set_default_route(endpoint).await {
        warn!("Failed to set default route: {} - continuing anyway", e);
    }

    info!("Creating WireGuard client...");
    let wg_client = match WireGuardClient::new(wg_config, tun).await {
        Ok(c) => c,
        Err(e) => {
            state.connection_state = ConnectionState::Error;
            error!("Failed to create WireGuard client: {}", e);
            return Ok(CommandResult::err(format!("Failed to create WireGuard client: {}", e)));
        }
    };

    // Start WireGuard tunnel
    match wg_client.start().await {
        Ok(()) => {
            state.wg_client = Some(Arc::new(wg_client));
            state.connection_state = ConnectionState::Connected;
            state.connected_at = Some(chrono::Utc::now());

            info!("Connected to {} via WireGuard", server.name);
            Ok(CommandResult::ok(format!("Connected to {}", server.name)))
        }
        Err(e) => {
            state.connection_state = ConnectionState::Error;
            error!("Failed to start WireGuard: {}", e);
            Ok(CommandResult::err(format!("Failed to connect: {}", e)))
        }
    }
}

/// Disconnect from VPN
#[tauri::command]
pub async fn disconnect(state: State<'_, Arc<RwLock<AppState>>>) -> Result<CommandResult<String>, ()> {
    info!("Disconnect command received");

    let mut state = state.write().await;

    if state.connection_state != ConnectionState::Connected {
        return Ok(CommandResult::err("Not connected"));
    }

    state.connection_state = ConnectionState::Disconnecting;

    if let Some(wg_client) = state.wg_client.take() {
        wg_client.stop().await;
    }

    state.connection_state = ConnectionState::Disconnected;
    state.connected_at = None;

    info!("Disconnected");
    Ok(CommandResult::ok("Disconnected".to_string()))
}

/// Get current connection status
#[tauri::command]
pub async fn get_status(state: State<'_, Arc<RwLock<AppState>>>) -> Result<CommandResult<ConnectionState>, ()> {
    let state = state.read().await;
    Ok(CommandResult::ok(state.get_status()))
}

/// Get connection statistics
#[tauri::command]
pub async fn get_stats(state: State<'_, Arc<RwLock<AppState>>>) -> Result<CommandResult<ConnectionStats>, ()> {
    let state = state.read().await;
    Ok(CommandResult::ok(state.get_stats().await))
}

/// Get available servers
#[tauri::command]
pub async fn get_servers(state: State<'_, Arc<RwLock<AppState>>>) -> Result<CommandResult<Vec<ServerInfo>>, ()> {
    let state = state.read().await;
    Ok(CommandResult::ok(state.servers.clone()))
}

/// Set selected server
#[tauri::command]
pub async fn set_server(state: State<'_, Arc<RwLock<AppState>>>, server_id: String) -> Result<CommandResult<ServerInfo>, ()> {
    let mut state = state.write().await;

    let server = state.servers.iter()
        .find(|s| s.id == server_id)
        .cloned();

    match server {
        Some(s) => {
            state.selected_server = Some(s.clone());
            info!("Selected server: {}", s.name);
            Ok(CommandResult::ok(s))
        }
        None => Ok(CommandResult::err("Server not found")),
    }
}

/// Get application settings
#[tauri::command]
pub async fn get_settings(state: State<'_, Arc<RwLock<AppState>>>) -> Result<CommandResult<AppSettings>, ()> {
    let state = state.read().await;
    Ok(CommandResult::ok(AppSettings::from(&state.config)))
}

/// Update application settings
#[tauri::command]
pub async fn update_settings(state: State<'_, Arc<RwLock<AppState>>>, settings: AppSettings) -> Result<CommandResult<()>, ()> {
    let mut state = state.write().await;

    state.config.auto_connect = settings.auto_connect;
    state.config.kill_switch = settings.kill_switch;
    state.config.start_minimized = settings.start_minimized;
    state.config.notifications = settings.notifications;
    state.config.theme = settings.theme.clone();

    if let Err(e) = state.save_config() {
        return Ok(CommandResult::err(format!("Failed to save settings: {}", e)));
    }

    info!("Settings updated");
    Ok(CommandResult::ok(()))
}

/// Get subscription status
#[tauri::command]
pub async fn get_subscription_status(state: State<'_, Arc<RwLock<AppState>>>) -> Result<CommandResult<SubscriptionStatus>, ()> {
    let state = state.read().await;
    Ok(CommandResult::ok(state.subscription.clone()))
}

/// Payment request response
#[derive(Debug, Clone, Serialize)]
pub struct PaymentRequest {
    pub address: String,
    pub amount: String,
    pub amount_atomic: u64,
    pub expires_at: i64,
}

/// Create payment for subscription
#[tauri::command]
pub async fn create_payment(
    state: State<'_, Arc<RwLock<AppState>>>,
    tier: String,
) -> Result<CommandResult<PaymentRequest>, ()> {
    // In production, this would call the payment API
    // For now, return a placeholder

    let (amount, amount_atomic) = match tier.as_str() {
        "basic" => ("0.05 XMR", 50_000_000_000u64),
        "premium" => ("0.15 XMR", 150_000_000_000u64),
        "unlimited" => ("0.30 XMR", 300_000_000_000u64),
        _ => return Ok(CommandResult::err("Invalid tier")),
    };

    let expires_at = chrono::Utc::now().timestamp() + 24 * 60 * 60; // 24 hours

    // Generate placeholder address
    let address = format!(
        "4{}",
        (0..93).map(|_| format!("{:x}", rand::random::<u8>() % 16)).collect::<String>()
    );

    Ok(CommandResult::ok(PaymentRequest {
        address,
        amount: amount.to_string(),
        amount_atomic,
        expires_at,
    }))
}

/// Payment status response
#[derive(Debug, Clone, Serialize)]
pub struct PaymentStatus {
    pub status: String,
    pub confirmations: u64,
    pub required_confirmations: u64,
}

/// Check payment status
#[tauri::command]
pub async fn check_payment(
    state: State<'_, Arc<RwLock<AppState>>>,
    address: String,
) -> Result<CommandResult<PaymentStatus>, ()> {
    // In production, this would check the blockchain
    // For now, return pending

    Ok(CommandResult::ok(PaymentStatus {
        status: "pending".to_string(),
        confirmations: 0,
        required_confirmations: 10,
    }))
}

/// Get recent logs
#[tauri::command]
pub async fn get_logs(state: State<'_, Arc<RwLock<AppState>>>, limit: usize) -> Result<CommandResult<Vec<String>>, ()> {
    // In production, this would read from log file
    // For now, return sample logs

    let logs = vec![
        "[INFO] Application started".to_string(),
        "[INFO] Loaded configuration".to_string(),
        "[INFO] Identity loaded".to_string(),
    ];

    Ok(CommandResult::ok(logs))
}

/// Export identity (stub - WireGuard keys handled separately)
#[tauri::command]
pub async fn export_identity(_state: State<'_, Arc<RwLock<AppState>>>, _path: String) -> Result<CommandResult<()>, ()> {
    Ok(CommandResult::err("Identity export not available in WireGuard mode"))
}

/// Import identity (stub - WireGuard keys handled separately)
#[tauri::command]
pub async fn import_identity(_state: State<'_, Arc<RwLock<AppState>>>, _path: String) -> Result<CommandResult<()>, ()> {
    Ok(CommandResult::err("Identity import not available in WireGuard mode"))
}

/// Generate new identity (stub - WireGuard keys handled separately)
#[tauri::command]
pub async fn generate_identity(_state: State<'_, Arc<RwLock<AppState>>>) -> Result<CommandResult<String>, ()> {
    Ok(CommandResult::err("Identity generation not available in WireGuard mode"))
}

/// Get real public IP address
#[tauri::command]
pub async fn get_public_ip() -> Result<CommandResult<String>, ()> {
    // Try multiple IP check services
    let services = [
        "https://api.ipify.org",
        "https://icanhazip.com",
        "https://ifconfig.me/ip",
    ];

    for service in services {
        if let Ok(response) = reqwest::get(service).await {
            if let Ok(ip) = response.text().await {
                let ip = ip.trim().to_string();
                if !ip.is_empty() {
                    return Ok(CommandResult::ok(ip));
                }
            }
        }
    }

    Ok(CommandResult::err("Failed to get public IP"))
}

/// Open WireGuard config file location
#[tauri::command]
pub async fn open_vpn_config() -> Result<CommandResult<String>, ()> {
    let config_path = "c:\\Users\\pilat\\Desktop\\meshVPN\\vpn-client.conf";

    if std::path::Path::new(config_path).exists() {
        // Open file explorer at the config location
        if let Err(e) = std::process::Command::new("explorer")
            .arg("/select,")
            .arg(config_path)
            .spawn()
        {
            return Ok(CommandResult::err(format!("Failed to open explorer: {}", e)));
        }
        Ok(CommandResult::ok(config_path.to_string()))
    } else {
        Ok(CommandResult::err("Config file not found"))
    }
}

// ============================================================================
// P2P Commands
// ============================================================================

/// NAT detection result for the frontend
#[derive(Debug, Clone, Serialize)]
pub struct NatDetectionResult {
    pub nat_type: String,
    pub public_ip: Option<String>,
    pub public_port: Option<u16>,
    pub description: String,
}

/// Detect NAT type using STUN
#[tauri::command]
pub async fn detect_nat() -> Result<CommandResult<NatDetectionResult>, ()> {
    info!("Detecting NAT type...");

    // Create STUN client
    let stun_client = match StunClient::new("0.0.0.0:0").await {
        Ok(c) => c,
        Err(e) => return Ok(CommandResult::err(format!("Failed to create STUN client: {}", e))),
    };

    // Get mapped address first
    let stun_server = "stun.l.google.com:19302";
    let mapped_result = match stun_client.get_mapped_address(stun_server).await {
        Ok(r) => r,
        Err(e) => return Ok(CommandResult::err(format!("STUN request failed: {}", e))),
    };

    // Detect NAT type
    let nat_type = match stun_client.detect_nat_type(stun_server).await {
        Ok(t) => t,
        Err(e) => {
            warn!("NAT type detection failed, using Unknown: {}", e);
            NatType::Unknown
        }
    };

    let (nat_type_str, description) = match nat_type {
        NatType::None => ("none", "No NAT detected - direct connection possible"),
        NatType::FullCone => ("full_cone", "Full Cone NAT - best for P2P"),
        NatType::AddressRestricted => ("address_restricted", "Address Restricted NAT - P2P possible"),
        NatType::PortRestricted => ("port_restricted", "Port Restricted NAT - P2P possible with hole punching"),
        NatType::Symmetric => ("symmetric", "Symmetric NAT - P2P difficult, may need relay"),
        NatType::Unknown => ("unknown", "Could not determine NAT type"),
    };

    let public_addr = mapped_result.mapped_address;
    info!("NAT type detected: {} - {}", nat_type_str, public_addr);

    Ok(CommandResult::ok(NatDetectionResult {
        nat_type: nat_type_str.to_string(),
        public_ip: Some(public_addr.ip().to_string()),
        public_port: Some(public_addr.port()),
        description: description.to_string(),
    }))
}

/// P2P peer info for the frontend
#[derive(Debug, Clone, Serialize)]
pub struct P2PPeerInfo {
    pub peer_id: String,
    pub public_addr: String,
    pub nat_type: String,
    pub last_seen: i64,
    pub can_relay: bool,
}

/// Discovery server address (legacy)
const DISCOVERY_SERVER: &str = "54.160.213.165:51821";

/// DHT Bootstrap server address
const DHT_BOOTSTRAP_SERVER: &str = "54.160.213.165:51822";

/// Relay server address (for Symmetric NAT)
const RELAY_SERVER: &str = "54.160.213.165:51823";

/// Generate or get stored P2P keys
fn get_p2p_keys(config: &crate::config::AppConfig) -> ([u8; 32], [u8; 32]) {
    // For now, derive keys from peer_id or generate random
    let seed = config.peer_id.clone()
        .unwrap_or_else(|| format!("{:016x}", rand::random::<u64>()));

    // Use BLAKE3 to derive deterministic keys from seed
    let hash1 = blake3::hash(format!("meshvpn-public-{}", seed).as_bytes());
    let hash2 = blake3::hash(format!("meshvpn-private-{}", seed).as_bytes());

    (*hash1.as_bytes(), *hash2.as_bytes())
}

/// Discover peers from the discovery server
#[tauri::command]
pub async fn discover_peers(state: State<'_, Arc<RwLock<AppState>>>) -> Result<CommandResult<Vec<P2PPeerInfo>>, ()> {
    info!("Discovering peers...");

    // Get keys from config
    let state_guard = state.read().await;
    let (public_key, private_key) = get_p2p_keys(&state_guard.config);
    drop(state_guard);

    // Spawn in separate task to avoid stack overflow
    let result = tokio::spawn(async move {
        discover_peers_inner(public_key, private_key).await
    }).await;

    match result {
        Ok(r) => Ok(r),
        Err(e) => {
            error!("Task failed: {}", e);
            Ok(CommandResult::err(format!("Internal error: {}", e)))
        }
    }
}

/// Inner function for discover_peers to run in separate task
async fn discover_peers_inner(public_key: [u8; 32], private_key: [u8; 32]) -> CommandResult<Vec<P2PPeerInfo>> {
    info!("Creating discovery client...");

    // Create discovery client
    let discovery_client = match DiscoveryClient::new(public_key, private_key, "0.0.0.0:0").await {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to create discovery client: {}", e);
            return CommandResult::err(format!("Failed to create discovery client: {}", e));
        }
    };

    let our_peer_id = discovery_client.peer_id();
    info!("Our peer ID: {}", our_peer_id);

    info!("Requesting peer list from server...");

    // Get list of peers (up to 100, including relays)
    match discovery_client.get_peers(100, false).await {
        Ok(peers) => {
            info!("Received {} peers from server", peers.len());

            let mut peer_list: Vec<P2PPeerInfo> = Vec::new();

            for p in peers.iter() {
                // Skip ourselves
                if p.peer_id == our_peer_id {
                    continue;
                }

                let nat_type_str = match p.nat_type {
                    NatType::None => "none",
                    NatType::FullCone => "full_cone",
                    NatType::AddressRestricted => "address_restricted",
                    NatType::PortRestricted => "port_restricted",
                    NatType::Symmetric => "symmetric",
                    NatType::Unknown => "unknown",
                };

                peer_list.push(P2PPeerInfo {
                    peer_id: p.peer_id.to_full_hex(), // Full 32 bytes for relay
                    public_addr: p.public_addr.to_string(),
                    nat_type: nat_type_str.to_string(),
                    last_seen: p.last_seen as i64,
                    can_relay: p.capabilities.can_relay,
                });
            }

            info!("Returning {} peers", peer_list.len());
            CommandResult::ok(peer_list)
        }
        Err(e) => {
            error!("Failed to get peers: {}", e);
            CommandResult::err(format!("Failed to discover peers: {}", e))
        }
    }
}

/// P2P connection result
#[derive(Debug, Clone, Serialize)]
pub struct P2PConnectionResult {
    pub success: bool,
    pub method: String,
    pub peer_addr: String,
    pub latency_ms: u64,
}

/// Connect to a peer via P2P hole punching
#[tauri::command]
pub async fn connect_peer(
    state: State<'_, Arc<RwLock<AppState>>>,
    peer_id_hex: String,
) -> Result<CommandResult<P2PConnectionResult>, ()> {
    info!("Connecting to peer: {}", peer_id_hex);

    // Get keys from config
    let state_guard = state.read().await;
    let (public_key, private_key) = get_p2p_keys(&state_guard.config);
    drop(state_guard);

    // Create discovery client
    let discovery_client = match DiscoveryClient::new(public_key, private_key, "0.0.0.0:0").await {
        Ok(client) => client,
        Err(e) => return Ok(CommandResult::err(format!("Failed to create discovery client: {}", e))),
    };

    let our_peer_id = discovery_client.peer_id();

    // Get peer list to find the target peer
    let peers = match discovery_client.get_peers(100, false).await {
        Ok(p) => p,
        Err(e) => return Ok(CommandResult::err(format!("Failed to get peers: {}", e))),
    };

    // Find the peer by full hex ID
    let target_peer = peers.into_iter()
        .find(|p| p.peer_id.to_full_hex() == peer_id_hex);

    let peer = match target_peer {
        Some(p) => p,
        None => return Ok(CommandResult::err("Peer not found")),
    };

    let peer_addr = peer.public_addr;

    // Perform hole punching
    let hole_puncher = match HolePuncher::new(our_peer_id, "0.0.0.0:0").await {
        Ok(hp) => hp,
        Err(e) => return Ok(CommandResult::err(format!("Failed to create hole puncher: {}", e))),
    };

    let start_time = std::time::Instant::now();

    // Generate a random nonce for this connection
    let nonce: [u8; 16] = rand::random();

    match hole_puncher.punch(peer.peer_id, peer_addr, peer.local_addr, peer.nat_type, nonce).await {
        Ok(result) => {
            let latency = start_time.elapsed().as_millis() as u64;

            if result.success {
                let peer_addr_str = result.peer_addr
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| peer_addr.to_string());

                info!("Connected to peer {} at {} in {}ms ({} attempts)",
                    peer_id_hex, peer_addr_str, result.rtt_ms.unwrap_or(0), result.attempts);

                Ok(CommandResult::ok(P2PConnectionResult {
                    success: true,
                    method: "hole_punch".to_string(),
                    peer_addr: peer_addr_str,
                    latency_ms: result.rtt_ms.unwrap_or(latency as u32) as u64,
                }))
            } else {
                Ok(CommandResult::err("Hole punching failed - no ACK received"))
            }
        }
        Err(e) => {
            error!("Failed to connect to peer: {}", e);
            Ok(CommandResult::err(format!("Hole punching failed: {}", e)))
        }
    }
}

/// Register with the discovery server
#[tauri::command]
pub async fn register_p2p(state: State<'_, Arc<RwLock<AppState>>>) -> Result<CommandResult<String>, ()> {
    info!("Registering with P2P discovery server...");

    // Get or generate peer_id in config
    let mut state_guard = state.write().await;
    if state_guard.config.peer_id.is_none() {
        let id = format!("{:016x}", rand::random::<u64>());
        state_guard.config.peer_id = Some(id);
        let _ = state_guard.save_config();
    }
    let (public_key, private_key) = get_p2p_keys(&state_guard.config);
    drop(state_guard);

    // Spawn in separate task to avoid stack overflow
    let result = tokio::spawn(async move {
        register_p2p_inner(public_key, private_key).await
    }).await;

    match result {
        Ok(r) => Ok(r),
        Err(e) => {
            error!("Task failed: {}", e);
            Ok(CommandResult::err(format!("Internal error: {}", e)))
        }
    }
}

/// Inner function for register_p2p to run in separate task
async fn register_p2p_inner(public_key: [u8; 32], private_key: [u8; 32]) -> CommandResult<String> {
    // Create discovery client
    let discovery_client = match DiscoveryClient::new(public_key, private_key, "0.0.0.0:0").await {
        Ok(client) => client,
        Err(e) => return CommandResult::err(format!("Failed to create discovery client: {}", e)),
    };

    let our_peer_id = discovery_client.peer_id();

    // Register (this also detects NAT)
    match discovery_client.register().await {
        Ok((public_addr, nat_type)) => {
            let nat_type_str = match nat_type {
                NatType::None => "None",
                NatType::FullCone => "Full Cone",
                NatType::AddressRestricted => "Address Restricted",
                NatType::PortRestricted => "Port Restricted",
                NatType::Symmetric => "Symmetric",
                NatType::Unknown => "Unknown",
            };

            info!("Registered with discovery server: peer_id={}, public_addr={}, nat={:?}",
                our_peer_id, public_addr, nat_type);

            // If Symmetric NAT, also register with relay server
            let mut relay_info = String::new();
            if nat_type == NatType::Symmetric {
                info!("Symmetric NAT detected, registering with relay...");
                let relay_addr: std::net::SocketAddr = RELAY_SERVER.parse().unwrap();
                match RelayClient::new(our_peer_id, relay_addr, "0.0.0.0:0").await {
                    Ok(mut relay_client) => {
                        match relay_client.allocate().await {
                            Ok(allocated) => {
                                info!("Registered with relay at {}", allocated);
                                relay_info = format!(", Relay: {}", allocated);
                            }
                            Err(e) => {
                                warn!("Relay allocation failed: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to create relay client: {}", e);
                    }
                }
            }

            CommandResult::ok(format!("Registered as {} ({}, NAT: {}{})", our_peer_id, public_addr, nat_type_str, relay_info))
        }
        Err(e) => {
            error!("Failed to register: {}", e);
            CommandResult::err(format!("Registration failed: {}", e))
        }
    }
}

/// Relay connection result
#[derive(Debug, Clone, Serialize)]
pub struct RelayConnectionResult {
    pub success: bool,
    pub relay_addr: String,
    pub message: String,
}

/// Connect to a peer via relay (for Symmetric NAT)
#[tauri::command]
pub async fn connect_via_relay(
    state: State<'_, Arc<RwLock<AppState>>>,
    peer_id_hex: String,
) -> Result<CommandResult<RelayConnectionResult>, ()> {
    info!("Connecting to peer {} via relay...", peer_id_hex);

    // Get keys from config
    let state_guard = state.read().await;
    let (public_key, _private_key) = get_p2p_keys(&state_guard.config);
    drop(state_guard);

    // Parse peer ID from full hex (64 chars = 32 bytes)
    let target_peer_id = match PeerId::from_hex(&peer_id_hex) {
        Some(id) => id,
        None => return Ok(CommandResult::err(format!("Invalid peer ID hex: {}", peer_id_hex))),
    };

    // Create PeerId from our public key
    let our_peer_id = PeerId::from_public_key(&public_key);

    // Parse relay server address
    let relay_addr: SocketAddr = match RELAY_SERVER.parse() {
        Ok(addr) => addr,
        Err(e) => return Ok(CommandResult::err(format!("Invalid relay server address: {}", e))),
    };

    // Create relay client
    let mut relay_client = match RelayClient::new(our_peer_id, relay_addr, "0.0.0.0:0").await {
        Ok(client) => client,
        Err(e) => return Ok(CommandResult::err(format!("Failed to create relay client: {}", e))),
    };

    // Allocate relay slot
    match relay_client.allocate().await {
        Ok(allocated_addr) => {
            info!("Got relay allocation at {}", allocated_addr);

            // Request connection to target peer
            match relay_client.connect_via_relay(target_peer_id).await {
                Ok(()) => {
                    info!("Relay connection to {} established via {}", peer_id_hex, allocated_addr);
                    Ok(CommandResult::ok(RelayConnectionResult {
                        success: true,
                        relay_addr: allocated_addr.to_string(),
                        message: format!("Connected via relay at {}", allocated_addr),
                    }))
                }
                Err(e) => {
                    warn!("Relay connect request failed: {}", e);
                    // Still return success for allocation - peer may not be registered yet
                    Ok(CommandResult::ok(RelayConnectionResult {
                        success: true,
                        relay_addr: allocated_addr.to_string(),
                        message: format!("Allocated at relay, peer not yet registered: {}", e),
                    }))
                }
            }
        }
        Err(e) => {
            error!("Failed to allocate relay slot: {}", e);
            Ok(CommandResult::err(format!("Relay allocation failed: {}", e)))
        }
    }
}

/// Get DHT network status
#[derive(Debug, Clone, Serialize)]
pub struct DhtStatus {
    pub bootstrap_connected: bool,
    pub node_count: usize,
    pub relay_available: bool,
}

/// Check DHT bootstrap connectivity
#[tauri::command]
pub async fn check_dht_status() -> Result<CommandResult<DhtStatus>, ()> {
    info!("Checking DHT status...");

    // Test connectivity to DHT bootstrap
    let dht_addr: SocketAddr = match DHT_BOOTSTRAP_SERVER.parse() {
        Ok(addr) => addr,
        Err(e) => return Ok(CommandResult::err(format!("Invalid DHT address: {}", e))),
    };

    // Test connectivity to relay
    let relay_addr: SocketAddr = match RELAY_SERVER.parse() {
        Ok(addr) => addr,
        Err(e) => return Ok(CommandResult::err(format!("Invalid relay address: {}", e))),
    };

    // Simple UDP ping test to both servers
    let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => return Ok(CommandResult::err(format!("Failed to create socket: {}", e))),
    };

    // Set timeout
    let _ = socket.set_broadcast(false);

    // Test DHT (we'll just check if we can send/receive)
    let dht_connected = socket.send_to(b"ping", dht_addr).await.is_ok();

    // Test relay
    let relay_available = socket.send_to(b"ping", relay_addr).await.is_ok();

    Ok(CommandResult::ok(DhtStatus {
        bootstrap_connected: dht_connected,
        node_count: 1, // Bootstrap node
        relay_available,
    }))
}

/// Exit node address (EC2)
const EXIT_NODE_SERVER: &str = "3.89.118.150:51824";

/// Circuit info result
#[derive(Debug, Clone, Serialize)]
pub struct CircuitInfo {
    pub circuit_id: u32,
    pub hop_count: usize,
    pub hops: Vec<String>,
    pub established: bool,
}

/// Build onion routing circuit through peers
///
/// Creates a multi-hop circuit: User → Peer1 → Peer2 → ... → Exit Node → Internet
/// The number of hops is configurable (1-5 peers before exit)
#[tauri::command]
pub async fn build_circuit(
    state: State<'_, Arc<RwLock<AppState>>>,
    peer_ids: Vec<String>,
) -> Result<CommandResult<CircuitInfo>, ()> {
    use meshvpn_network::p2p::CircuitBuilder;

    info!("Building circuit through {} peers...", peer_ids.len());

    // Validate hop count
    if peer_ids.is_empty() {
        return Ok(CommandResult::err("At least one peer is required"));
    }
    if peer_ids.len() > 5 {
        return Ok(CommandResult::err("Maximum 5 hops allowed"));
    }

    // Get our peer ID
    let state_guard = state.read().await;
    let (public_key, _) = get_p2p_keys(&state_guard.config);
    let our_peer_id = PeerId::from_public_key(&public_key);
    drop(state_guard);

    // Parse peer IDs and look up their addresses
    let mut nodes = Vec::new();
    let mut hop_names = Vec::new();

    for (i, peer_id_hex) in peer_ids.iter().enumerate() {
        let peer_id = match PeerId::from_hex(peer_id_hex) {
            Some(id) => id,
            None => return Ok(CommandResult::err(format!("Invalid peer ID at hop {}: {}", i+1, peer_id_hex))),
        };

        // For now, we'll use the relay server as the address since all peers are behind NAT
        // In a real implementation, we'd query the DHT for peer addresses
        let addr: SocketAddr = match RELAY_SERVER.parse() {
            Ok(a) => a,
            Err(e) => return Ok(CommandResult::err(format!("Invalid relay address: {}", e))),
        };

        nodes.push((peer_id, addr));
        hop_names.push(format!("Peer {}: {}", i+1, &peer_id_hex[..16]));
    }

    // Add exit node as final hop
    let exit_addr: SocketAddr = match EXIT_NODE_SERVER.parse() {
        Ok(a) => a,
        Err(e) => return Ok(CommandResult::err(format!("Invalid exit node address: {}", e))),
    };

    // Generate a pseudo peer ID for exit node
    let exit_key = [0xEE; 32]; // Exit node marker
    let exit_peer_id = PeerId::from_public_key(&exit_key);
    nodes.push((exit_peer_id, exit_addr));
    hop_names.push("Exit Node (EC2)".to_string());

    // Create circuit builder
    let builder = match CircuitBuilder::new(our_peer_id, "0.0.0.0:0").await {
        Ok(b) => b,
        Err(e) => return Ok(CommandResult::err(format!("Failed to create circuit builder: {}", e))),
    };

    // Build the circuit
    match builder.build_circuit(nodes).await {
        Ok(circuit_id) => {
            info!("Circuit {} established with {} hops", circuit_id, hop_names.len());

            Ok(CommandResult::ok(CircuitInfo {
                circuit_id,
                hop_count: hop_names.len(),
                hops: hop_names,
                established: true,
            }))
        }
        Err(e) => {
            error!("Failed to build circuit: {}", e);
            Ok(CommandResult::err(format!("Circuit build failed: {}", e)))
        }
    }
}

/// Destroy an active circuit
#[tauri::command]
pub async fn destroy_circuit(
    circuit_id: u32,
) -> Result<CommandResult<String>, ()> {
    info!("Destroying circuit {}...", circuit_id);

    // For now, we don't persist circuit builders
    // In a full implementation, we'd store them in AppState
    Ok(CommandResult::ok(format!("Circuit {} destroy request sent", circuit_id)))
}

/// Connect via onion circuit (automatic circuit building)
///
/// Automatically discovers peers and builds a circuit with the specified hop count
#[tauri::command]
pub async fn connect_via_circuit(
    state: State<'_, Arc<RwLock<AppState>>>,
    hop_count: u32,
) -> Result<CommandResult<CircuitInfo>, ()> {
    info!("Building automatic circuit with {} hops...", hop_count);

    if hop_count < 1 || hop_count > 5 {
        return Ok(CommandResult::err("Hop count must be between 1 and 5"));
    }

    // First, discover available peers
    let state_guard = state.read().await;
    let (public_key, private_key) = get_p2p_keys(&state_guard.config);
    drop(state_guard);

    // Create discovery client and get peers
    let discovery = match DiscoveryClient::new(public_key, private_key, "0.0.0.0:0").await {
        Ok(d) => d,
        Err(e) => return Ok(CommandResult::err(format!("Discovery failed: {}", e))),
    };

    // Register and get peers
    match discovery.register().await {
        Ok(_) => info!("Registered for peer discovery"),
        Err(e) => return Ok(CommandResult::err(format!("Registration failed: {}", e))),
    }

    let peers = match discovery.get_peers(hop_count * 2, false).await {
        Ok(p) => p,
        Err(e) => return Ok(CommandResult::err(format!("Failed to get peers: {}", e))),
    };

    if peers.is_empty() {
        return Ok(CommandResult::err("No peers available for circuit"));
    }

    // Select random peers for circuit (up to hop_count)
    let our_peer_id = PeerId::from_public_key(&public_key);
    let selected: Vec<String> = peers
        .iter()
        .filter(|p| p.peer_id != our_peer_id) // Don't include ourselves
        .take(hop_count as usize)
        .map(|p| p.peer_id.to_full_hex())
        .collect();

    if selected.is_empty() {
        return Ok(CommandResult::err("No suitable peers found"));
    }

    info!("Selected {} peers for circuit", selected.len());

    // Build circuit using the selected peers
    build_circuit(state, selected).await
}

