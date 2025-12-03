//! MeshVPN Client implementation

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::RwLock;
use tracing::{info, debug, warn};

use meshvpn_crypto::NodeIdentity;
use meshvpn_core::{CircuitManager, CoreConfig};
use meshvpn_dht::DhtNode;

use crate::config::ClientConfig;

/// Exit node information for listing
#[derive(Debug, Clone)]
pub struct ExitNodeInfo {
    pub node_id: meshvpn_crypto::NodeId,
    pub region: Option<String>,
    pub load: u8,
    pub latency: Option<u32>,
    pub status: meshvpn_dht::NodeStatus,
}

/// Connectivity test result
#[derive(Debug)]
pub struct ConnectivityResult {
    pub public_ip: String,
    pub latency_ms: u32,
    pub exit_node: String,
}

/// Main MeshVPN client
pub struct MeshVpnClient {
    config: ClientConfig,
    identity: NodeIdentity,
    circuit_manager: Arc<CircuitManager>,
    dht: Arc<RwLock<DhtNode>>,
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl MeshVpnClient {
    /// Create a new client
    pub async fn new(config: ClientConfig) -> Result<Self> {
        // Load or generate identity
        let identity = Self::load_or_generate_identity(&config).await?;
        info!("Node ID: {}", identity.node_id());

        // Create circuit manager
        let circuit_manager = Arc::new(CircuitManager::new(
            config.circuit.hop_count.max(10),
        ));

        // Create DHT node
        let listen_addr = format!("0.0.0.0:{}", config.network.listen_port)
            .parse()
            .unwrap();
        let dht = DhtNode::new(identity.clone(), vec![listen_addr]);

        Ok(Self {
            config,
            identity,
            circuit_manager,
            dht: Arc::new(RwLock::new(dht)),
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Load identity from disk or generate new one
    async fn load_or_generate_identity(config: &ClientConfig) -> Result<NodeIdentity> {
        let identity_path = directories::BaseDirs::new()
            .map(|d| d.home_dir().join(".meshvpn").join("identity.key"))
            .unwrap_or_else(|| std::path::PathBuf::from("identity.key"));

        if identity_path.exists() {
            let data = tokio::fs::read(&identity_path).await?;
            if data.len() == 64 {
                let mut signing = [0u8; 32];
                let mut encryption = [0u8; 32];
                signing.copy_from_slice(&data[..32]);
                encryption.copy_from_slice(&data[32..]);
                return Ok(NodeIdentity::from_keys(signing, encryption)?);
            }
        }

        // Generate new identity
        let identity = NodeIdentity::generate();
        info!("Generated new identity");

        // Save it
        if let Some(parent) = identity_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let (signing, encryption) = identity.export_secrets();
        let data = [signing, encryption].concat();
        tokio::fs::write(&identity_path, &data).await?;

        Ok(identity)
    }

    /// Start the VPN client
    pub async fn start(&self) -> Result<()> {
        info!("Starting MeshVPN client...");
        self.running.store(true, std::sync::atomic::Ordering::SeqCst);

        // Bootstrap DHT
        self.bootstrap_dht().await?;

        // Build initial circuit
        self.build_circuit().await?;

        // Start TUN device
        self.start_tun().await?;

        // Start relay if enabled
        if self.config.relay.enabled {
            self.start_relay().await?;
        }

        info!("MeshVPN started successfully");
        Ok(())
    }

    /// Stop the VPN client
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping MeshVPN client...");
        self.running.store(false, std::sync::atomic::Ordering::SeqCst);

        // Cleanup circuits
        // Stop TUN device
        // Announce departure to DHT

        info!("MeshVPN stopped");
        Ok(())
    }

    /// Bootstrap the DHT with known nodes
    async fn bootstrap_dht(&self) -> Result<()> {
        info!("Bootstrapping DHT...");

        let bootstrap_nodes: Vec<_> = self.config.bootstrap.nodes
            .iter()
            .chain(self.config.bootstrap.custom_nodes.iter())
            .collect();

        if bootstrap_nodes.is_empty() {
            warn!("No bootstrap nodes configured!");
            return Ok(());
        }

        for node_addr in bootstrap_nodes {
            debug!("Contacting bootstrap node: {}", node_addr);
            // TODO: Implement actual bootstrap
        }

        info!("DHT bootstrap complete");
        Ok(())
    }

    /// Build a circuit through relay nodes to an exit
    async fn build_circuit(&self) -> Result<()> {
        info!("Building circuit with {} hops...", self.config.circuit.hop_count);

        // TODO: Implement actual circuit building
        // 1. Query DHT for relay nodes
        // 2. Select path using PathSelector
        // 3. Perform handshakes with each hop
        // 4. Build circuit

        info!("Circuit built successfully");
        Ok(())
    }

    /// Start the TUN device and route traffic
    async fn start_tun(&self) -> Result<()> {
        info!("Starting TUN device: {}", self.config.network.tun_name);

        // TODO: Implement actual TUN setup
        // This requires platform-specific code

        Ok(())
    }

    /// Start relay functionality
    async fn start_relay(&self) -> Result<()> {
        info!("Starting relay (max {} circuits)", self.config.relay.max_circuits);

        // TODO: Implement relay
        // Announce ourselves to DHT as relay

        Ok(())
    }

    /// List available exit nodes
    pub async fn list_exit_nodes(&self, region: Option<&str>) -> Result<Vec<ExitNodeInfo>> {
        debug!("Querying exit nodes (region: {:?})", region);

        // TODO: Query DHT for exit nodes
        // For now, return mock data
        Ok(vec![])
    }

    /// Test connectivity through the VPN
    pub async fn test_connectivity(&self, target: &str) -> Result<ConnectivityResult> {
        debug!("Testing connectivity to: {}", target);

        // TODO: Implement actual connectivity test
        // Make request through circuit

        Ok(ConnectivityResult {
            public_ip: "Unknown".to_string(),
            latency_ms: 0,
            exit_node: "Unknown".to_string(),
        })
    }
}
