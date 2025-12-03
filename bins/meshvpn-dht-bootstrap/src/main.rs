//! MeshVPN DHT Bootstrap Node
//!
//! This node serves as an entry point for peers to join the DHT network.
//! It also runs a relay service for peers behind Symmetric NAT.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use tokio::sync::RwLock;
use tracing::{info, warn, error, Level};
use tracing_subscriber::FmtSubscriber;

use meshvpn_crypto::NodeIdentity;
use meshvpn_dht::{DhtNode, DhtNetwork, NodeStatus};
use meshvpn_network::p2p::RelayServer;

/// MeshVPN DHT Bootstrap Node
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// DHT listen address
    #[arg(short, long, default_value = "0.0.0.0:51822")]
    listen: String,

    /// Relay service listen address
    #[arg(short, long, default_value = "0.0.0.0:51823")]
    relay: String,

    /// Other bootstrap nodes (comma-separated)
    #[arg(short, long)]
    bootstrap: Option<String>,

    /// Identity file path
    #[arg(short, long)]
    identity: Option<String>,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Setup logging
    let level = match args.log_level.as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting MeshVPN DHT Bootstrap Node...");
    info!("DHT listen: {}", args.listen);
    info!("Relay listen: {}", args.relay);

    // Load or generate identity
    let identity = if let Some(path) = &args.identity {
        if std::path::Path::new(path).exists() {
            let data = std::fs::read(path)?;
            // Format: 32 bytes signing key + 32 bytes encryption key
            if data.len() != 64 {
                return Err(anyhow::anyhow!("Invalid identity file format"));
            }
            let mut signing_key = [0u8; 32];
            let mut encryption_key = [0u8; 32];
            signing_key.copy_from_slice(&data[..32]);
            encryption_key.copy_from_slice(&data[32..]);
            NodeIdentity::from_keys(signing_key, encryption_key)
                .map_err(|e| anyhow::anyhow!("Failed to load identity: {}", e))?
        } else {
            let identity = NodeIdentity::generate();
            let (signing_key, encryption_key) = identity.export_secrets();
            let mut data = Vec::with_capacity(64);
            data.extend_from_slice(&signing_key);
            data.extend_from_slice(&encryption_key);
            std::fs::write(path, &data)?;
            info!("Generated new identity and saved to {}", path);
            identity
        }
    } else {
        info!("No identity file specified, generating ephemeral identity");
        NodeIdentity::generate()
    };

    info!("Node ID: {:?}", identity.node_id());

    // Parse bootstrap nodes
    let bootstrap_nodes: Vec<SocketAddr> = if let Some(bootstrap) = &args.bootstrap {
        bootstrap
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect()
    } else {
        Vec::new()
    };

    info!("Bootstrap nodes: {:?}", bootstrap_nodes);

    // Get our addresses
    let dht_addr: SocketAddr = args.listen.parse()?;
    let relay_addr: SocketAddr = args.relay.parse()?;

    let our_addresses = vec![dht_addr];

    // Create DHT node
    let dht_node = DhtNode::new(identity, our_addresses);

    // Create DHT network
    let mut dht_network = DhtNetwork::new(dht_node, &args.listen, bootstrap_nodes)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create DHT network: {}", e))?;

    // Start DHT
    dht_network.start()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start DHT: {}", e))?;

    info!("DHT network started");

    // Start relay server
    let relay_server = RelayServer::new(&args.relay)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create relay server: {}", e))?;

    // Spawn relay server
    let relay_server = Arc::new(relay_server);
    let relay_clone = relay_server.clone();

    tokio::spawn(async move {
        if let Err(e) = relay_clone.run().await {
            error!("Relay server error: {}", e);
        }
    });

    info!("Relay server started");

    // Stats loop
    let dht_network = Arc::new(RwLock::new(dht_network));

    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;

        let dht = dht_network.read().await;
        let node_count = dht.node_count().await;
        let relay_stats = relay_server.stats().await;

        info!(
            "Stats: {} DHT nodes, {} relay allocations, {} bytes relayed",
            node_count,
            relay_stats.active_allocations,
            relay_stats.total_bytes_relayed
        );

        // Announce ourselves periodically
        if let Err(e) = dht.announce().await {
            warn!("Failed to announce: {}", e);
        }
    }
}
