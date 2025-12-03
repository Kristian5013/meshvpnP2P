//! MeshVPN Bootstrap Node
//!
//! Minimal DHT bootstrap server for initial peer discovery.

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use meshvpn_crypto::NodeIdentity;
use meshvpn_dht::DhtNode;

/// MeshVPN Bootstrap Node
#[derive(Parser)]
#[command(name = "meshvpn-bootstrap")]
#[command(author, version, about)]
struct Cli {
    /// Listen address
    #[arg(short, long, default_value = "0.0.0.0:51820")]
    listen: String,

    /// Identity file
    #[arg(short, long, default_value = "/etc/meshvpn/bootstrap.key")]
    identity: PathBuf,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = match cli.log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting MeshVPN Bootstrap Node...");

    // Load or generate identity
    let identity = load_or_generate_identity(&cli.identity).await?;
    info!("Node ID: {}", identity.node_id());

    // Parse listen address
    let listen_addr: std::net::SocketAddr = cli.listen.parse()?;
    info!("Listening on {}", listen_addr);

    // Create DHT node
    let dht = DhtNode::new(identity, vec![listen_addr]);

    info!("Bootstrap node started");
    info!("Share this address with clients: {}", listen_addr);

    // Wait for shutdown
    tokio::signal::ctrl_c().await?;

    info!("Shutting down...");
    Ok(())
}

async fn load_or_generate_identity(path: &PathBuf) -> Result<NodeIdentity> {
    if path.exists() {
        let data = tokio::fs::read(path).await?;
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
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let (signing, encryption) = identity.export_secrets();
    let data = [signing, encryption].concat();
    tokio::fs::write(path, &data).await?;

    Ok(identity)
}
