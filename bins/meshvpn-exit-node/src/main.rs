//! MeshVPN Exit Node
//!
//! Runs on controlled EC2 instances to provide exit points for the VPN network.
//! Supports both legacy config-based mode and simple circuit mode.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use meshvpn_exit::{ExitConfig, ExitNode};
use meshvpn_network::p2p::{CircuitNode, PeerId};

/// MeshVPN Exit Node
#[derive(Parser)]
#[command(name = "meshvpn-exit")]
#[command(author, version, about)]
struct Cli {
    /// Config file path
    #[arg(short, long, default_value = "/etc/meshvpn/exit.toml")]
    config: PathBuf,

    /// Log level
    #[arg(short, long, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the exit node (legacy mode with config)
    Start,

    /// Start in simple circuit mode (no config needed)
    Circuit {
        /// Listen address for circuit messages
        #[arg(short, long, default_value = "0.0.0.0:51824")]
        listen: String,
    },

    /// Stop the exit node
    Stop,

    /// Show status
    Status,

    /// Generate default config
    GenConfig {
        /// Output path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
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

    match cli.command {
        Commands::Start => cmd_start(cli.config).await,
        Commands::Circuit { listen } => cmd_circuit(listen).await,
        Commands::Stop => cmd_stop().await,
        Commands::Status => cmd_status().await,
        Commands::GenConfig { output } => cmd_gen_config(output).await,
    }
}

/// Start in circuit mode - simple onion routing exit node
async fn cmd_circuit(listen_addr: String) -> Result<()> {
    info!("Starting MeshVPN Exit Node in circuit mode...");
    info!("Listen address: {}", listen_addr);

    // Generate a random peer ID for the exit node
    let exit_key: [u8; 32] = rand::random();
    let peer_id = PeerId::from_public_key(&exit_key);

    info!("Exit node peer ID: {}", peer_id);

    // Create circuit node in exit mode
    let circuit_node = CircuitNode::new(peer_id, &listen_addr, true)
        .await
        .context("Failed to create circuit node")?;

    let local_addr = circuit_node.local_addr()
        .context("Failed to get local address")?;

    info!("Circuit exit node listening on {}", local_addr);
    info!("Ready to accept circuit connections");

    // Run the circuit node
    let node = Arc::new(circuit_node);
    let node_clone = node.clone();

    // Handle shutdown signal
    let shutdown_handle = tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Shutdown signal received");
        node_clone.stop();
    });

    // Run the node
    if let Err(e) = node.run().await {
        warn!("Circuit node stopped: {}", e);
    }

    shutdown_handle.abort();
    info!("Exit node stopped");

    Ok(())
}

async fn cmd_start(config_path: PathBuf) -> Result<()> {
    info!("Starting MeshVPN Exit Node (legacy mode)...");

    // Load config
    let config = load_config(&config_path).await?;

    info!("Region: {}", config.region);
    info!("Interface: {}", config.outbound_interface);

    // Create exit node
    let _exit_node = ExitNode::new(config).await?;

    info!("Exit node started");

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;

    info!("Shutting down...");
    Ok(())
}

async fn cmd_stop() -> Result<()> {
    info!("Stopping exit node...");
    // TODO: Send stop signal to running daemon
    Ok(())
}

async fn cmd_status() -> Result<()> {
    println!("Exit node status: TODO");
    Ok(())
}

async fn cmd_gen_config(output: Option<PathBuf>) -> Result<()> {
    let config = ExitConfig::default();
    let toml = toml::to_string_pretty(&config)?;

    if let Some(path) = output {
        tokio::fs::write(&path, &toml).await?;
        println!("Config written to {:?}", path);
    } else {
        println!("{}", toml);
    }

    Ok(())
}

async fn load_config(path: &PathBuf) -> Result<ExitConfig> {
    let contents = tokio::fs::read_to_string(path)
        .await
        .context("Failed to read config file")?;

    toml::from_str(&contents).context("Failed to parse config")
}
