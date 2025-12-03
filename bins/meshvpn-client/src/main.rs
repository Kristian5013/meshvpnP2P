//! MeshVPN Client
//!
//! Privacy-focused P2P VPN client that routes traffic through
//! multiple relay nodes before reaching exit nodes.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::sync::RwLock;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

mod config;
mod client;
mod daemon;

use config::ClientConfig;
use client::MeshVpnClient;

/// MeshVPN - Privacy-focused P2P VPN
#[derive(Parser)]
#[command(name = "meshvpn")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Config file path
    #[arg(short, long, default_value = "~/.meshvpn/config.toml")]
    config: PathBuf,

    /// Log level
    #[arg(short, long, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the VPN client
    Start {
        /// Number of relay hops (1-5)
        #[arg(short, long, default_value = "3")]
        hops: usize,

        /// Preferred exit region (e.g., "us-east", "eu-west")
        #[arg(short, long)]
        region: Option<String>,

        /// Run as daemon
        #[arg(short, long)]
        daemon: bool,
    },

    /// Stop the VPN client
    Stop,

    /// Show current status
    Status,

    /// Generate new identity
    Init {
        /// Force overwrite existing identity
        #[arg(short, long)]
        force: bool,
    },

    /// List available exit nodes
    ListExits {
        /// Filter by region
        #[arg(short, long)]
        region: Option<String>,
    },

    /// Show circuit information
    Circuits,

    /// Show relay statistics (if relay is enabled)
    RelayStats,

    /// Test connectivity
    Test {
        /// Target to test (default: check.meshvpn.net)
        #[arg(default_value = "check.meshvpn.net")]
        target: String,
    },

    /// Show configuration
    Config,
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
        .with_target(false)
        .with_thread_ids(false)
        .compact()
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .context("Failed to set tracing subscriber")?;

    // Expand config path
    let config_path = expand_path(&cli.config)?;

    match cli.command {
        Commands::Start { hops, region, daemon } => {
            cmd_start(config_path, hops, region, daemon).await
        }
        Commands::Stop => cmd_stop().await,
        Commands::Status => cmd_status().await,
        Commands::Init { force } => cmd_init(config_path, force).await,
        Commands::ListExits { region } => cmd_list_exits(config_path, region).await,
        Commands::Circuits => cmd_circuits().await,
        Commands::RelayStats => cmd_relay_stats().await,
        Commands::Test { target } => cmd_test(config_path, target).await,
        Commands::Config => cmd_config(config_path).await,
    }
}

async fn cmd_start(config_path: PathBuf, hops: usize, region: Option<String>, daemon: bool) -> Result<()> {
    info!("Starting MeshVPN...");

    // Load or create config
    let mut config = ClientConfig::load_or_create(&config_path).await?;
    config.circuit.hop_count = hops;
    if let Some(r) = region {
        config.circuit.preferred_region = Some(r);
    }

    // Validate
    config.validate()?;

    if daemon {
        info!("Running as daemon...");
        daemon::run_daemon(config).await
    } else {
        // Run in foreground
        let client = MeshVpnClient::new(config).await?;
        client.start().await?;

        // Wait for shutdown signal
        tokio::signal::ctrl_c().await?;
        info!("Shutting down...");
        client.stop().await?;
        Ok(())
    }
}

async fn cmd_stop() -> Result<()> {
    info!("Stopping MeshVPN...");
    daemon::send_stop_signal().await
}

async fn cmd_status() -> Result<()> {
    match daemon::get_status().await {
        Ok(status) => {
            println!("MeshVPN Status");
            println!("==============");
            println!("State: {}", status.state);
            println!("Connected: {}", status.connected);
            if let Some(ip) = status.public_ip {
                println!("Public IP: {}", ip);
            }
            if let Some(circuit) = status.current_circuit {
                println!("Circuit: {} hops", circuit.hop_count);
                println!("Exit: {} ({})", circuit.exit_node, circuit.exit_region);
            }
            println!("Uptime: {} seconds", status.uptime_secs);
            println!("Traffic: {} sent, {} received",
                     format_bytes(status.bytes_sent),
                     format_bytes(status.bytes_received));
            Ok(())
        }
        Err(_) => {
            println!("MeshVPN is not running");
            Ok(())
        }
    }
}

async fn cmd_init(config_path: PathBuf, force: bool) -> Result<()> {
    let config_dir = config_path.parent().unwrap_or(&config_path);

    if config_path.exists() && !force {
        anyhow::bail!(
            "Config already exists at {:?}. Use --force to overwrite.",
            config_path
        );
    }

    // Create directory
    tokio::fs::create_dir_all(config_dir).await?;

    // Generate identity
    let identity = meshvpn_crypto::NodeIdentity::generate();
    let node_id = identity.node_id();

    info!("Generated new identity: {}", node_id);

    // Save identity
    let identity_path = config_dir.join("identity.key");
    let (signing, encryption) = identity.export_secrets();
    let identity_data = [signing, encryption].concat();
    tokio::fs::write(&identity_path, &identity_data).await?;

    info!("Identity saved to {:?}", identity_path);

    // Create default config
    let config = ClientConfig::default();
    config.save(&config_path).await?;

    info!("Config saved to {:?}", config_path);

    println!("\nMeshVPN initialized successfully!");
    println!("Node ID: {}", node_id);
    println!("\nYou can now start the VPN with: meshvpn start");

    Ok(())
}

async fn cmd_list_exits(config_path: PathBuf, region: Option<String>) -> Result<()> {
    let config = ClientConfig::load(&config_path).await?;
    let client = MeshVpnClient::new(config).await?;

    println!("Fetching exit nodes...\n");

    let exits = client.list_exit_nodes(region.as_deref()).await?;

    if exits.is_empty() {
        println!("No exit nodes found");
        return Ok(());
    }

    println!("{:<20} {:<15} {:<10} {:<10} {:<10}",
             "Node ID", "Region", "Load", "Latency", "Status");
    println!("{}", "-".repeat(65));

    for exit in exits {
        println!("{:<20} {:<15} {:<10} {:<10} {:<10}",
                 &exit.node_id.to_hex()[..16],
                 exit.region.as_deref().unwrap_or("unknown"),
                 format!("{}%", exit.load),
                 exit.latency.map(|l| format!("{}ms", l)).unwrap_or_else(|| "?".to_string()),
                 format!("{:?}", exit.status));
    }

    Ok(())
}

async fn cmd_circuits() -> Result<()> {
    match daemon::get_circuits().await {
        Ok(circuits) => {
            if circuits.is_empty() {
                println!("No active circuits");
                return Ok(());
            }

            println!("{:<12} {:<8} {:<15} {:<15} {:<10}",
                     "Circuit ID", "Hops", "Sent", "Received", "Age");
            println!("{}", "-".repeat(60));

            for circuit in circuits {
                println!("{:<12} {:<8} {:<15} {:<15} {:<10}",
                         circuit.id,
                         circuit.hop_count,
                         format_bytes(circuit.bytes_sent),
                         format_bytes(circuit.bytes_received),
                         format!("{}s", circuit.age_secs));
            }

            Ok(())
        }
        Err(_) => {
            println!("MeshVPN is not running");
            Ok(())
        }
    }
}

async fn cmd_relay_stats() -> Result<()> {
    match daemon::get_relay_stats().await {
        Ok(stats) => {
            println!("Relay Statistics");
            println!("================");
            println!("Enabled: {}", stats.enabled);
            println!("Active circuits: {}", stats.active_circuits);
            println!("Total relayed: {}", format_bytes(stats.total_bytes));
            println!("Bandwidth limit: {}",
                     if stats.bandwidth_limit == 0 {
                         "unlimited".to_string()
                     } else {
                         format!("{}/s", format_bytes(stats.bandwidth_limit))
                     });
            Ok(())
        }
        Err(_) => {
            println!("MeshVPN is not running");
            Ok(())
        }
    }
}

async fn cmd_test(config_path: PathBuf, target: String) -> Result<()> {
    println!("Testing MeshVPN connectivity...\n");

    let config = ClientConfig::load(&config_path).await?;
    let client = MeshVpnClient::new(config).await?;

    match client.test_connectivity(&target).await {
        Ok(result) => {
            println!("✓ Connection successful");
            println!("  Public IP: {}", result.public_ip);
            println!("  Latency: {}ms", result.latency_ms);
            println!("  Exit node: {}", result.exit_node);
        }
        Err(e) => {
            println!("✗ Connection failed: {}", e);
        }
    }

    Ok(())
}

async fn cmd_config(config_path: PathBuf) -> Result<()> {
    let config = ClientConfig::load(&config_path).await?;
    let toml = toml::to_string_pretty(&config)?;
    println!("{}", toml);
    Ok(())
}

// Helper functions

fn expand_path(path: &PathBuf) -> Result<PathBuf> {
    let path_str = path.to_string_lossy();
    if path_str.starts_with("~/") {
        let home = directories::BaseDirs::new()
            .context("Failed to get home directory")?
            .home_dir()
            .to_path_buf();
        Ok(home.join(&path_str[2..]))
    } else {
        Ok(path.clone())
    }
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
