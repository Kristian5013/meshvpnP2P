//! Daemon mode for background operation

use anyhow::Result;
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tracing::{info, debug, error};

use crate::config::ClientConfig;
use crate::client::MeshVpnClient;

/// Socket path for IPC
#[cfg(unix)]
const SOCKET_PATH: &str = "/tmp/meshvpn.sock";
#[cfg(windows)]
const SOCKET_PATH: &str = r"\\.\pipe\meshvpn";

/// Status response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub state: String,
    pub connected: bool,
    pub public_ip: Option<String>,
    pub current_circuit: Option<CircuitInfo>,
    pub uptime_secs: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// Circuit info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitInfo {
    pub id: u32,
    pub hop_count: usize,
    pub exit_node: String,
    pub exit_region: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub age_secs: u64,
}

/// Relay statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayStats {
    pub enabled: bool,
    pub active_circuits: usize,
    pub total_bytes: u64,
    pub bandwidth_limit: u64,
}

/// IPC commands
#[derive(Debug, Clone, Serialize, Deserialize)]
enum IpcCommand {
    Status,
    Stop,
    GetCircuits,
    GetRelayStats,
}

/// IPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
enum IpcResponse {
    Status(StatusResponse),
    Circuits(Vec<CircuitInfo>),
    RelayStats(RelayStats),
    Ok,
    Error(String),
}

/// Run the client as a daemon
pub async fn run_daemon(config: ClientConfig) -> Result<()> {
    info!("Starting MeshVPN daemon...");

    // Create client
    let client = MeshVpnClient::new(config).await?;

    // Start client
    client.start().await?;

    // Start IPC server
    let ipc_handle = tokio::spawn(run_ipc_server());

    // Wait for shutdown
    tokio::signal::ctrl_c().await?;

    info!("Daemon shutting down...");
    client.stop().await?;
    ipc_handle.abort();

    Ok(())
}

/// Run the IPC server for receiving commands
async fn run_ipc_server() -> Result<()> {
    // Remove old socket
    #[cfg(unix)]
    let _ = std::fs::remove_file(SOCKET_PATH);

    #[cfg(unix)]
    let listener = UnixListener::bind(SOCKET_PATH)?;

    info!("IPC server listening on {}", SOCKET_PATH);

    #[cfg(unix)]
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(handle_ipc_connection(stream));
            }
            Err(e) => {
                error!("IPC accept error: {}", e);
            }
        }
    }

    #[cfg(windows)]
    {
        // Windows named pipe implementation would go here
        // For now, just wait forever
        std::future::pending::<()>().await;
        Ok(())
    }
}

#[cfg(unix)]
async fn handle_ipc_connection(mut stream: UnixStream) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await?;

    if n == 0 {
        return Ok(());
    }

    let command: IpcCommand = serde_json::from_slice(&buf[..n])?;
    debug!("IPC command: {:?}", command);

    let response = match command {
        IpcCommand::Status => {
            // TODO: Get actual status from client
            IpcResponse::Status(StatusResponse {
                state: "running".to_string(),
                connected: true,
                public_ip: Some("1.2.3.4".to_string()),
                current_circuit: Some(CircuitInfo {
                    id: 12345,
                    hop_count: 3,
                    exit_node: "exit1".to_string(),
                    exit_region: "us-east".to_string(),
                    bytes_sent: 1024 * 1024,
                    bytes_received: 2048 * 1024,
                    age_secs: 300,
                }),
                uptime_secs: 3600,
                bytes_sent: 10 * 1024 * 1024,
                bytes_received: 50 * 1024 * 1024,
            })
        }
        IpcCommand::Stop => {
            // TODO: Trigger shutdown
            IpcResponse::Ok
        }
        IpcCommand::GetCircuits => {
            // TODO: Get actual circuits
            IpcResponse::Circuits(vec![])
        }
        IpcCommand::GetRelayStats => {
            // TODO: Get actual relay stats
            IpcResponse::RelayStats(RelayStats {
                enabled: true,
                active_circuits: 5,
                total_bytes: 100 * 1024 * 1024,
                bandwidth_limit: 0,
            })
        }
    };

    let response_bytes = serde_json::to_vec(&response)?;
    stream.write_all(&response_bytes).await?;

    Ok(())
}

/// Send a command to the daemon
async fn send_command(command: IpcCommand) -> Result<IpcResponse> {
    #[cfg(unix)]
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = UnixStream::connect(SOCKET_PATH).await?;

        let command_bytes = serde_json::to_vec(&command)?;
        stream.write_all(&command_bytes).await?;

        let mut buf = vec![0u8; 65536];
        let n = stream.read(&mut buf).await?;

        let response: IpcResponse = serde_json::from_slice(&buf[..n])?;
        Ok(response)
    }

    #[cfg(windows)]
    {
        anyhow::bail!("Windows IPC not yet implemented")
    }
}

/// Get daemon status
pub async fn get_status() -> Result<StatusResponse> {
    match send_command(IpcCommand::Status).await? {
        IpcResponse::Status(status) => Ok(status),
        IpcResponse::Error(e) => anyhow::bail!(e),
        _ => anyhow::bail!("Unexpected response"),
    }
}

/// Send stop signal to daemon
pub async fn send_stop_signal() -> Result<()> {
    match send_command(IpcCommand::Stop).await? {
        IpcResponse::Ok => Ok(()),
        IpcResponse::Error(e) => anyhow::bail!(e),
        _ => anyhow::bail!("Unexpected response"),
    }
}

/// Get circuit information
pub async fn get_circuits() -> Result<Vec<CircuitInfo>> {
    match send_command(IpcCommand::GetCircuits).await? {
        IpcResponse::Circuits(circuits) => Ok(circuits),
        IpcResponse::Error(e) => anyhow::bail!(e),
        _ => anyhow::bail!("Unexpected response"),
    }
}

/// Get relay statistics
pub async fn get_relay_stats() -> Result<RelayStats> {
    match send_command(IpcCommand::GetRelayStats).await? {
        IpcResponse::RelayStats(stats) => Ok(stats),
        IpcResponse::Error(e) => anyhow::bail!(e),
        _ => anyhow::bail!("Unexpected response"),
    }
}
