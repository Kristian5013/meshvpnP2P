//! WireGuard protocol implementation using boringtun
//!
//! This module provides a userspace WireGuard implementation for connecting
//! to standard WireGuard servers.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{info, debug, warn};

use crate::error::{NetworkError, NetworkResult};
use crate::tun::TunDevice;

/// WireGuard configuration
#[derive(Debug, Clone)]
pub struct WireGuardConfig {
    /// Our private key (base64)
    pub private_key: String,
    /// Server's public key (base64)
    pub server_public_key: String,
    /// Server endpoint (ip:port)
    pub endpoint: SocketAddr,
    /// Our VPN IP address
    pub address: Ipv4Addr,
    /// Netmask
    pub netmask: Ipv4Addr,
    /// Persistent keepalive interval (seconds)
    pub keepalive: Option<u16>,
}

/// WireGuard tunnel client
pub struct WireGuardClient {
    /// The tunnel state
    tunnel: Arc<Mutex<Tunn>>,
    /// UDP socket for WireGuard packets
    socket: Arc<UdpSocket>,
    /// Server endpoint
    endpoint: SocketAddr,
    /// TUN device
    tun: Arc<dyn TunDevice>,
    /// Running flag
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl WireGuardClient {
    /// Create a new WireGuard client
    pub async fn new(
        config: WireGuardConfig,
        tun: Box<dyn TunDevice>,
    ) -> NetworkResult<Self> {
        // Decode keys
        let private_key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&config.private_key)
            .map_err(|e| NetworkError::ConfigError(format!("Invalid private key: {}", e)))?;

        let server_pubkey_bytes = base64::engine::general_purpose::STANDARD
            .decode(&config.server_public_key)
            .map_err(|e| NetworkError::ConfigError(format!("Invalid server public key: {}", e)))?;

        if private_key_bytes.len() != 32 || server_pubkey_bytes.len() != 32 {
            return Err(NetworkError::ConfigError("Keys must be 32 bytes".into()));
        }

        let mut private_key_arr = [0u8; 32];
        let mut server_pubkey_arr = [0u8; 32];
        private_key_arr.copy_from_slice(&private_key_bytes);
        server_pubkey_arr.copy_from_slice(&server_pubkey_bytes);

        let private_key = StaticSecret::from(private_key_arr);
        let server_pubkey = PublicKey::from(server_pubkey_arr);

        // Create tunnel
        let tunnel = Tunn::new(
            private_key,
            server_pubkey,
            None, // preshared key
            config.keepalive,
            0, // index
            None, // rate limiter
        );

        // Bind UDP socket
        let socket = UdpSocket::bind("0.0.0.0:0").await
            .map_err(|e| NetworkError::IoError(e.to_string()))?;

        info!("WireGuard client created, endpoint: {}", config.endpoint);

        Ok(Self {
            tunnel: Arc::new(Mutex::new(tunnel)),
            socket: Arc::new(socket),
            endpoint: config.endpoint,
            tun: Arc::from(tun),
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Start the WireGuard tunnel
    pub async fn start(&self) -> NetworkResult<()> {
        use std::sync::atomic::Ordering;

        if self.running.load(Ordering::SeqCst) {
            return Err(NetworkError::AlreadyRunning);
        }

        self.running.store(true, Ordering::SeqCst);
        info!("Starting WireGuard tunnel...");

        // Send initial handshake
        self.send_handshake().await?;

        // Start packet processing tasks
        let running = self.running.clone();
        let socket = self.socket.clone();
        let tunnel = self.tunnel.clone();
        let tun = self.tun.clone();
        let endpoint = self.endpoint;

        // Task: Read from TUN, encrypt, send to server
        let running_tun = running.clone();
        let socket_tun = socket.clone();
        let tunnel_tun = tunnel.clone();
        let tun_read = tun.clone();

        tokio::spawn(async move {
            let mut dst = vec![0u8; 65536];

            while running_tun.load(Ordering::SeqCst) {
                // Read from TUN - returns Bytes
                let packet = match tokio::time::timeout(
                    Duration::from_millis(100),
                    tun_read.read(),
                ).await {
                    Ok(Ok(bytes)) => bytes,
                    Ok(Err(e)) => {
                        warn!("TUN read error: {}", e);
                        continue;
                    }
                    Err(_) => continue, // timeout
                };

                if packet.is_empty() {
                    continue;
                }

                // Encrypt and send
                let mut tunnel_guard = tunnel_tun.lock().await;
                match tunnel_guard.encapsulate(&packet, &mut dst) {
                    TunnResult::WriteToNetwork(data) => {
                        if let Err(e) = socket_tun.send_to(data, endpoint).await {
                            warn!("Failed to send to server: {}", e);
                        }
                    }
                    TunnResult::Err(e) => {
                        warn!("Encapsulation error: {:?}", e);
                    }
                    _ => {}
                }
            }
        });

        // Task: Read from server, decrypt, write to TUN
        let running_net = running.clone();
        let socket_net = socket.clone();
        let tunnel_net = tunnel.clone();
        let tun_write = tun.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            let mut dst = vec![0u8; 65536];

            while running_net.load(Ordering::SeqCst) {
                // Read from network
                let (n, _addr) = match tokio::time::timeout(
                    Duration::from_millis(100),
                    socket_net.recv_from(&mut buf),
                ).await {
                    Ok(Ok(result)) => result,
                    Ok(Err(e)) => {
                        warn!("Network read error: {}", e);
                        continue;
                    }
                    Err(_) => continue, // timeout
                };

                if n == 0 {
                    continue;
                }

                // Decrypt
                let mut tunnel_guard = tunnel_net.lock().await;
                let mut result = tunnel_guard.decapsulate(None, &buf[..n], &mut dst);

                loop {
                    match result {
                        TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                            if let Err(e) = tun_write.write(data).await {
                                warn!("TUN write error: {}", e);
                            }
                            break;
                        }
                        TunnResult::WriteToNetwork(data) => {
                            // Need to send response (e.g., handshake response)
                            if let Err(e) = socket_net.send_to(data, endpoint).await {
                                warn!("Failed to send response: {}", e);
                            }
                            // Check if there's more to process
                            result = tunnel_guard.decapsulate(None, &[], &mut dst);
                        }
                        TunnResult::Done => break,
                        TunnResult::Err(e) => {
                            debug!("Decapsulation error: {:?}", e);
                            break;
                        }
                    }
                }
            }
        });

        // Task: Send keepalives
        let running_ka = running.clone();
        let socket_ka = socket.clone();
        let tunnel_ka = tunnel.clone();

        tokio::spawn(async move {
            let mut dst = vec![0u8; 256];
            let mut interval = tokio::time::interval(Duration::from_secs(10));

            while running_ka.load(Ordering::SeqCst) {
                interval.tick().await;

                let mut tunnel_guard = tunnel_ka.lock().await;
                match tunnel_guard.update_timers(&mut dst) {
                    TunnResult::WriteToNetwork(data) => {
                        debug!("Sending keepalive");
                        if let Err(e) = socket_ka.send_to(data, endpoint).await {
                            warn!("Failed to send keepalive: {}", e);
                        }
                    }
                    TunnResult::Err(e) => {
                        warn!("Timer update error: {:?}", e);
                    }
                    _ => {}
                }
            }
        });

        info!("WireGuard tunnel started");
        Ok(())
    }

    /// Send initial handshake
    async fn send_handshake(&self) -> NetworkResult<()> {
        let mut dst = vec![0u8; 256];
        let mut tunnel = self.tunnel.lock().await;

        // Force handshake
        match tunnel.format_handshake_initiation(&mut dst, false) {
            TunnResult::WriteToNetwork(data) => {
                self.socket.send_to(data, self.endpoint).await
                    .map_err(|e| NetworkError::IoError(e.to_string()))?;
                info!("Handshake initiation sent to {}", self.endpoint);
            }
            TunnResult::Err(e) => {
                return Err(NetworkError::WireGuardError(format!("Handshake error: {:?}", e)));
            }
            _ => {}
        }

        Ok(())
    }

    /// Stop the tunnel
    pub async fn stop(&self) {
        use std::sync::atomic::Ordering;
        self.running.store(false, Ordering::SeqCst);
        info!("WireGuard tunnel stopped");
    }

    /// Check if tunnel is running
    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Get traffic statistics from TUN device
    pub fn get_stats(&self) -> crate::tun::TrafficStats {
        self.tun.get_stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_parse() {
        let config = WireGuardConfig {
            private_key: "EDqHUtmfXNMpJrB6Gld2DJp8E3RuC864mQ5goyjUwnU=".to_string(),
            server_public_key: "3MfeMN/bN/CfxWyxfgtvtfQ0HV2K59UZaNaVW4sPLTs=".to_string(),
            endpoint: "50.17.62.209:51820".parse().unwrap(),
            address: Ipv4Addr::new(10, 200, 0, 2),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            keepalive: Some(25),
        };

        assert_eq!(config.endpoint.port(), 51820);
    }
}
