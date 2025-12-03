//! UDP Hole Punching Implementation
//!
//! Implements NAT traversal using simultaneous UDP hole punching.
//! This allows peers behind NAT to establish direct connections.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout};
use tracing::{debug, info, warn};

use super::protocol::{
    HolePunchPacket, HolePunchAck, P2PMessage, PeerId, NatType,
    serialize_message, deserialize_message,
};
use crate::error::{NetworkError, NetworkResult};

/// Result of hole punch attempt
#[derive(Debug, Clone)]
pub struct HolePunchResult {
    /// Successfully established connection
    pub success: bool,
    /// Remote peer's verified address
    pub peer_addr: Option<SocketAddr>,
    /// Round trip time in milliseconds
    pub rtt_ms: Option<u32>,
    /// Number of attempts needed
    pub attempts: u32,
}

/// Configuration for hole punching
#[derive(Debug, Clone)]
pub struct HolePunchConfig {
    /// Maximum number of punch attempts
    pub max_attempts: u32,
    /// Delay between punch attempts (ms)
    pub punch_interval_ms: u64,
    /// Timeout for entire hole punch process
    pub timeout_secs: u64,
    /// Initial delay to allow both peers to start
    pub sync_delay_ms: u64,
}

impl Default for HolePunchConfig {
    fn default() -> Self {
        Self {
            max_attempts: 30,
            punch_interval_ms: 100,
            timeout_secs: 10,
            sync_delay_ms: 50,
        }
    }
}

/// UDP Hole Puncher
pub struct HolePuncher {
    /// Our peer ID
    peer_id: PeerId,
    /// UDP socket for punching
    socket: Arc<UdpSocket>,
    /// Configuration
    config: HolePunchConfig,
    /// Active punch sessions
    sessions: Arc<Mutex<Vec<PunchSession>>>,
}

/// Active punch session
struct PunchSession {
    peer_id: PeerId,
    target_addr: SocketAddr,
    nonce: [u8; 16],
    started: Instant,
    received_ack: bool,
}

impl HolePuncher {
    /// Create a new hole puncher
    pub async fn new(peer_id: PeerId, bind_addr: &str) -> NetworkResult<Self> {
        let socket = UdpSocket::bind(bind_addr).await
            .map_err(|e| NetworkError::IoError(e.to_string()))?;

        Ok(Self {
            peer_id,
            socket: Arc::new(socket),
            config: HolePunchConfig::default(),
            sessions: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Create from existing socket
    pub fn from_socket(peer_id: PeerId, socket: Arc<UdpSocket>) -> Self {
        Self {
            peer_id,
            socket,
            config: HolePunchConfig::default(),
            sessions: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Get the local address
    pub fn local_addr(&self) -> NetworkResult<SocketAddr> {
        self.socket.local_addr()
            .map_err(|e| NetworkError::IoError(e.to_string()))
    }

    /// Perform hole punch to establish direct connection
    ///
    /// Both peers must call this simultaneously with each other's addresses.
    /// The nonce must be agreed upon via the discovery server.
    pub async fn punch(
        &self,
        target_peer_id: PeerId,
        target_addr: SocketAddr,
        target_local_addr: Option<SocketAddr>,
        target_nat_type: NatType,
        nonce: [u8; 16],
    ) -> NetworkResult<HolePunchResult> {
        info!(
            "Starting hole punch to peer {} at {} (NAT: {:?})",
            target_peer_id, target_addr, target_nat_type
        );

        // Create session
        let session = PunchSession {
            peer_id: target_peer_id,
            target_addr,
            nonce,
            started: Instant::now(),
            received_ack: false,
        };

        {
            let mut sessions = self.sessions.lock().await;
            sessions.push(session);
        }

        // If we're on the same LAN, try local address first
        let addresses_to_try: Vec<SocketAddr> = if let Some(local) = target_local_addr {
            vec![local, target_addr]
        } else {
            vec![target_addr]
        };

        // Small delay for synchronization
        sleep(Duration::from_millis(self.config.sync_delay_ms)).await;

        let mut result = HolePunchResult {
            success: false,
            peer_addr: None,
            rtt_ms: None,
            attempts: 0,
        };

        let start_time = Instant::now();
        let overall_timeout = Duration::from_secs(self.config.timeout_secs);

        // Start receiver task
        let socket_recv = self.socket.clone();
        let peer_id = self.peer_id;
        let sessions_recv = self.sessions.clone();

        let receiver = tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                match socket_recv.recv_from(&mut buf).await {
                    Ok((n, from)) => {
                        if let Ok(msg) = deserialize_message(&buf[..n]) {
                            match msg {
                                P2PMessage::HolePunch(punch) => {
                                    if punch.nonce == nonce {
                                        debug!("Received hole punch from {}", from);
                                        // Send ACK
                                        let ack = P2PMessage::HolePunchAck(HolePunchAck {
                                            peer_id,
                                            nonce,
                                            ack_seq: punch.seq,
                                            echo_timestamp: punch.timestamp,
                                        });
                                        if let Ok(data) = serialize_message(&ack) {
                                            let _ = socket_recv.send_to(&data, from).await;
                                        }
                                    }
                                }
                                P2PMessage::HolePunchAck(ack) => {
                                    if ack.nonce == nonce {
                                        debug!("Received hole punch ACK from {}", from);
                                        let mut sessions = sessions_recv.lock().await;
                                        if let Some(session) = sessions.iter_mut()
                                            .find(|s| s.nonce == nonce)
                                        {
                                            session.received_ack = true;
                                        }
                                        return Some((from, ack.echo_timestamp));
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Receive error: {}", e);
                        break;
                    }
                }
            }
            None
        });

        // Send punch packets
        for attempt in 0..self.config.max_attempts {
            if start_time.elapsed() > overall_timeout {
                break;
            }

            result.attempts = attempt + 1;
            let timestamp = start_time.elapsed().as_micros() as u64;

            let punch_packet = P2PMessage::HolePunch(HolePunchPacket {
                peer_id: self.peer_id,
                nonce,
                seq: attempt,
                timestamp,
            });

            let data = serialize_message(&punch_packet)
                .map_err(|e| NetworkError::Protocol(e.to_string()))?;

            // Send to all target addresses
            for addr in &addresses_to_try {
                if let Err(e) = self.socket.send_to(&data, addr).await {
                    debug!("Failed to send punch to {}: {}", addr, e);
                }
            }

            // Check if receiver got ACK
            {
                let sessions = self.sessions.lock().await;
                if let Some(session) = sessions.iter().find(|s| s.nonce == nonce) {
                    if session.received_ack {
                        break;
                    }
                }
            }

            sleep(Duration::from_millis(self.config.punch_interval_ms)).await;
        }

        // Wait a bit more for final ACKs
        match timeout(Duration::from_millis(500), receiver).await {
            Ok(Ok(Some((addr, echo_ts)))) => {
                let now = start_time.elapsed().as_micros() as u64;
                let rtt = (now.saturating_sub(echo_ts)) / 1000; // microseconds to milliseconds

                result.success = true;
                result.peer_addr = Some(addr);
                result.rtt_ms = Some(rtt as u32);

                info!(
                    "Hole punch SUCCESS to {} in {} attempts, RTT: {}ms",
                    addr, result.attempts, rtt
                );
            }
            _ => {
                warn!(
                    "Hole punch FAILED to {} after {} attempts",
                    target_addr, result.attempts
                );
            }
        }

        // Clean up session
        {
            let mut sessions = self.sessions.lock().await;
            sessions.retain(|s| s.nonce != nonce);
        }

        Ok(result)
    }

    /// Perform parallel hole punch trying multiple port predictions
    ///
    /// For symmetric NAT, we try to predict the port allocation pattern.
    pub async fn punch_symmetric(
        &self,
        target_peer_id: PeerId,
        target_addr: SocketAddr,
        observed_ports: &[u16],
        nonce: [u8; 16],
    ) -> NetworkResult<HolePunchResult> {
        if observed_ports.len() < 2 {
            return self.punch(
                target_peer_id,
                target_addr,
                None,
                NatType::Symmetric,
                nonce,
            ).await;
        }

        info!("Attempting symmetric NAT traversal with port prediction");

        // Predict port increment
        let port_delta = observed_ports[1] as i32 - observed_ports[0] as i32;
        let last_port = *observed_ports.last().unwrap();

        // Generate predicted ports
        let mut predicted_ports: Vec<u16> = Vec::new();
        for i in 1..=20 {
            let predicted = (last_port as i32 + port_delta * i) as u16;
            if predicted > 1024 && predicted < 65535 {
                predicted_ports.push(predicted);
            }
        }

        info!("Port prediction: delta={}, trying {} ports", port_delta, predicted_ports.len());

        // Try all predicted ports in parallel
        let socket = self.socket.clone();
        let peer_id = self.peer_id;

        let start_time = Instant::now();
        let mut buf = [0u8; 1500];

        // Send to all predicted ports
        for attempt in 0..15 {
            let timestamp = start_time.elapsed().as_micros() as u64;

            let punch_packet = P2PMessage::HolePunch(HolePunchPacket {
                peer_id,
                nonce,
                seq: attempt,
                timestamp,
            });

            let data = serialize_message(&punch_packet)
                .map_err(|e| NetworkError::Protocol(e.to_string()))?;

            // Send to known address
            let _ = socket.send_to(&data, target_addr).await;

            // Send to predicted ports
            for port in &predicted_ports {
                let addr = SocketAddr::new(target_addr.ip(), *port);
                let _ = socket.send_to(&data, addr).await;
            }

            // Brief wait between bursts
            sleep(Duration::from_millis(50)).await;
        }

        // Wait for response
        match timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) => {
                if let Ok(P2PMessage::HolePunchAck(_)) = deserialize_message(&buf[..n]) {
                    info!("Symmetric NAT traversal SUCCESS via port {}", from.port());
                    return Ok(HolePunchResult {
                        success: true,
                        peer_addr: Some(from),
                        rtt_ms: Some(start_time.elapsed().as_millis() as u32),
                        attempts: 15,
                    });
                }
            }
            _ => {}
        }

        warn!("Symmetric NAT traversal failed, will need relay");
        Ok(HolePunchResult {
            success: false,
            peer_addr: None,
            rtt_ms: None,
            attempts: 15,
        })
    }
}

/// Determine hole punch strategy based on NAT types
pub fn get_punch_strategy(our_nat: NatType, their_nat: NatType) -> HolePunchStrategy {
    match (our_nat, their_nat) {
        // Both public or full cone - simple direct connection
        (NatType::None, _) | (_, NatType::None) => HolePunchStrategy::Direct,
        (NatType::FullCone, _) | (_, NatType::FullCone) => HolePunchStrategy::Direct,

        // Both restricted - simultaneous punch
        (NatType::AddressRestricted, NatType::AddressRestricted) |
        (NatType::AddressRestricted, NatType::PortRestricted) |
        (NatType::PortRestricted, NatType::AddressRestricted) |
        (NatType::PortRestricted, NatType::PortRestricted) => {
            HolePunchStrategy::Simultaneous
        }

        // One symmetric - try port prediction
        (NatType::Symmetric, _) | (_, NatType::Symmetric) => {
            HolePunchStrategy::PortPrediction
        }

        // Unknown - try simultaneous
        _ => HolePunchStrategy::Simultaneous,
    }
}

/// Strategy for hole punching
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HolePunchStrategy {
    /// Direct connection possible
    Direct,
    /// Simultaneous hole punch from both sides
    Simultaneous,
    /// Need port prediction (symmetric NAT)
    PortPrediction,
    /// Must use relay (symmetric + symmetric)
    Relay,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_punch_strategy() {
        assert_eq!(
            get_punch_strategy(NatType::None, NatType::PortRestricted),
            HolePunchStrategy::Direct
        );
        assert_eq!(
            get_punch_strategy(NatType::PortRestricted, NatType::PortRestricted),
            HolePunchStrategy::Simultaneous
        );
        assert_eq!(
            get_punch_strategy(NatType::Symmetric, NatType::PortRestricted),
            HolePunchStrategy::PortPrediction
        );
    }

    #[test]
    fn test_config_defaults() {
        let config = HolePunchConfig::default();
        assert_eq!(config.max_attempts, 30);
        assert_eq!(config.timeout_secs, 10);
    }
}
