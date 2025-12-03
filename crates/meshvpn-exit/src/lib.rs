//! MeshVPN Exit Node
//!
//! Exit nodes are the final hop in a circuit, routing traffic to the internet.
//! Only controlled EC2 instances should run as exit nodes.
//!
//! Features:
//! - NAT and routing for outbound traffic
//! - Legal compliance logging (destination only, not content)
//! - Multi-region synchronization
//! - Token verification for paid users
//! - Circuit-based onion routing support

pub mod nat;
pub mod logging;
pub mod sync;
pub mod config;
pub mod error;
pub mod circuit_handler;

pub use config::ExitConfig;
pub use error::{ExitError, ExitResult};
pub use nat::NatRouter;
pub use logging::ComplianceLogger;
pub use sync::RegionSync;
pub use circuit_handler::CircuitExitHandler;

/// Exit node implementation
pub struct ExitNode {
    config: ExitConfig,
    nat_router: NatRouter,
    logger: ComplianceLogger,
    sync: Option<RegionSync>,
}

impl ExitNode {
    /// Create a new exit node
    pub async fn new(config: ExitConfig) -> ExitResult<Self> {
        let nat_router = NatRouter::new(&config)?;
        let logger = ComplianceLogger::new(&config.logging)?;
        let sync = if config.sync.enabled {
            Some(RegionSync::new(&config.sync).await?)
        } else {
            None
        };

        Ok(Self {
            config,
            nat_router,
            logger,
            sync,
        })
    }

    /// Process a packet from the circuit and forward to internet
    pub async fn process_outbound(
        &self,
        circuit_id: u32,
        packet: &[u8],
    ) -> ExitResult<Option<Vec<u8>>> {
        // Log the connection (for legal compliance)
        if let Some(dest) = extract_destination(packet) {
            self.logger.log_connection(circuit_id, dest).await?;
        }

        // Forward through NAT
        self.nat_router.forward_outbound(packet).await
    }

    /// Process a response from internet and return to circuit
    pub async fn process_inbound(
        &self,
        packet: &[u8],
    ) -> ExitResult<Option<(u32, Vec<u8>)>> {
        // Reverse NAT lookup
        self.nat_router.process_inbound(packet).await
    }
}

/// Extract destination IP from packet
fn extract_destination(packet: &[u8]) -> Option<std::net::IpAddr> {
    if packet.len() < 20 {
        return None;
    }

    // IPv4
    if (packet[0] >> 4) == 4 {
        Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        )))
    } else {
        None
    }
}
