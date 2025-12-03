//! NAT router for exit node

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};

use tokio::sync::RwLock;
use tracing::debug;

use crate::config::ExitConfig;
use crate::error::{ExitError, ExitResult};

/// NAT mapping entry
#[derive(Debug, Clone)]
struct NatEntry {
    /// Internal circuit ID
    circuit_id: u32,
    /// Original source IP
    original_src: IpAddr,
    /// Original source port
    original_port: u16,
    /// Mapped external port
    external_port: u16,
    /// Creation time
    created_at: std::time::Instant,
}

/// NAT router for translating circuit traffic to internet
pub struct NatRouter {
    /// Outbound interface
    interface: String,
    /// External IP address
    external_ip: IpAddr,
    /// NAT table (external port -> entry)
    nat_table: RwLock<HashMap<u16, NatEntry>>,
    /// Reverse NAT (circuit_id, original_src, original_port -> external_port)
    reverse_nat: RwLock<HashMap<(u32, IpAddr, u16), u16>>,
    /// Next available port
    next_port: AtomicU16,
    /// Port range start
    port_start: u16,
    /// Port range end
    port_end: u16,
}

impl NatRouter {
    /// Create a new NAT router
    pub fn new(config: &ExitConfig) -> ExitResult<Self> {
        // Get external IP from interface
        let external_ip = Self::get_interface_ip(&config.outbound_interface)?;

        Ok(Self {
            interface: config.outbound_interface.clone(),
            external_ip,
            nat_table: RwLock::new(HashMap::new()),
            reverse_nat: RwLock::new(HashMap::new()),
            next_port: AtomicU16::new(40000),
            port_start: 40000,
            port_end: 60000,
        })
    }

    /// Get IP address of interface
    fn get_interface_ip(interface: &str) -> ExitResult<IpAddr> {
        // TODO: Implement actual interface lookup
        // For now, return a placeholder
        Ok(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)))
    }

    /// Forward outbound packet (from circuit to internet)
    pub async fn forward_outbound(&self, packet: &[u8]) -> ExitResult<Option<Vec<u8>>> {
        // TODO: Implement actual NAT
        // 1. Parse IP packet
        // 2. Allocate external port
        // 3. Rewrite source IP/port
        // 4. Store mapping
        // 5. Send to internet

        Ok(None)
    }

    /// Process inbound packet (from internet to circuit)
    pub async fn process_inbound(&self, packet: &[u8]) -> ExitResult<Option<(u32, Vec<u8>)>> {
        // TODO: Implement actual NAT
        // 1. Parse IP packet
        // 2. Look up NAT mapping by destination port
        // 3. Rewrite destination IP/port
        // 4. Return circuit ID and packet

        Ok(None)
    }

    /// Allocate an external port
    fn allocate_port(&self) -> Option<u16> {
        for _ in 0..1000 {
            let port = self.next_port.fetch_add(1, Ordering::SeqCst);
            if port >= self.port_end {
                self.next_port.store(self.port_start, Ordering::SeqCst);
                continue;
            }
            return Some(port);
        }
        None
    }

    /// Clean up expired NAT entries
    pub async fn cleanup(&self, max_age: std::time::Duration) -> usize {
        let now = std::time::Instant::now();
        let mut count = 0;

        let mut nat_table = self.nat_table.write().await;
        let mut reverse_nat = self.reverse_nat.write().await;

        let to_remove: Vec<_> = nat_table
            .iter()
            .filter(|(_, e)| now.duration_since(e.created_at) > max_age)
            .map(|(port, _)| *port)
            .collect();

        for port in to_remove {
            if let Some(entry) = nat_table.remove(&port) {
                reverse_nat.remove(&(entry.circuit_id, entry.original_src, entry.original_port));
                count += 1;
            }
        }

        if count > 0 {
            debug!("Cleaned up {} NAT entries", count);
        }

        count
    }
}
