//! Traffic Router
//!
//! Routes IP traffic through circuits based on destination.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::{debug, trace};

use crate::circuit::{Circuit, CircuitId, CircuitManager};
use crate::error::{CoreError, CoreResult};

/// Routing decision
#[derive(Debug, Clone)]
pub enum RouteDecision {
    /// Route through a specific circuit
    Circuit(CircuitId),
    /// Route directly (bypass VPN)
    Direct,
    /// Drop the packet
    Drop,
    /// No route available
    NoRoute,
}

/// Routing rule
#[derive(Debug, Clone)]
pub struct RoutingRule {
    /// Rule name (for logging)
    pub name: String,
    /// Destination network/IP to match
    pub destination: IpNetwork,
    /// Routing action
    pub action: RouteAction,
    /// Rule priority (higher = more specific)
    pub priority: u32,
}

/// Routing action
#[derive(Debug, Clone)]
pub enum RouteAction {
    /// Route through VPN (default circuit)
    Vpn,
    /// Route through specific circuit
    VpnCircuit(CircuitId),
    /// Route directly (split tunneling)
    Direct,
    /// Block/drop traffic
    Block,
}

/// IP network specification
#[derive(Debug, Clone, Copy)]
pub struct IpNetwork {
    pub address: IpAddr,
    pub prefix_len: u8,
}

impl IpNetwork {
    /// Create a new IP network
    pub fn new(address: IpAddr, prefix_len: u8) -> Self {
        Self { address, prefix_len }
    }

    /// Create for a single host (/32 or /128)
    pub fn host(address: IpAddr) -> Self {
        let prefix_len = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        Self { address, prefix_len }
    }

    /// Check if an IP matches this network
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.address, ip) {
            (IpAddr::V4(net), IpAddr::V4(target)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let mask = !0u32 << (32 - self.prefix_len);
                let net_bits = u32::from(net) & mask;
                let target_bits = u32::from(target) & mask;
                net_bits == target_bits
            }
            (IpAddr::V6(net), IpAddr::V6(target)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let mask = !0u128 << (128 - self.prefix_len);
                let net_bits = u128::from(net) & mask;
                let target_bits = u128::from(target) & mask;
                net_bits == target_bits
            }
            _ => false, // IPv4/IPv6 mismatch
        }
    }

    /// Default route (0.0.0.0/0)
    pub fn default_v4() -> Self {
        Self {
            address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            prefix_len: 0,
        }
    }

    /// Loopback network (127.0.0.0/8)
    pub fn loopback_v4() -> Self {
        Self {
            address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
            prefix_len: 8,
        }
    }

    /// Private network 10.0.0.0/8
    pub fn private_10() -> Self {
        Self {
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefix_len: 8,
        }
    }

    /// Private network 172.16.0.0/12
    pub fn private_172() -> Self {
        Self {
            address: IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)),
            prefix_len: 12,
        }
    }

    /// Private network 192.168.0.0/16
    pub fn private_192() -> Self {
        Self {
            address: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
            prefix_len: 16,
        }
    }
}

/// Routing table
pub struct RoutingTable {
    rules: RwLock<Vec<RoutingRule>>,
}

impl RoutingTable {
    /// Create a new routing table
    pub fn new() -> Self {
        Self {
            rules: RwLock::new(Vec::new()),
        }
    }

    /// Create with default rules (route all through VPN)
    pub fn with_defaults() -> Self {
        let table = Self::new();

        // Will be populated asynchronously
        table
    }

    /// Add default VPN routing rules
    pub async fn add_default_rules(&self) {
        let mut rules = self.rules.write().await;

        // Always route loopback directly
        rules.push(RoutingRule {
            name: "loopback".to_string(),
            destination: IpNetwork::loopback_v4(),
            action: RouteAction::Direct,
            priority: 1000,
        });

        // Route private networks directly (split tunneling for LAN)
        rules.push(RoutingRule {
            name: "private-10".to_string(),
            destination: IpNetwork::private_10(),
            action: RouteAction::Direct,
            priority: 100,
        });
        rules.push(RoutingRule {
            name: "private-172".to_string(),
            destination: IpNetwork::private_172(),
            action: RouteAction::Direct,
            priority: 100,
        });
        rules.push(RoutingRule {
            name: "private-192".to_string(),
            destination: IpNetwork::private_192(),
            action: RouteAction::Direct,
            priority: 100,
        });

        // Default: route through VPN
        rules.push(RoutingRule {
            name: "default".to_string(),
            destination: IpNetwork::default_v4(),
            action: RouteAction::Vpn,
            priority: 0,
        });

        // Sort by priority (highest first)
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Add a routing rule
    pub async fn add_rule(&self, rule: RoutingRule) {
        let mut rules = self.rules.write().await;
        rules.push(rule);
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Remove rules by name
    pub async fn remove_rule(&self, name: &str) {
        let mut rules = self.rules.write().await;
        rules.retain(|r| r.name != name);
    }

    /// Find matching rule for destination
    pub async fn lookup(&self, destination: IpAddr) -> Option<RouteAction> {
        let rules = self.rules.read().await;

        for rule in rules.iter() {
            if rule.destination.contains(destination) {
                trace!("Route {} matched rule '{}'", destination, rule.name);
                return Some(rule.action.clone());
            }
        }

        None
    }

    /// Get all rules
    pub async fn rules(&self) -> Vec<RoutingRule> {
        let rules = self.rules.read().await;
        rules.clone()
    }
}

impl Default for RoutingTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Main traffic router
pub struct Router {
    /// Routing table
    routing_table: RoutingTable,

    /// Circuit manager
    circuits: Arc<CircuitManager>,

    /// Destination -> Circuit mapping cache
    dest_circuits: RwLock<HashMap<IpAddr, CircuitId>>,
}

impl Router {
    /// Create a new router
    pub fn new(circuits: Arc<CircuitManager>) -> Self {
        Self {
            routing_table: RoutingTable::with_defaults(),
            circuits,
            dest_circuits: RwLock::new(HashMap::new()),
        }
    }

    /// Initialize with default rules
    pub async fn init(&self) {
        self.routing_table.add_default_rules().await;
    }

    /// Get the routing table
    pub fn routing_table(&self) -> &RoutingTable {
        &self.routing_table
    }

    /// Route a packet based on destination IP
    pub async fn route(&self, destination: IpAddr) -> RouteDecision {
        // Check routing table first
        if let Some(action) = self.routing_table.lookup(destination).await {
            match action {
                RouteAction::Vpn => {
                    // Use default or cached circuit
                    if let Some(circuit_id) = self.get_circuit_for_dest(destination).await {
                        return RouteDecision::Circuit(circuit_id);
                    }
                    // Get any ready circuit
                    if let Some(circuit) = self.circuits.get_ready().await {
                        let id = circuit.read().await.id();
                        self.cache_dest_circuit(destination, id).await;
                        return RouteDecision::Circuit(id);
                    }
                    return RouteDecision::NoRoute;
                }
                RouteAction::VpnCircuit(id) => {
                    return RouteDecision::Circuit(id);
                }
                RouteAction::Direct => {
                    return RouteDecision::Direct;
                }
                RouteAction::Block => {
                    return RouteDecision::Drop;
                }
            }
        }

        RouteDecision::NoRoute
    }

    /// Get cached circuit for destination
    async fn get_circuit_for_dest(&self, dest: IpAddr) -> Option<CircuitId> {
        let cache = self.dest_circuits.read().await;
        cache.get(&dest).copied()
    }

    /// Cache circuit for destination
    async fn cache_dest_circuit(&self, dest: IpAddr, circuit_id: CircuitId) {
        let mut cache = self.dest_circuits.write().await;
        cache.insert(dest, circuit_id);
    }

    /// Clear cache for a specific destination
    pub async fn clear_dest_cache(&self, dest: IpAddr) {
        let mut cache = self.dest_circuits.write().await;
        cache.remove(&dest);
    }

    /// Clear all destination cache
    pub async fn clear_all_cache(&self) {
        let mut cache = self.dest_circuits.write().await;
        cache.clear();
    }

    /// Assign a specific circuit to a destination
    pub async fn assign_circuit(&self, dest: IpAddr, circuit_id: CircuitId) -> CoreResult<()> {
        // Verify circuit exists
        self.circuits
            .get(circuit_id)
            .await
            .ok_or(CoreError::CircuitNotFound(circuit_id))?;

        self.cache_dest_circuit(dest, circuit_id).await;
        debug!("Assigned circuit {} to destination {}", circuit_id, dest);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_network_contains() {
        let net = IpNetwork::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8);

        assert!(net.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(net.contains(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))));
        assert!(!net.contains(IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))));
    }

    #[test]
    fn test_ip_network_host() {
        let host = IpNetwork::host(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));

        assert!(host.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        assert!(!host.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101))));
    }

    #[test]
    fn test_default_route() {
        let default = IpNetwork::default_v4();

        // Should match everything
        assert!(default.contains(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert!(default.contains(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255))));
    }

    #[tokio::test]
    async fn test_routing_table() {
        let table = RoutingTable::new();
        table.add_default_rules().await;

        // Loopback should be direct
        let action = table.lookup(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))).await;
        assert!(matches!(action, Some(RouteAction::Direct)));

        // Private network should be direct
        let action = table.lookup(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))).await;
        assert!(matches!(action, Some(RouteAction::Direct)));

        // Public IP should go through VPN
        let action = table.lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))).await;
        assert!(matches!(action, Some(RouteAction::Vpn)));
    }
}
