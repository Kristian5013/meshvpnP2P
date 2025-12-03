//! Core configuration

use std::time::Duration;
use serde::{Deserialize, Serialize};

/// Core protocol configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoreConfig {
    /// Number of relay hops (1-5 recommended)
    pub circuit_length: usize,

    /// Circuit rotation interval
    pub circuit_rotation: Duration,

    /// Keep-alive interval for circuits
    pub keepalive_interval: Duration,

    /// Maximum concurrent circuits
    pub max_circuits: usize,

    /// Handshake timeout
    pub handshake_timeout: Duration,

    /// Enable guard nodes (first hop stability)
    pub enable_guard_nodes: bool,

    /// Number of guard nodes to maintain
    pub guard_node_count: usize,

    /// Guard node rotation interval (longer than regular circuits)
    pub guard_rotation: Duration,

    /// Prefer geographic diversity in path selection
    pub prefer_geo_diversity: bool,

    /// Maximum relay capacity (circuits per relay)
    pub max_relay_circuits: usize,

    /// Bandwidth limit for relay (bytes/sec, 0 = unlimited)
    pub relay_bandwidth_limit: u64,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            circuit_length: 3,
            circuit_rotation: Duration::from_secs(600),  // 10 minutes
            keepalive_interval: Duration::from_secs(30),
            max_circuits: 10,
            handshake_timeout: Duration::from_secs(30),
            enable_guard_nodes: true,
            guard_node_count: 3,
            guard_rotation: Duration::from_secs(86400 * 30), // 30 days
            prefer_geo_diversity: true,
            max_relay_circuits: 100,
            relay_bandwidth_limit: 0, // Unlimited
        }
    }
}

impl CoreConfig {
    /// Create config for maximum privacy (more hops, frequent rotation)
    pub fn max_privacy() -> Self {
        Self {
            circuit_length: 5,
            circuit_rotation: Duration::from_secs(300), // 5 minutes
            enable_guard_nodes: true,
            prefer_geo_diversity: true,
            ..Default::default()
        }
    }

    /// Create config for better performance (fewer hops)
    pub fn performance() -> Self {
        Self {
            circuit_length: 2,
            circuit_rotation: Duration::from_secs(1800), // 30 minutes
            enable_guard_nodes: false,
            ..Default::default()
        }
    }

    /// Create config for relay-only mode (not initiating circuits)
    pub fn relay_only() -> Self {
        Self {
            max_circuits: 0,
            max_relay_circuits: 200,
            ..Default::default()
        }
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.circuit_length == 0 {
            return Err("Circuit length must be at least 1".into());
        }
        if self.circuit_length > super::MAX_CIRCUIT_LENGTH {
            return Err(format!(
                "Circuit length {} exceeds maximum {}",
                self.circuit_length,
                super::MAX_CIRCUIT_LENGTH
            ));
        }
        if self.guard_node_count == 0 && self.enable_guard_nodes {
            return Err("Guard node count must be > 0 when guard nodes enabled".into());
        }
        Ok(())
    }
}
