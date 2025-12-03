//! Path Selection
//!
//! Algorithms for selecting relay nodes to build circuits through.
//! Considers: latency, capacity, geographic diversity, node reputation.

use std::collections::HashSet;
use std::net::IpAddr;

use meshvpn_crypto::NodeId;
use rand::seq::SliceRandom;
use tracing::debug;

use crate::error::{CoreError, CoreResult};

/// Path selection strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathSelectionStrategy {
    /// Random selection (simple, good for privacy)
    Random,
    /// Prefer low-latency nodes
    LowLatency,
    /// Prefer high-bandwidth nodes
    HighBandwidth,
    /// Maximize geographic diversity
    GeoDiverse,
    /// Balanced (considers multiple factors)
    Balanced,
}

/// Information about a candidate relay node
#[derive(Debug, Clone)]
pub struct RelayCandidate {
    /// Node identifier
    pub node_id: NodeId,
    /// Node's public encryption key
    pub public_key: meshvpn_crypto::PublicKey,
    /// Network address
    pub address: std::net::SocketAddr,
    /// Estimated latency in milliseconds
    pub latency_ms: Option<u32>,
    /// Available bandwidth (bytes/sec)
    pub bandwidth: Option<u64>,
    /// Geographic region (ISO 3166-1 alpha-2)
    pub region: Option<String>,
    /// Country code
    pub country: Option<String>,
    /// ASN (Autonomous System Number)
    pub asn: Option<u32>,
    /// Is this an exit node?
    pub is_exit: bool,
    /// Node's self-reported capacity
    pub capacity: u32,
    /// Current load (0-100)
    pub load: u8,
    /// Uptime percentage
    pub uptime: f32,
    /// Last seen timestamp
    pub last_seen: std::time::Instant,
}

impl RelayCandidate {
    /// Check if node is suitable for relaying
    pub fn is_suitable(&self) -> bool {
        // Node should be recently seen and not overloaded
        self.last_seen.elapsed().as_secs() < 300 && self.load < 90
    }

    /// Calculate a score for this node (higher is better)
    pub fn score(&self, strategy: PathSelectionStrategy) -> f64 {
        let mut score = 100.0;

        // Base adjustments
        if self.load > 0 {
            score -= self.load as f64 * 0.5;
        }
        score += self.uptime as f64 * 0.2;

        match strategy {
            PathSelectionStrategy::Random => {
                // Add randomness
                score += rand::random::<f64>() * 50.0;
            }
            PathSelectionStrategy::LowLatency => {
                if let Some(latency) = self.latency_ms {
                    // Penalize high latency
                    score -= latency as f64 * 0.5;
                }
            }
            PathSelectionStrategy::HighBandwidth => {
                if let Some(bw) = self.bandwidth {
                    // Reward high bandwidth
                    score += (bw as f64 / 1_000_000.0) * 10.0; // Per MB/s
                }
            }
            PathSelectionStrategy::GeoDiverse => {
                // Handled at path level, not node level
            }
            PathSelectionStrategy::Balanced => {
                if let Some(latency) = self.latency_ms {
                    score -= latency as f64 * 0.2;
                }
                if let Some(bw) = self.bandwidth {
                    score += (bw as f64 / 1_000_000.0) * 5.0;
                }
            }
        }

        score.max(0.0)
    }
}

/// Path selector for choosing relay nodes
pub struct PathSelector {
    strategy: PathSelectionStrategy,
    min_hops: usize,
    max_hops: usize,
    require_exit: bool,
    exclude_nodes: HashSet<NodeId>,
    exclude_countries: HashSet<String>,
    exclude_asns: HashSet<u32>,
}

impl PathSelector {
    /// Create a new path selector
    pub fn new(strategy: PathSelectionStrategy) -> Self {
        Self {
            strategy,
            min_hops: 1,
            max_hops: 5,
            require_exit: true,
            exclude_nodes: HashSet::new(),
            exclude_countries: HashSet::new(),
            exclude_asns: HashSet::new(),
        }
    }

    /// Set minimum hops
    pub fn min_hops(mut self, hops: usize) -> Self {
        self.min_hops = hops;
        self
    }

    /// Set maximum hops
    pub fn max_hops(mut self, hops: usize) -> Self {
        self.max_hops = hops;
        self
    }

    /// Set whether an exit node is required
    pub fn require_exit(mut self, require: bool) -> Self {
        self.require_exit = require;
        self
    }

    /// Exclude specific nodes
    pub fn exclude_nodes(mut self, nodes: impl IntoIterator<Item = NodeId>) -> Self {
        self.exclude_nodes.extend(nodes);
        self
    }

    /// Exclude specific countries
    pub fn exclude_countries(mut self, countries: impl IntoIterator<Item = String>) -> Self {
        self.exclude_countries.extend(countries);
        self
    }

    /// Exclude specific ASNs
    pub fn exclude_asns(mut self, asns: impl IntoIterator<Item = u32>) -> Self {
        self.exclude_asns.extend(asns);
        self
    }

    /// Select a path from available candidates
    pub fn select_path(
        &self,
        candidates: &[RelayCandidate],
        hop_count: usize,
    ) -> CoreResult<Vec<RelayCandidate>> {
        if hop_count < self.min_hops {
            return Err(CoreError::PathTooLong {
                length: hop_count,
                max: self.min_hops,
            });
        }
        if hop_count > self.max_hops {
            return Err(CoreError::PathTooLong {
                length: hop_count,
                max: self.max_hops,
            });
        }

        // Filter suitable candidates
        let suitable: Vec<_> = candidates
            .iter()
            .filter(|c| self.is_candidate_allowed(c))
            .cloned()
            .collect();

        if suitable.len() < hop_count {
            return Err(CoreError::NoPathAvailable);
        }

        // Separate exit nodes from relays
        let (exits, relays): (Vec<_>, Vec<_>) =
            suitable.into_iter().partition(|c| c.is_exit);

        if self.require_exit && exits.is_empty() {
            return Err(CoreError::NoPathAvailable);
        }

        // Select path based on strategy
        let path = match self.strategy {
            PathSelectionStrategy::Random => {
                self.select_random(&relays, &exits, hop_count)?
            }
            PathSelectionStrategy::GeoDiverse => {
                self.select_geo_diverse(&relays, &exits, hop_count)?
            }
            _ => {
                self.select_scored(&relays, &exits, hop_count)?
            }
        };

        debug!(
            "Selected path with {} hops: {:?}",
            path.len(),
            path.iter().map(|c| &c.node_id).collect::<Vec<_>>()
        );

        Ok(path)
    }

    /// Check if a candidate is allowed
    fn is_candidate_allowed(&self, candidate: &RelayCandidate) -> bool {
        if !candidate.is_suitable() {
            return false;
        }
        if self.exclude_nodes.contains(&candidate.node_id) {
            return false;
        }
        if let Some(ref country) = candidate.country {
            if self.exclude_countries.contains(country) {
                return false;
            }
        }
        if let Some(asn) = candidate.asn {
            if self.exclude_asns.contains(&asn) {
                return false;
            }
        }
        true
    }

    /// Random path selection
    fn select_random(
        &self,
        relays: &[RelayCandidate],
        exits: &[RelayCandidate],
        hop_count: usize,
    ) -> CoreResult<Vec<RelayCandidate>> {
        let mut rng = rand::thread_rng();
        let mut path = Vec::with_capacity(hop_count);

        // Select relays (all but last hop)
        let relay_count = if self.require_exit {
            hop_count.saturating_sub(1)
        } else {
            hop_count
        };

        let mut available_relays = relays.to_vec();
        available_relays.shuffle(&mut rng);

        for relay in available_relays.into_iter().take(relay_count) {
            path.push(relay);
        }

        // Add exit node if required
        if self.require_exit {
            let mut available_exits = exits.to_vec();
            available_exits.shuffle(&mut rng);
            if let Some(exit) = available_exits.into_iter().next() {
                path.push(exit);
            } else {
                return Err(CoreError::NoPathAvailable);
            }
        }

        if path.len() < hop_count {
            return Err(CoreError::NoPathAvailable);
        }

        Ok(path)
    }

    /// Score-based path selection
    fn select_scored(
        &self,
        relays: &[RelayCandidate],
        exits: &[RelayCandidate],
        hop_count: usize,
    ) -> CoreResult<Vec<RelayCandidate>> {
        let mut path = Vec::with_capacity(hop_count);

        // Score and sort relays
        let mut scored_relays: Vec<_> = relays
            .iter()
            .map(|r| (r.clone(), r.score(self.strategy)))
            .collect();
        scored_relays.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

        // Select top relays
        let relay_count = if self.require_exit {
            hop_count.saturating_sub(1)
        } else {
            hop_count
        };

        let mut used_asns = HashSet::new();
        for (relay, _) in scored_relays {
            if path.len() >= relay_count {
                break;
            }

            // Avoid same ASN for diversity
            if let Some(asn) = relay.asn {
                if used_asns.contains(&asn) {
                    continue;
                }
                used_asns.insert(asn);
            }

            path.push(relay);
        }

        // Add best exit
        if self.require_exit {
            let mut scored_exits: Vec<_> = exits
                .iter()
                .map(|e| (e.clone(), e.score(self.strategy)))
                .collect();
            scored_exits.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

            if let Some((exit, _)) = scored_exits.into_iter().next() {
                path.push(exit);
            } else {
                return Err(CoreError::NoPathAvailable);
            }
        }

        if path.len() < hop_count {
            return Err(CoreError::NoPathAvailable);
        }

        Ok(path)
    }

    /// Geographic diversity path selection
    fn select_geo_diverse(
        &self,
        relays: &[RelayCandidate],
        exits: &[RelayCandidate],
        hop_count: usize,
    ) -> CoreResult<Vec<RelayCandidate>> {
        let mut path = Vec::with_capacity(hop_count);
        let mut used_countries = HashSet::new();
        let mut used_asns = HashSet::new();

        let relay_count = if self.require_exit {
            hop_count.saturating_sub(1)
        } else {
            hop_count
        };

        // Shuffle to avoid always picking same nodes
        let mut shuffled_relays = relays.to_vec();
        shuffled_relays.shuffle(&mut rand::thread_rng());

        // First pass: unique countries
        for relay in &shuffled_relays {
            if path.len() >= relay_count {
                break;
            }

            if let Some(ref country) = relay.country {
                if !used_countries.contains(country) {
                    used_countries.insert(country.clone());
                    if let Some(asn) = relay.asn {
                        used_asns.insert(asn);
                    }
                    path.push(relay.clone());
                }
            }
        }

        // Second pass: fill remaining with different ASNs
        for relay in &shuffled_relays {
            if path.len() >= relay_count {
                break;
            }

            if let Some(asn) = relay.asn {
                if !used_asns.contains(&asn) {
                    used_asns.insert(asn);
                    path.push(relay.clone());
                }
            }
        }

        // Third pass: just fill
        for relay in shuffled_relays {
            if path.len() >= relay_count {
                break;
            }
            if !path.iter().any(|p| p.node_id == relay.node_id) {
                path.push(relay);
            }
        }

        // Add exit from different country if possible
        if self.require_exit {
            let mut best_exit: Option<RelayCandidate> = None;

            for exit in exits {
                if let Some(ref country) = exit.country {
                    if !used_countries.contains(country) {
                        best_exit = Some(exit.clone());
                        break;
                    }
                }
                if best_exit.is_none() {
                    best_exit = Some(exit.clone());
                }
            }

            if let Some(exit) = best_exit {
                path.push(exit);
            } else {
                return Err(CoreError::NoPathAvailable);
            }
        }

        if path.len() < hop_count {
            return Err(CoreError::NoPathAvailable);
        }

        Ok(path)
    }
}

impl Default for PathSelector {
    fn default() -> Self {
        Self::new(PathSelectionStrategy::Balanced)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn make_relay(id: u8, country: &str, is_exit: bool) -> RelayCandidate {
        RelayCandidate {
            node_id: NodeId::from_bytes([id; 20]),
            public_key: meshvpn_crypto::PublicKey::from_bytes([id; 32]),
            address: format!("10.0.0.{}:8080", id).parse().unwrap(),
            latency_ms: Some(50 + id as u32 * 10),
            bandwidth: Some(1_000_000 * id as u64),
            region: Some(country.to_string()),
            country: Some(country.to_string()),
            asn: Some(id as u32 * 1000),
            is_exit,
            capacity: 100,
            load: 20,
            uptime: 0.99,
            last_seen: Instant::now(),
        }
    }

    #[test]
    fn test_random_path_selection() {
        let candidates = vec![
            make_relay(1, "US", false),
            make_relay(2, "DE", false),
            make_relay(3, "JP", false),
            make_relay(4, "BR", false),
            make_relay(5, "US", true),
        ];

        let selector = PathSelector::new(PathSelectionStrategy::Random);
        let path = selector.select_path(&candidates, 3).unwrap();

        assert_eq!(path.len(), 3);
        assert!(path.last().unwrap().is_exit);
    }

    #[test]
    fn test_geo_diverse_path_selection() {
        let candidates = vec![
            make_relay(1, "US", false),
            make_relay(2, "US", false),
            make_relay(3, "DE", false),
            make_relay(4, "JP", false),
            make_relay(5, "AU", true),
        ];

        let selector = PathSelector::new(PathSelectionStrategy::GeoDiverse);
        let path = selector.select_path(&candidates, 3).unwrap();

        assert_eq!(path.len(), 3);

        // Should have diverse countries
        let countries: HashSet<_> = path
            .iter()
            .filter_map(|p| p.country.clone())
            .collect();
        assert!(countries.len() >= 2);
    }

    #[test]
    fn test_exclude_nodes() {
        let candidates = vec![
            make_relay(1, "US", false),
            make_relay(2, "DE", false),
            make_relay(3, "JP", true),
        ];

        let exclude = NodeId::from_bytes([1; 20]);
        let selector = PathSelector::new(PathSelectionStrategy::Random)
            .exclude_nodes([exclude]);

        let path = selector.select_path(&candidates, 2).unwrap();

        assert!(!path.iter().any(|p| p.node_id == exclude));
    }
}
