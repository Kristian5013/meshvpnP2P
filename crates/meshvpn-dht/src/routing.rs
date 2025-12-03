//! Kademlia Routing Table

use std::collections::VecDeque;
use std::time::Instant;

use meshvpn_crypto::NodeId;
use tracing::{debug, trace};

use crate::node::NodeEntry;
use crate::{K, NUM_BUCKETS};

/// A K-bucket in the routing table
#[derive(Debug)]
pub struct KBucket {
    /// Nodes in this bucket (oldest first)
    nodes: VecDeque<NodeEntry>,
    /// Last refresh time
    last_refresh: Instant,
    /// Replacement cache (nodes that couldn't fit)
    replacement_cache: VecDeque<NodeEntry>,
}

impl KBucket {
    /// Create a new empty bucket
    pub fn new() -> Self {
        Self {
            nodes: VecDeque::with_capacity(K),
            last_refresh: Instant::now(),
            replacement_cache: VecDeque::with_capacity(K),
        }
    }

    /// Check if bucket is full
    pub fn is_full(&self) -> bool {
        self.nodes.len() >= K
    }

    /// Get number of nodes
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Add a node to the bucket
    pub fn add(&mut self, entry: NodeEntry) -> bool {
        // Check if already exists
        if let Some(pos) = self.nodes.iter().position(|n| n.info.node_id == entry.info.node_id) {
            // Move to back (most recently seen)
            self.nodes.remove(pos);
            self.nodes.push_back(entry);
            return true;
        }

        // Not full - just add
        if !self.is_full() {
            self.nodes.push_back(entry);
            return true;
        }

        // Full - add to replacement cache
        if self.replacement_cache.len() >= K {
            self.replacement_cache.pop_front();
        }
        self.replacement_cache.push_back(entry);
        false
    }

    /// Get a node by ID
    pub fn get(&self, id: &NodeId) -> Option<&NodeEntry> {
        self.nodes.iter().find(|n| n.info.node_id == *id)
    }

    /// Get a node mutably by ID
    pub fn get_mut(&mut self, id: &NodeId) -> Option<&mut NodeEntry> {
        self.nodes.iter_mut().find(|n| n.info.node_id == *id)
    }

    /// Remove a node by ID
    pub fn remove(&mut self, id: &NodeId) -> Option<NodeEntry> {
        if let Some(pos) = self.nodes.iter().position(|n| n.info.node_id == *id) {
            let removed = self.nodes.remove(pos)?;

            // Try to promote from replacement cache
            if let Some(replacement) = self.replacement_cache.pop_front() {
                self.nodes.push_back(replacement);
            }

            return Some(removed);
        }
        None
    }

    /// Get the oldest node (for ping checking)
    pub fn oldest(&self) -> Option<&NodeEntry> {
        self.nodes.front()
    }

    /// Get all nodes
    pub fn nodes(&self) -> impl Iterator<Item = &NodeEntry> {
        self.nodes.iter()
    }

    /// Touch (refresh) the bucket
    pub fn touch(&mut self) {
        self.last_refresh = Instant::now();
    }

    /// Check if bucket needs refresh
    pub fn needs_refresh(&self, max_age: std::time::Duration) -> bool {
        self.last_refresh.elapsed() > max_age
    }

    /// Remove dead nodes and promote from cache
    pub fn cleanup(&mut self) -> usize {
        let before = self.nodes.len();

        // Remove dead nodes
        self.nodes.retain(|n| !n.is_dead());

        // Promote from replacement cache
        while !self.is_full() {
            if let Some(replacement) = self.replacement_cache.pop_front() {
                self.nodes.push_back(replacement);
            } else {
                break;
            }
        }

        before - self.nodes.len()
    }
}

impl Default for KBucket {
    fn default() -> Self {
        Self::new()
    }
}

/// Kademlia routing table
pub struct RoutingTable {
    /// Our node ID
    local_id: NodeId,
    /// K-buckets (one for each bit of distance)
    buckets: Vec<KBucket>,
}

impl RoutingTable {
    /// Create a new routing table
    pub fn new(local_id: NodeId) -> Self {
        let buckets = (0..NUM_BUCKETS).map(|_| KBucket::new()).collect();
        Self { local_id, buckets }
    }

    /// Get bucket index for a node ID
    fn bucket_index(&self, id: &NodeId) -> usize {
        let leading_zeros = self.local_id.leading_zeros(id) as usize;
        // Bucket 0 = closest (most leading zeros in XOR)
        // Bucket 159 = furthest (0 leading zeros)
        (NUM_BUCKETS - 1).saturating_sub(leading_zeros)
    }

    /// Add a node to the routing table
    pub fn add(&mut self, entry: NodeEntry) -> bool {
        let index = self.bucket_index(&entry.info.node_id);
        let added = self.buckets[index].add(entry.clone());

        if added {
            trace!("Added node {:?} to bucket {}", entry.info.node_id, index);
        }

        added
    }

    /// Get a node by ID
    pub fn get(&self, id: &NodeId) -> Option<NodeEntry> {
        let index = self.bucket_index(id);
        self.buckets[index].get(id).cloned()
    }

    /// Get a node mutably
    pub fn get_mut(&mut self, id: &NodeId) -> Option<&mut NodeEntry> {
        let index = self.bucket_index(id);
        self.buckets[index].get_mut(id)
    }

    /// Remove a node
    pub fn remove(&mut self, id: &NodeId) -> Option<NodeEntry> {
        let index = self.bucket_index(id);
        self.buckets[index].remove(id)
    }

    /// Find the K closest nodes to a target
    pub fn find_closest(&self, target: &NodeId, count: usize) -> Vec<NodeEntry> {
        let mut all_nodes: Vec<_> = self
            .buckets
            .iter()
            .flat_map(|b| b.nodes())
            .cloned()
            .collect();

        // Sort by XOR distance to target
        all_nodes.sort_by(|a, b| {
            let dist_a = target.distance(&a.info.node_id);
            let dist_b = target.distance(&b.info.node_id);
            dist_a.cmp(&dist_b)
        });

        all_nodes.truncate(count);
        all_nodes
    }

    /// Get all nodes
    pub fn all_nodes(&self) -> Vec<NodeEntry> {
        self.buckets
            .iter()
            .flat_map(|b| b.nodes())
            .cloned()
            .collect()
    }

    /// Get total node count
    pub fn len(&self) -> usize {
        self.buckets.iter().map(|b| b.len()).sum()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.buckets.iter().all(|b| b.is_empty())
    }

    /// Get bucket at index
    pub fn bucket(&self, index: usize) -> Option<&KBucket> {
        self.buckets.get(index)
    }

    /// Get bucket mutably at index
    pub fn bucket_mut(&mut self, index: usize) -> Option<&mut KBucket> {
        self.buckets.get_mut(index)
    }

    /// Find buckets that need refresh
    pub fn buckets_needing_refresh(&self, max_age: std::time::Duration) -> Vec<usize> {
        self.buckets
            .iter()
            .enumerate()
            .filter(|(_, b)| b.needs_refresh(max_age))
            .map(|(i, _)| i)
            .collect()
    }

    /// Clean up all buckets
    pub fn cleanup(&mut self) -> usize {
        let mut removed = 0;
        for bucket in &mut self.buckets {
            removed += bucket.cleanup();
        }
        if removed > 0 {
            debug!("Cleaned up {} dead nodes from routing table", removed);
        }
        removed
    }

    /// Get a random node ID for refreshing a specific bucket
    pub fn random_id_for_bucket(&self, bucket_index: usize) -> NodeId {
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let mut id_bytes = [0u8; 20];
        rng.fill(&mut id_bytes);

        // Set the appropriate prefix to land in the target bucket
        let bit_position = NUM_BUCKETS - 1 - bucket_index;

        // Copy our local ID prefix
        let local_bytes = self.local_id.as_bytes();
        let byte_pos = bit_position / 8;
        let bit_pos = bit_position % 8;

        for (i, b) in id_bytes.iter_mut().enumerate().take(byte_pos) {
            *b = local_bytes[i];
        }

        // Flip the target bit
        id_bytes[byte_pos] = local_bytes[byte_pos] ^ (0x80 >> bit_pos);

        NodeId::from_bytes(id_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::NodeInfo;
    use meshvpn_crypto::PublicKey;

    fn make_node_id(seed: u8) -> NodeId {
        NodeId::from_bytes([seed; 20])
    }

    fn make_entry(id: NodeId) -> NodeEntry {
        let info = NodeInfo {
            node_id: id,
            public_key: PublicKey::from_bytes([1u8; 32]),
            signing_key: [2u8; 32],
            addresses: vec!["127.0.0.1:8080".parse().unwrap()],
            status: crate::node::NodeStatus::Active,
            capacity: 100,
            load: 0,
            version: 1,
            region: None,
            country: None,
            timestamp: 0,
            signature: [0u8; 64],
        };
        NodeEntry::new(info)
    }

    #[test]
    fn test_bucket_add() {
        let mut bucket = KBucket::new();

        for i in 0..K {
            let entry = make_entry(make_node_id(i as u8));
            assert!(bucket.add(entry));
        }

        assert!(bucket.is_full());

        // Adding more goes to replacement cache
        let extra = make_entry(make_node_id(100));
        assert!(!bucket.add(extra));
    }

    #[test]
    fn test_routing_table_add() {
        let local_id = make_node_id(0);
        let mut table = RoutingTable::new(local_id);

        for i in 1..=10 {
            let entry = make_entry(make_node_id(i));
            table.add(entry);
        }

        assert_eq!(table.len(), 10);
    }

    #[test]
    fn test_find_closest() {
        let local_id = make_node_id(0);
        let mut table = RoutingTable::new(local_id);

        // Add nodes
        for i in 1..20 {
            let entry = make_entry(make_node_id(i));
            table.add(entry);
        }

        let target = make_node_id(5);
        let closest = table.find_closest(&target, 5);

        assert_eq!(closest.len(), 5);

        // First result should be the target itself or closest to it
        // The exact order depends on XOR distance
    }

    #[test]
    fn test_bucket_index() {
        let local_id = make_node_id(0);
        let table = RoutingTable::new(local_id);

        // Same ID should have highest bucket index (closest)
        // But we don't add ourselves, so this is theoretical

        // Very different ID
        let far_id = make_node_id(255);
        let index = table.bucket_index(&far_id);
        assert!(index < NUM_BUCKETS);
    }
}
