//! DHT Value Storage

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tracing::debug;

/// A stored value with metadata
#[derive(Debug, Clone)]
pub struct StoredValue {
    /// The value data
    pub value: Vec<u8>,
    /// When this value was stored
    pub stored_at: Instant,
    /// When this value expires
    pub expires_at: Instant,
    /// Original publisher (for republishing)
    pub publisher: meshvpn_crypto::NodeId,
}

impl StoredValue {
    /// Create a new stored value
    pub fn new(value: Vec<u8>, ttl: Duration, publisher: meshvpn_crypto::NodeId) -> Self {
        let now = Instant::now();
        Self {
            value,
            stored_at: now,
            expires_at: now + ttl,
            publisher,
        }
    }

    /// Check if expired
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Remaining TTL
    pub fn remaining_ttl(&self) -> Duration {
        self.expires_at.saturating_duration_since(Instant::now())
    }
}

/// DHT key-value storage
pub struct DhtStorage {
    /// Stored values by key
    values: HashMap<[u8; 32], StoredValue>,
    /// Maximum entries
    max_entries: usize,
    /// Maximum value size
    max_value_size: usize,
}

impl DhtStorage {
    /// Create new storage
    pub fn new() -> Self {
        Self {
            values: HashMap::new(),
            max_entries: 10000,
            max_value_size: 65536,
        }
    }

    /// Create with custom limits
    pub fn with_limits(max_entries: usize, max_value_size: usize) -> Self {
        Self {
            values: HashMap::new(),
            max_entries,
            max_value_size,
        }
    }

    /// Store a value
    pub fn store(
        &mut self,
        key: [u8; 32],
        value: Vec<u8>,
        ttl: Duration,
        publisher: meshvpn_crypto::NodeId,
    ) -> bool {
        // Check size limit
        if value.len() > self.max_value_size {
            return false;
        }

        // Check entry limit
        if !self.values.contains_key(&key) && self.values.len() >= self.max_entries {
            // Try to make room
            self.cleanup();
            if self.values.len() >= self.max_entries {
                return false;
            }
        }

        let stored = StoredValue::new(value, ttl, publisher);
        self.values.insert(key, stored);
        true
    }

    /// Get a value
    pub fn get(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        let value = self.values.get(key)?;
        if value.is_expired() {
            None
        } else {
            Some(value.value.clone())
        }
    }

    /// Get stored value with metadata
    pub fn get_full(&self, key: &[u8; 32]) -> Option<&StoredValue> {
        let value = self.values.get(key)?;
        if value.is_expired() {
            None
        } else {
            Some(value)
        }
    }

    /// Simple put (uses default publisher)
    pub fn put(&mut self, key: [u8; 32], value: Vec<u8>, ttl_secs: u32) -> bool {
        let default_publisher = meshvpn_crypto::NodeId::from_bytes([0u8; 20]);
        self.store(key, value, std::time::Duration::from_secs(ttl_secs as u64), default_publisher)
    }

    /// Remove a value
    pub fn remove(&mut self, key: &[u8; 32]) -> Option<StoredValue> {
        self.values.remove(key)
    }

    /// Check if key exists
    pub fn contains(&self, key: &[u8; 32]) -> bool {
        self.get(key).is_some()
    }

    /// Get number of entries
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Clean up expired entries
    pub fn cleanup(&mut self) -> usize {
        let before = self.values.len();
        self.values.retain(|_, v| !v.is_expired());
        let removed = before - self.values.len();
        if removed > 0 {
            debug!("Cleaned up {} expired DHT entries", removed);
        }
        removed
    }

    /// Get all keys (for republishing)
    pub fn keys(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.values.keys()
    }

    /// Get entries that need republishing
    pub fn entries_for_republish(&self, max_age: Duration) -> Vec<([u8; 32], StoredValue)> {
        let now = Instant::now();
        self.values
            .iter()
            .filter(|(_, v)| now.duration_since(v.stored_at) >= max_age && !v.is_expired())
            .map(|(k, v)| (*k, v.clone()))
            .collect()
    }
}

impl Default for DhtStorage {
    fn default() -> Self {
        Self::new()
    }
}

/// Key generation helpers
pub mod keys {
    use blake3::Hasher;

    /// Generate key for a node announcement
    pub fn node_key(node_id: &meshvpn_crypto::NodeId) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(b"meshvpn:node:");
        hasher.update(node_id.as_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Generate key for exit node list
    pub fn exit_nodes_key(region: &str) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(b"meshvpn:exits:");
        hasher.update(region.as_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Generate key for relay node list
    pub fn relay_nodes_key(region: &str) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(b"meshvpn:relays:");
        hasher.update(region.as_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Generate key from arbitrary data
    pub fn custom_key(namespace: &str, data: &[u8]) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(b"meshvpn:custom:");
        hasher.update(namespace.as_bytes());
        hasher.update(b":");
        hasher.update(data);
        *hasher.finalize().as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node_id() -> meshvpn_crypto::NodeId {
        meshvpn_crypto::NodeId::from_bytes([1u8; 20])
    }

    #[test]
    fn test_store_and_get() {
        let mut storage = DhtStorage::new();

        let key = [1u8; 32];
        let value = b"test data".to_vec();

        assert!(storage.store(key, value.clone(), Duration::from_secs(60), test_node_id()));
        assert!(storage.contains(&key));

        let retrieved = storage.get(&key).unwrap();
        assert_eq!(retrieved, value);
    }

    #[test]
    fn test_expiry() {
        let mut storage = DhtStorage::new();

        let key = [2u8; 32];
        let value = b"expiring".to_vec();

        // Store with 0 TTL (immediately expired)
        storage.store(key, value, Duration::from_secs(0), test_node_id());

        // Should not be retrievable
        assert!(storage.get(&key).is_none());
    }

    #[test]
    fn test_cleanup() {
        let mut storage = DhtStorage::new();

        // Store multiple values
        for i in 0..5 {
            let mut key = [0u8; 32];
            key[0] = i;

            // Alternating TTL: some expired, some not
            let ttl = if i % 2 == 0 {
                Duration::from_secs(0)
            } else {
                Duration::from_secs(3600)
            };

            storage.store(key, vec![i], ttl, test_node_id());
        }

        // Cleanup expired
        let removed = storage.cleanup();

        // Should have removed the even-numbered entries
        assert_eq!(removed, 3); // 0, 2, 4
        assert_eq!(storage.len(), 2); // 1, 3
    }

    #[test]
    fn test_max_entries() {
        let mut storage = DhtStorage::with_limits(3, 1024);

        // Fill to capacity
        for i in 0..3 {
            let mut key = [0u8; 32];
            key[0] = i;
            assert!(storage.store(key, vec![i], Duration::from_secs(3600), test_node_id()));
        }

        // Fourth should fail
        let mut key = [0u8; 32];
        key[0] = 99;
        assert!(!storage.store(key, vec![99], Duration::from_secs(3600), test_node_id()));
    }

    #[test]
    fn test_key_generation() {
        let node_id = test_node_id();
        let key1 = keys::node_key(&node_id);
        let key2 = keys::node_key(&node_id);

        // Should be deterministic
        assert_eq!(key1, key2);

        // Different inputs should give different keys
        let key3 = keys::exit_nodes_key("us-east");
        assert_ne!(key1, key3);
    }
}
