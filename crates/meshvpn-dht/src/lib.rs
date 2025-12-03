//! MeshVPN Distributed Hash Table
//!
//! Implements Kademlia-based peer discovery for finding relay nodes
//! and exit nodes in the MeshVPN network.

pub mod routing;
pub mod node;
pub mod protocol;
pub mod storage;
pub mod error;
pub mod network;

pub use routing::{RoutingTable, KBucket};
pub use node::{DhtNode, NodeInfo, NodeStatus, NodeEntry};
pub use protocol::{DhtMessage, DhtRequest, DhtResponse, RpcMessage};
pub use storage::{DhtStorage, keys};
pub use error::{DhtError, DhtResult};
pub use network::DhtNetwork;

/// Kademlia K parameter (bucket size)
pub const K: usize = 20;

/// Alpha parameter (parallelism factor)
pub const ALPHA: usize = 3;

/// Node ID bit length
pub const ID_BITS: usize = 160;

/// Number of buckets
pub const NUM_BUCKETS: usize = ID_BITS;

/// Refresh interval for buckets
pub const BUCKET_REFRESH_INTERVAL_SECS: u64 = 3600; // 1 hour

/// Expiry time for stored values
pub const VALUE_EXPIRY_SECS: u64 = 86400; // 24 hours

/// Republish interval
pub const REPUBLISH_INTERVAL_SECS: u64 = 3600; // 1 hour
