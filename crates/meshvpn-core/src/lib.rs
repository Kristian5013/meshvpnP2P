//! MeshVPN Core Protocol
//!
//! Implements the core MeshVPN protocol:
//! - Circuit building and management
//! - Relay node operations
//! - Traffic routing through circuits
//! - Path selection algorithms

pub mod circuit;
pub mod relay;
pub mod router;
pub mod path;
pub mod handshake;
pub mod error;
pub mod config;
pub mod engine;

pub use circuit::{Circuit, CircuitBuilder, CircuitId, CircuitState, CircuitManager};
pub use relay::{RelayNode, RelayManager};
pub use router::{Router, RoutingTable};
pub use path::{PathSelector, PathSelectionStrategy};
pub use handshake::{Handshake, HandshakeState};
pub use error::{CoreError, CoreResult};
pub use config::CoreConfig;
pub use engine::{VpnEngine, EngineState, EngineStats, PeerInfo};

/// Protocol version
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum circuit length (hops)
pub const MAX_CIRCUIT_LENGTH: usize = 7;

/// Default circuit length
pub const DEFAULT_CIRCUIT_LENGTH: usize = 3;

/// Circuit rotation interval
pub const CIRCUIT_ROTATION_SECS: u64 = 600; // 10 minutes

/// Keep-alive interval
pub const KEEPALIVE_INTERVAL_SECS: u64 = 30;
