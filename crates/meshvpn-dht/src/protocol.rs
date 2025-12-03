//! DHT Protocol Messages

use meshvpn_crypto::NodeId;
use serde::{Deserialize, Serialize};

use crate::node::NodeInfo;

/// DHT message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtMessage {
    /// Request message
    Request(DhtRequest),
    /// Response message
    Response(DhtResponse),
}

/// DHT request types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtRequest {
    /// Ping - check if node is alive
    Ping {
        /// Sender's node ID
        sender_id: NodeId,
    },

    /// Find node - find K closest nodes to target
    FindNode {
        /// Sender's node ID
        sender_id: NodeId,
        /// Target node ID to find
        target: NodeId,
    },

    /// Find value - find value by key
    FindValue {
        /// Sender's node ID
        sender_id: NodeId,
        /// Key to look up
        key: [u8; 32],
    },

    /// Store value
    Store {
        /// Sender's node ID
        sender_id: NodeId,
        /// Key
        key: [u8; 32],
        /// Value
        value: Vec<u8>,
        /// Time to live in seconds
        ttl: u32,
    },

    /// Announce - announce ourselves to the network
    Announce {
        /// Our node info
        info: NodeInfo,
    },

    /// Get nodes - request known exit nodes
    GetExitNodes {
        /// Sender's node ID
        sender_id: NodeId,
        /// Maximum count
        max_count: u32,
    },

    /// Get relay nodes
    GetRelayNodes {
        /// Sender's node ID
        sender_id: NodeId,
        /// Maximum count
        max_count: u32,
        /// Minimum capacity
        min_capacity: Option<u32>,
    },
}

/// DHT response types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtResponse {
    /// Pong - response to ping
    Pong {
        /// Responder's node ID
        sender_id: NodeId,
    },

    /// Nodes found
    NodesFound {
        /// Responder's node ID
        sender_id: NodeId,
        /// Found nodes (up to K)
        nodes: Vec<NodeInfo>,
    },

    /// Value found
    ValueFound {
        /// Responder's node ID
        sender_id: NodeId,
        /// The value
        value: Vec<u8>,
    },

    /// Value not found, returning closest nodes instead
    ValueNotFound {
        /// Responder's node ID
        sender_id: NodeId,
        /// Closest nodes to the key
        closest_nodes: Vec<NodeInfo>,
    },

    /// Store acknowledged
    StoreAck {
        /// Responder's node ID
        sender_id: NodeId,
        /// Success
        success: bool,
    },

    /// Exit nodes response
    ExitNodes {
        /// Responder's node ID
        sender_id: NodeId,
        /// Exit node infos
        nodes: Vec<NodeInfo>,
    },

    /// Relay nodes response
    RelayNodes {
        /// Responder's node ID
        sender_id: NodeId,
        /// Relay node infos
        nodes: Vec<NodeInfo>,
    },

    /// Error response
    Error {
        /// Responder's node ID
        sender_id: NodeId,
        /// Error code
        code: u32,
        /// Error message
        message: String,
    },
}

impl DhtMessage {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::DhtError> {
        bincode::serialize(self)
            .map_err(|e| crate::error::DhtError::SerializationError(e.to_string()))
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::DhtError> {
        bincode::deserialize(bytes)
            .map_err(|e| crate::error::DhtError::SerializationError(e.to_string()))
    }

    /// Get the sender ID
    pub fn sender_id(&self) -> Option<NodeId> {
        match self {
            DhtMessage::Request(req) => match req {
                DhtRequest::Ping { sender_id } => Some(*sender_id),
                DhtRequest::FindNode { sender_id, .. } => Some(*sender_id),
                DhtRequest::FindValue { sender_id, .. } => Some(*sender_id),
                DhtRequest::Store { sender_id, .. } => Some(*sender_id),
                DhtRequest::Announce { info } => Some(info.node_id),
                DhtRequest::GetExitNodes { sender_id, .. } => Some(*sender_id),
                DhtRequest::GetRelayNodes { sender_id, .. } => Some(*sender_id),
            },
            DhtMessage::Response(resp) => match resp {
                DhtResponse::Pong { sender_id } => Some(*sender_id),
                DhtResponse::NodesFound { sender_id, .. } => Some(*sender_id),
                DhtResponse::ValueFound { sender_id, .. } => Some(*sender_id),
                DhtResponse::ValueNotFound { sender_id, .. } => Some(*sender_id),
                DhtResponse::StoreAck { sender_id, .. } => Some(*sender_id),
                DhtResponse::ExitNodes { sender_id, .. } => Some(*sender_id),
                DhtResponse::RelayNodes { sender_id, .. } => Some(*sender_id),
                DhtResponse::Error { sender_id, .. } => Some(*sender_id),
            },
        }
    }
}

/// RPC ID for matching requests to responses
pub type RpcId = u64;

/// Wrapped message with RPC ID
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcMessage {
    /// Unique RPC ID
    pub rpc_id: RpcId,
    /// The message
    pub message: DhtMessage,
}

impl RpcMessage {
    /// Create a new RPC message
    pub fn new(message: DhtMessage) -> Self {
        Self {
            rpc_id: rand::random(),
            message,
        }
    }

    /// Create a response with same RPC ID
    pub fn response(&self, message: DhtMessage) -> Self {
        Self {
            rpc_id: self.rpc_id,
            message,
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::DhtError> {
        bincode::serialize(self)
            .map_err(|e| crate::error::DhtError::SerializationError(e.to_string()))
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::DhtError> {
        bincode::deserialize(bytes)
            .map_err(|e| crate::error::DhtError::SerializationError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node_id() -> NodeId {
        NodeId::from_bytes([1u8; 20])
    }

    #[test]
    fn test_message_serialization() {
        let msg = DhtMessage::Request(DhtRequest::Ping {
            sender_id: test_node_id(),
        });

        let bytes = msg.to_bytes().unwrap();
        let decoded = DhtMessage::from_bytes(&bytes).unwrap();

        match decoded {
            DhtMessage::Request(DhtRequest::Ping { sender_id }) => {
                assert_eq!(sender_id, test_node_id());
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_rpc_message() {
        let msg = DhtMessage::Request(DhtRequest::Ping {
            sender_id: test_node_id(),
        });

        let rpc = RpcMessage::new(msg);
        let response = rpc.response(DhtMessage::Response(DhtResponse::Pong {
            sender_id: test_node_id(),
        }));

        assert_eq!(rpc.rpc_id, response.rpc_id);
    }
}
