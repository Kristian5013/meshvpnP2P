# MeshVPN Architecture

This document provides a technical deep dive into MeshVPN's architecture, design decisions, and implementation details.

## Table of Contents
- [System Overview](#system-overview)
- [Design Goals](#design-goals)
- [Component Architecture](#component-architecture)
- [Network Layers](#network-layers)
- [Cryptography](#cryptography)
- [Protocol Design](#protocol-design)
- [Security Model](#security-model)
- [Performance Considerations](#performance-considerations)

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         MeshVPN Network                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐  │
│  │  Client  │───▶│  Guard   │───▶│  Middle  │───▶│   Exit   │  │
│  │          │    │   Node   │    │   Node   │    │   Node   │  │
│  └────┬─────┘    └──────────┘    └──────────┘    └────┬─────┘  │
│       │                                                 │         │
│       │          ┌──────────────────────┐              │         │
│       └─────────▶│    Relay Server      │◀─────────────┘         │
│                  │  (Symmetric NAT)     │                        │
│                  └──────────────────────┘                        │
│                                                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                     DHT Network                             │  │
│  │  (Kademlia for decentralized peer discovery)               │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

## Design Goals

### 1. Censorship Resistance
- **Decentralized discovery**: No central directory to block
- **Dynamic network**: Nodes can join/leave freely
- **Traffic obfuscation**: Looks like HTTPS traffic
- **AWS IP ranges**: Blocking = collateral damage to businesses

### 2. Privacy
- **Onion routing**: No single node sees full path
- **End-to-end encryption**: Even infrastructure can't read content
- **No logging**: Distributed architecture = no central logs
- **Metadata protection**: Circuit IDs rotate, no linkability

### 3. NAT Traversal
- **UDP hole punching**: Direct P2P when possible
- **STUN detection**: Automatic NAT type identification
- **Relay fallback**: Works even through symmetric NAT
- **Automatic selection**: Chooses best connection method

### 4. Modularity
- **Pluggable components**: Easy to replace/upgrade
- **Clear interfaces**: Well-defined boundaries
- **Minimal dependencies**: Each crate is self-contained

## Component Architecture

### Core Crates (6 total)

#### 1. meshvpn-dht (655 lines)
**Purpose**: Decentralized peer discovery using Kademlia DHT

**Key Files**:
- `network.rs`: DHT network layer, UDP transport
- `routing.rs`: K-bucket routing table (K=20)
- `protocol.rs`: PING, FIND_NODE, STORE messages
- `node.rs`: Node ID (256-bit), distance calculation
- `storage.rs`: DHT key-value store

**Features**:
- 160-bit node IDs (SHA-1 for compatibility)
- K-bucket routing with 20 nodes per bucket
- Iterative lookups (α = 3 concurrent queries)
- Automatic bucket refresh
- Bootstrap node support

**DHT Operations**:
```rust
// Find closest nodes to target ID
pub async fn find_node(&self, target: NodeId) -> Result<Vec<NodeInfo>>

// Store value in DHT
pub async fn store(&self, key: Key, value: Vec<u8>) -> Result<()>

// Lookup value from DHT
pub async fn lookup(&self, key: Key) -> Result<Option<Vec<u8>>>
```

#### 2. meshvpn-network
**Purpose**: P2P networking, NAT traversal, TUN interfaces

**Key Subsystems**:

**P2P Layer** (`src/p2p/`):
- `stun.rs`: NAT type detection via STUN protocol
- `hole_punch.rs`: UDP hole punching implementation
- `relay.rs`: Relay protocol for symmetric NAT
- `discovery.rs`: Peer discovery via DHT
- `protocol.rs`: P2P message format

**TUN Layer** (`src/tun/`):
- `linux.rs`: Linux TUN interface (/dev/net/tun)
- `macos.rs`: macOS utun interface
- `windows.rs`: Windows TAP adapter (Wintun)
- Platform-specific implementations for packet I/O

**Connection Management**:
```rust
pub enum ConnectionType {
    Direct,        // UDP hole punching succeeded
    Relay,         // Through relay server
    Failed,        // Connection failed
}

pub struct Connection {
    conn_type: ConnectionType,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    relay_addr: Option<SocketAddr>,
}
```

#### 3. meshvpn-crypto
**Purpose**: Onion routing encryption

**Primitives**:
- **Key Exchange**: X25519 (Curve25519 ECDH)
- **Symmetric Encryption**: ChaCha20-Poly1305 (AEAD)
- **Hashing**: BLAKE3 (fast, secure)
- **Key Derivation**: HKDF-SHA256

**Onion Encryption**:
```rust
// Build onion packet: encrypt for each hop in reverse order
pub fn build_onion<I>(
    payload: &[u8],
    path: I,
) -> Result<Vec<u8>>
where
    I: Iterator<Item = PublicKey>,

// Peel one layer: decrypt and forward
pub fn peel_layer(
    packet: &[u8],
    private_key: &PrivateKey,
) -> Result<(Vec<u8>, bool)>  // (decrypted, is_final)
```

**Key Management**:
- Ephemeral keys per circuit (rotated)
- Forward secrecy (old keys deleted)
- Key confirmation handshake

#### 4. meshvpn-core
**Purpose**: Circuit building and routing logic

**Key Components**:
- `circuit.rs`: Circuit builder (⚠️ currently over-engineered)
- `path.rs`: Path selection algorithms
- `router.rs`: Packet routing
- `engine.rs`: Main VPN engine
- `relay.rs`: Relay node logic

**Circuit Building** (needs refactoring):
```rust
pub struct Circuit {
    id: CircuitId,
    path: Vec<NodeId>,
    keys: Vec<SessionKey>,
    state: CircuitState,
}

pub async fn build_circuit(
    dht: &Dht,
    target: NodeId,
    hops: usize,
) -> Result<Circuit>
```

**Path Selection** (to be implemented):
- Guard node selection (stable, high-uptime)
- Middle node selection (random)
- Exit node selection (by geography/policy)
- Avoid same /16 subnet
- Load balancing

#### 5. meshvpn-exit
**Purpose**: Exit node implementation

**Key Functions**:
- `nat.rs`: NAT configuration (iptables/pf)
- `circuit_handler.rs`: Handle incoming circuits
- `logging.rs`: Minimal logging (exit policies only)

**Exit Policies** (to be implemented):
```rust
pub struct ExitPolicy {
    allowed_ports: Vec<u16>,
    blocked_ips: Vec<IpAddr>,
    bandwidth_limit: u64,
}
```

#### 6. meshvpn-payment
**Purpose**: Monero integration (Phase 4)

**Planned Features**:
- Monero RPC integration
- Payment verification
- Bandwidth accounting
- Token issuance

### Binaries (5 total)

1. **meshvpn-bootstrap**: Initialize network, deploy bootstrap nodes
2. **meshvpn-client**: Client daemon + TUN interface
3. **meshvpn-dht-bootstrap**: DHT bootstrap node
4. **meshvpn-discovery**: Discovery service
5. **meshvpn-exit-node**: Exit node server

## Network Layers

### Layer 1: DHT Network (Overlay)

**Topology**: Kademlia DHT with 160-bit node IDs

**Distance Metric**: XOR distance
```
distance(A, B) = A XOR B
```

**Routing Table**: 160 buckets, up to 20 nodes per bucket

**Lookup Algorithm**:
1. Start with α (3) closest known nodes
2. Query each node for closer nodes
3. Repeat with newly discovered nodes
4. Converge when no closer nodes found

**Bootstrap Process**:
```
Client → Connect to bootstrap node
       → Get initial peer list
       → Populate routing table
       → Join DHT network
```

### Layer 2: P2P Network (Transport)

**Protocol**: Custom UDP-based

**NAT Traversal**:

```
1. STUN Phase:
   Client → STUN server
          ← NAT type detection
   
2. Direct Connection Attempt:
   Peer A → Simultaneous UDP send → Peer B
          ← Hole punching
   
3. Relay Fallback:
   Peer A → Relay Server → Peer B
          (if both symmetric NAT)
```

**NAT Types Supported**:
- ✅ Full Cone NAT (direct)
- ✅ Restricted Cone NAT (direct)
- ✅ Port-Restricted Cone NAT (direct)
- ✅ Symmetric NAT (relay)

**Connection State Machine**:
```
INIT → STUN → HOLE_PUNCH → ESTABLISHED
         ↓                      ↑
         └─→ RELAY ────────────┘
```

### Layer 3: Circuit Layer (Onion Routing)

**Circuit Structure**:
```
Client → Guard → Middle1 → Middle2 → Exit → Internet
   └──────────── Encrypted Path ──────────┘
```

**Encryption Layers** (simplified):
```
Layer 1: E_exit(E_middle2(E_middle1(E_guard(payload))))
Layer 2: E_middle2(E_middle1(E_guard(payload)))
Layer 3: E_middle1(E_guard(payload))
Layer 4: E_guard(payload)
Layer 5: payload
```

Each node peels one layer, sees next hop only.

**Circuit Lifecycle**:
```
BUILD → EXTEND → EXTEND → READY → RELAY → TEARDOWN
```

### Layer 4: TUN Interface (Virtual Network)

**IP Assignment**: 10.8.0.0/24 range

**Packet Flow**:
```
Application → TUN interface → Encapsulate → Circuit → Exit → Internet
          ← Decapsulate ← Circuit ← Exit ← Internet
```

**TUN Operations**:
- Read: `read()` from TUN fd
- Write: `write()` to TUN fd
- MTU: 1420 bytes (1500 - overhead)

## Cryptography

### Onion Routing Encryption

**Key Exchange** (per hop):
```
1. Client generates ephemeral X25519 keypair
2. Client → Node: ephemeral_public_key
3. Node generates ephemeral keypair
4. Node → Client: ephemeral_public_key
5. Both compute shared_secret = ECDH(private, other_public)
6. Derive session keys: HKDF-SHA256(shared_secret)
```

**Symmetric Encryption**:
```
ChaCha20-Poly1305 AEAD:
- Key: 256 bits
- Nonce: 96 bits (incremental)
- Tag: 128 bits
```

**Layered Encryption**:
```rust
// Build onion (encrypt from exit to entry):
let mut packet = payload;
for hop in path.iter().rev() {
    packet = encrypt_layer(packet, hop.key);
}

// Peel onion (decrypt at each hop):
let (decrypted, is_exit) = decrypt_layer(packet, my_key);
if !is_exit {
    forward_to_next_hop(decrypted);
} else {
    deliver_to_application(decrypted);
}
```

### Key Rotation

- **Circuit keys**: Rotated every 1 hour or 1 GB
- **Ephemeral keys**: Per circuit, deleted after
- **Forward secrecy**: Old keys never stored

## Protocol Design

### Message Format

```
┌────────────────────────────────────────────┐
│           Message Header (32 bytes)        │
├────────────────────────────────────────────┤
│ Circuit ID (16 bytes)                      │
│ Command (2 bytes)                          │
│ Length (2 bytes)                           │
│ Padding (12 bytes)                         │
├────────────────────────────────────────────┤
│           Payload (variable)               │
├────────────────────────────────────────────┤
│        Poly1305 Tag (16 bytes)             │
└────────────────────────────────────────────┘
```

### Commands

```rust
pub enum Command {
    // Circuit management
    Create = 0x01,
    Created = 0x02,
    Extend = 0x03,
    Extended = 0x04,
    Destroy = 0x05,
    
    // Data relay
    Relay = 0x06,
    RelayData = 0x07,
    RelayBegin = 0x08,
    RelayEnd = 0x09,
    
    // DHT
    DhtPing = 0x10,
    DhtFindNode = 0x11,
    DhtStore = 0x12,
}
```

### Circuit Building Protocol

```
Client → Guard: CREATE (ephemeral key)
Guard → Client: CREATED (ephemeral key)
[Session key established]

Client → Guard → Middle: EXTEND (next hop, ephemeral key)
Guard → Middle: CREATE (forwarded)
Middle → Guard → Client: EXTENDED (ephemeral key)
[Second hop session key established]

Client → Guard → Middle → Exit: EXTEND (next hop, ephemeral key)
...
[Third hop session key established]

Circuit ready for RELAY DATA
```

## Security Model

### Threat Model

**Assumptions**:
- Adversary controls some nodes (< 50%)
- Adversary monitors network traffic
- Adversary may run malicious relays
- Adversary may attempt to deanonymize users

**Protections**:
- ✅ Traffic analysis: Multiple hops prevent correlation
- ✅ Content inspection: End-to-end encryption
- ✅ Node compromise: Multi-hop = no single point
- ⚠️ Timing attacks: Not yet mitigated (future work)
- ⚠️ Sybil attacks: No reputation system yet

### Trust Boundaries

```
┌──────────────────────────────────────────┐
│           Trusted Zone                    │
│  ┌────────────────────────────────────┐  │
│  │    Client Application              │  │
│  │  (knows full path, plaintext)      │  │
│  └────────────────────────────────────┘  │
└──────────────────────────────────────────┘
                    ↕
┌──────────────────────────────────────────┐
│           Untrusted Zone                  │
│  ┌────────────────────────────────────┐  │
│  │  Guard, Middle, Exit Nodes         │  │
│  │  (know predecessor + successor)    │  │
│  │  (cannot read content)             │  │
│  └────────────────────────────────────┘  │
└──────────────────────────────────────────┘
```

### Security Properties

**Confidentiality**:
- End-to-end encryption (client ↔ exit)
- Hop-by-hop encryption (onion layers)

**Integrity**:
- AEAD tags prevent tampering
- Circuit IDs prevent injection

**Anonymity**:
- No node knows full path
- Timing analysis difficult (future padding)

**Deniability**:
- Exit node IP, not client IP, appears in logs
- No persistent identifiers

## Performance Considerations

### Latency

**Components**:
```
Total = DHT_lookup + Circuit_build + Relay_hops + Exit_processing

DHT_lookup: ~100-500ms (Kademlia iterative)
Circuit_build: ~500-1000ms (3 handshakes)
Relay_hops: ~50ms per hop (3 hops = 150ms)
Exit_processing: ~10-50ms

Total: ~800-1700ms initial
Steady-state: ~150-200ms per request
```

### Throughput

**Bottlenecks**:
1. **Encryption overhead**: ChaCha20-Poly1305 is fast (~3 GB/s on modern CPU)
2. **Network bandwidth**: Limited by weakest link
3. **Relay capacity**: Depends on relay resources

**Optimizations** (future):
- Zero-copy packet forwarding
- SIMD-accelerated crypto
- Connection pooling
- Congestion control

### Scalability

**DHT Network**:
- O(log N) lookups
- ~20 connections per node
- Scales to millions of nodes

**Circuit Capacity**:
- 1 guard node can handle ~1000 circuits
- Load balancing via path selection

## Future Improvements

### Short-term (Phase 2-3)
- [ ] Fix circuit.rs over-engineering
- [ ] Implement path selection
- [ ] Add TUN integration
- [ ] Performance benchmarks

### Medium-term (Phase 4-5)
- [ ] Padding for timing attack mitigation
- [ ] Congestion control
- [ ] Mobile support
- [ ] GUI improvements

### Long-term (2026+)
- [ ] Post-quantum cryptography (Kyber)
- [ ] DAO governance
- [ ] Anonymous reputation system
- [ ] Cross-protocol bridges

## References

1. **Tor Design**: https://svn.torproject.org/svn/projects/design-paper/tor-design.pdf
2. **Kademlia DHT**: http://www.scs.stanford.edu/~dm/home/papers/kpos.pdf
3. **WireGuard**: https://www.wireguard.com/papers/wireguard.pdf
4. **X25519**: RFC 7748
5. **ChaCha20-Poly1305**: RFC 8439
6. **BLAKE3**: https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf

---

**Last Updated**: December 2024  
**Status**: Phase 1 complete, Phase 2 in progress
