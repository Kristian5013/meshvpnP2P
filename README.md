# MeshVPN - Decentralized P2P VPN Network

[![Status](https://img.shields.io/badge/status-WIP-yellow)](https://github.com/Kristian5013/meshvpnP2P)
[![Phase 1](https://img.shields.io/badge/Phase%201-Complete-green)]()
[![Phase 2](https://img.shields.io/badge/Phase%202-In%20Progress-orange)]()
[![Built by](https://img.shields.io/badge/built%20by-15yo%20developer-blue)]()
[![Time](https://img.shields.io/badge/development-7%20hours-purple)]()

> **⚠️ WORK IN PROGRESS** - Built in 7 hours by a 15-year-old developer. Phase 1 complete, Phase 2 in progress.

A decentralized, censorship-resistant VPN combining Tor-style onion routing with P2P mesh networking. Built in Rust with a focus on privacy, resilience, and distributed architecture.

## 🎯 What Makes This Different

MeshVPN is not just another VPN - it's a research project exploring the intersection of:
- **Tor-style onion routing** (multi-hop encryption)
- **P2P mesh networking** (decentralized infrastructure)
- **VPN technology** (secure tunneling)

Traditional VPNs have single points of failure. MeshVPN distributes trust across multiple nodes, making it harder to block, monitor, or compromise.

## 🚧 Current Status

### Phase 1: P2P Foundation ✅ COMPLETE
- ✅ P2P peer discovery via Kademlia DHT
- ✅ NAT traversal (STUN + UDP hole punching)
- ✅ Relay protocol for symmetric NAT
- ✅ GUI client (Tauri + React)
- ✅ Two laptops successfully connected

### Phase 2: Circuit Routing 🚧 IN PROGRESS
- 🔨 Circuit/onion routing through multiple nodes
- 🔨 Exit node implementation
- 🔨 TUN interface integration
- 📋 Path selection algorithms

### Phase 3: Production Ready 📋 PLANNED
- 📋 Monero payment integration
- 📋 Production deployment
- 📋 Security audit
- 📋 Performance optimization

## 🏗️ Architecture

### System Components

```
┌─────────────────────────────────────────────────────────┐
│                     MeshVPN Network                      │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  Client ──► DHT Discovery ──► Circuit Building ──► Exit  │
│    │            │                    │              │    │
│    │            │                    │              │    │
│    └──► P2P ────┴──► Relay ─────────┴──► Onion ────┘    │
│         Layer         Server          Routing            │
│                                                           │
└─────────────────────────────────────────────────────────┘
```

### Crates Structure

**6 modular crates, 47 Rust files, 5 binaries:**

- **meshvpn-dht** (655 lines): Kademlia DHT for peer discovery
- **meshvpn-network**: P2P networking, NAT traversal, TUN drivers
- **meshvpn-crypto**: Onion routing encryption (X25519, ChaCha20-Poly1305)
- **meshvpn-core**: Circuit building, routing logic
- **meshvpn-exit**: Exit node implementation
- **meshvpn-payment**: Monero integration (planned)

### Key Technologies

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **DHT** | Kademlia | Decentralized peer discovery |
| **P2P** | Custom UDP | Direct peer connections |
| **NAT** | STUN + Hole Punching | Traversal through firewalls |
| **Crypto** | X25519, ChaCha20 | End-to-end encryption |
| **Onion** | Layered encryption | Multi-hop privacy |
| **TUN** | Cross-platform drivers | Virtual network interface |
| **GUI** | Tauri + React | Desktop application |
| **Relay** | AWS EC2 | Fallback for symmetric NAT |

## 🔒 How It Works

### 1. Peer Discovery (DHT)
```
Client → Bootstrap Node → DHT Network → Find Peers
```
Uses Kademlia DHT to find available nodes without central coordination.

### 2. Circuit Building (Onion Routing)
```
Client → Guard → Middle → Exit → Internet
   └──encrypted──┴──encrypted──┴──encrypted──┘
```
Each hop only knows its predecessor and successor, never the full path.

### 3. NAT Traversal
```
Peer A ←──UDP Hole Punch──→ Peer B
   └──fails──→ Relay Server ←──fails──┘
```
Direct P2P when possible, relay fallback for symmetric NAT.

## 💡 Why This Approach?

### Censorship Resistance
- **No central servers** to block (DHT-based discovery)
- **Dynamic relay network** (can't blacklist all nodes)
- **Uses AWS IP ranges** (blocking = collateral damage to businesses)
- **Looks like normal HTTPS** traffic (mimics legitimate patterns)

### Privacy
- **Onion routing**: No single node sees full path
- **P2P mesh**: Traffic distributed across network
- **End-to-end encryption**: Even relay servers can't read content
- **No logs**: Decentralized architecture = no central logging

### Resilience
- **No single point of failure**: Network continues if nodes go down
- **Automatic failover**: Circuit rebuilds if hop fails
- **Distributed bandwidth**: Load shared across participants

## 🚀 Quick Start

### Prerequisites
- Rust 1.70+ (`rustup install stable`)
- Node.js 18+ (for GUI)
- Linux/macOS/Windows

### Build
```bash
git clone https://github.com/Kristian5013/meshvpnP2P
cd meshvpnP2P

# Build all components
cargo build --release

# Build GUI
cd gui
npm install
npm run tauri build
```

### Run Bootstrap Node
```bash
cargo run --bin meshvpn-dht-bootstrap
```

### Run Client
```bash
cargo run --bin meshvpn-client
```

### Run GUI
```bash
cd gui
npm run tauri dev
```

## 📚 Documentation

- [Architecture Deep Dive](docs/ARCHITECTURE.md) - Technical implementation details
- [Roadmap](docs/ROADMAP.md) - Development timeline and milestones
- [Pressure Ontology](docs/PRESSURE_ONTOLOGY.md) - Philosophical foundation
- [Contributing Guide](CONTRIBUTING.md) - How to contribute

## 🎓 Development Context

This project was built in approximately **7 hours of active development** by a **15-year-old developer** using:
- Rust + Tokio for async networking
- AI assistance (Claude Opus) for architecture guidance
- Iterative development with rapid prototyping

The speed was possible because:
1. Clear architectural vision from the start
2. Modular design allowing parallel development
3. AI assistance for boilerplate and debugging
4. Focus on core functionality first, optimization later

## 🧠 Philosophical Foundation

MeshVPN is inspired by **Pressure Ontology** - a unified philosophical framework that explains how systems seek equilibrium through local interactions:

- **DHT routing**: Center-seeking through distance minimization
- **Circuit building**: Sequential deviation compensation  
- **Relay mechanics**: Pressure redistribution
- **Path selection**: Following gradients toward equilibrium

See [PRESSURE_ONTOLOGY.md](docs/PRESSURE_ONTOLOGY.md) for the complete framework.

## 🤝 Contributing

We're looking for:
- **Code reviewers**: Especially for crypto and networking code
- **Security auditors**: Help identify vulnerabilities
- **Testers**: Different NAT types, operating systems
- **Contributors**: See [CONTRIBUTING.md](CONTRIBUTING.md) for areas needing help

**Priority areas for Phase 2:**
- Circuit/onion routing implementation
- Exit node NAT/routing logic
- TUN interface integration
- Performance benchmarking

## ⚠️ Security Notice

**This is a research project and NOT production-ready:**
- ❌ No security audit completed
- ❌ Crypto implementation not peer-reviewed
- ❌ May contain vulnerabilities
- ❌ Use at your own risk

**DO NOT use for sensitive communications without independent security review.**

## 📊 Project Stats

- **Lines of Code**: ~8,000 (Rust + TypeScript)
- **Crates**: 6 modular components
- **Binaries**: 5 executable programs
- **Development Time**: 7 hours active coding
- **GUI Framework**: Tauri + React + TypeScript
- **Network Stack**: Custom UDP + Tokio

## 🔗 Links

- **GitHub**: [github.com/Kristian5013/meshvpnP2P](https://github.com/Kristian5013/meshvpnP2P)
- **Issues**: [GitHub Issues](https://github.com/Kristian5013/meshvpnP2P/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Kristian5013/meshvpnP2P/discussions)

## 📝 License

MIT License - See [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- **Tor Project**: Inspiration for onion routing design
- **Kademlia**: DHT algorithm design
- **WireGuard**: VPN protocol inspiration
- **Claude (Anthropic)**: AI assistance during development

## 💬 Contact

- Open an issue for bugs/features
- Start a discussion for questions
- Email: [contact information]

---

**Built by a 15-year-old developer exploring the intersection of philosophy, cryptography, and distributed systems.**

*"The code is philosophy made executable."*
