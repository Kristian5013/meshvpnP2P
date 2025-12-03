# Contributing to MeshVPN

Thank you for your interest in contributing to MeshVPN! This document provides guidelines for contributing to the project.

## 🎯 Project Vision

MeshVPN aims to create a **censorship-resistant, privacy-focused VPN** that combines:
- Tor-style onion routing
- P2P mesh networking
- Decentralized infrastructure

We prioritize **security, privacy, and resilience** over performance optimization.

## 🚧 Current Status: Phase 2

**Phase 1** (P2P foundation) is complete. We're now working on **Phase 2** (circuit routing):

### Priority Tasks for Phase 2:
1. **Circuit/Onion Routing** (`meshvpn-core/src/circuit.rs`)
   - Implement circuit building protocol
   - Fix current over-engineered approach
   - Add path selection logic

2. **Exit Node Implementation** (`meshvpn-exit/`)
   - NAT configuration
   - Traffic routing to internet
   - Exit policies

3. **TUN Integration** (`meshvpn-network/src/tun/`)
   - Wire up TUN interface to circuit routing
   - Handle IP packet encapsulation
   - Platform-specific implementations

4. **Testing & Validation**
   - Different NAT types
   - Circuit failure scenarios
   - Performance benchmarks

## 🛠️ Development Setup

### Prerequisites
```bash
# Rust toolchain
rustup install stable
rustup component add clippy rustfmt

# Node.js (for GUI)
node --version  # Should be 18+
npm --version
```

### Clone and Build
```bash
git clone https://github.com/Kristian5013/meshvpnP2P
cd meshvpnP2P

# Build all crates
cargo build

# Run tests
cargo test

# Lint code
cargo clippy -- -D warnings

# Format code
cargo fmt
```

### Project Structure
```
meshvpnP2P/
├── bins/              # Executable binaries
│   ├── meshvpn-bootstrap/
│   ├── meshvpn-client/
│   ├── meshvpn-dht-bootstrap/
│   ├── meshvpn-discovery/
│   └── meshvpn-exit-node/
├── crates/            # Library crates
│   ├── meshvpn-core/
│   ├── meshvpn-crypto/
│   ├── meshvpn-dht/
│   ├── meshvpn-exit/
│   ├── meshvpn-network/
│   └── meshvpn-payment/
├── gui/               # Tauri GUI application
└── docs/              # Documentation
```

## 📝 How to Contribute

### 1. Report Bugs
Open an issue with:
- Clear description of the bug
- Steps to reproduce
- Expected vs actual behavior
- System information (OS, Rust version)
- Relevant logs

### 2. Suggest Features
Open a discussion with:
- Clear use case
- Proposed implementation (if technical)
- Alignment with project goals

### 3. Submit Code

#### Before Starting
1. Check existing issues/PRs to avoid duplication
2. For major changes, open a discussion first
3. Fork the repository

#### Development Workflow
```bash
# Create feature branch
git checkout -b feature/your-feature-name

# Make changes
# Write tests
# Run tests: cargo test
# Run clippy: cargo clippy
# Format: cargo fmt

# Commit with clear message
git commit -m "Add feature: description"

# Push to your fork
git push origin feature/your-feature-name

# Open Pull Request
```

#### Code Style
- Follow Rust standard formatting (`cargo fmt`)
- Pass all clippy lints (`cargo clippy -- -D warnings`)
- Add tests for new functionality
- Document public APIs with `///` comments
- Use meaningful variable names
- Keep functions under 50 lines when possible

#### Commit Messages
```
Add feature: brief description

Longer explanation if needed:
- What changed
- Why it changed
- Any breaking changes
```

### 4. Improve Documentation
- Fix typos, clarify explanations
- Add examples
- Improve architecture diagrams
- Translate to other languages

## 🧪 Testing

### Unit Tests
```bash
cargo test
```

### Integration Tests
```bash
cargo test --test '*'
```

### Manual Testing
```bash
# Terminal 1: Bootstrap node
cargo run --bin meshvpn-dht-bootstrap

# Terminal 2: Client
cargo run --bin meshvpn-client
```

## 🔒 Security

### Reporting Vulnerabilities
**DO NOT** open public issues for security vulnerabilities.

Instead:
1. Email: [security contact - to be added]
2. Include detailed description
3. Proof of concept if applicable
4. Suggested fix if available

We'll respond within 48 hours and work on a fix before public disclosure.

### Security Review Areas
Priority areas needing security review:
- Crypto implementation (`meshvpn-crypto/`)
- Circuit building logic (`meshvpn-core/src/circuit.rs`)
- Network protocol (`meshvpn-network/`)
- Exit node routing (`meshvpn-exit/`)

## 📚 Code Review Guidelines

When reviewing PRs:
- ✅ Code follows style guidelines
- ✅ Tests pass and new tests added
- ✅ Documentation updated
- ✅ No security vulnerabilities introduced
- ✅ Performance implications considered
- ✅ Error handling is robust

## 🎨 Design Principles

### 1. Modular Architecture
- Each crate has single responsibility
- Clear interfaces between components
- Minimal dependencies

### 2. Security First
- Assume all network input is hostile
- Validate everything
- Fail securely (default deny)

### 3. Privacy by Design
- Minimize data collection
- No persistent logs
- Encryption everywhere

### 4. Resilience
- Handle failures gracefully
- No single points of failure
- Automatic recovery when possible

## 🤝 Community Guidelines

### Be Respectful
- Assume good intentions
- Be patient with newcomers
- Give constructive feedback
- Celebrate contributions

### Be Professional
- Focus on technical merit
- Avoid personal attacks
- Keep discussions on-topic
- Respect maintainer decisions

### Be Collaborative
- Share knowledge
- Help others learn
- Document your decisions
- Credit others' work

## 📊 Areas Looking for Help

### High Priority
- [ ] Circuit routing implementation
- [ ] Exit node NAT configuration
- [ ] TUN interface integration
- [ ] Security audit

### Medium Priority
- [ ] Performance benchmarking
- [ ] Cross-platform testing
- [ ] Documentation improvements
- [ ] GUI enhancements

### Low Priority
- [ ] Code cleanup/refactoring
- [ ] Additional language bindings
- [ ] Mobile support research
- [ ] Alternative crypto primitives

## 🎯 Skill Match Guide

**Rust Beginners:**
- Documentation improvements
- Code comments
- Simple bug fixes
- Test coverage

**Experienced Rust:**
- Core architecture
- Performance optimization
- Error handling patterns
- Async code review

**Networking Experts:**
- NAT traversal improvements
- Protocol design
- Performance tuning
- Relay logic

**Cryptography:**
- Crypto implementation review
- Onion routing protocol
- Key management
- Security audit

**Frontend:**
- GUI improvements
- User experience
- Design/styling
- Cross-platform testing

## 📜 License

By contributing, you agree that your contributions will be licensed under the MIT License.

## ❓ Questions?

- Open a [Discussion](https://github.com/Kristian5013/meshvpnP2P/discussions)
- Check existing [Issues](https://github.com/Kristian5013/meshvpnP2P/issues)
- Read the [Architecture docs](docs/ARCHITECTURE.md)

---

**Thank you for contributing to MeshVPN! Together we can build censorship-resistant infrastructure.**
