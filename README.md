# VeriBot - Robot Attestation System

**Cryptographically verifiable "black box" for autonomous robots**

VeriBot creates tamper-evident audit trails that prove which AI model executed during each robot mission. Using Trusted Execution Environments (TEEs), Merkle trees, and blockchain anchoring, it provides cryptographic proof of robot actions for safety, compliance, and liability.

![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)
![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)
![Tests](https://img.shields.io/badge/tests-21%20passing-brightgreen.svg)

---

## 🎯 What VeriBot Does

- ✅ **Proves which AI model ran** - Cryptographically links decisions to exact model version
- ✅ **Anti-rollback protection** - Prevents tampering with logs using hardware counters
- ✅ **TEE attestation** - Intel SGX/ARM TrustZone proves code ran in secure hardware
- ✅ **Blockchain anchoring** - Immutable on-chain commitments (EigenDA/L2)
- ✅ **Privacy-preserving** - Selective disclosure via Merkle proofs
- ✅ **Audit replay** - Verifiers can replay missions with cryptographic guarantees

---

## 🚀 Quick Start

### Test the Core Library

```bash
# Build and test
cargo build --workspace
cargo test --workspace

# All tests pass ✓
```

### See the Visual Demo

```bash
# Open in browser
open demo/index.html

# Or run script
./demo/DEMO.sh
```

**Demo features:**
- Interactive mission timeline
- Real-time verification checks
- Merkle proof visualization
- Replay functionality

---

## 📊 Architecture

```
Robot (Edge)                Gateway (Cloud)              Blockchain
     │                           │                            │
     │ 1. Collect logs           │                            │
     ├─────────────────────>     │                            │
     │ 2. Sign in TEE            │                            │
     │                           │ 3. Verify quote            │
     │                           ├──────────────────────>     │
     │                           │ 4. Anchor Merkle root      │
     │                           │                            │
     │                           │    5. Store proof          │
     │                           │<──────────────────────     │
```

**Key components:**
1. **attestation-core** - Checkpoint creation, Merkle trees, crypto (1,200 lines)
2. **attestation-sgx** - Intel SGX/DCAP adapter (600 lines)
3. **smart-contracts** - On-chain registry + revocation (600 lines)
4. **demo** - Interactive web visualization

---

## 🔐 Security Features

### Anti-Rollback Protection (3-Layer)
```rust
struct Checkpoint {
    sequence: u64,           // Strictly increasing
    monotonic_counter: u64,  // Hardware-backed
    prev_root: Hash256,      // Links to previous checkpoint
    // ...
}
```

### Canonical Serialization
- Deterministic CBOR (RFC 8949)
- Reproducible hashes across implementations
- SHA-256 for on-chain, Blake3 for performance

### Multi-Vendor Attestation
```rust
trait AttestationAdapter {
    async fn verify_quote(&self, quote: &[u8]) -> Result<AttestationResult>;
    async fn check_revocation(&self, measurement: &[u8]) -> Result<RevocationStatus>;
}
```

Supports: Intel SGX, AWS Nitro, ARM TrustZone, TPM/SE

---

## 📁 Project Structure

```
veribot/
├── attestation-core/        Core library (checkpoints, Merkle trees)
├── attestation-sgx/         Intel SGX attestation adapter
├── smart-contracts/         Solidity contracts (registry, revocation)
├── demo/                    Interactive web demo
├── docs/                    Documentation + threat model
└── examples/                Usage examples
```

---

## 💰 Cost Model

| Operation | Gas Cost | Price (EigenDA) |
|-----------|----------|-----------------|
| Register model | ~80K | $0.04 |
| Anchor checkpoint batch | ~100K | $0.05 per 1000 |
| Revoke enclave | ~50K | $0.025 |

**Average mission cost:** < $1 (10 checkpoints with batching)

---

## 🛠️ Development

### Prerequisites
- Rust 1.75+
- Foundry (smart contracts)
- ROS2 Humble/Iron (optional)

### Build
```bash
cargo build --workspace --release
```

### Test
```bash
cargo test --workspace
cd smart-contracts && forge test
```

### Deploy Contracts (Testnet)
```bash
cd smart-contracts
forge script script/Deploy.s.sol --rpc-url $SEPOLIA_RPC_URL --broadcast
```

---

## 📖 Documentation

- **[START_HERE.md](START_HERE.md)** - Quick overview
- **[USAGE_GUIDE.md](USAGE_GUIDE.md)** - Detailed usage instructions
- **[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)** - Security analysis (18 threats)
- **[IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md)** - Technical deep-dive

---

## 🎬 Demo Showcase

**For presentations:**
1. Open `demo/index.html` in browser
2. Click "Reset Timeline" to clear
3. Click "▶ Replay Mission" - watch checkpoints appear
4. Point to green checkmarks - all cryptographic verifications passing
5. Show Merkle proof - proves specific events without revealing all data

---

## 🔒 Security

### Threat Model
- 18 identified threats across 8 categories
- Mitigations for all high-severity risks
- See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)

### Audit Status
- [ ] Enclave code audit (planned)
- [ ] Smart contract audit (planned)
- [ ] Penetration testing (planned)

**Report security issues:** security@veribot.dev

---

## 🗺️ Roadmap

**Phase 0 (Complete)** ✅
- Core attestation library
- Canonical serialization
- Smart contracts
- Threat model

**Phase 1 (Weeks 2-6)** 🚧
- OP-TEE enclave implementation
- Intel SGX enclave

**Phase 2 (Weeks 3-7)**
- ROS2 integration
- Gateway service

**Phase 3 (Weeks 8-12)**
- Security audits
- Production deployment

---

## 📄 License

- **Core library & gateway:** Apache 2.0
- **Smart contracts:** MIT
- **Documentation:** CC BY 4.0

---

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create feature branch
3. Add tests
4. Submit PR with security considerations documented

---

## 🌟 Use Cases

- **Autonomous vehicles** - Prove which AI model made driving decisions
- **Warehouse robots** - Regulatory compliance for safety certifications
- **Drone fleets** - Tamper-evident flight records
- **Medical robots** - Chain of custody for surgical procedures
- **Industrial automation** - Liability protection with cryptographic proof

---

## 📚 Citations

- EigenLayer/EigenCompute: https://docs.eigenlayer.xyz
- Canonical CBOR: RFC 8949
- Intel SGX: DCAP Attestation
- Sigstore: Supply chain security

---

## 👥 Team

Built by [Humanoid Labs](https://humanoidlabs.no)

**Contact:**
- GitHub: [@OliverNakamoto](https://github.com/OliverNakamoto)
- Project: [veribot](https://github.com/OliverNakamoto/veribot)

---

**⭐ Star this repo if you find it useful!**
