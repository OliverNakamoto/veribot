# Quick Reference Guide

## 📁 What's Where

```
attestation-core/         Core library (checkpoints, Merkle trees, crypto)
attestation-sgx/          Intel SGX attestation adapter
smart-contracts/          Solidity contracts (registry, revocation)
docs/THREAT_MODEL.md     Security threat analysis
examples/                Example code
```

## 🚀 Common Commands

```bash
# Build everything
cargo build --workspace

# Run tests
cargo test --workspace

# Test smart contracts
cd smart-contracts && forge test -vvv

# Deploy to testnet
cd smart-contracts
forge script script/Deploy.s.sol --rpc-url $SEPOLIA_RPC_URL --broadcast
```

## 📖 Key Concepts

**Checkpoint** = Signed snapshot of robot state with anti-rollback protection
**Merkle Root** = Hash of all log entries (proves integrity)
**Monotonic Counter** = Hardware counter that only increases (prevents replay)
**Enclave Measurement** = Hash of TEE code (proves which software ran)
**Prev Root** = Hash of previous checkpoint (creates chain)

## 🔗 Architecture Flow

```
Robot → Log Entries → Merkle Tree → Checkpoint → Enclave Signs → Gateway Verifies → Blockchain Anchors
```

## 💰 Costs (Testnet ETH)

- Register model: ~80K gas (~$0.04)
- Anchor checkpoint batch: ~100K gas (~$0.05 per 1000 checkpoints)
- Revoke enclave: ~50K gas (~$0.025)

## ⚡ Getting Help

1. Check `USAGE_GUIDE.md` for how-to
2. Check `GETTING_STARTED.md` for setup
3. Check `IMPLEMENTATION_SUMMARY.md` for technical details
4. Check `docs/THREAT_MODEL.md` for security

## 🎯 Next Immediate Steps

1. ✅ Run: `cargo build --workspace`
2. ✅ Run: `cargo test --workspace`
3. ⏭️ Deploy smart contracts to testnet
4. ⏭️ Implement OP-TEE enclave (critical path)
