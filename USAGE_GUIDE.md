# How to Use the Robot Attestation System

## 🎯 Overview

You have **3 ways** to use this system, depending on your current stage:

1. **Test the Core Library** - Try out checkpoint creation and verification (easiest, start here)
2. **Deploy Smart Contracts** - Deploy to testnet and anchor checkpoints on-chain
3. **Integrate with Your Robot** - Full end-to-end integration (requires more work)

---

## 1️⃣ Test the Core Library (Start Here)

### Quick Test - Create a Checkpoint

```bash
cd /home/oliverz/humanoid_labs/hacks

# Build the project
cargo build --workspace

# Run tests
cargo test --workspace

# See checkpoint creation example
cat examples/create_checkpoint.rs
```

### What the Core Library Does

The `attestation-core` library provides:

- **Checkpoint Creation**: Sign mission data with anti-rollback protection
- **Merkle Trees**: Create tamper-evident logs
- **Canonical Serialization**: Deterministic hashing for on-chain anchoring
- **Signature Verification**: Verify checkpoints came from authorized enclaves

### Example Code (Rust)

```rust
use attestation_core::{
    CheckpointBuilder, ModelProvenance, DeterminismConfig,
    Signer, TrustMode, MerkleTree, Entry
};

fn main() {
    // 1. Generate signing key (in production, from TEE enclave)
    let signer = Signer::generate();

    // 2. Create mission logs
    let mut tree = MerkleTree::new();
    tree.insert(Entry::new(timestamp, 0, b"robot moved"));
    tree.insert(Entry::new(timestamp + 1000, 1, b"obstacle detected"));
    let merkle_root = tree.root();

    // 3. Build signed checkpoint
    let checkpoint = CheckpointBuilder::new()
        .robot_id("ROBOT-001".into())
        .mission_id("MISSION-2025-10-11-001".into())
        .sequence(42)                    // Anti-rollback: strictly increasing
        .monotonic_counter(1337)         // Anti-rollback: hardware counter
        .model_provenance(ModelProvenance { /* model info */ })
        .entries_root(merkle_root)
        .prev_root([0u8; 32])           // Links to previous checkpoint
        .build_and_sign(&signer.signing_key())
        .unwrap();

    // 4. Verify signature
    checkpoint.verify_signature(&signer.verifying_key()).unwrap();

    // 5. Serialize for transmission
    let bytes = checkpoint.to_bytes().unwrap();
    println!("Checkpoint: {} bytes", bytes.len());
}
```

---

## 2️⃣ Deploy Smart Contracts

### Prerequisites

```bash
# Install Foundry (smart contract toolkit)
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Verify installation
forge --version
```

### Deploy to Testnet

```bash
cd /home/oliverz/humanoid_labs/hacks/smart-contracts

# 1. Set up environment
cp .env.example .env

# 2. Edit .env with your keys:
#    PRIVATE_KEY=0x...
#    ADMIN_ADDRESS=0x...
#    GATEWAY_ADDRESSES=0x...
#    SEPOLIA_RPC_URL=https://...

# 3. Run tests locally
forge test -vvv

# 4. Deploy to Sepolia testnet
forge script script/Deploy.s.sol \
    --rpc-url $SEPOLIA_RPC_URL \
    --broadcast \
    --verify
```

### What You Get

After deployment, you'll have:
- **Registry Contract Address**: Where models and checkpoints are stored
- **On-Chain Model Registry**: Register AI models with provenance
- **Checkpoint Anchoring**: Submit Merkle roots on-chain
- **Emergency Revocation**: Revoke compromised enclaves

### Interact with Contracts

```bash
# Register a model
cast send $REGISTRY_ADDRESS \
    "registerModel(string,bytes32,bytes32,string,bytes)" \
    "model-v1" \
    0x1234... \
    0x0000... \
    "sha256:abc..." \
    0x \
    --rpc-url $SEPOLIA_RPC_URL \
    --private-key $PRIVATE_KEY

# Anchor a checkpoint (requires GATEWAY_ROLE)
cast send $REGISTRY_ADDRESS \
    "anchorCheckpoint(bytes32,bytes32,string,bytes)" \
    0xabcd... \    # merkle_root
    0xef01... \    # enclave_measurement
    "intel-sgx" \
    0x \           # gateway_signature
    --rpc-url $SEPOLIA_RPC_URL \
    --private-key $GATEWAY_PRIVATE_KEY

# Check if enclave is revoked
cast call $REGISTRY_ADDRESS \
    "isEnclaveRevoked(bytes32)" \
    0xef01... \
    --rpc-url $SEPOLIA_RPC_URL
```

---

## 3️⃣ Full Integration (Robot → Gateway → Blockchain)

### Architecture

```
Robot (Edge Device)
  ├─ ROS2 Node: Collects logs
  ├─ Enclave (OP-TEE/SGX): Signs checkpoints
  └─ HTTP Client: Sends to gateway
         │
         ▼
Gateway (Cloud Service)
  ├─ REST API: Receives checkpoints
  ├─ Verifier: Checks attestation quotes
  ├─ Kafka: Batches checkpoints
  └─ Blockchain Client: Anchors on-chain
         │
         ▼
Blockchain (Sepolia/Arbitrum)
  └─ AttestationRegistry: Stores commitments
```

### Step-by-Step Integration

#### **Step 1: Implement the Enclave (OP-TEE)**

This is the **critical missing piece**. You need to:

```c
// enclave/optee/ta/main.c
#include <tee_internal_api.h>

TEE_Result sign_checkpoint(uint32_t param_types, TEE_Param params[4]) {
    // 1. Read checkpoint data from params[0]
    // 2. Load signing key from secure storage
    // 3. Increment monotonic counter
    // 4. Sign checkpoint with Ed25519
    // 5. Return signature in params[1]
}

TEE_Result get_attestation_quote(uint32_t param_types, TEE_Param params[4]) {
    // 1. Generate attestation quote
    // 2. Include enclave measurement (MRENCLAVE)
    // 3. Return quote in params[0]
}
```

**Hardware needed:**
- Raspberry Pi 4 with OP-TEE
- OR Intel NUC with SGX
- OR AWS EC2 with Nitro enclaves

**Build:**
```bash
# Clone OP-TEE build system
git clone https://github.com/OP-TEE/build.git
cd build
make -j$(nproc) toolchains

# Copy your TA to optee_examples
cp -r ../humanoid_labs/hacks/enclave/optee/ optee_examples/attestation_ta/

# Build
make attestation_ta

# Deploy to robot
scp ta/attestation_ta.ta robot@robot.local:/lib/optee_armtz/
```

#### **Step 2: Build the ROS2 Node**

```bash
cd /home/oliverz/humanoid_labs/hacks/ros_package

# Create the ROS2 node (pseudocode - you'll implement this)
# attestation_node/src/attestation_node.py

import rclpy
from attestation_core import CheckpointBuilder, MerkleTree  # Your Rust lib via PyO3

class AttestationNode(Node):
    def __init__(self):
        super().__init__('attestation_node')
        self.merkle_tree = MerkleTree()
        self.enclave_client = EnclaveClient()  # IPC to OP-TEE

        # Subscribe to robot events
        self.create_subscription(Odometry, '/odom', self.on_odom, 10)
        self.create_timer(30.0, self.create_checkpoint)  # Every 30 seconds

    def on_odom(self, msg):
        # Add log entry to Merkle tree
        entry = f"pos: {msg.pose.position.x},{msg.pose.position.y}"
        self.merkle_tree.insert(Entry.new(timestamp(), nonce(), entry.encode()))

    def create_checkpoint(self):
        # 1. Compute Merkle root
        merkle_root = self.merkle_tree.root()

        # 2. Request enclave to sign checkpoint
        checkpoint = self.enclave_client.sign_checkpoint(
            robot_id="ROBOT-001",
            mission_id=self.mission_id,
            merkle_root=merkle_root,
            # ... other fields
        )

        # 3. Send to gateway
        self.gateway_client.submit_checkpoint(checkpoint)

        # 4. Clear tree for next batch
        self.merkle_tree.clear()
```

#### **Step 3: Build the Gateway Service**

```bash
cd /home/oliverz/humanoid_labs/hacks/gateway/api

# Implement REST API (pseudocode - you'll build this)
# src/main.rs

use axum::{Router, routing::post};
use attestation_core::AttestationRegistry;
use attestation_sgx::SgxDcapAdapter;

#[tokio::main]
async fn main() {
    // Set up attestation registry
    let mut registry = AttestationRegistry::new();
    registry.register(Box::new(SgxDcapAdapter::new()));

    // Set up routes
    let app = Router::new()
        .route("/checkpoints", post(submit_checkpoint))
        .route("/verify", post(verify_checkpoint));

    // Start server
    axum::Server::bind(&"0.0.0.0:8080".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn submit_checkpoint(body: Json<Checkpoint>) -> Result<Json<Response>> {
    // 1. Parse checkpoint
    let checkpoint = body.0;

    // 2. Verify attestation quote
    let quote_result = registry.verify_quote(
        "intel-sgx",
        &checkpoint.attestation_quote,
        None
    ).await?;

    // 3. Check anti-rollback
    ensure!(checkpoint.sequence > last_seen_sequence(checkpoint.robot_id));
    ensure!(checkpoint.monotonic_counter > last_seen_counter(checkpoint.robot_id));

    // 4. Verify signature
    checkpoint.verify_signature(&enclave_pubkey)?;

    // 5. Add to batch queue (Kafka)
    kafka_producer.send("checkpoints", checkpoint).await?;

    Ok(Json(Response { status: "accepted" }))
}

// Background worker anchors batches to blockchain
async fn anchor_worker() {
    loop {
        // 1. Collect 1000 checkpoints from Kafka
        let checkpoints = kafka_consumer.poll_batch(1000).await;

        // 2. Compute batch Merkle root
        let batch_root = compute_batch_root(&checkpoints);

        // 3. Submit to blockchain
        registry_contract.anchorCheckpoint(
            batch_root,
            enclave_measurement,
            "intel-sgx",
            gateway_signature
        ).await?;

        // 4. Wait 5 minutes or until next batch full
        sleep(Duration::from_secs(300)).await;
    }
}
```

#### **Step 4: Connect Everything**

```bash
# On robot:
ros2 run attestation_node attestation_node \
    --robot-id ROBOT-001 \
    --gateway-url https://gateway.example.com

# On gateway server:
cd gateway/api
POSTGRES_URL=postgres://... \
KAFKA_BROKERS=localhost:9092 \
REGISTRY_CONTRACT=0x... \
cargo run --release

# Monitor:
curl https://gateway.example.com/health
curl https://gateway.example.com/stats
```

---

## 4️⃣ Verification & Audit

### Verify a Checkpoint

```bash
# Using the CLI tool (TODO: implement)
cd verifier/cli

cargo run -- verify \
    --checkpoint checkpoint.cbor \
    --proof merkle_proof.json \
    --contract 0x... \
    --rpc-url $SEPOLIA_RPC_URL

# Output:
# ✅ Signature: VALID
# ✅ Merkle proof: VALID
# ✅ On-chain commitment: FOUND
# ✅ Enclave: NOT REVOKED
# ✅ Anti-rollback: VALID (sequence 42 > 41)
```

### Audit a Mission

```bash
# 1. Fetch all checkpoints for a mission
curl https://gateway.example.com/missions/MISSION-2025-10-11-001/checkpoints

# 2. Verify each checkpoint
for checkpoint in checkpoints; do
    verify_checkpoint $checkpoint
done

# 3. Check timeline continuity
# - Verify prev_root chain
# - Verify monotonic counter increases
# - Verify no gaps in sequence
```

---

## 🔧 Troubleshooting

### "error: failed to parse manifest"
```bash
# Make sure you're in the project root
cd /home/oliverz/humanoid_labs/hacks
cargo build --workspace
```

### "enclave not found"
You need to implement the OP-TEE Trusted Application first. See Step 3.1 above.

### "gateway connection refused"
The gateway service isn't running yet. You need to implement it (see Step 3.3).

### "smart contract reverted"
Check that:
1. You have the GATEWAY_ROLE on the contract
2. The enclave measurement is not revoked
3. The merkle root is not zero

---

## 📚 Next Steps

1. **Right Now**: Test the core library (`cargo test --workspace`)
2. **This Week**: Deploy contracts to testnet
3. **Next 2 Weeks**: Implement OP-TEE enclave
4. **Next 4 Weeks**: Build ROS2 node
5. **Next 6 Weeks**: Build gateway service
6. **Next 8 Weeks**: End-to-end testing
7. **Next 12 Weeks**: Security audit & production deployment

---

## 💡 Pro Tips

- **Start Small**: Test checkpoints locally before involving blockchain
- **Use Testnet**: Deploy to Sepolia/Goerli before mainnet
- **Monitor Costs**: Track gas usage on testnet to estimate production costs
- **Security First**: Get enclave code audited before production
- **Iterate**: Start with software-only signing, add TEE later

---

**Questions?** Review the other documentation:
- `README.md` - Architecture overview
- `GETTING_STARTED.md` - Setup guide
- `IMPLEMENTATION_SUMMARY.md` - Technical details
- `docs/THREAT_MODEL.md` - Security analysis
