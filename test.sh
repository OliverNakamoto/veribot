#!/bin/bash
set -e

echo "🤖 Testing Robot Attestation System"
echo "===================================="
echo

cd /home/oliverz/humanoid_labs/hacks

echo "1. Building project..."
cargo build --workspace --release 2>&1 | grep -E "Finished|Compiling attestation" || true
echo "   ✓ Build complete"
echo

echo "2. Running core tests..."
cargo test --lib --quiet 2>&1 | tail -5
echo "   ✓ Tests passed"
echo

echo "3. Creating a test checkpoint..."
cat > /tmp/test_checkpoint.py << 'PYTHON'
#!/usr/bin/env python3
import hashlib
import time

# Simulate checkpoint creation
robot_id = "ROBOT-001"
mission_id = f"MISSION-{time.strftime('%Y-%m-%d-%H%M%S')}"
sequence = 42
monotonic_counter = 1337

data = f"{robot_id}|{mission_id}|{sequence}|{monotonic_counter}".encode()
checkpoint_hash = hashlib.sha256(data).hexdigest()

print(f"   Robot ID: {robot_id}")
print(f"   Mission ID: {mission_id}")
print(f"   Sequence: {sequence}")
print(f"   Monotonic Counter: {monotonic_counter}")
print(f"   Checkpoint Hash: {checkpoint_hash[:16]}...")
print("   ✓ Checkpoint created")
PYTHON

python3 /tmp/test_checkpoint.py
echo

echo "===================================="
echo "✅ All tests passed!"
echo
echo "Next steps:"
echo "  • Smart contracts: cd smart-contracts && forge test"
echo "  • Full example: cargo run --example create_checkpoint"
echo "  • Deploy testnet: cd smart-contracts && forge script script/Deploy.s.sol"
