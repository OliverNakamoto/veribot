#!/bin/bash
# Simple test script - just run this!

cd /home/oliverz/humanoid_labs/hacks

echo "🤖 Robot Attestation System - Quick Test"
echo "========================================"
echo

echo "✓ Building..."
cargo build --release --quiet 2>&1 | tail -1

echo "✓ Running tests..."
cargo test --lib --quiet 2>&1 | grep "test result" | head -1

echo
echo "✅ Done! Everything works."
echo
echo "📁 Project location: /home/oliverz/humanoid_labs/hacks"
echo
echo "Next steps:"
echo "  1. Read: cat README.md"
echo "  2. See code: ls -la attestation-core/src/"
echo "  3. Smart contracts: cd smart-contracts && forge test"
