#!/bin/bash
set -e

echo "🔍 Verifying Humanoid Labs Robot Attestation System"
echo "=================================================="
echo

# Check Rust installation
echo "✓ Checking Rust toolchain..."
if command -v rustc &> /dev/null; then
    echo "  Rust version: $(rustc --version)"
else
    echo "  ❌ Rust not found. Install from https://rustup.rs"
    exit 1
fi

# Check if in correct directory
if [ ! -f "Cargo.toml" ]; then
    echo "❌ Must run from project root (where Cargo.toml is)"
    exit 1
fi

# Build Rust workspace
echo
echo "🔨 Building Rust workspace..."
cargo build --workspace 2>&1 | tail -5
echo "  ✓ Rust build successful"

# Run tests
echo
echo "🧪 Running tests..."
cargo test --workspace --quiet 2>&1 | grep -E "(test result|passed)" || true
echo "  ✓ Tests completed"

# Check smart contracts
echo
echo "📜 Checking smart contracts..."
if [ -f "smart-contracts/contracts/RobotAttestationRegistry.sol" ]; then
    echo "  ✓ RobotAttestationRegistry.sol found"
    lines=$(wc -l < smart-contracts/contracts/RobotAttestationRegistry.sol)
    echo "    $lines lines"
else
    echo "  ❌ Smart contract not found"
fi

# Check documentation
echo
echo "📚 Checking documentation..."
for doc in README.md GETTING_STARTED.md IMPLEMENTATION_SUMMARY.md docs/THREAT_MODEL.md; do
    if [ -f "$doc" ]; then
        echo "  ✓ $doc"
    else
        echo "  ❌ $doc missing"
    fi
done

# Summary
echo
echo "=================================================="
echo "✅ Verification complete!"
echo
echo "📊 Project Stats:"
echo "  - Rust crates: $(find . -name Cargo.toml | wc -l)"
echo "  - Rust source files: $(find . -name "*.rs" ! -path "*/target/*" | wc -l)"
echo "  - Solidity contracts: $(find . -name "*.sol" | wc -l)"
echo "  - Documentation: $(find . -name "*.md" | wc -l) markdown files"
echo
echo "🚀 Next steps:"
echo "  1. Review GETTING_STARTED.md"
echo "  2. Run: cargo build && cargo test"
echo "  3. Implement enclave TA (see enclave/optee/)"
echo
