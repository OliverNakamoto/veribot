# Humanoid Labs Robot Attestation - Task Runner
# Install: cargo install just
# Usage: just <recipe>

# Default recipe
default:
    @just --list

# Build all Rust components
build:
    cargo build --release --workspace

# Run tests for all Rust components
test:
    cargo test --workspace

# Build ROS2 package
ros-build:
    cd ros_package && colcon build --symlink-install

# Source ROS2 environment
ros-source:
    . ros_package/install/setup.bash

# Build and test smart contracts
contracts-build:
    cd smart-contracts && forge build

contracts-test:
    cd smart-contracts && forge test -vvv

# Run gateway locally (requires PostgreSQL + Redis + Kafka)
gateway-dev:
    cd gateway/api && cargo run

# Run attestation verification CLI
verify checkpoint_file proof_file:
    cargo run --bin verifier-cli -- verify --checkpoint {{checkpoint_file}} --proof {{proof_file}}

# Format all code
fmt:
    cargo fmt --all
    cd smart-contracts && forge fmt

# Lint all code
lint:
    cargo clippy --workspace -- -D warnings
    cd smart-contracts && forge fmt --check

# Run security audit tools
audit:
    cargo audit
    cd smart-contracts && slither contracts/

# Generate documentation
docs:
    cargo doc --workspace --no-deps --open

# Clean build artifacts
clean:
    cargo clean
    cd ros_package && rm -rf build install log
    cd smart-contracts && forge clean

# Run integration tests (requires Docker)
integration-test:
    docker-compose -f tests/docker-compose.yml up --abort-on-container-exit

# Deploy contracts to testnet
contracts-deploy-testnet rpc_url:
    cd smart-contracts && forge script script/Deploy.s.sol --rpc-url {{rpc_url}} --broadcast --verify

# Start local development environment (Postgres, Redis, Kafka, Anvil)
dev-env-up:
    docker-compose -f docker-compose.dev.yml up -d

dev-env-down:
    docker-compose -f docker-compose.dev.yml down

# Benchmark checkpoint signing performance
bench-enclave:
    cargo bench --package attestation-core --bench checkpoint_signing
