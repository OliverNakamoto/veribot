//! # Attestation Core
//!
//! Provides canonical data structures, serialization, and cryptographic primitives
//! for robot attestation checkpoints with anti-rollback protection.
//!
//! ## Key Features
//! - **Canonical CBOR serialization**: Deterministic, reproducible hashes
//! - **Anti-rollback**: Monotonic counters + prev_root chaining
//! - **Multi-vendor attestation**: Pluggable adapter interface
//! - **Merkle trees**: Incremental, sorted by timestamp+nonce

pub mod attestation;
pub mod checkpoint;
pub mod crypto;
pub mod merkle;
pub mod serialization;
pub mod types;

pub use attestation::{AttestationAdapter, AttestationError, AttestationRegistry};
pub use checkpoint::{Checkpoint, CheckpointBuilder};
pub use crypto::{Signature, Signer};
pub use merkle::{Entry, MerkleTree, MerkleProof};
pub use types::*;

// Re-export Hash256 from types
pub use types::Hash256;

/// Re-export for convenience
pub use ed25519_dalek::{SigningKey, VerifyingKey};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert_eq!(env!("CARGO_PKG_VERSION"), "0.1.0");
    }
}
