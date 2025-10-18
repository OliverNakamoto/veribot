//! Cryptographic primitives for attestation.

use crate::types::Hash256;
pub use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// Compute SHA-256 hash of data.
pub fn sha256(data: &[u8]) -> Hash256 {
    let hash = Sha256::digest(data);
    hash.into()
}

/// Compute Blake3 hash of data (faster, for non-consensus critical paths).
pub fn blake3(data: &[u8]) -> Hash256 {
    let hash = blake3::hash(data);
    *hash.as_bytes()
}

/// A signer that can create Ed25519 signatures.
pub struct Signer {
    signing_key: SigningKey,
}

impl Signer {
    /// Create a new signer from a signing key.
    pub fn new(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    /// Generate a new random signing key.
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        Self { signing_key }
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Signature {
        use ed25519_dalek::Signer as _;
        self.signing_key.sign(message)
    }

    /// Get the verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get the signing key (use with caution).
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let data = b"test data";
        let hash1 = sha256(data);
        let hash2 = sha256(data);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn test_blake3() {
        let data = b"test data";
        let hash1 = blake3(data);
        let hash2 = blake3(data);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn test_signer() {
        let signer = Signer::generate();
        let message = b"test message";
        let signature = signer.sign(message);

        // Verify
        use ed25519_dalek::Verifier;
        assert!(signer.verifying_key().verify(message, &signature).is_ok());
    }
}
