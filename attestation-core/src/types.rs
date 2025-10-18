//! Core types used across the attestation system.

use serde::{Deserialize, Serialize};
use std::fmt;

/// SHA-256 hash (32 bytes)
pub type Hash256 = [u8; 32];

/// Ed25519 signature (64 bytes) - wrapped for Serde support
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureBytes(#[serde(with = "serde_arrays")] pub [u8; 64]);

impl From<[u8; 64]> for SignatureBytes {
    fn from(bytes: [u8; 64]) -> Self {
        SignatureBytes(bytes)
    }
}

impl AsRef<[u8; 64]> for SignatureBytes {
    fn as_ref(&self) -> &[u8; 64] {
        &self.0
    }
}

// Serde support for large arrays
mod serde_arrays {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error> {
        bytes.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 64], D::Error> {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        bytes.try_into()
            .map_err(|_| serde::de::Error::custom("Invalid signature length"))
    }
}

/// Robot identifier (unique per robot)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RobotId(pub String);

impl fmt::Display for RobotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Mission identifier (unique per mission)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MissionId(pub String);

impl fmt::Display for MissionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Trust mode for attestation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustMode {
    /// Full TEE attestation with hardware root-of-trust
    Trusted,
    /// Secure Element + signed boot (lower assurance)
    SoftAttestation,
    /// Software-only signing (development/testing)
    Untrusted,
}

impl fmt::Display for TrustMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustMode::Trusted => write!(f, "Trusted"),
            TrustMode::SoftAttestation => write!(f, "Soft-Attestation"),
            TrustMode::Untrusted => write!(f, "Untrusted"),
        }
    }
}

/// Model provenance information (supply chain security)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelProvenance {
    /// Model name and version tag
    pub name: String,
    /// Model binary + weights hash (SHA-256)
    pub model_hash: Hash256,
    /// Dataset hash (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dataset_hash: Option<Hash256>,
    /// Container image digest (e.g., sha256:...)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_digest: Option<String>,
    /// Sigstore/in-toto signature bundle
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_bundle: Option<Vec<u8>>,
}

/// Determinism configuration for inference reproducibility
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterminismConfig {
    /// RNG seed used for sampling
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rng_seed: Option<u64>,
    /// Batch size
    pub batch_size: u32,
    /// Deterministic mode flags (e.g., "cudnn_deterministic=true")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<Vec<String>>,
}

/// Attestation result from verification adapter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResult {
    /// Vendor name (e.g., "intel-sgx", "aws-nitro", "arm-trustzone")
    pub vendor: String,
    /// Enclave/TEE measurement (code hash)
    pub enclave_measurement: Vec<u8>,
    /// Whether the attestation quote was verified successfully
    pub quote_verified: bool,
    /// Timestamp of verification
    pub verified_at: chrono::DateTime<chrono::Utc>,
    /// Revocation check status
    pub revoke_check: RevocationStatus,
    /// Raw attestation quote (vendor-specific format)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_quote: Option<Vec<u8>>,
    /// PCK certificate chain (Intel SGX only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pck_chain: Option<String>,
}

/// Revocation status for attestation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RevocationStatus {
    /// Attestation is valid, no revocation
    Ok,
    /// Enclave measurement is on revocation list
    Revoked,
    /// Could not check revocation (CRL unavailable, etc.)
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_mode_display() {
        assert_eq!(TrustMode::Trusted.to_string(), "Trusted");
        assert_eq!(TrustMode::SoftAttestation.to_string(), "Soft-Attestation");
        assert_eq!(TrustMode::Untrusted.to_string(), "Untrusted");
    }

    #[test]
    fn test_robot_id() {
        let id = RobotId("R-001".to_string());
        assert_eq!(id.to_string(), "R-001");
    }
}
