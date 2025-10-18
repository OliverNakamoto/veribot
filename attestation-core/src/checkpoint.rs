//! Checkpoint data structure with anti-rollback protection.
//!
//! A checkpoint is a tamper-evident snapshot of robot state at a given time,
//! cryptographically signed by a TEE enclave.

use crate::serialization::{from_canonical_cbor, to_canonical_cbor, SerializationError};
use crate::types::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Checkpoint version (for schema evolution)
pub const CHECKPOINT_VERSION: u8 = 1;

/// A cryptographically signed checkpoint with anti-rollback protection.
///
/// ## Anti-Rollback Mechanisms
/// 1. **Monotonic counter**: Hardware-backed counter that strictly increases
/// 2. **Previous root**: Hash of previous checkpoint (blockchain-like chaining)
/// 3. **Sequence number**: Strictly increasing per-robot sequence
///
/// ## Canonical Serialization
/// All fields serialize to canonical CBOR for deterministic hashing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Schema version
    pub version: u8,

    /// Robot identifier
    pub robot_id: RobotId,

    /// Mission identifier
    pub mission_id: MissionId,

    /// Strictly increasing sequence number (per robot)
    pub sequence: u64,

    /// Hardware-backed monotonic counter (TEE-stored)
    pub monotonic_counter: u64,

    /// Timestamp from robot clock (local, not authoritative)
    pub local_timestamp_utc: DateTime<Utc>,

    /// Model provenance (hash + supply chain metadata)
    pub model_provenance: ModelProvenance,

    /// Firmware/OS hash
    pub firmware_hash: Hash256,

    /// TEE enclave measurement (code hash)
    pub enclave_measurement: Vec<u8>,

    /// Hash of previous checkpoint root (anti-rollback chaining)
    pub prev_root: Hash256,

    /// Merkle root of log entries since last checkpoint
    pub entries_root: Hash256,

    /// Deterministic inference configuration
    pub inference_config: DeterminismConfig,

    /// Trust mode
    pub trust_mode: TrustMode,

    /// Ed25519 signature over canonical CBOR of all fields above
    pub signature: SignatureBytes,
}

impl Checkpoint {
    /// Compute the canonical hash of this checkpoint (for prev_root chaining).
    ///
    /// This hash is computed over the *unsigned* checkpoint (all fields except signature).
    pub fn compute_hash(&self) -> Result<Hash256, SerializationError> {
        // Create unsigned version for hashing
        let unsigned = UnsignedCheckpoint {
            version: self.version,
            robot_id: self.robot_id.clone(),
            mission_id: self.mission_id.clone(),
            sequence: self.sequence,
            monotonic_counter: self.monotonic_counter,
            local_timestamp_utc: self.local_timestamp_utc,
            model_provenance: self.model_provenance.clone(),
            firmware_hash: self.firmware_hash,
            enclave_measurement: self.enclave_measurement.clone(),
            prev_root: self.prev_root,
            entries_root: self.entries_root,
            inference_config: self.inference_config.clone(),
            trust_mode: self.trust_mode,
        };

        let bytes = to_canonical_cbor(&unsigned)?;
        let hash = Sha256::digest(&bytes);
        Ok(hash.into())
    }

    /// Verify the signature on this checkpoint.
    pub fn verify_signature(&self, public_key: &ed25519_dalek::VerifyingKey) -> Result<(), SignatureError> {
        use ed25519_dalek::Verifier;

        let unsigned = UnsignedCheckpoint {
            version: self.version,
            robot_id: self.robot_id.clone(),
            mission_id: self.mission_id.clone(),
            sequence: self.sequence,
            monotonic_counter: self.monotonic_counter,
            local_timestamp_utc: self.local_timestamp_utc,
            model_provenance: self.model_provenance.clone(),
            firmware_hash: self.firmware_hash,
            enclave_measurement: self.enclave_measurement.clone(),
            prev_root: self.prev_root,
            entries_root: self.entries_root,
            inference_config: self.inference_config.clone(),
            trust_mode: self.trust_mode,
        };

        let message = to_canonical_cbor(&unsigned)
            .map_err(|_| SignatureError::SerializationFailed)?;

        let signature = ed25519_dalek::Signature::from_bytes(self.signature.as_ref());

        public_key.verify(&message, &signature)
            .map_err(|_| SignatureError::InvalidSignature)
    }

    /// Serialize to canonical CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        to_canonical_cbor(self)
    }

    /// Deserialize from canonical CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        from_canonical_cbor(bytes)
    }
}

/// Unsigned checkpoint (for signature computation)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UnsignedCheckpoint {
    pub version: u8,
    pub robot_id: RobotId,
    pub mission_id: MissionId,
    pub sequence: u64,
    pub monotonic_counter: u64,
    pub local_timestamp_utc: DateTime<Utc>,
    pub model_provenance: ModelProvenance,
    pub firmware_hash: Hash256,
    pub enclave_measurement: Vec<u8>,
    pub prev_root: Hash256,
    pub entries_root: Hash256,
    pub inference_config: DeterminismConfig,
    pub trust_mode: TrustMode,
}

/// Builder for constructing checkpoints.
pub struct CheckpointBuilder {
    robot_id: Option<RobotId>,
    mission_id: Option<MissionId>,
    sequence: Option<u64>,
    monotonic_counter: Option<u64>,
    local_timestamp_utc: Option<DateTime<Utc>>,
    model_provenance: Option<ModelProvenance>,
    firmware_hash: Option<Hash256>,
    enclave_measurement: Option<Vec<u8>>,
    prev_root: Option<Hash256>,
    entries_root: Option<Hash256>,
    inference_config: Option<DeterminismConfig>,
    trust_mode: Option<TrustMode>,
}

impl CheckpointBuilder {
    pub fn new() -> Self {
        Self {
            robot_id: None,
            mission_id: None,
            sequence: None,
            monotonic_counter: None,
            local_timestamp_utc: None,
            model_provenance: None,
            firmware_hash: None,
            enclave_measurement: None,
            prev_root: None,
            entries_root: None,
            inference_config: None,
            trust_mode: None,
        }
    }

    pub fn robot_id(mut self, id: RobotId) -> Self {
        self.robot_id = Some(id);
        self
    }

    pub fn mission_id(mut self, id: MissionId) -> Self {
        self.mission_id = Some(id);
        self
    }

    pub fn sequence(mut self, seq: u64) -> Self {
        self.sequence = Some(seq);
        self
    }

    pub fn monotonic_counter(mut self, counter: u64) -> Self {
        self.monotonic_counter = Some(counter);
        self
    }

    pub fn timestamp(mut self, ts: DateTime<Utc>) -> Self {
        self.local_timestamp_utc = Some(ts);
        self
    }

    pub fn model_provenance(mut self, prov: ModelProvenance) -> Self {
        self.model_provenance = Some(prov);
        self
    }

    pub fn firmware_hash(mut self, hash: Hash256) -> Self {
        self.firmware_hash = Some(hash);
        self
    }

    pub fn enclave_measurement(mut self, measurement: Vec<u8>) -> Self {
        self.enclave_measurement = Some(measurement);
        self
    }

    pub fn prev_root(mut self, root: Hash256) -> Self {
        self.prev_root = Some(root);
        self
    }

    pub fn entries_root(mut self, root: Hash256) -> Self {
        self.entries_root = Some(root);
        self
    }

    pub fn inference_config(mut self, config: DeterminismConfig) -> Self {
        self.inference_config = Some(config);
        self
    }

    pub fn trust_mode(mut self, mode: TrustMode) -> Self {
        self.trust_mode = Some(mode);
        self
    }

    /// Build and sign the checkpoint using the provided signing key.
    pub fn build_and_sign(
        self,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Checkpoint, BuildError> {
        use ed25519_dalek::Signer;

        let unsigned = UnsignedCheckpoint {
            version: CHECKPOINT_VERSION,
            robot_id: self.robot_id.ok_or(BuildError::MissingField("robot_id"))?,
            mission_id: self.mission_id.ok_or(BuildError::MissingField("mission_id"))?,
            sequence: self.sequence.ok_or(BuildError::MissingField("sequence"))?,
            monotonic_counter: self.monotonic_counter.ok_or(BuildError::MissingField("monotonic_counter"))?,
            local_timestamp_utc: self.local_timestamp_utc.unwrap_or_else(Utc::now),
            model_provenance: self.model_provenance.ok_or(BuildError::MissingField("model_provenance"))?,
            firmware_hash: self.firmware_hash.ok_or(BuildError::MissingField("firmware_hash"))?,
            enclave_measurement: self.enclave_measurement.ok_or(BuildError::MissingField("enclave_measurement"))?,
            prev_root: self.prev_root.ok_or(BuildError::MissingField("prev_root"))?,
            entries_root: self.entries_root.ok_or(BuildError::MissingField("entries_root"))?,
            inference_config: self.inference_config.ok_or(BuildError::MissingField("inference_config"))?,
            trust_mode: self.trust_mode.unwrap_or(TrustMode::Trusted),
        };

        let message = to_canonical_cbor(&unsigned)
            .map_err(|_| BuildError::SerializationFailed)?;

        let signature = signing_key.sign(&message);

        Ok(Checkpoint {
            version: unsigned.version,
            robot_id: unsigned.robot_id,
            mission_id: unsigned.mission_id,
            sequence: unsigned.sequence,
            monotonic_counter: unsigned.monotonic_counter,
            local_timestamp_utc: unsigned.local_timestamp_utc,
            model_provenance: unsigned.model_provenance,
            firmware_hash: unsigned.firmware_hash,
            enclave_measurement: unsigned.enclave_measurement,
            prev_root: unsigned.prev_root,
            entries_root: unsigned.entries_root,
            inference_config: unsigned.inference_config,
            trust_mode: unsigned.trust_mode,
            signature: SignatureBytes::from(signature.to_bytes()),
        })
    }
}

impl Default for CheckpointBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("Missing required field: {0}")]
    MissingField(&'static str),

    #[error("Serialization failed")]
    SerializationFailed,
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("Serialization failed")]
    SerializationFailed,

    #[error("Invalid signature")]
    InvalidSignature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn create_test_checkpoint() -> (Checkpoint, SigningKey) {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);

        let checkpoint = CheckpointBuilder::new()
            .robot_id(RobotId("R-001".to_string()))
            .mission_id(MissionId("M-2025-10-11-01".to_string()))
            .sequence(1)
            .monotonic_counter(100)
            .model_provenance(ModelProvenance {
                name: "model-v1".to_string(),
                model_hash: [0u8; 32],
                dataset_hash: None,
                container_digest: None,
                signature_bundle: None,
            })
            .firmware_hash([1u8; 32])
            .enclave_measurement(vec![2u8; 48])
            .prev_root([0u8; 32])
            .entries_root([3u8; 32])
            .inference_config(DeterminismConfig {
                rng_seed: Some(42),
                batch_size: 1,
                flags: None,
            })
            .trust_mode(TrustMode::Trusted)
            .build_and_sign(&signing_key)
            .unwrap();

        (checkpoint, signing_key)
    }

    #[test]
    fn test_checkpoint_signature_verification() {
        let (checkpoint, signing_key) = create_test_checkpoint();
        let verifying_key = signing_key.verifying_key();

        assert!(checkpoint.verify_signature(&verifying_key).is_ok());
    }

    #[test]
    fn test_checkpoint_hash_determinism() {
        let (checkpoint, _) = create_test_checkpoint();

        let hash1 = checkpoint.compute_hash().unwrap();
        let hash2 = checkpoint.compute_hash().unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_checkpoint_serialization_roundtrip() {
        let (checkpoint, signing_key) = create_test_checkpoint();
        let verifying_key = signing_key.verifying_key();

        let bytes = checkpoint.to_bytes().unwrap();
        let decoded = Checkpoint::from_bytes(&bytes).unwrap();

        assert_eq!(checkpoint, decoded);
        assert!(decoded.verify_signature(&verifying_key).is_ok());
    }
}
