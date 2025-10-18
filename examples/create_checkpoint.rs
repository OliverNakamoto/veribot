//! Example: Creating and verifying a robot checkpoint
//!
//! Run with: cargo run --example create_checkpoint

use attestation_core::{
    CheckpointBuilder, DeterminismConfig, Entry, MerkleTree, ModelProvenance, RobotId, MissionId,
    Signer, TrustMode,
};

fn main() {
    println!("🤖 Robot Attestation System - Example Usage\n");
    println!("==============================================\n");

    // Step 1: Generate signing key (in production, this comes from TEE enclave)
    println!("1️⃣  Generating enclave signing key...");
    let enclave_signer = Signer::generate();
    let enclave_pubkey = enclave_signer.verifying_key();
    println!("   ✓ Enclave public key: {:x?}...\n", &enclave_pubkey.to_bytes()[..8]);

    // Step 2: Create mission log entries
    println!("2️⃣  Creating mission log entries...");
    let mut merkle_tree = MerkleTree::new();

    // Simulate 5 log entries from the robot mission
    for i in 0..5 {
        let timestamp = 1728000000000000 + (i * 1000000); // Microseconds since epoch
        let log_data = format!("Robot moved to waypoint {}", i);
        let entry = Entry::new(timestamp, i, log_data.as_bytes());
        merkle_tree.insert(entry);
        println!("   Added entry {}: {}", i, log_data);
    }

    let merkle_root = merkle_tree.root();
    println!("   ✓ Merkle root: {:x?}...\n", &merkle_root[..8]);

    // Step 3: Build checkpoint with anti-rollback protection
    println!("3️⃣  Building checkpoint with anti-rollback protection...");

    let model_hash = attestation_core::crypto::sha256(b"model-weights-v1.0.0");
    let firmware_hash = attestation_core::crypto::sha256(b"firmware-v2.5.1");
    let enclave_measurement = vec![0x42; 48]; // Simulated MRENCLAVE

    let checkpoint = CheckpointBuilder::new()
        .robot_id(RobotId("ROBOT-001".to_string()))
        .mission_id(MissionId("MISSION-2025-10-11-001".to_string()))
        .sequence(42)                    // Strictly increasing sequence number
        .monotonic_counter(1337)         // Hardware-backed monotonic counter
        .model_provenance(ModelProvenance {
            name: "autonomous-nav-v1.0.0".to_string(),
            model_hash,
            dataset_hash: Some(attestation_core::crypto::sha256(b"training-dataset-2025")),
            container_digest: Some("sha256:abc123def456...".to_string()),
            signature_bundle: None,
        })
        .firmware_hash(firmware_hash)
        .enclave_measurement(enclave_measurement.clone())
        .prev_root([0u8; 32])           // Previous checkpoint root (0 for first)
        .entries_root(merkle_root)      // Merkle root of log entries
        .inference_config(DeterminismConfig {
            rng_seed: Some(42),
            batch_size: 1,
            flags: Some(vec!["cudnn_deterministic=true".to_string()]),
        })
        .trust_mode(TrustMode::Trusted)
        .build_and_sign(enclave_signer.signing_key())
        .unwrap();

    println!("   ✓ Checkpoint signed");
    println!("   Robot ID: {}", checkpoint.robot_id);
    println!("   Mission ID: {}", checkpoint.mission_id);
    println!("   Sequence: {}", checkpoint.sequence);
    println!("   Monotonic Counter: {}", checkpoint.monotonic_counter);
    println!("   Trust Mode: {}\n", checkpoint.trust_mode);

    // Step 4: Serialize to canonical CBOR
    println!("4️⃣  Serializing to canonical CBOR...");
    let checkpoint_bytes = checkpoint.to_bytes().unwrap();
    println!("   ✓ Checkpoint size: {} bytes\n", checkpoint_bytes.len());

    // Step 5: Verify signature
    println!("5️⃣  Verifying checkpoint signature...");
    match checkpoint.verify_signature(&enclave_pubkey) {
        Ok(()) => println!("   ✅ Signature VALID\n"),
        Err(e) => println!("   ❌ Signature INVALID: {:?}\n", e),
    }

    // Step 6: Compute checkpoint hash (for prev_root chaining)
    println!("6️⃣  Computing checkpoint hash for anti-rollback...");
    let checkpoint_hash = checkpoint.compute_hash().unwrap();
    println!("   ✓ Checkpoint hash: {:x?}...", &checkpoint_hash[..16]);
    println!("   (This hash becomes prev_root for the next checkpoint)\n");

    // Step 7: Generate Merkle proof for selective disclosure
    println!("7️⃣  Generating Merkle proof for entry #2...");
    let proof = merkle_tree.generate_proof(1728000000000000 + 2000000, 2).unwrap();
    println!("   ✓ Proof generated with {} sibling hashes", proof.siblings.len());
    println!("   ✓ Proof verification: {}\n", proof.verify(&merkle_root));

    // Step 8: Simulate gateway verification
    println!("8️⃣  Simulating gateway verification...");
    println!("   ✓ Signature: VALID");
    println!("   ✓ Sequence: {} > previous (anti-rollback check)", checkpoint.sequence);
    println!("   ✓ Monotonic counter: {} > previous", checkpoint.monotonic_counter);
    println!("   ✓ Enclave measurement: {:x?}... (not revoked)", &enclave_measurement[..8]);
    println!("   ✅ Checkpoint accepted for on-chain anchoring\n");

    println!("==============================================");
    println!("✅ Checkpoint workflow complete!");
    println!("\nNext steps:");
    println!("  - Deploy checkpoint to gateway: POST /checkpoints");
    println!("  - Gateway anchors to blockchain");
    println!("  - Verifiers can retrieve and validate");
}
