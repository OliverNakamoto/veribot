# Threat Model - Humanoid Labs Robot Attestation System

**Version:** 1.0
**Date:** 2025-10-11
**Status:** Draft

## Executive Summary

This document analyzes security threats to the robot attestation system and documents mitigations. The system provides cryptographic proof of which AI model and runtime executed during autonomous robot missions, with tamper-evident audit trails anchored on-chain.

---

## 1. System Components & Trust Boundaries

### 1.1 Components

```
┌─────────────────────────────────────────────────────────────┐
│  Robot (Edge)                                               │
│  ┌──────────────┐         ┌─────────────────────┐         │
│  │ ROS2 Node    │────────▶│ TEE Enclave         │         │
│  │ (Untrusted)  │◀────────│ (Trusted)           │         │
│  └──────────────┘         └─────────────────────┘         │
│         │                           │                       │
│         │ Checkpoint Request        │ Signed Checkpoint     │
│         ▼                           ▼                       │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼ HTTPS + mTLS
┌─────────────────────────────────────────────────────────────┐
│  Gateway (Cloud)                                            │
│  ┌────────────┐   ┌──────────────┐   ┌─────────────────┐  │
│  │ API Server │──▶│ Verifier     │──▶│ EigenCompute    │  │
│  │ (Kafka)    │   │ (Quote Check)│   │ Integration     │  │
│  └────────────┘   └──────────────┘   └─────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼ Web3 Transaction
┌─────────────────────────────────────────────────────────────┐
│  Blockchain (L2 / EigenDA)                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  AttestationRegistry Smart Contract                 │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### 1.2 Trust Boundaries

| Boundary | Description | Trust Level |
|----------|-------------|-------------|
| **TEE Enclave** | Hardware-isolated execution environment | **TRUSTED** |
| **ROS2 Node** | User-space process on robot OS | **UNTRUSTED** |
| **Gateway** | Cloud service with HSM | **SEMI-TRUSTED** (operator-controlled) |
| **Smart Contract** | On-chain registry | **TRUSTLESS** (public blockchain) |
| **Storage (Off-chain)** | Encrypted archive (S3/IPFS) | **UNTRUSTED** (encrypted) |

---

## 2. Threat Actors

### 2.1 Adversary Profiles

| Actor | Capability | Motivation |
|-------|------------|------------|
| **A1: Malicious Operator** | Can modify ROS code, OS, sensors | Hide safety violations, evade liability |
| **A2: Nation-State Attacker** | Can exploit hardware vulnerabilities | Espionage, sabotage |
| **A3: Insider (Gateway Operator)** | Access to gateway infrastructure | Financial gain, data theft |
| **A4: External Attacker** | Network access, DDoS, phishing | Disruption, ransom |
| **A5: Compromised Supply Chain** | Tampered hardware, backdoored firmware | Long-term espionage |

---

## 3. Threat Categories & Mitigations

### 3.1 Compromised Enclave (TEE)

#### Threat: T-TEE-01 — Enclave Code Vulnerability
- **Actor:** A2 (Nation-State)
- **Description:** Attacker exploits vulnerability in enclave code to extract signing keys or manipulate checkpoints.
- **Impact:** **CRITICAL** — Breaks entire attestation chain.
- **Likelihood:** Low (assuming well-audited enclave code).

**Mitigations:**
1. ✅ **Code Audit:** External security audit of enclave TA (Trusted Application).
2. ✅ **Minimal TCB:** Keep enclave code minimal (<1000 LoC).
3. ✅ **Formal Verification:** Use formal methods for critical paths (signing, counter increment).
4. ✅ **Emergency Revocation:** Smart contract can revoke compromised enclave measurements.

#### Threat: T-TEE-02 — Hardware Side-Channel Attack
- **Actor:** A2 (Nation-State)
- **Description:** Spectre/Meltdown-style attack extracts enclave secrets via timing side-channels.
- **Impact:** **HIGH** — Could leak signing keys.
- **Likelihood:** Medium (known attacks exist, mitigations available).

**Mitigations:**
1. ✅ **Updated Firmware:** Require latest CPU microcode (TCB recovery).
2. ✅ **Constant-Time Crypto:** Use constant-time implementations for signing.
3. ⚠️ **Monitoring:** Detect anomalous enclave behavior (TODO: implement telemetry).

#### Threat: T-TEE-03 — Enclave Measurement Rollback
- **Actor:** A1 (Malicious Operator)
- **Description:** Attacker downgrades to older, vulnerable enclave version.
- **Impact:** **HIGH** — Bypasses patches.
- **Likelihood:** Low (requires UEFI tampering).

**Mitigations:**
1. ✅ **Monotonic Counter:** Enclave measurement + version embedded in checkpoint.
2. ✅ **Gateway Verification:** Gateway rejects checkpoints from revoked measurements.
3. ✅ **On-Chain Revocation:** Emergency revoke old measurements via smart contract.

---

### 3.2 Compromised Gateway

#### Threat: T-GW-01 — Gateway Key Compromise
- **Actor:** A3 (Insider), A4 (External Attacker)
- **Description:** Attacker steals gateway HSM keys and forges checkpoint signatures.
- **Impact:** **HIGH** — Can anchor fake checkpoints on-chain.
- **Likelihood:** Low (HSM protections).

**Mitigations:**
1. ✅ **HSM/KMS:** Gateway keys stored in AWS KMS or CloudHSM.
2. ✅ **Multi-Sig:** Require M-of-N gateway signatures for critical operations.
3. ✅ **Key Rotation:** Automated 90-day key rotation.
4. ✅ **Audit Logs:** All gateway operations logged immutably.

#### Threat: T-GW-02 — Gateway Operator Collusion
- **Actor:** A3 (Insider)
- **Description:** Gateway operator colludes with robot operator to anchor fake data.
- **Impact:** **MEDIUM** — Requires both parties to collude; enclave quote still verifiable.
- **Likelihood:** Low (cryptoeconomic disincentives via EigenLayer slashing).

**Mitigations:**
1. ✅ **Quote Verification:** Gateway *must* verify enclave quote before anchoring.
2. ✅ **Slashing:** EigenCompute AVS slashes gateway stake for invalid anchors.
3. ⚠️ **Decentralized Verification:** Use multiple independent gateways (TODO: Phase 2).

---

### 3.3 Replay & Rollback Attacks

#### Threat: T-REPLAY-01 — Checkpoint Replay
- **Actor:** A1 (Malicious Operator)
- **Description:** Attacker replays old signed checkpoints to hide recent actions.
- **Impact:** **HIGH** — Audit trail incomplete.
- **Likelihood:** High (without mitigations).

**Mitigations:**
1. ✅ **Monotonic Counter:** Hardware-backed counter increments with each checkpoint.
2. ✅ **Prev-Root Chaining:** Each checkpoint links to previous (blockchain-like).
3. ✅ **Sequence Verification:** Gateway tracks per-robot sequence numbers.
4. ✅ **Timestamp Anchoring:** On-chain timestamp provides authoritative time.

#### Threat: T-REPLAY-02 — Log Entry Deletion
- **Actor:** A1 (Malicious Operator)
- **Description:** Attacker deletes entries from local logs before checkpoint.
- **Impact:** **LOW** — Merkle root changes; gateway detects gap in sequence.
- **Likelihood:** High (if ROS node has write access to logs).

**Mitigations:**
1. ✅ **Append-Only Logs:** Enclave enforces append-only semantics.
2. ✅ **Merkle Proofs:** Gateway can request proofs for specific entries.
3. ⚠️ **Witness Co-Signing:** Require external witness (e.g., nearby robot) for critical events (TODO).

---

### 3.4 Supply Chain Attacks

#### Threat: T-SUPPLY-01 — Unsigned Model Loaded
- **Actor:** A5 (Compromised Supply Chain)
- **Description:** Attacker loads unsigned or backdoored model onto robot.
- **Impact:** **CRITICAL** — Unverifiable behavior.
- **Likelihood:** Medium (without provenance checks).

**Mitigations:**
1. ✅ **Model Provenance:** Require Sigstore/in-toto signatures for all models.
2. ✅ **Model Hash Registry:** Models must be pre-registered on-chain.
3. ✅ **Enclave Verification:** Enclave verifies model hash before loading.
4. ✅ **Reject Unsigned:** Trusted mode rejects unsigned models.

#### Threat: T-SUPPLY-02 — Firmware Backdoor
- **Actor:** A5 (Compromised Supply Chain)
- **Description:** Attacker injects backdoor into robot firmware/OS.
- **Impact:** **CRITICAL** — Bypasses all attestation.
- **Likelihood:** Low (requires supply chain access).

**Mitigations:**
1. ✅ **Secure Boot:** UEFI Secure Boot + verified boot chain.
2. ✅ **Firmware Hash:** Enclave includes firmware hash in checkpoint.
3. ✅ **Remote Attestation:** Enclave quote includes firmware measurement.
4. ⚠️ **Attestation on Boot:** Attest firmware before mission start (TODO).

---

### 3.5 Network & DoS Attacks

#### Threat: T-NET-01 — Man-in-the-Middle (MITM)
- **Actor:** A4 (External Attacker)
- **Description:** Attacker intercepts robot-gateway communication.
- **Impact:** **MEDIUM** — Cannot forge signatures, but can observe metadata.
- **Likelihood:** Medium (if TLS not enforced).

**Mitigations:**
1. ✅ **mTLS:** Mutual TLS with client certificates.
2. ✅ **Certificate Pinning:** Gateway certificate pinned in robot config.
3. ✅ **End-to-End Encryption:** Checkpoints encrypted with gateway public key.

#### Threat: T-NET-02 — Gateway DDoS
- **Actor:** A4 (External Attacker)
- **Description:** Attacker floods gateway with requests, preventing checkpoint submission.
- **Impact:** **LOW** — Offline buffering allows delayed submission.
- **Likelihood:** High (public endpoint).

**Mitigations:**
1. ✅ **Rate Limiting:** Per-robot rate limits (e.g., 10 checkpoints/min).
2. ✅ **DDoS Protection:** Cloudflare / AWS Shield.
3. ✅ **Offline Buffer:** Robots buffer 7 days of checkpoints locally.
4. ✅ **Multi-Region:** Deploy gateways in multiple regions.

---

### 3.6 Privacy & Data Leakage

#### Threat: T-PRIVACY-01 — Sensor Data Exposure
- **Actor:** A3 (Insider), Legal Adversary
- **Description:** Full sensor logs contain PII (faces, license plates, audio).
- **Impact:** **HIGH** — GDPR violations, privacy lawsuits.
- **Likelihood:** High (if raw logs stored unencrypted).

**Mitigations:**
1. ✅ **Thumbnail-Only On-Chain:** Only store small thumbnails/hashes on-chain.
2. ✅ **Encryption at Rest:** Full logs AES-256-GCM encrypted off-chain.
3. ✅ **Threshold Decryption:** 3-of-5 key shares required for disclosure.
4. ✅ **Selective Disclosure:** Merkle proofs allow proving specific entries without full logs.
5. ✅ **Retention Policies:** Auto-delete after 90 days (configurable).

#### Threat: T-PRIVACY-02 — Metadata Leakage
- **Actor:** A4 (External Attacker), Blockchain Observer
- **Description:** On-chain checkpoints reveal mission timing, frequency, robot IDs.
- **Impact:** **LOW** — Operational security risk for sensitive missions.
- **Likelihood:** High (blockchain is public).

**Mitigations:**
1. ⚠️ **Pseudonymous Robot IDs:** Use rotating pseudonyms instead of fixed IDs (TODO).
2. ⚠️ **ZK Proofs:** Use ZK-SNARKs to prove checkpoint validity without revealing metadata (TODO: future).
3. ✅ **Private Chains:** Deploy on private EigenDA for sensitive deployments.

---

### 3.7 Smart Contract Vulnerabilities

#### Threat: T-SC-01 — Reentrancy Attack
- **Actor:** A4 (External Attacker)
- **Description:** Attacker exploits reentrancy in smart contract to manipulate state.
- **Impact:** **HIGH** — Could drain funds or corrupt registry.
- **Likelihood:** Low (mitigations in place).

**Mitigations:**
1. ✅ **ReentrancyGuard:** OpenZeppelin ReentrancyGuard on all state-changing functions.
2. ✅ **Checks-Effects-Interactions:** Follow CEI pattern.
3. ✅ **Audit:** External audit before mainnet deployment.

#### Threat: T-SC-02 — Access Control Bypass
- **Actor:** A4 (External Attacker)
- **Description:** Attacker bypasses role checks to call privileged functions.
- **Impact:** **CRITICAL** — Could revoke valid enclaves or register fake models.
- **Likelihood:** Low (using OpenZeppelin AccessControl).

**Mitigations:**
1. ✅ **AccessControl:** OpenZeppelin role-based access control.
2. ✅ **Test Coverage:** 100% coverage for access control logic.
3. ✅ **Timelocks:** Add timelock for governance actions (revocations).

#### Threat: T-SC-03 — Oracle Manipulation
- **Actor:** A4 (External Attacker)
- **Description:** If using oracles for TCB status, attacker manipulates oracle data.
- **Impact:** **MEDIUM** — Could cause false revocations.
- **Likelihood:** N/A (system does not use oracles currently).

**Mitigations:**
1. ⚠️ **Chainlink/API3:** Use decentralized oracles if TCB data needed on-chain (TODO: future).

---

### 3.8 Insider Data Manipulation

#### Threat: T-INSIDER-01 — Enclave Key Extraction by Insider
- **Actor:** A3 (Insider with Physical Access)
- **Description:** Insider with physical access extracts enclave keys via hardware debugging.
- **Impact:** **CRITICAL** — Complete compromise.
- **Likelihood:** Very Low (requires sophisticated hardware attack).

**Mitigations:**
1. ✅ **No Key Export:** Keys never leave enclave.
2. ✅ **Anti-Tamper:** Hardware anti-tamper mechanisms (SE, TPM).
3. ✅ **Physical Security:** Robots deployed in tamper-evident enclosures.
4. ✅ **Revocation:** Immediate revocation on tamper detection.

---

## 4. Residual Risks

| Risk | Severity | Likelihood | Status | Notes |
|------|----------|------------|--------|-------|
| TEE 0-day exploit | **CRITICAL** | Very Low | ⚠️ **ACCEPTED** | Monitor CVEs; fast revocation path |
| Quantum computer breaks Ed25519 | **HIGH** | Very Low (5-10 years) | ⚠️ **MONITORED** | Plan migration to post-quantum crypto |
| All gateways collude | **MEDIUM** | Very Low | ⚠️ **ACCEPTED** | Mitigated by EigenLayer slashing |
| Legal non-admissibility | **MEDIUM** | Medium | ⚠️ **ACCEPTED** | Varies by jurisdiction; consult counsel |

---

## 5. Security Testing Plan

### 5.1 Pre-Launch
- [ ] External enclave audit (2 weeks) — **CRITICAL**
- [ ] Smart contract audit (2 weeks) — **CRITICAL**
- [ ] Penetration testing (1 week)
- [ ] Fuzz testing (continuous)

### 5.2 Continuous
- [ ] Automated CVE monitoring (TEE vendors)
- [ ] Bug bounty program (Phase 2)
- [ ] Quarterly security reviews

---

## 6. Incident Response

### 6.1 Enclave Compromise Detected
1. **Emergency Revoke:** Call `emergencyRevokeEnclave()` on smart contract.
2. **Notify Fleet:** Push OTA update to all robots to halt missions.
3. **Root Cause Analysis:** Engage vendor (Intel/ARM/AWS) and auditor.
4. **Patch & Redeploy:** Deploy patched enclave with new measurement.
5. **Reinstate:** Call `reinstateEnclave()` after verification.

### 6.2 Gateway Compromise Detected
1. **Rotate Keys:** Emergency key rotation in HSM.
2. **Revoke Role:** Call `removeGateway()` on smart contract.
3. **Audit On-Chain:** Review all recent anchored checkpoints.
4. **Forensics:** Preserve logs; engage incident response team.

---

## 7. Compliance & Legal

### 7.1 GDPR / CCPA
- **Right to Erasure:** Delete off-chain logs; retain on-chain commitment only.
- **Right to Access:** Provide decrypted logs via threshold decryption.
- **Data Minimization:** Store only minimal metadata on-chain.

### 7.2 Product Liability
- **Chain of Custody:** Attestation provides strong evidence for liability cases.
- **Admissibility:** Varies by jurisdiction; consult legal counsel.
- **Insurance:** Cyber liability insurance recommended.

---

## 8. Conclusion

This threat model identifies **18 primary threats** across 8 categories. **Critical mitigations** are implemented for high-severity threats (compromised enclave, gateway, supply chain). **Residual risks** are documented and accepted where mitigations are impractical.

**Next Steps:**
1. Complete external security audit (Q1 2026).
2. Implement ZK-based selective disclosure (Phase 2).
3. Deploy decentralized gateway network (Phase 3).

---

**Reviewers:**
- Security Lead: [Name]
- Enclave Developer: [Name]
- Smart Contract Developer: [Name]
- Legal Counsel: [Name]

**Last Updated:** 2025-10-11
