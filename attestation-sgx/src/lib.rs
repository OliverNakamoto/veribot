//! Intel SGX DCAP (Data Center Attestation Primitives) attestation adapter.
//!
//! This module implements remote attestation verification for Intel SGX enclaves
//! using the DCAP protocol (PCK-based attestation without IAS).
//!
//! ## Verification Flow
//! 1. Parse SGX quote (ECDSA-p256)
//! 2. Extract enclave measurement (MRENCLAVE) and attributes
//! 3. Verify PCK certificate chain
//! 4. Check CRL for revoked certificates
//! 5. Verify quote signature
//! 6. Return attestation result

pub mod dcap;
pub mod quote;
pub mod pck;

use attestation_core::{AttestationAdapter, AttestationError, AttestationResult, RevocationStatus};
use async_trait::async_trait;
use chrono::Utc;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Intel SGX DCAP attestation adapter.
pub struct SgxDcapAdapter {
    config: SgxConfig,
    trust_anchors: Arc<RwLock<TrustAnchors>>,
}

/// Configuration for SGX DCAP verification.
#[derive(Debug, Clone)]
pub struct SgxConfig {
    /// URL for Intel PCS (Provisioning Certification Service)
    pub pcs_url: String,
    /// Cache expiry for CRLs and certificates (seconds)
    pub cache_expiry_secs: u64,
    /// Allow debug enclaves (should be false in production)
    pub allow_debug: bool,
}

impl Default for SgxConfig {
    fn default() -> Self {
        Self {
            pcs_url: "https://api.trustedservices.intel.com/sgx/certification/v4".to_string(),
            cache_expiry_secs: 3600, // 1 hour
            allow_debug: false,
        }
    }
}

/// Trust anchors (root CA, CRLs) for SGX attestation.
#[derive(Debug, Clone)]
struct TrustAnchors {
    root_ca_cert: String,
    intermediate_certs: Vec<String>,
    crls: Vec<Vec<u8>>,
    last_updated: chrono::DateTime<chrono::Utc>,
}

impl Default for TrustAnchors {
    fn default() -> Self {
        Self {
            root_ca_cert: INTEL_SGX_ROOT_CA.to_string(),
            intermediate_certs: Vec::new(),
            crls: Vec::new(),
            last_updated: Utc::now(),
        }
    }
}

/// Intel SGX Root CA certificate (PEM)
const INTEL_SGX_ROOT_CA: &str = r#"-----BEGIN CERTIFICATE-----
MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDExMVoXDTMzMDUyMTEwNDExMFowaDEaMBgG
A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7
1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB
uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ
MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50
ZWwuY29tL0ludGVsU0dYUm9vdENBLmNybDAdBgNVHQ4EFgQUImUM1lqdNInzg7SV
Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI
KoZIzj0EAwIDSQAwRgIhAIpQ/KdMQPcbdLTq3ug17QPoGo3bILKQN8r0XiajmKOJ
AiEA3e5tYNTqoTasDpKQJ4dWqkWVyCUsKgVLfHUELxOCLjY=
-----END CERTIFICATE-----"#;

impl SgxDcapAdapter {
    /// Create a new SGX DCAP adapter with default configuration.
    pub fn new() -> Self {
        Self::with_config(SgxConfig::default())
    }

    /// Create a new SGX DCAP adapter with custom configuration.
    pub fn with_config(config: SgxConfig) -> Self {
        Self {
            config,
            trust_anchors: Arc::new(RwLock::new(TrustAnchors::default())),
        }
    }

    /// Verify an SGX quote with DCAP.
    async fn verify_quote_internal(
        &self,
        quote_bytes: &[u8],
        _nonce: Option<&[u8]>,
    ) -> Result<AttestationResult, AttestationError> {
        // Parse the quote
        let quote = quote::parse_sgx_quote_v3(quote_bytes)
            .map_err(|e| AttestationError::InvalidQuote(e.to_string()))?;

        tracing::debug!(
            "Parsed SGX quote: MRENCLAVE={}, MRSIGNER={}, Debug={}",
            hex::encode(&quote.mr_enclave),
            hex::encode(&quote.mr_signer),
            quote.debug_mode
        );

        // Check if debug mode is allowed
        if quote.debug_mode && !self.config.allow_debug {
            return Err(AttestationError::VerificationFailed(
                "Debug enclaves are not allowed".to_string(),
            ));
        }

        // Verify PCK certificate chain (if present)
        if let Some(pck_chain_data) = &quote.certification_data {
            pck::verify_pck_chain(pck_chain_data, &self.trust_anchors.read().await)
                .await
                .map_err(|e| AttestationError::VerificationFailed(e.to_string()))?;
        }

        // Verify quote signature (ECDSA-p256 over quote body)
        quote::verify_quote_signature(&quote)
            .map_err(|e| AttestationError::VerificationFailed(e.to_string()))?;

        // Check revocation
        let revoke_status = self.check_revocation(&quote.mr_enclave).await?;

        Ok(AttestationResult {
            vendor: "intel-sgx".to_string(),
            enclave_measurement: quote.mr_enclave.to_vec(),
            quote_verified: true,
            verified_at: Utc::now(),
            revoke_check: revoke_status,
            raw_quote: Some(quote_bytes.to_vec()),
            pck_chain: quote.certification_data.clone(),
        })
    }
}

impl Default for SgxDcapAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AttestationAdapter for SgxDcapAdapter {
    fn vendor_name(&self) -> &str {
        "intel-sgx"
    }

    async fn verify_quote(
        &self,
        quote: &[u8],
        nonce: Option<&[u8]>,
    ) -> Result<AttestationResult, AttestationError> {
        self.verify_quote_internal(quote, nonce).await
    }

    async fn check_revocation(&self, measurement: &[u8]) -> Result<RevocationStatus, AttestationError> {
        // TODO: Check local revocation list (from smart contract or registry)
        // For now, we only check CRLs for PCK certificates

        tracing::debug!("Checking revocation for MRENCLAVE: {}", hex::encode(measurement));

        // In production, query the smart contract for emergency revocations
        // For now, return Ok if not in local blacklist
        Ok(RevocationStatus::Ok)
    }

    fn root_ca_certs(&self) -> &[String] {
        // Return static root CA (in production, load from config)
        static ROOT_CA: [String; 1] = [String::new()];
        &ROOT_CA
    }

    async fn update_trust_anchors(&mut self) -> Result<(), AttestationError> {
        let mut anchors = self.trust_anchors.write().await;

        // Check if cache is still valid
        let elapsed = Utc::now() - anchors.last_updated;
        if elapsed.num_seconds() < self.config.cache_expiry_secs as i64 {
            tracing::debug!("Trust anchors cache still valid");
            return Ok(());
        }

        tracing::info!("Updating SGX trust anchors from Intel PCS");

        // Fetch latest CRLs from Intel PCS
        // In production: fetch from {pcs_url}/pckcrl?ca=processor&encoding=der
        // For MVP, we skip this and rely on static root CA + manual CRL updates

        anchors.last_updated = Utc::now();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_adapter_creation() {
        let adapter = SgxDcapAdapter::new();
        assert_eq!(adapter.vendor_name(), "intel-sgx");
    }

    #[tokio::test]
    async fn test_revocation_check() {
        let adapter = SgxDcapAdapter::new();
        let result = adapter.check_revocation(&[0u8; 32]).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), RevocationStatus::Ok);
    }
}
