//! Attestation adapter interface for multi-vendor TEE support.
//!
//! This module defines the trait that all attestation adapters must implement,
//! providing a unified API for verifying TEE quotes across different vendors.

use crate::types::{AttestationResult, RevocationStatus};
use async_trait::async_trait;
use std::fmt;
use thiserror::Error;

/// Trait for attestation verification adapters.
///
/// Each vendor (Intel SGX, AWS Nitro, ARM TrustZone) implements this trait
/// to provide quote verification according to their specific protocol.
#[async_trait]
pub trait AttestationAdapter: Send + Sync {
    /// Get the vendor name (e.g., "intel-sgx", "aws-nitro", "arm-trustzone").
    fn vendor_name(&self) -> &str;

    /// Verify an attestation quote.
    ///
    /// # Arguments
    /// * `quote` - The raw attestation quote bytes (vendor-specific format)
    /// * `nonce` - Optional nonce to prevent replay (if supported by vendor)
    ///
    /// # Returns
    /// An `AttestationResult` with verification details, or an error if verification fails.
    async fn verify_quote(
        &self,
        quote: &[u8],
        nonce: Option<&[u8]>,
    ) -> Result<AttestationResult, AttestationError>;

    /// Check if an enclave measurement is revoked.
    ///
    /// # Arguments
    /// * `measurement` - The enclave measurement (code hash)
    ///
    /// # Returns
    /// The revocation status of the measurement.
    async fn check_revocation(&self, measurement: &[u8]) -> Result<RevocationStatus, AttestationError>;

    /// Get the root CA certificates for this vendor's attestation chain.
    ///
    /// Returns PEM-encoded certificates.
    fn root_ca_certs(&self) -> &[String];

    /// Update cached CRLs and root certificates.
    ///
    /// Should be called periodically to refresh revocation lists.
    async fn update_trust_anchors(&mut self) -> Result<(), AttestationError>;
}

/// Errors that can occur during attestation verification.
#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("Invalid quote format: {0}")]
    InvalidQuote(String),

    #[error("Quote verification failed: {0}")]
    VerificationFailed(String),

    #[error("Revocation check failed: {0}")]
    RevocationCheckFailed(String),

    #[error("Enclave measurement is revoked")]
    MeasurementRevoked,

    #[error("Network error: {0}")]
    Network(String),

    #[error("Unsupported vendor: {0}")]
    UnsupportedVendor(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Registry of attestation adapters.
///
/// Allows dynamic selection of adapter based on vendor name.
pub struct AttestationRegistry {
    adapters: std::collections::HashMap<String, Box<dyn AttestationAdapter>>,
}

impl AttestationRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            adapters: std::collections::HashMap::new(),
        }
    }

    /// Register an attestation adapter.
    pub fn register(&mut self, adapter: Box<dyn AttestationAdapter>) {
        let vendor = adapter.vendor_name().to_string();
        self.adapters.insert(vendor, adapter);
    }

    /// Get an adapter by vendor name.
    pub fn get(&self, vendor: &str) -> Option<&dyn AttestationAdapter> {
        self.adapters.get(vendor).map(|b| b.as_ref())
    }

    /// Get a mutable adapter by vendor name.
    pub fn get_mut(&mut self, vendor: &str) -> Option<&mut Box<dyn AttestationAdapter>> {
        self.adapters.get_mut(vendor)
    }

    /// Get all registered vendor names.
    pub fn vendors(&self) -> Vec<&str> {
        self.adapters.keys().map(|s| s.as_str()).collect()
    }

    /// Verify a quote using the appropriate adapter.
    pub async fn verify_quote(
        &self,
        vendor: &str,
        quote: &[u8],
        nonce: Option<&[u8]>,
    ) -> Result<AttestationResult, AttestationError> {
        let adapter = self.get(vendor)
            .ok_or_else(|| AttestationError::UnsupportedVendor(vendor.to_string()))?;

        adapter.verify_quote(quote, nonce).await
    }
}

impl Default for AttestationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for AttestationRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttestationRegistry")
            .field("vendors", &self.vendors())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    // Mock adapter for testing
    struct MockAdapter {
        vendor: String,
    }

    #[async_trait]
    impl AttestationAdapter for MockAdapter {
        fn vendor_name(&self) -> &str {
            &self.vendor
        }

        async fn verify_quote(
            &self,
            _quote: &[u8],
            _nonce: Option<&[u8]>,
        ) -> Result<AttestationResult, AttestationError> {
            Ok(AttestationResult {
                vendor: self.vendor.clone(),
                enclave_measurement: vec![0u8; 32],
                quote_verified: true,
                verified_at: Utc::now(),
                revoke_check: RevocationStatus::Ok,
                raw_quote: None,
                pck_chain: None,
            })
        }

        async fn check_revocation(&self, _measurement: &[u8]) -> Result<RevocationStatus, AttestationError> {
            Ok(RevocationStatus::Ok)
        }

        fn root_ca_certs(&self) -> &[String] {
            &[]
        }

        async fn update_trust_anchors(&mut self) -> Result<(), AttestationError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_registry() {
        let mut registry = AttestationRegistry::new();

        registry.register(Box::new(MockAdapter {
            vendor: "mock-vendor".to_string(),
        }));

        assert_eq!(registry.vendors(), vec!["mock-vendor"]);

        let result = registry.verify_quote("mock-vendor", b"test", None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_unsupported_vendor() {
        let registry = AttestationRegistry::new();
        let result = registry.verify_quote("nonexistent", b"test", None).await;
        assert!(matches!(result, Err(AttestationError::UnsupportedVendor(_))));
    }
}
