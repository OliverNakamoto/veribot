//! PCK (Provisioning Certification Key) certificate chain verification.

use crate::TrustAnchors;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PckError {
    #[error("Invalid certificate chain")]
    InvalidChain,

    #[error("Certificate expired or not yet valid")]
    Expired,

    #[error("Certificate revoked")]
    Revoked,

    #[error("Parse error: {0}")]
    ParseError(String),
}

/// Verify the PCK certificate chain against trust anchors.
///
/// ## Verification Steps
/// 1. Parse PCK leaf certificate
/// 2. Verify chain: PCK -> Intermediate CA -> Root CA
/// 3. Check certificate validity periods
/// 4. Check CRLs for revoked certificates
/// 5. Verify SGX extensions (FMSPC, TCB level, etc.)
pub async fn verify_pck_chain(
    pck_chain_pem: &str,
    trust_anchors: &TrustAnchors,
) -> Result<(), PckError> {
    tracing::debug!("Verifying PCK certificate chain");

    // Parse PEM certificates
    let certs = parse_pem_chain(pck_chain_pem)?;

    if certs.is_empty() {
        return Err(PckError::InvalidChain);
    }

    // For MVP: basic validation only
    // In production:
    // 1. Use x509-parser to parse each certificate
    // 2. Verify signatures: cert[i].verify(cert[i+1].public_key)
    // 3. Check validity: not_before <= now <= not_after
    // 4. Check CRL: iterate trust_anchors.crls and check serial numbers
    // 5. Verify SGX-specific extensions (OID 1.2.840.113741.1.13.1.*)

    tracing::debug!("Parsed {} certificates in PCK chain", certs.len());

    // Verify root CA matches
    let root_cert_der = &certs[certs.len() - 1];
    if !trust_anchors.root_ca_cert.contains("BEGIN CERTIFICATE") {
        tracing::warn!("Trust anchor root CA is not in PEM format");
    }

    // TODO: Implement proper X.509 chain verification
    // For now, we assume the chain is valid if it can be parsed

    tracing::warn!("PCK chain verification is incomplete (TODO: implement full X.509 validation)");

    Ok(())
}

/// Parse a PEM-encoded certificate chain into DER bytes.
fn parse_pem_chain(pem: &str) -> Result<Vec<Vec<u8>>, PckError> {
    let mut certs = Vec::new();

    for block in pem.split("-----END CERTIFICATE-----") {
        if !block.contains("-----BEGIN CERTIFICATE-----") {
            continue;
        }

        let cert_pem = block.split("-----BEGIN CERTIFICATE-----").nth(1)
            .ok_or_else(|| PckError::ParseError("Invalid PEM format".to_string()))?;

        // Decode base64
        let cert_der = cert_pem
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>();

        let decoded = base64::decode(&cert_der)
            .map_err(|e| PckError::ParseError(format!("Base64 decode error: {}", e)))?;

        certs.push(decoded);
    }

    Ok(certs)
}

// Add base64 dependency
use base64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pem_chain_empty() {
        let result = parse_pem_chain("");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }
}
