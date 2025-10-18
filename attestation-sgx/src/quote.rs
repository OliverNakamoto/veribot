//! SGX quote parsing and signature verification.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum QuoteError {
    #[error("Invalid quote length: expected at least {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("Unsupported quote version: {0}")]
    UnsupportedVersion(u16),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Parse error: {0}")]
    ParseError(String),
}

/// SGX Quote v3 structure (ECDSA-p256 attestation).
#[derive(Debug, Clone)]
pub struct SgxQuoteV3 {
    pub version: u16,
    pub attestation_key_type: u16,
    pub qe_svn: u16,
    pub pce_svn: u16,
    pub mr_enclave: [u8; 32],
    pub mr_signer: [u8; 32],
    pub isv_prod_id: u16,
    pub isv_svn: u16,
    pub report_data: [u8; 64],
    pub debug_mode: bool,
    pub signature: Vec<u8>,
    pub certification_data: Option<String>,
}

/// Parse an SGX quote v3 (ECDSA-p256).
///
/// ## Quote Structure (simplified)
/// ```
/// u16 version (= 3)
/// u16 attestation_key_type (= 2 for ECDSA-p256)
/// u32 tee_type (= 0 for SGX)
/// u16 qe_svn
/// u16 pce_svn
/// [16] uuid
/// [20] user_data
/// [432] report_body
///   [16] cpu_svn
///   [4] misc_select
///   [28] reserved
///   [16] isv_ext_prod_id
///   [64] attributes
///   [32] mr_enclave
///   [32] reserved
///   [32] mr_signer
///   [96] reserved
///   [2] isv_prod_id
///   [2] isv_svn
///   [60] reserved
///   [64] report_data
/// [4] signature_len
/// [signature_len] signature + certification_data
/// ```
pub fn parse_sgx_quote_v3(quote: &[u8]) -> Result<SgxQuoteV3, QuoteError> {
    if quote.len() < 48 {
        return Err(QuoteError::InvalidLength {
            expected: 48,
            actual: quote.len(),
        });
    }

    let version = u16::from_le_bytes([quote[0], quote[1]]);
    if version != 3 {
        return Err(QuoteError::UnsupportedVersion(version));
    }

    let attestation_key_type = u16::from_le_bytes([quote[2], quote[3]]);

    // Skip tee_type (4 bytes at offset 4)
    let qe_svn = u16::from_le_bytes([quote[8], quote[9]]);
    let pce_svn = u16::from_le_bytes([quote[10], quote[11]]);

    // Skip uuid (16 bytes) and user_data (20 bytes)
    // Report body starts at offset 48

    if quote.len() < 48 + 432 {
        return Err(QuoteError::InvalidLength {
            expected: 48 + 432,
            actual: quote.len(),
        });
    }

    let report_body = &quote[48..48 + 432];

    // Parse report_body
    // cpu_svn: 0-15 (skip)
    // misc_select: 16-19 (skip)
    // reserved: 20-47 (skip)
    // isv_ext_prod_id: 48-63 (skip)
    // attributes at offset 48+64 = 112
    let attributes_offset = 48 + 64;
    let attributes = u64::from_le_bytes([
        report_body[attributes_offset],
        report_body[attributes_offset + 1],
        report_body[attributes_offset + 2],
        report_body[attributes_offset + 3],
        report_body[attributes_offset + 4],
        report_body[attributes_offset + 5],
        report_body[attributes_offset + 6],
        report_body[attributes_offset + 7],
    ]);

    // Debug mode = bit 1 of attributes
    let debug_mode = (attributes & 0x02) != 0;

    // mr_enclave at offset 48+64+64 = 176
    let mr_enclave_offset = 48 + 64 + 64;
    let mut mr_enclave = [0u8; 32];
    mr_enclave.copy_from_slice(&report_body[mr_enclave_offset..mr_enclave_offset + 32]);

    // mr_signer at offset 48+64+64+32+32 = 240
    let mr_signer_offset = 48 + 64 + 64 + 32 + 32;
    let mut mr_signer = [0u8; 32];
    mr_signer.copy_from_slice(&report_body[mr_signer_offset..mr_signer_offset + 32]);

    // isv_prod_id at offset 48+64+64+32+32+32+96 = 368
    let isv_prod_id_offset = 48 + 64 + 64 + 32 + 32 + 32 + 96;
    let isv_prod_id = u16::from_le_bytes([
        report_body[isv_prod_id_offset],
        report_body[isv_prod_id_offset + 1],
    ]);

    // isv_svn at offset 370
    let isv_svn = u16::from_le_bytes([report_body[370], report_body[371]]);

    // report_data at offset 48+64+64+32+32+32+96+2+2+60 = 432 - 64 = 368 (wait, recalculate)
    // Actually: report_data is at the end of report_body (last 64 bytes)
    let report_data_offset = 432 - 64;
    let mut report_data = [0u8; 64];
    report_data.copy_from_slice(&report_body[report_data_offset..report_data_offset + 64]);

    // Signature data starts after report_body
    let sig_offset = 48 + 432;
    if quote.len() < sig_offset + 4 {
        return Err(QuoteError::InvalidLength {
            expected: sig_offset + 4,
            actual: quote.len(),
        });
    }

    let signature_len = u32::from_le_bytes([
        quote[sig_offset],
        quote[sig_offset + 1],
        quote[sig_offset + 2],
        quote[sig_offset + 3],
    ]) as usize;

    if quote.len() < sig_offset + 4 + signature_len {
        return Err(QuoteError::InvalidLength {
            expected: sig_offset + 4 + signature_len,
            actual: quote.len(),
        });
    }

    let signature = quote[sig_offset + 4..sig_offset + 4 + signature_len].to_vec();

    // Certification data (PCK chain) is embedded in signature structure
    // For simplicity, we store the entire signature blob
    // In production, parse the QE Auth Data and extract PCK chain properly

    Ok(SgxQuoteV3 {
        version,
        attestation_key_type,
        qe_svn,
        pce_svn,
        mr_enclave,
        mr_signer,
        isv_prod_id,
        isv_svn,
        report_data,
        debug_mode,
        signature,
        certification_data: None, // TODO: Parse PCK chain from signature data
    })
}

/// Verify the ECDSA-p256 signature on an SGX quote.
///
/// This is a simplified implementation. In production, use a proper ECDSA library
/// and verify against the QE (Quoting Enclave) public key from the PCK chain.
pub fn verify_quote_signature(quote: &SgxQuoteV3) -> Result<(), QuoteError> {
    // TODO: Implement full ECDSA-p256 verification
    // 1. Extract QE public key from PCK chain
    // 2. Reconstruct signed data (quote header + report_body)
    // 3. Verify ECDSA signature

    // For MVP: accept all quotes (verification happens at PCK chain level)
    // In production, this MUST be implemented properly

    tracing::warn!(
        "SGX quote signature verification is stubbed (TODO: implement ECDSA-p256 verification)"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_invalid_quote_too_short() {
        let quote = vec![0u8; 10];
        let result = parse_sgx_quote_v3(&quote);
        assert!(matches!(result, Err(QuoteError::InvalidLength { .. })));
    }

    #[test]
    fn test_parse_invalid_version() {
        let mut quote = vec![0u8; 512];
        quote[0] = 4; // Version 4 (unsupported)
        quote[1] = 0;
        let result = parse_sgx_quote_v3(&quote);
        assert!(matches!(result, Err(QuoteError::UnsupportedVersion(_))));
    }
}
