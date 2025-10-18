//! DCAP (Data Center Attestation Primitives) protocol implementation.
//!
//! This module handles communication with Intel PCS (Provisioning Certification Service)
//! for fetching PCK certificates, CRLs, and TCB info.

use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DcapError {
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("PCS API error: {0}")]
    PcsApi(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),
}

/// Intel PCS client for fetching attestation collateral.
pub struct PcsClient {
    client: Client,
    base_url: String,
}

impl PcsClient {
    /// Create a new PCS client.
    pub fn new(base_url: String) -> Self {
        Self {
            client: Client::new(),
            base_url,
        }
    }

    /// Fetch PCK certificate for a given platform.
    ///
    /// # Arguments
    /// * `fmspc` - Platform family/model/stepping (6 bytes hex)
    /// * `pce_id` - PCE identifier (2 bytes hex)
    pub async fn get_pck_certificate(
        &self,
        fmspc: &str,
        pce_id: &str,
    ) -> Result<String, DcapError> {
        let url = format!(
            "{}/pckcert?fmspc={}&pceid={}",
            self.base_url, fmspc, pce_id
        );

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(DcapError::PcsApi(format!(
                "HTTP {}",
                response.status()
            )));
        }

        let cert = response.text().await?;
        Ok(cert)
    }

    /// Fetch PCK CRL (Certificate Revocation List).
    ///
    /// # Arguments
    /// * `ca` - CA type ("processor" or "platform")
    pub async fn get_pck_crl(&self, ca: &str) -> Result<Vec<u8>, DcapError> {
        let url = format!(
            "{}/pckcrl?ca={}&encoding=der",
            self.base_url, ca
        );

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(DcapError::PcsApi(format!(
                "HTTP {}",
                response.status()
            )));
        }

        let crl = response.bytes().await?;
        Ok(crl.to_vec())
    }

    /// Fetch TCB (Trusted Computing Base) info for a platform.
    ///
    /// # Arguments
    /// * `fmspc` - Platform family/model/stepping (6 bytes hex)
    pub async fn get_tcb_info(&self, fmspc: &str) -> Result<TcbInfo, DcapError> {
        let url = format!("{}/tcb?fmspc={}", self.base_url, fmspc);

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(DcapError::PcsApi(format!(
                "HTTP {}",
                response.status()
            )));
        }

        let tcb_info: TcbInfo = response.json().await?;
        Ok(tcb_info)
    }
}

/// TCB (Trusted Computing Base) information from Intel PCS.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfo {
    pub version: u32,
    pub issue_date: String,
    pub next_update: String,
    pub fmspc: String,
    pub pce_id: String,
    pub tcb_type: u32,
    pub tcb_evaluation_data_number: u32,
    pub tcb_levels: Vec<TcbLevel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbLevel {
    pub tcb: TcbComponents,
    pub tcb_date: String,
    pub tcb_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbComponents {
    pub sgxtcbcomp01svn: u8,
    pub sgxtcbcomp02svn: u8,
    pub sgxtcbcomp03svn: u8,
    pub sgxtcbcomp04svn: u8,
    pub sgxtcbcomp05svn: u8,
    pub sgxtcbcomp06svn: u8,
    pub sgxtcbcomp07svn: u8,
    pub sgxtcbcomp08svn: u8,
    pub sgxtcbcomp09svn: u8,
    pub sgxtcbcomp10svn: u8,
    pub sgxtcbcomp11svn: u8,
    pub sgxtcbcomp12svn: u8,
    pub sgxtcbcomp13svn: u8,
    pub sgxtcbcomp14svn: u8,
    pub sgxtcbcomp15svn: u8,
    pub sgxtcbcomp16svn: u8,
    pub pcesvn: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcs_client_creation() {
        let client = PcsClient::new("https://api.trustedservices.intel.com".to_string());
        assert_eq!(client.base_url, "https://api.trustedservices.intel.com");
    }
}
