use crate::types::{
    AtmInfo, BlindSignRequest, BlindSignResponse, CreditRequest, CreditResponse, Keyset, Proof,
    SettleResponse,
};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug)]
pub enum ClientError {
    Transport(String),
    HttpStatus(u16, String),
    Serialization(String),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::Transport(e) => write!(f, "Network transport error: {e}"),
            ClientError::HttpStatus(code, msg) => write!(f, "HTTP error {code}: {msg}"),
            ClientError::Serialization(e) => write!(f, "JSON serialization error: {e}"),
        }
    }
}

impl std::error::Error for ClientError {}

#[derive(Debug)]
struct DangerAcceptAllVerifier;

impl rustls::client::danger::ServerCertVerifier for DangerAcceptAllVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Clone)]
pub struct AtmClient {
    base_url: String,
    agent: ureq::Agent,
}

impl AtmClient {
    pub fn new(base_url: &str, insecure: bool) -> Result<Self, ClientError> {
        let clean_url = base_url.trim_end_matches('/').to_string();
        let mut builder = ureq::builder().timeout(Duration::from_secs(10));

        if insecure {
            let config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(DangerAcceptAllVerifier))
                .with_no_client_auth();
            builder = builder.tls_config(Arc::new(config));
        }

        Ok(Self {
            base_url: clean_url,
            agent: builder.build(),
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn get_info(&self) -> Result<AtmInfo, ClientError> {
        let url = format!("{}/v1/info", self.base_url);
        let resp_str = self
            .agent
            .get(&url)
            .call()
            .map_err(|e| ClientError::Transport(e.to_string()))?
            .into_string()
            .map_err(|e| ClientError::Transport(e.to_string()))?;

        serde_json::from_str(&resp_str)
            .map_err(|e| ClientError::Serialization(e.to_string()))
    }

    pub fn get_keyset(&self) -> Result<Keyset, ClientError> {
        let url = format!("{}/v1/keyset", self.base_url);
        let resp_str = self
            .agent
            .get(&url)
            .call()
            .map_err(|e| ClientError::Transport(e.to_string()))?
            .into_string()
            .map_err(|e| ClientError::Transport(e.to_string()))?;

        serde_json::from_str(&resp_str)
            .map_err(|e| ClientError::Serialization(e.to_string()))
    }

    pub fn credit_reserve(&self, amount: f64) -> Result<f64, ClientError> {
        let url = format!("{}/v1/credit", self.base_url);
        let payload = CreditRequest { amount };
        let req_json = serde_json::to_string(&payload)
            .map_err(|e| ClientError::Serialization(e.to_string()))?;

        let resp_str = self
            .agent
            .post(&url)
            .set("Content-Type", "application/json")
            .send_string(&req_json)
            .map_err(|e| ClientError::Transport(e.to_string()))?
            .into_string()
            .map_err(|e| ClientError::Transport(e.to_string()))?;

        let res: CreditResponse = serde_json::from_str(&resp_str)
            .map_err(|e| ClientError::Serialization(e.to_string()))?;
        Ok(res.reserve)
    }

    pub fn blind_sign(&self, blinded_b64: &str, amount: u32) -> Result<String, ClientError> {
        let url = format!("{}/v1/blind-sign", self.base_url);
        let payload = BlindSignRequest {
            blinded_message: blinded_b64.to_string(),
            amount,
        };
        let req_json = serde_json::to_string(&payload)
            .map_err(|e| ClientError::Serialization(e.to_string()))?;

        let resp = match self
            .agent
            .post(&url)
            .set("Content-Type", "application/json")
            .send_string(&req_json)
        {
            Ok(r) => r,
            Err(ureq::Error::Status(code, resp)) => {
                let err_body = resp.into_string().unwrap_or_default();
                return Err(ClientError::HttpStatus(code, err_body));
            }
            Err(e) => return Err(ClientError::Transport(e.to_string())),
        };

        let resp_str = resp
            .into_string()
            .map_err(|e| ClientError::Transport(e.to_string()))?;

        let res: BlindSignResponse = serde_json::from_str(&resp_str)
            .map_err(|e| ClientError::Serialization(e.to_string()))?;
        Ok(res.blind_signature)
    }

    pub fn settle(&self, proof: &Proof) -> Result<(bool, String), ClientError> {
        let url = format!("{}/v1/settle", self.base_url);
        let req_json = serde_json::to_string(proof)
            .map_err(|e| ClientError::Serialization(e.to_string()))?;

        match self
            .agent
            .post(&url)
            .set("Content-Type", "application/json")
            .send_string(&req_json)
        {
            Ok(resp) => {
                let resp_str = resp
                    .into_string()
                    .map_err(|e| ClientError::Transport(e.to_string()))?;
                let res: SettleResponse = serde_json::from_str(&resp_str)
                    .map_err(|e| ClientError::Serialization(e.to_string()))?;
                Ok((true, res.result))
            }
            Err(ureq::Error::Status(409, resp)) => {
                let resp_str = resp.into_string().unwrap_or_default();
                if let Ok(res) = serde_json::from_str::<SettleResponse>(&resp_str) {
                    Ok((false, res.result))
                } else {
                    Ok((false, resp_str))
                }
            }
            Err(ureq::Error::Status(code, resp)) => {
                let err_body = resp.into_string().unwrap_or_default();
                Err(ClientError::HttpStatus(code, err_body))
            }
            Err(e) => Err(ClientError::Transport(e.to_string())),
        }
    }
}
