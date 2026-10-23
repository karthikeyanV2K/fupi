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

/// How the client authenticates the ATM's TLS certificate.
#[derive(Debug, Clone)]
pub enum TlsMode {
    /// Normal WebPKI validation (CA-signed certificate). The default.
    Strict,
    /// Accept exactly the certificate whose SHA-256 (hex, colons/case ignored)
    /// matches. Use this for the kiosk's self-signed certificate: copy the
    /// fingerprint from the kiosk log / dashboard once, over a trusted channel.
    Pinned(String),
    /// DANGEROUS: accept any certificate. Local development only.
    Insecure,
}

pub fn normalize_fingerprint(fp: &str) -> String {
    fp.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_ascii_lowercase()
}

pub fn fingerprint_matches(cert_der: &[u8], pin: &str) -> bool {
    use sha2::{Digest, Sha256};
    let got = crate::crypto::hex_encode(&Sha256::digest(cert_der));
    got == normalize_fingerprint(pin)
}

#[derive(Debug)]
struct PinnedVerifier {
    pin: String,
}

fn sig_algs() -> rustls::crypto::WebPkiSupportedAlgorithms {
    rustls::crypto::ring::default_provider().signature_verification_algorithms
}

impl rustls::client::danger::ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if fingerprint_matches(end_entity.as_ref(), &self.pin) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "ATM certificate does not match the pinned SHA-256 fingerprint".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &sig_algs())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &sig_algs())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        sig_algs().supported_schemes()
    }
}

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
        sig_algs().supported_schemes()
    }
}

#[derive(Clone)]
pub struct AtmClient {
    base_url: String,
    agent: ureq::Agent,
}

impl AtmClient {
    /// Back-compat helper: `true` = Insecure, `false` = Strict.
    pub fn new(base_url: &str, insecure: bool) -> Result<Self, ClientError> {
        Self::with_tls(base_url, if insecure { TlsMode::Insecure } else { TlsMode::Strict })
    }

    pub fn with_tls(base_url: &str, tls: TlsMode) -> Result<Self, ClientError> {
        let clean_url = base_url.trim_end_matches('/').to_string();
        let mut builder = ureq::builder().timeout(Duration::from_secs(10));

        let verifier: Option<Arc<dyn rustls::client::danger::ServerCertVerifier>> = match tls {
            TlsMode::Strict => None,
            TlsMode::Insecure => Some(Arc::new(DangerAcceptAllVerifier)),
            TlsMode::Pinned(fp) => {
                if normalize_fingerprint(&fp).len() != 64 {
                    return Err(ClientError::Transport(
                        "pin must be a SHA-256 fingerprint (64 hex chars)".into(),
                    ));
                }
                Some(Arc::new(PinnedVerifier { pin: fp }))
            }
        };
        if let Some(v) = verifier {
            let config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(v)
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

    /// Operator action: credit the kiosk reserve for a verified inbound payment.
    /// The request body is authenticated with HMAC-SHA256(secret, body) and `reference`
    /// must be unique (a replay is rejected with HTTP 409).
    pub fn credit_reserve(&self, amount: f64, reference: &str, secret: &str) -> Result<f64, ClientError> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let url = format!("{}/v1/credit", self.base_url);
        let payload = CreditRequest {
            amount,
            reference: reference.to_string(),
        };
        let req_json = serde_json::to_string(&payload)
            .map_err(|e| ClientError::Serialization(e.to_string()))?;
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
            .map_err(|e| ClientError::Serialization(e.to_string()))?;
        mac.update(req_json.as_bytes());
        let sig = crate::crypto::hex_encode(&mac.finalize().into_bytes());

        let resp = match self
            .agent
            .post(&url)
            .set("Content-Type", "application/json")
            .set("X-Fupi-Signature", &sig)
            .send_string(&req_json)
        {
            Ok(r) => r,
            Err(ureq::Error::Status(code, resp)) => {
                return Err(ClientError::HttpStatus(code, resp.into_string().unwrap_or_default()));
            }
            Err(e) => return Err(ClientError::Transport(e.to_string())),
        };
        let resp_str = resp
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_normalisation_and_match() {
        use sha2::{Digest, Sha256};
        let der = b"fake-der-bytes";
        let hex = crate::crypto::hex_encode(&Sha256::digest(der));
        let upper_colon = hex
            .to_ascii_uppercase()
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(":");
        assert!(fingerprint_matches(der, &hex));
        assert!(fingerprint_matches(der, &upper_colon));
        assert!(!fingerprint_matches(b"other", &hex));
    }

    #[test]
    fn pin_must_be_full_sha256() {
        assert!(AtmClient::with_tls("https://127.0.0.1:1", TlsMode::Pinned("abcd".into())).is_err());
        assert!(AtmClient::with_tls("https://127.0.0.1:1", TlsMode::Pinned("ab".repeat(32))).is_ok());
    }
}
