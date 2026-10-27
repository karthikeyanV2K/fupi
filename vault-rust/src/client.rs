use crate::types::{
    AllocateRequest, AllocateResponse, AtmInfo, BlindSignRequest, BlindSignResponse,
    CreditRequest, CreditResponse, Keyset, KeysetsResponse, Proof, SettleResponse, SwapOut,
    SwapRequest, SwapResponse,
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

    fn post_json(&self, path: &str, body: &str, signature: Option<&str>) -> Result<String, ClientError> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.agent.post(&url).set("Content-Type", "application/json");
        if let Some(sig) = signature {
            req = req.set("X-Fupi-Signature", sig);
        }
        match req.send_string(body) {
            Ok(r) => r
                .into_string()
                .map_err(|e| ClientError::Transport(e.to_string())),
            Err(ureq::Error::Status(code, resp)) => {
                Err(ClientError::HttpStatus(code, resp.into_string().unwrap_or_default()))
            }
            Err(e) => Err(ClientError::Transport(e.to_string())),
        }
    }

    fn hmac_hex(secret: &str, body: &str) -> Result<String, ClientError> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
            .map_err(|e| ClientError::Serialization(e.to_string()))?;
        mac.update(body.as_bytes());
        Ok(crate::crypto::hex_encode(&mac.finalize().into_bytes()))
    }

    /// Operator action: credit the kiosk reserve for a verified inbound payment.
    /// The request body is authenticated with HMAC-SHA256(secret, body) and `reference`
    /// must be unique (a replay is rejected with HTTP 409).
    pub fn credit_reserve(&self, amount: f64, reference: &str, secret: &str) -> Result<f64, ClientError> {
        let body = serde_json::to_string(&CreditRequest {
            amount,
            reference: reference.to_string(),
        })
        .map_err(|e| ClientError::Serialization(e.to_string()))?;
        let sig = Self::hmac_hex(secret, &body)?;
        let resp = self.post_json("/v1/credit", &body, Some(&sig))?;
        let res: CreditResponse = serde_json::from_str(&resp)
            .map_err(|e| ClientError::Serialization(e.to_string()))?;
        Ok(res.reserve)
    }

    /// Operator action: give a device (ed25519 public key hex) issuance quota.
    pub fn allocate(&self, device: &str, amount: f64, reference: &str, secret: &str) -> Result<f64, ClientError> {
        let body = serde_json::to_string(&AllocateRequest {
            device: device.to_string(),
            amount,
            reference: reference.to_string(),
        })
        .map_err(|e| ClientError::Serialization(e.to_string()))?;
        let sig = Self::hmac_hex(secret, &body)?;
        let resp = self.post_json("/v1/allocate", &body, Some(&sig))?;
        let res: AllocateResponse = serde_json::from_str(&resp)
            .map_err(|e| ClientError::Serialization(e.to_string()))?;
        Ok(res.allocated)
    }

    /// Public keys of every denomination the kiosk signs.
    pub fn get_keysets(&self) -> Result<Vec<Keyset>, ClientError> {
        let url = format!("{}/v1/keysets", self.base_url);
        let resp = self
            .agent
            .get(&url)
            .call()
            .map_err(|e| ClientError::Transport(e.to_string()))?
            .into_string()
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        let r: KeysetsResponse = serde_json::from_str(&resp)
            .map_err(|e| ClientError::Serialization(e.to_string()))?;
        Ok(r.keysets)
    }

    /// Ask for one proof of `denomination`, authenticated by this device's signature.
    pub fn blind_sign_device(
        &self,
        blinded_b64: &str,
        denomination: u32,
        device: &str,
        seq: u64,
        device_sig: &str,
    ) -> Result<String, ClientError> {
        let body = serde_json::to_string(&BlindSignRequest {
            blinded_message: blinded_b64.to_string(),
            amount: denomination,
            device: Some(device.to_string()),
            seq: Some(seq),
            device_sig: Some(device_sig.to_string()),
        })
        .map_err(|e| ClientError::Serialization(e.to_string()))?;
        let resp = self.post_json("/v1/blind-sign", &body, None)?;
        let r: BlindSignResponse = serde_json::from_str(&resp)
            .map_err(|e| ClientError::Serialization(e.to_string()))?;
        Ok(r.blind_signature)
    }

    /// Exchange proofs for fresh blind-signed ones of equal total value. Idempotent on the
    /// kiosk: re-sending the identical request returns the same signatures.
    pub fn swap(&self, inputs: &[Proof], outputs: &[(String, u64)]) -> Result<Vec<String>, ClientError> {
        let body = serde_json::to_string(&SwapRequest {
            inputs,
            outputs: outputs
                .iter()
                .map(|(b, a)| SwapOut { blinded_message: b.clone(), amount: *a })
                .collect(),
        })
        .map_err(|e| ClientError::Serialization(e.to_string()))?;
        let resp = self.post_json("/v1/swap", &body, None)?;
        let r: SwapResponse = serde_json::from_str(&resp)
            .map_err(|e| ClientError::Serialization(e.to_string()))?;
        Ok(r.signatures)
    }

    pub fn blind_sign(&self, blinded_b64: &str, amount: u32) -> Result<String, ClientError> {
        let url = format!("{}/v1/blind-sign", self.base_url);
        let payload = BlindSignRequest {
            blinded_message: blinded_b64.to_string(),
            amount,
            device: None,
            seq: None,
            device_sig: None,
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
        self.settle_as(proof, None)
    }

    /// Settle, naming the payee (`X-Fupi-Merchant`). The label only says who the operator
    /// should pay; it is not authenticated and gives no claim on the money.
    pub fn settle_as(&self, proof: &Proof, merchant: Option<&str>) -> Result<(bool, String), ClientError> {
        let url = format!("{}/v1/settle", self.base_url);
        let req_json = serde_json::to_string(proof)
            .map_err(|e| ClientError::Serialization(e.to_string()))?;

        let mut req = self.agent.post(&url).set("Content-Type", "application/json");
        if let Some(m) = merchant {
            req = req.set("X-Fupi-Merchant", m);
        }
        match req.send_string(&req_json) {
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

    /// Operator report: settlement log since `since` plus every merchant's owed balance.
    /// The HMAC covers the request URI (a GET has no body).
    pub fn settlements(
        &self,
        since: u64,
        merchant: Option<&str>,
        secret: &str,
    ) -> Result<serde_json::Value, ClientError> {
        let mut uri = format!("/v1/settlements?since={since}");
        if let Some(m) = merchant {
            uri.push_str(&format!("&merchant={m}"));
        }
        let sig = Self::hmac_hex(secret, &uri)?;
        match self
            .agent
            .get(&format!("{}{}", self.base_url, uri))
            .set("X-Fupi-Signature", &sig)
            .call()
        {
            Ok(r) => {
                let body = r.into_string().map_err(|e| ClientError::Transport(e.to_string()))?;
                serde_json::from_str(&body).map_err(|e| ClientError::Serialization(e.to_string()))
            }
            Err(ureq::Error::Status(code, resp)) => {
                Err(ClientError::HttpStatus(code, resp.into_string().unwrap_or_default()))
            }
            Err(e) => Err(ClientError::Transport(e.to_string())),
        }
    }

    /// Operator action: record a bank payout to a merchant (lowers what they are owed).
    pub fn payout(
        &self,
        merchant: &str,
        amount: u64,
        reference: &str,
        secret: &str,
    ) -> Result<serde_json::Value, ClientError> {
        let body = serde_json::json!({"merchant": merchant, "amount": amount, "ref": reference}).to_string();
        let sig = Self::hmac_hex(secret, &body)?;
        let resp = self.post_json("/v1/payout", &body, Some(&sig))?;
        serde_json::from_str(&resp).map_err(|e| ClientError::Serialization(e.to_string()))
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
