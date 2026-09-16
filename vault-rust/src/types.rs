use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Keyset {
    pub keyset_id: String,
    pub n: String,
    pub e: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    pub secret: String,
    pub sig: String,
    #[serde(default)]
    pub n: String,
    #[serde(default = "default_exponent")]
    pub e: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keyset_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p2pk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claimer: Option<String>,
}

fn default_exponent() -> u64 {
    65537
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtmInfo {
    pub name: String,
    pub version: String,
    pub keyset_id: String,
    pub reserve: f64,
    pub issued: i64,
    pub spent_count: usize,
    pub tls_enabled: bool,
    #[serde(default)]
    pub tls_fingerprint_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FlashState {
    pub proofs: Vec<Proof>,
    pub journal: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_keyset: Option<Keyset>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreditRequest {
    pub amount: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreditResponse {
    pub reserve: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlindSignRequest {
    pub blinded_message: String,
    pub amount: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlindSignResponse {
    pub blind_signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SettleResponse {
    pub result: String,
}
