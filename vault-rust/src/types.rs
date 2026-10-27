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
    /// Bearer tokens that were emitted by `pay` and not yet acknowledged.
    /// Written in the SAME atomic save that removes the proofs, so a lost
    /// terminal/QR never destroys money: `outbox` re-shows the token.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbox: Vec<String>,
    /// Every pinned ATM keyset (one per denomination). `trusted_keyset` above is the legacy
    /// single-keyset field, still read for state written by older versions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keysets: Vec<Keyset>,
    /// This vault's ed25519 device key (hex secret). The operator allocates quota to its
    /// public key, and every issuance request is signed with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_key: Option<String>,
    /// Last request sequence number used (strictly increasing; persisted BEFORE each request).
    #[serde(default)]
    pub device_seq: u64,
    /// A change-making swap that was started but not finished. Written before the request is
    /// sent, so after a crash the identical request can be re-sent and the kiosk returns the
    /// same signatures (the swap is idempotent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_swap: Option<PendingSwap>,
    /// Merchant mode: one receipt per accepted payment (kept after settlement as the audit log).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<Receipt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// 1-based, stable, never reused.
    pub id: u64,
    pub invoice: Option<String>,
    pub amount: u64,
    /// Secrets of the proofs this payment brought (settlement status is tracked per secret).
    pub secrets: Vec<String>,
    /// Unix seconds when accepted (0 if the device has no clock).
    pub ts: u64,
    pub settled: u64,
    pub rejected: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingOut {
    pub secret: String,
    /// Blinding factor r (base64url big-endian), needed to unblind the signature.
    pub r: String,
    pub blinded: String,
    pub amount: u64,
    pub keyset_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingSwap {
    pub inputs: Vec<Proof>,
    pub outputs: Vec<PendingOut>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreditRequest {
    pub amount: f64,
    /// Unique external payment reference (bank UTR / order id). Replays are rejected.
    #[serde(rename = "ref")]
    pub reference: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreditResponse {
    pub reserve: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlindSignRequest {
    pub blinded_message: String,
    /// Denomination of the proof being issued.
    pub amount: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_sig: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlindSignResponse {
    pub blind_signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SettleResponse {
    pub result: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AllocateRequest {
    pub device: String,
    pub amount: f64,
    #[serde(rename = "ref")]
    pub reference: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AllocateResponse {
    pub allocated: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapOut {
    pub blinded_message: String,
    pub amount: u64,
}

#[derive(Debug, Serialize)]
pub struct SwapRequest<'a> {
    pub inputs: &'a [Proof],
    pub outputs: Vec<SwapOut>,
}

#[derive(Debug, Deserialize)]
pub struct SwapResponse {
    pub signatures: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct KeysetsResponse {
    pub keysets: Vec<Keyset>,
}
