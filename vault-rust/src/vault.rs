use crate::client::{AtmClient, ClientError};
use crate::crypto::{
    b64_decode, b64_encode, b64_to_biguint, biguint_to_b64, blind, generate_secret,
    hash_to_scalar, random_blinder, unblind, verify, CryptoError,
};
use crate::storage::{FlashStorage, StorageError};
use crate::types::{FlashState, Keyset, Proof};
use num_bigint::BigUint;
use std::fmt;

#[derive(Debug)]
pub enum VaultError {
    InsufficientFunds { have: usize, requested: usize },
    Crypto(CryptoError),
    Storage(StorageError),
    Client(ClientError),
    NoClientConfigured,
    InvalidToken(String),
    VerificationFailed(String),
    KeysetMismatch { expected: String, actual: String },
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::InsufficientFunds { have, requested } => {
                write!(f, "Insufficient funds: have {have} proofs, requested {requested}")
            }
            VaultError::Crypto(e) => write!(f, "Cryptographic error: {e}"),
            VaultError::Storage(e) => write!(f, "Storage error: {e}"),
            VaultError::Client(e) => write!(f, "ATM Client error: {e}"),
            VaultError::NoClientConfigured => write!(f, "No ATM client configured for network action"),
            VaultError::InvalidToken(e) => write!(f, "Invalid bearer token string: {e}"),
            VaultError::VerificationFailed(e) => write!(f, "Proof verification failed: {e}"),
            VaultError::KeysetMismatch { expected, actual } => {
                write!(f, "Keyset mismatch: expected {expected}, got {actual}")
            }
        }
    }
}

impl std::error::Error for VaultError {}

impl From<CryptoError> for VaultError {
    fn from(e: CryptoError) -> Self {
        VaultError::Crypto(e)
    }
}

impl From<StorageError> for VaultError {
    fn from(e: StorageError) -> Self {
        VaultError::Storage(e)
    }
}

impl From<ClientError> for VaultError {
    fn from(e: ClientError) -> Self {
        VaultError::Client(e)
    }
}

pub struct Vault {
    storage: FlashStorage,
    state: FlashState,
    client: Option<AtmClient>,
}

impl Vault {
    pub fn new(storage: FlashStorage, client: Option<AtmClient>) -> Result<Self, VaultError> {
        let state = storage.load()?;
        Ok(Self {
            storage,
            state,
            client,
        })
    }

    pub fn set_client(&mut self, client: AtmClient) {
        self.client = Some(client);
    }

    pub fn client(&self) -> Option<&AtmClient> {
        self.client.as_ref()
    }

    pub fn trusted_keyset(&self) -> Option<&Keyset> {
        self.state.trusted_keyset.as_ref()
    }

    pub fn cache_keyset(&mut self, keyset: Keyset) -> Result<(), VaultError> {
        self.state.trusted_keyset = Some(keyset);
        self.storage.save(&self.state)?;
        Ok(())
    }

    pub fn balance(&self) -> usize {
        self.state.proofs.len()
    }

    pub fn proofs(&self) -> &[Proof] {
        &self.state.proofs
    }

    pub fn journal(&self) -> &[String] {
        &self.state.journal
    }

    pub fn storage_path(&self) -> &std::path::Path {
        self.storage.path()
    }

    /// Top-up withdrawal against ATM:
    /// For each requested token, generates a secret, blinds it, requests blind signature
    /// from the ATM, unblinds the signature, verifies on-chip, and stores in flash.
    /// Resilient: saves proofs after each token so unexpected drops never lose money.
    pub fn topup(&mut self, amount: usize) -> Result<usize, VaultError> {
        if amount == 0 {
            return Ok(0);
        }
        let client = self.client.as_ref().ok_or(VaultError::NoClientConfigured)?;
        let keyset = client.get_keyset()?;
        self.state.trusted_keyset = Some(keyset.clone());
        let n = b64_to_biguint(&keyset.n)?;
        let e = BigUint::from(keyset.e);

        let mut loaded = 0;
        let mut rng = rand::rngs::OsRng;
        let mut topup_err = None;

        for _ in 0..amount {
            let secret = generate_secret();
            let m = hash_to_scalar(secret.as_bytes(), &n);
            let r = random_blinder(&mut rng, &n);
            let m_blind = blind(&m, &r, &e, &n);

            let blinded_b64 = biguint_to_b64(&m_blind);
            let sig_blind_b64 = match client.blind_sign(&blinded_b64, 1) {
                Ok(s) => s,
                Err(e) => {
                    topup_err = Some(VaultError::Client(e));
                    break;
                }
            };

            let s_blind = match b64_to_biguint(&sig_blind_b64) {
                Ok(s) => s,
                Err(e) => {
                    topup_err = Some(VaultError::Crypto(e));
                    break;
                }
            };
            let sig = match unblind(&s_blind, &r, &n) {
                Ok(s) => s,
                Err(e) => {
                    topup_err = Some(VaultError::Crypto(e));
                    break;
                }
            };

            // Critical: on-chip verification before accepting into vault
            if !verify(&m, &sig, &e, &n) {
                topup_err = Some(VaultError::VerificationFailed(
                    "ATM blind signature failed local on-chip RSA check".into(),
                ));
                break;
            }

            let proof = Proof {
                secret,
                sig: biguint_to_b64(&sig),
                n: keyset.n.clone(),
                e: keyset.e,
                keyset_id: Some(keyset.keyset_id.clone()),
                p2pk: None,
                claimer: None,
            };

            self.state.proofs.push(proof);
            loaded += 1;
            // Immediate atomic persistence protects money against mid-topup failure
            self.storage.save(&self.state)?;
        }

        if loaded > 0 {
            self.state.journal.push(format!(
                "topup +{} (balance {})",
                loaded,
                self.state.proofs.len()
            ));
            self.storage.save(&self.state)?;
        }

        if let Some(err) = topup_err {
            return Err(err);
        }

        Ok(loaded)
    }

    /// Spend bearer proofs:
    /// Takes `amount` proofs out of the vault, optionally attaches a P2PK lock,
    /// and serializes them into a bearer token (Base64 URL-safe JSON).
    /// Once emitted, the tokens leave the vault permanently.
    pub fn make_payment(&mut self, amount: usize, p2pk: Option<String>) -> Result<String, VaultError> {
        if amount == 0 {
            return Err(VaultError::InsufficientFunds {
                have: self.balance(),
                requested: 0,
            });
        }
        if self.balance() < amount {
            return Err(VaultError::InsufficientFunds {
                have: self.balance(),
                requested: amount,
            });
        }

        let mut chosen: Vec<Proof> = self.state.proofs.drain(..amount).collect();
        if let Some(ref lock) = p2pk {
            for p in &mut chosen {
                p.p2pk = Some(lock.clone());
            }
        }

        let json_bytes = serde_json::to_vec(&chosen)
            .map_err(|e| VaultError::InvalidToken(e.to_string()))?;
        let token_str = b64_encode(&json_bytes);

        self.state.journal.push(format!(
            "spent {} (balance {})",
            amount,
            self.state.proofs.len()
        ));
        self.storage.save(&self.state)?;
        Ok(token_str)
    }

    /// Decode a base64 bearer token string into a list of Proofs.
    pub fn decode_token(token_str: &str) -> Result<Vec<Proof>, VaultError> {
        let json_bytes = b64_decode(token_str.trim())
            .map_err(|e| VaultError::InvalidToken(e.to_string()))?;
        let proofs: Vec<Proof> = serde_json::from_slice(&json_bytes)
            .map_err(|e| VaultError::InvalidToken(format!("JSON parse error: {e}")))?;
        Ok(proofs)
    }

    /// Receiver-side offline verification:
    /// Decodes bearer token and verifies each proof against the keyset locally.
    /// ZERO network required — the receiver knows the money is authentic instantly.
    /// Enforces trusted keyset verification so forged tokens cannot fabricate a custom modulus.
    pub fn verify_offline(
        token_str: &str,
        expected_keyset: Option<&Keyset>,
    ) -> Result<Vec<Proof>, VaultError> {
        let proofs = Self::decode_token(token_str)?;
        if proofs.is_empty() {
            return Err(VaultError::InvalidToken("Token contains 0 proofs".into()));
        }

        for p in &proofs {
            if let Some(ks) = expected_keyset {
                if let Some(ref kid) = p.keyset_id {
                    if kid != &ks.keyset_id {
                        return Err(VaultError::KeysetMismatch {
                            expected: ks.keyset_id.clone(),
                            actual: kid.clone(),
                        });
                    }
                }
                // Modulus check against trusted ATM keyset (blocks forged modulus attack)
                if !p.n.is_empty() && p.n != ks.n {
                    return Err(VaultError::VerificationFailed(
                        "Proof modulus does not match trusted ATM keyset (forgery detected)".into(),
                    ));
                }
            }

            let n_str = if let Some(ks) = expected_keyset {
                &ks.n
            } else if !p.n.is_empty() {
                &p.n
            } else {
                return Err(VaultError::InvalidToken("Proof missing modulus N".into()));
            };

            let n = b64_to_biguint(n_str)?;
            let e = BigUint::from(p.e);
            let m = hash_to_scalar(p.secret.as_bytes(), &n);
            let sig = b64_to_biguint(&p.sig)?;

            if !verify(&m, &sig, &e, &n) {
                return Err(VaultError::VerificationFailed(format!(
                    "Proof for secret '{}' signature is invalid",
                    p.secret
                )));
            }
        }

        Ok(proofs)
    }

    /// Verify a token against the vault's cached keyset.
    pub fn verify_token(&self, token_str: &str) -> Result<Vec<Proof>, VaultError> {
        Self::verify_offline(token_str, self.state.trusted_keyset.as_ref())
    }

    /// Receive bearer proofs into the vault offline (peer-to-peer cash receipt).
    /// Validates signatures offline against trusted keyset, checks for duplicates,
    /// adds proofs to flash balance, and writes atomically.
    pub fn receive_token(
        &mut self,
        token_str: &str,
        expected_keyset: Option<&Keyset>,
    ) -> Result<usize, VaultError> {
        let target_keyset = expected_keyset.or(self.state.trusted_keyset.as_ref());
        let verified = Self::verify_offline(token_str, target_keyset)?;

        let mut received = 0;
        for p in verified {
            if self.state.proofs.iter().any(|existing| existing.secret == p.secret) {
                continue; // Skip duplicate secret
            }
            self.state.proofs.push(p);
            received += 1;
        }

        if received == 0 {
            return Err(VaultError::InvalidToken(
                "All proofs in token were duplicates of existing vault proofs".into(),
            ));
        }

        self.state.journal.push(format!(
            "received +{} (balance {})",
            received,
            self.state.proofs.len()
        ));
        self.storage.save(&self.state)?;
        Ok(received)
    }

    /// Settle bearer proofs at the ATM over HTTPS.
    /// Can settle received tokens directly into cash or another rail.
    pub fn settle_token(
        &self,
        token_str: &str,
        claimer: Option<String>,
    ) -> Result<Vec<(String, bool, String)>, VaultError> {
        let client = self.client.as_ref().ok_or(VaultError::NoClientConfigured)?;
        let mut proofs = Self::decode_token(token_str)?;
        let mut results = Vec::new();

        for p in &mut proofs {
            if claimer.is_some() {
                p.claimer = claimer.clone();
            }
            let (ok, msg) = client.settle(p)?;
            results.push((p.secret.clone(), ok, msg));
        }

        Ok(results)
    }

    /// Complete vault wipe (e.g. tamper detection / duress).
    pub fn wipe(&mut self) -> Result<(), VaultError> {
        self.state.proofs.clear();
        self.state.journal.clear();
        self.storage.wipe()?;
        Ok(())
    }
}
