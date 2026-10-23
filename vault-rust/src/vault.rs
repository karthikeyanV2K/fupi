use crate::client::{AtmClient, ClientError};
use crate::crypto::{
    b64_decode, b64_encode, b64_to_biguint, biguint_to_b64, blind, claim_signature,
    generate_locked_secret, generate_secret, hash_to_scalar, lock_of, random_blinder, unblind,
    verify, CryptoError,
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
        self.topup_locked(amount, None)
    }

    /// Check a keyset offered by the ATM against the one pinned in flash.
    /// First use pins (trust-on-first-use); after that ANY change is refused —
    /// a swapped mint key would otherwise let a MITM mint "your" money.
    /// Re-pinning is an explicit, separate action (`cache_keyset` / CLI `pin --force`).
    pub fn check_keyset_pin(pinned: Option<&Keyset>, offered: &Keyset) -> Result<(), VaultError> {
        if offered.e < 3 || offered.e % 2 == 0 {
            return Err(VaultError::VerificationFailed("keyset has an invalid public exponent".into()));
        }
        match pinned {
            None => Ok(()),
            Some(p) if p == offered => Ok(()),
            Some(p) if p.keyset_id != offered.keyset_id => Err(VaultError::KeysetMismatch {
                expected: p.keyset_id.clone(),
                actual: offered.keyset_id.clone(),
            }),
            Some(_) => Err(VaultError::VerificationFailed(
                "ATM keyset modulus changed since it was pinned; refusing. \
                 Verify the new fingerprint out-of-band, then run `pin --force`"
                    .into(),
            )),
        }
    }

    /// Like `topup`, but when `lock` (ed25519 public key hex) is given every new
    /// proof's secret is locked to that key: only its owner can settle it.
    pub fn topup_locked(&mut self, amount: usize, lock: Option<String>) -> Result<usize, VaultError> {
        if amount == 0 {
            return Ok(0);
        }
        let client = self.client.as_ref().ok_or(VaultError::NoClientConfigured)?;
        let keyset = client.get_keyset()?;
        Self::check_keyset_pin(self.state.trusted_keyset.as_ref(), &keyset)?;
        if self.state.trusted_keyset.is_none() {
            self.state.trusted_keyset = Some(keyset.clone());
            self.storage.save(&self.state)?;
        }
        let n = b64_to_biguint(&keyset.n)?;
        let e = BigUint::from(keyset.e);

        let mut loaded = 0;
        let mut rng = rand::rngs::OsRng;
        let mut topup_err = None;

        for _ in 0..amount {
            let secret = match lock.as_deref() {
                Some(pk) => generate_locked_secret(pk)?,
                None => generate_secret(),
            };
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

    /// Spend bearer proofs.
    ///
    /// With `lock = None` only UNLOCKED proofs are spent. With `lock = Some(pubkey_hex)`
    /// only proofs whose secret is locked to exactly that key are spent (the payee
    /// must then sign a claim with the matching key to settle). A lock can only be
    /// set at issuance (`topup --lock`), because it must be inside the blind-signed
    /// secret; it cannot be bolted on afterwards.
    ///
    /// The emitted token is stored in the `outbox` in the SAME atomic save that removes
    /// the proofs, so a lost screen/QR/terminal never destroys value.
    pub fn make_payment(&mut self, amount: usize, lock: Option<String>) -> Result<String, VaultError> {
        if amount == 0 {
            return Err(VaultError::InsufficientFunds {
                have: self.balance(),
                requested: 0,
            });
        }
        let want_lock: Option<[u8; 32]> = match lock.as_deref() {
            Some(hex) => Some(
                crate::crypto::hex_decode(hex)
                    .and_then(|b| b.try_into().ok())
                    .ok_or_else(|| CryptoError::InvalidLock("lock must be 32 bytes of hex".into()))?,
            ),
            None => None,
        };
        let mut idx = Vec::with_capacity(amount);
        for (i, p) in self.state.proofs.iter().enumerate() {
            if lock_of(&p.secret).ok().flatten() == want_lock {
                idx.push(i);
                if idx.len() == amount {
                    break;
                }
            }
        }
        if idx.len() < amount {
            return Err(VaultError::InsufficientFunds {
                have: idx.len(),
                requested: amount,
            });
        }

        let chosen: Vec<Proof> = idx.iter().map(|&i| self.state.proofs[i].clone()).collect();
        let json_bytes = serde_json::to_vec(&chosen)
            .map_err(|e| VaultError::InvalidToken(e.to_string()))?;
        let token_str = b64_encode(&json_bytes);

        // Mutate a copy, persist, and only then adopt it: on a failed save nothing is lost.
        let mut next = self.state.clone();
        for &i in idx.iter().rev() {
            next.proofs.remove(i);
        }
        next.outbox.push(token_str.clone());
        next.journal.push(format!("spent {} (balance {})", amount, next.proofs.len()));
        self.storage.save(&next)?;
        self.state = next;
        Ok(token_str)
    }

    /// Tokens emitted by `make_payment` and not yet acknowledged as delivered.
    pub fn outbox(&self) -> &[String] {
        &self.state.outbox
    }

    /// Drop an acknowledged token from the outbox (1-based index as shown by the CLI).
    pub fn ack_outbox(&mut self, index_1based: usize) -> Result<bool, VaultError> {
        if index_1based == 0 || index_1based > self.state.outbox.len() {
            return Ok(false);
        }
        self.state.outbox.remove(index_1based - 1);
        self.storage.save(&self.state)?;
        Ok(true)
    }

    /// Decode a base64 bearer token string into a list of Proofs.
    pub fn decode_token(token_str: &str) -> Result<Vec<Proof>, VaultError> {
        let json_bytes = b64_decode(token_str.trim())
            .map_err(|e| VaultError::InvalidToken(e.to_string()))?;
        let proofs: Vec<Proof> = serde_json::from_slice(&json_bytes)
            .map_err(|e| VaultError::InvalidToken(format!("JSON parse error: {e}")))?;
        Ok(proofs)
    }

    /// Receiver-side offline verification.
    ///
    /// SECURITY: the public key (n, e) comes ONLY from the pinned keyset, never from the
    /// token. A token may repeat n / e / keyset_id, but if it does they must equal the
    /// pinned ones. Without a pinned keyset nothing can be verified (refusing is the
    /// only safe answer: a token could carry its own key, or e=1, and "verify").
    pub fn verify_offline(
        token_str: &str,
        expected_keyset: Option<&Keyset>,
    ) -> Result<Vec<Proof>, VaultError> {
        let ks = expected_keyset.ok_or_else(|| {
            VaultError::VerificationFailed(
                "no pinned ATM keyset: refusing to trust key material from the token \
                 (run `pin` first)"
                    .into(),
            )
        })?;
        if ks.e < 3 || ks.e % 2 == 0 {
            return Err(VaultError::VerificationFailed("pinned keyset has an invalid exponent".into()));
        }
        let proofs = Self::decode_token(token_str)?;
        if proofs.is_empty() {
            return Err(VaultError::InvalidToken("Token contains 0 proofs".into()));
        }
        let n = b64_to_biguint(&ks.n)?;
        let e = BigUint::from(ks.e);

        for p in &proofs {
            if let Some(ref kid) = p.keyset_id {
                if kid != &ks.keyset_id {
                    return Err(VaultError::KeysetMismatch {
                        expected: ks.keyset_id.clone(),
                        actual: kid.clone(),
                    });
                }
            }
            if !p.n.is_empty() && p.n != ks.n {
                return Err(VaultError::VerificationFailed(
                    "Proof modulus does not match trusted ATM keyset (forgery detected)".into(),
                ));
            }
            if p.e != ks.e {
                return Err(VaultError::VerificationFailed(
                    "Proof exponent does not match trusted ATM keyset (forgery detected)".into(),
                ));
            }
            lock_of(&p.secret)?; // reject malformed locks early
            if p.secret.is_empty() || p.secret.len() > 256 {
                return Err(VaultError::InvalidToken("secret length out of range".into()));
            }

            let m = hash_to_scalar(p.secret.as_bytes(), &n);
            let sig = b64_to_biguint(&p.sig)?;
            if sig >= n || !verify(&m, &sig, &e, &n) {
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
    /// `claim_key` (ed25519 secret key hex) signs a claim for every locked proof; the
    /// ATM verifies it against the key embedded in the secret. Unlocked proofs ignore it.
    pub fn settle_token(
        &self,
        token_str: &str,
        claim_key: Option<String>,
    ) -> Result<Vec<(String, bool, String)>, VaultError> {
        let client = self.client.as_ref().ok_or(VaultError::NoClientConfigured)?;
        let mut proofs = Self::decode_token(token_str)?;
        let mut results = Vec::new();

        for p in &mut proofs {
            p.p2pk = None; // legacy unauthenticated label: never sent
            if let (Some(key), Some(_)) = (claim_key.as_deref(), lock_of(&p.secret)?) {
                p.claimer = Some(claim_signature(key, &p.secret)?);
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
