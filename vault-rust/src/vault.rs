use crate::client::{AtmClient, ClientError};
use crate::crypto::{
    b64_decode, b64_encode, b64_to_biguint, biguint_to_b64, blind, claim_signature,
    device_sign_message, generate_claim_keypair, generate_locked_secret, generate_secret,
    hash_to_scalar, lock_of, public_key_of, random_blinder, sign_bytes, unblind, verify,
    CryptoError,
};
use crate::denom::{denomination_of, exact_subset, keyset_id_for, proof_value, split_amount, MAX_EXACT_TARGET};
use crate::storage::{FlashStorage, StorageError};
use crate::types::{FlashState, Keyset, PendingOut, PendingSwap, Proof};
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
    /// The vault holds enough value but not in coins that add up to the amount.
    NeedChange { requested: usize, have: usize },
    UnsupportedAmount(String),
    /// A change-making swap was started and not finished. Run `recover`.
    SwapPending(String),
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
            VaultError::NeedChange { requested, have } => write!(
                f,
                "Cannot pay exactly {requested}: holding {have} but not in coins that add up (change needed)"
            ),
            VaultError::UnsupportedAmount(m) => write!(f, "Unsupported amount: {m}"),
            VaultError::SwapPending(m) => write!(
                f,
                "A change-making swap is unfinished ({m}). Run `recover` (or `recover --abandon` \
                 if the ATM refused it)"
            ),
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

    /// Pin (or replace) one keyset. Also keeps the legacy single-keyset field in step.
    pub fn cache_keyset(&mut self, keyset: Keyset) -> Result<(), VaultError> {
        Self::upsert(&mut self.state.keysets, keyset.clone());
        self.state.trusted_keyset = Some(keyset);
        self.storage.save(&self.state)?;
        Ok(())
    }

    /// Pin (or replace) a whole set of denomination keysets.
    pub fn cache_keysets(&mut self, keysets: &[Keyset]) -> Result<(), VaultError> {
        for k in keysets {
            Self::upsert(&mut self.state.keysets, k.clone());
            if k.keyset_id == crate::denom::LEGACY_KEYSET_ID {
                self.state.trusted_keyset = Some(k.clone());
            }
        }
        self.storage.save(&self.state)?;
        Ok(())
    }

    fn upsert(list: &mut Vec<Keyset>, k: Keyset) {
        match list.iter_mut().find(|x| x.keyset_id == k.keyset_id) {
            Some(slot) => *slot = k,
            None => list.push(k),
        }
    }

    /// Every pinned keyset (new multi-denomination list plus the legacy single field).
    pub fn pinned_keysets(&self) -> Vec<Keyset> {
        let mut v = self.state.keysets.clone();
        if let Some(t) = &self.state.trusted_keyset {
            if !v.iter().any(|k| k.keyset_id == t.keyset_id) {
                v.push(t.clone());
            }
        }
        v
    }

    /// Spendable value (sum of face values), not the number of proofs.
    pub fn balance(&self) -> usize {
        self.state.proofs.iter().map(|p| proof_value(p) as usize).sum()
    }

    pub fn proof_count(&self) -> usize {
        self.state.proofs.len()
    }

    /// (denomination, count) pairs, largest first.
    pub fn breakdown(&self) -> Vec<(u64, usize)> {
        let mut m: std::collections::BTreeMap<u64, usize> = Default::default();
        for p in &self.state.proofs {
            *m.entry(proof_value(p)).or_default() += 1;
        }
        m.into_iter().rev().collect()
    }

    /// This vault's device public key (hex). Generated and persisted on first use.
    pub fn device_public_key(&mut self) -> Result<String, VaultError> {
        if self.state.device_key.is_none() {
            let (sk, _pk) = generate_claim_keypair();
            self.state.device_key = Some(sk);
            self.storage.save(&self.state)?;
        }
        Ok(public_key_of(self.state.device_key.as_deref().unwrap_or_default())?)
    }

    /// Fetch every denomination keyset (falls back to the single legacy key on old kiosks).
    pub fn fetch_keysets(&self) -> Result<Vec<Keyset>, VaultError> {
        let c = self.client.as_ref().ok_or(VaultError::NoClientConfigured)?;
        match c.get_keysets() {
            Ok(v) if !v.is_empty() => Ok(v),
            _ => Ok(vec![c.get_keyset()?]),
        }
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

    /// Withdraw `amount` of value as denominated proofs. Returns (value, proofs loaded).
    pub fn topup(&mut self, amount: usize) -> Result<(usize, usize), VaultError> {
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

    /// Check the whole offered keyset list against the pinned list. Known ids must be
    /// unchanged; ids not pinned yet are accepted only when nothing is pinned (first use) or
    /// `allow_new` is set (an explicit `pin --force`).
    pub fn check_keyset_set(
        pinned: &[Keyset],
        offered: &[Keyset],
        allow_new: bool,
    ) -> Result<(), VaultError> {
        if offered.is_empty() {
            return Err(VaultError::VerificationFailed("ATM offered no keysets".into()));
        }
        for o in offered {
            match pinned.iter().find(|p| p.keyset_id == o.keyset_id) {
                Some(p) => Self::check_keyset_pin(Some(p), o)?,
                None => {
                    Self::check_keyset_pin(None, o)?;
                    if !pinned.is_empty() && !allow_new {
                        return Err(VaultError::VerificationFailed(format!(
                            "ATM offered keyset '{}' that is not pinned; verify it out-of-band, \
                             then run `pin --force`",
                            o.keyset_id
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    /// Like `topup`, but when `lock` (ed25519 public key hex) is given every new proof's
    /// secret is locked to that key: only its owner can settle it.
    ///
    /// `amount` is split into the ATM's denominations. Each proof is requested with a
    /// request signed by this vault's device key and a strictly increasing sequence number
    /// (persisted BEFORE the request is sent), so the ATM can enforce a per-device quota.
    /// Returns (value loaded, proofs loaded). Every proof is persisted as it arrives.
    pub fn topup_locked(&mut self, amount: usize, lock: Option<String>) -> Result<(usize, usize), VaultError> {
        if amount == 0 {
            return Ok((0, 0));
        }
        self.recover()?;
        let offered = self.fetch_keysets()?;
        let pinned = self.pinned_keysets();
        Self::check_keyset_set(&pinned, &offered, false)?;
        if pinned.is_empty() {
            self.cache_keysets(&offered)?;
        }
        let avail: Vec<u64> = offered.iter().filter_map(|k| denomination_of(&k.keyset_id)).collect();
        let plan = split_amount(amount as u64, &avail)
            .ok_or_else(|| VaultError::UnsupportedAmount(format!("{amount} cannot be made from the ATM's denominations")))?;

        let device = self.device_public_key()?;
        let device_sk = self.state.device_key.clone().unwrap_or_default();
        let client = self.client.as_ref().ok_or(VaultError::NoClientConfigured)?;

        let mut loaded_value = 0usize;
        let mut loaded = 0usize;
        let mut rng = rand::rngs::OsRng;
        let mut topup_err = None;

        for d in plan {
            let kid = keyset_id_for(d);
            let keyset = match offered.iter().find(|k| k.keyset_id == kid) {
                Some(k) => k,
                None => {
                    topup_err = Some(VaultError::KeysetMismatch { expected: kid, actual: "(not offered)".into() });
                    break;
                }
            };
            let n = b64_to_biguint(&keyset.n)?;
            let e = BigUint::from(keyset.e);
            let secret = match lock.as_deref() {
                Some(pk) => generate_locked_secret(pk)?,
                None => generate_secret(),
            };
            let m = hash_to_scalar(secret.as_bytes(), &n);
            let r = random_blinder(&mut rng, &n);
            let blinded_b64 = biguint_to_b64(&blind(&m, &r, &e, &n));

            // Burn the sequence number on disk first: a crash can waste one, never reuse one.
            self.state.device_seq += 1;
            self.storage.save(&self.state)?;
            let seq = self.state.device_seq;
            let msg = device_sign_message(&device, seq, d, &blinded_b64);
            let dsig = sign_bytes(&device_sk, msg.as_bytes())?;

            let sig_blind_b64 = match client.blind_sign_device(&blinded_b64, d as u32, &device, seq, &dsig) {
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
            // Critical: on-chip verification before accepting into the vault.
            if !verify(&m, &sig, &e, &n) {
                topup_err = Some(VaultError::VerificationFailed(
                    "ATM blind signature failed local RSA check".into(),
                ));
                break;
            }
            self.state.proofs.push(Proof {
                secret,
                sig: biguint_to_b64(&sig),
                n: keyset.n.clone(),
                e: keyset.e,
                keyset_id: Some(keyset.keyset_id.clone()),
                p2pk: None,
                claimer: None,
            });
            loaded += 1;
            loaded_value += d as usize;
            self.storage.save(&self.state)?;
        }

        if loaded > 0 {
            self.state.journal.push(format!(
                "topup +{loaded_value} in {loaded} proofs (balance {})",
                self.balance()
            ));
            self.storage.save(&self.state)?;
        }
        match topup_err {
            Some(err) => Err(err),
            None => Ok((loaded_value, loaded)),
        }
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
        if amount as u64 > MAX_EXACT_TARGET {
            return Err(VaultError::UnsupportedAmount(format!("{amount} is above the per-payment limit")));
        }
        // (index, face value) of every proof carrying exactly the wanted lock, largest first.
        let mut cand: Vec<(usize, u64)> = self
            .state
            .proofs
            .iter()
            .enumerate()
            .filter(|(_, p)| lock_of(&p.secret).ok().flatten() == want_lock)
            .map(|(i, p)| (i, proof_value(p)))
            .collect();
        let total: u64 = cand.iter().map(|c| c.1).sum();
        if total < amount as u64 {
            return Err(VaultError::InsufficientFunds { have: total as usize, requested: amount });
        }
        cand.sort_by(|a, b| b.1.cmp(&a.1));
        let vals: Vec<u64> = cand.iter().map(|c| c.1).collect();
        let pick = exact_subset(&vals, amount as u64)
            .ok_or(VaultError::NeedChange { requested: amount, have: total as usize })?;
        let mut idx: Vec<usize> = pick.iter().map(|&j| cand[j].0).collect();
        idx.sort_unstable();

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

    /// Pay exactly `amount`. If the coins do not add up (and the payment is unlocked) the
    /// vault first makes change through the ATM (`/v1/swap`), then pays.
    pub fn pay(&mut self, amount: usize, lock: Option<String>) -> Result<String, VaultError> {
        self.recover()?;
        match self.make_payment(amount, lock.clone()) {
            Err(VaultError::NeedChange { .. }) if lock.is_none() => {
                self.make_change(amount)?;
                self.make_payment(amount, None)
            }
            other => other,
        }
    }

    /// Exchange unlocked proofs for fresh ones so that exactly `amount` can be paid.
    ///
    /// Write-ahead: the inputs, the new secrets and the blinding factors are saved in
    /// `pending_swap` (and the inputs removed from the spendable set) BEFORE the request is
    /// sent. The ATM's swap is idempotent, so after a crash `recover` re-sends the identical
    /// request and gets the same signatures: nothing is lost and nothing can be spent twice.
    pub fn make_change(&mut self, amount: usize) -> Result<(), VaultError> {
        if self.client.is_none() {
            return Err(VaultError::NoClientConfigured);
        }
        let pinned = self.pinned_keysets();
        let avail: Vec<u64> = pinned.iter().filter_map(|k| denomination_of(&k.keyset_id)).collect();
        let target = amount as u64;

        let mut cand: Vec<(usize, u64)> = self
            .state
            .proofs
            .iter()
            .enumerate()
            .filter(|(_, p)| lock_of(&p.secret).ok().flatten().is_none())
            .map(|(i, p)| (i, proof_value(p)))
            .collect();
        let total_have: u64 = cand.iter().map(|c| c.1).sum();
        if total_have < target {
            return Err(VaultError::InsufficientFunds { have: total_have as usize, requested: amount });
        }
        cand.sort_by_key(|c| c.1); // ascending
        let mut chosen: Vec<usize> = Vec::new(); // positions in `cand`
        if let Some(pos) = cand.iter().position(|c| c.1 > target) {
            chosen.push(pos); // smallest single coin that covers it
        } else {
            let mut sum = 0;
            for pos in (0..cand.len()).rev() {
                chosen.push(pos);
                sum += cand[pos].1;
                if sum >= target {
                    break;
                }
            }
        }
        let in_total: u64 = chosen.iter().map(|&p| cand[p].1).sum();
        let mut amounts = split_amount(target, &avail)
            .ok_or_else(|| VaultError::UnsupportedAmount(format!("{amount} cannot be made from pinned denominations")))?;
        if in_total > target {
            amounts.extend(
                split_amount(in_total - target, &avail)
                    .ok_or_else(|| VaultError::UnsupportedAmount("change cannot be made from pinned denominations".into()))?,
            );
        }

        let mut rng = rand::rngs::OsRng;
        let mut outputs = Vec::with_capacity(amounts.len());
        for d in amounts {
            let kid = keyset_id_for(d);
            let ks = pinned
                .iter()
                .find(|k| k.keyset_id == kid)
                .ok_or_else(|| VaultError::KeysetMismatch { expected: kid.clone(), actual: "(not pinned)".into() })?;
            let n = b64_to_biguint(&ks.n)?;
            let e = BigUint::from(ks.e);
            let secret = generate_secret();
            let m = hash_to_scalar(secret.as_bytes(), &n);
            let r = random_blinder(&mut rng, &n);
            outputs.push(PendingOut {
                blinded: biguint_to_b64(&blind(&m, &r, &e, &n)),
                r: biguint_to_b64(&r),
                secret,
                amount: d,
                keyset_id: kid,
            });
        }

        let mut idx: Vec<usize> = chosen.iter().map(|&p| cand[p].0).collect();
        idx.sort_unstable();
        let inputs: Vec<Proof> = idx.iter().map(|&i| self.state.proofs[i].clone()).collect();
        let mut next = self.state.clone();
        for &i in idx.iter().rev() {
            next.proofs.remove(i);
        }
        next.pending_swap = Some(PendingSwap { inputs, outputs });
        self.storage.save(&next)?;
        self.state = next;
        self.complete_pending_swap(true)
    }

    fn complete_pending_swap(&mut self, first_attempt: bool) -> Result<(), VaultError> {
        let pending = match self.state.pending_swap.clone() {
            Some(p) => p,
            None => return Ok(()),
        };
        let client = self.client.as_ref().ok_or(VaultError::NoClientConfigured)?;
        let outs: Vec<(String, u64)> = pending.outputs.iter().map(|o| (o.blinded.clone(), o.amount)).collect();
        let sigs = match client.swap(&pending.inputs, &outs) {
            Ok(s) => s,
            Err(ClientError::HttpStatus(code, body)) if first_attempt => {
                // The ATM answered and refused the first send: nothing was exchanged.
                self.abandon_pending()?;
                return Err(VaultError::Client(ClientError::HttpStatus(code, body)));
            }
            Err(e) => return Err(VaultError::SwapPending(e.to_string())),
        };
        if sigs.len() != pending.outputs.len() {
            return Err(VaultError::SwapPending("ATM returned the wrong number of signatures".into()));
        }
        let pinned = self.pinned_keysets();
        let mut fresh = Vec::with_capacity(sigs.len());
        for (o, sb) in pending.outputs.iter().zip(sigs.iter()) {
            let ks = pinned
                .iter()
                .find(|k| k.keyset_id == o.keyset_id)
                .ok_or_else(|| VaultError::KeysetMismatch { expected: o.keyset_id.clone(), actual: "(not pinned)".into() })?;
            let n = b64_to_biguint(&ks.n)?;
            let e = BigUint::from(ks.e);
            let r = b64_to_biguint(&o.r)?;
            let sig = unblind(&b64_to_biguint(sb)?, &r, &n)?;
            let m = hash_to_scalar(o.secret.as_bytes(), &n);
            if !verify(&m, &sig, &e, &n) {
                return Err(VaultError::VerificationFailed("swap signature failed local RSA check".into()));
            }
            fresh.push(Proof {
                secret: o.secret.clone(),
                sig: biguint_to_b64(&sig),
                n: ks.n.clone(),
                e: ks.e,
                keyset_id: Some(ks.keyset_id.clone()),
                p2pk: None,
                claimer: None,
            });
        }
        let mut next = self.state.clone();
        let value: u64 = pending.outputs.iter().map(|o| o.amount).sum();
        next.proofs.extend(fresh);
        next.pending_swap = None;
        next.journal.push(format!("swap {value} into {} proofs", pending.outputs.len()));
        self.storage.save(&next)?;
        self.state = next;
        Ok(())
    }

    /// Finish an interrupted swap (idempotent). Returns whether there was one.
    pub fn recover(&mut self) -> Result<bool, VaultError> {
        if self.state.pending_swap.is_none() {
            return Ok(false);
        }
        self.complete_pending_swap(false)?;
        Ok(true)
    }

    pub fn has_pending_swap(&self) -> bool {
        self.state.pending_swap.is_some()
    }

    /// Give up on an unfinished swap and put its input proofs back (only safe when the ATM
    /// has refused the swap; if it may have executed, the inputs are already spent).
    pub fn abandon_pending(&mut self) -> Result<bool, VaultError> {
        let mut next = self.state.clone();
        match next.pending_swap.take() {
            None => Ok(false),
            Some(p) => {
                next.proofs.extend(p.inputs);
                next.journal.push("swap abandoned; inputs restored".into());
                self.storage.save(&next)?;
                self.state = next;
                Ok(true)
            }
        }
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
        match expected_keyset {
            Some(k) => Self::verify_offline_set(token_str, std::slice::from_ref(k)),
            None => Self::verify_offline_set(token_str, &[]),
        }
    }

    /// Verify against a set of pinned keysets (one per denomination). Each proof is checked
    /// with the pinned key named by its `keyset_id`; a proof naming no pinned key is refused.
    pub fn verify_offline_set(token_str: &str, keysets: &[Keyset]) -> Result<Vec<Proof>, VaultError> {
        if keysets.is_empty() {
            return Err(VaultError::VerificationFailed(
                "no pinned ATM keyset: refusing to trust key material from the token \
                 (run `pin` first)"
                    .into(),
            ));
        }
        if keysets.iter().any(|k| k.e < 3 || k.e % 2 == 0) {
            return Err(VaultError::VerificationFailed("pinned keyset has an invalid exponent".into()));
        }
        let proofs = Self::decode_token(token_str)?;
        if proofs.is_empty() {
            return Err(VaultError::InvalidToken("Token contains 0 proofs".into()));
        }
        for p in &proofs {
            let ks = match &p.keyset_id {
                Some(kid) => keysets.iter().find(|k| &k.keyset_id == kid).ok_or_else(|| {
                    VaultError::KeysetMismatch { expected: keysets[0].keyset_id.clone(), actual: kid.clone() }
                })?,
                None if keysets.len() == 1 => &keysets[0],
                None => {
                    return Err(VaultError::VerificationFailed("proof names no keyset".into()));
                }
            };
            let n = b64_to_biguint(&ks.n)?;
            let e = BigUint::from(ks.e);
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
        Self::verify_offline_set(token_str, &self.pinned_keysets())
    }

    /// Receive bearer proofs into the vault offline (peer-to-peer cash receipt).
    /// Validates signatures offline against trusted keyset, checks for duplicates,
    /// adds proofs to flash balance, and writes atomically.
    pub fn receive_token(
        &mut self,
        token_str: &str,
        expected_keyset: Option<&Keyset>,
    ) -> Result<usize, VaultError> {
        let verified = match expected_keyset {
            Some(k) => Self::verify_offline_set(token_str, std::slice::from_ref(k))?,
            None => Self::verify_offline_set(token_str, &self.pinned_keysets())?,
        };

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
        self.state = FlashState::default();
        self.storage.wipe()?;
        Ok(())
    }
}
