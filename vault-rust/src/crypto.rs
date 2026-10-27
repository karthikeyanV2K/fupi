use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    Base64DecodeError(String),
    NoModularInverse,
    VerificationFailed,
    InvalidExponent,
    InvalidLock(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::Base64DecodeError(e) => write!(f, "Base64 decode error: {e}"),
            CryptoError::NoModularInverse => write!(f, "No modular inverse exists (gcd != 1)"),
            CryptoError::VerificationFailed => write!(f, "Signature verification failed"),
            CryptoError::InvalidExponent => write!(f, "Invalid RSA public exponent"),
            CryptoError::InvalidLock(e) => write!(f, "Invalid P2PK lock: {e}"),
        }
    }
}

impl std::error::Error for CryptoError {}

pub fn b64_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>, CryptoError> {
    let clean = s.trim();
    let unpadded = clean.trim_end_matches('=');
    if let Ok(bytes) = URL_SAFE_NO_PAD.decode(unpadded) {
        return Ok(bytes);
    }
    if let Ok(bytes) = URL_SAFE.decode(clean) {
        return Ok(bytes);
    }
    if let Ok(bytes) = STANDARD_NO_PAD.decode(unpadded) {
        return Ok(bytes);
    }
    STANDARD
        .decode(clean)
        .map_err(|e| CryptoError::Base64DecodeError(e.to_string()))
}

pub fn biguint_to_b64(val: &BigUint) -> String {
    b64_encode(&val.to_bytes_be())
}

pub fn b64_to_biguint(s: &str) -> Result<BigUint, CryptoError> {
    let bytes = b64_decode(s)?;
    Ok(BigUint::from_bytes_be(&bytes))
}

pub fn hash_to_scalar(secret: &[u8], n: &BigUint) -> BigUint {
    let digest = Sha256::digest(secret);
    let mut m = BigUint::from_bytes_be(&digest) % n;
    if m < BigUint::from(2u32) {
        m = BigUint::from(2u32);
    }
    m
}

pub fn modinv(a: &BigUint, m: &BigUint) -> Result<BigUint, CryptoError> {
    if m <= &BigUint::one() {
        return Err(CryptoError::NoModularInverse);
    }
    let a_signed = BigInt::from_biguint(Sign::Plus, a.clone());
    let m_signed = BigInt::from_biguint(Sign::Plus, m.clone());

    let ext = a_signed.extended_gcd(&m_signed);
    if ext.gcd != BigInt::one() {
        return Err(CryptoError::NoModularInverse);
    }
    let mut res = ext.x % &m_signed;
    if res < BigInt::zero() {
        res += &m_signed;
    }
    res.to_biguint().ok_or(CryptoError::NoModularInverse)
}

pub fn random_blinder<R: RngCore + CryptoRng>(rng: &mut R, n: &BigUint) -> BigUint {
    let byte_len = (n.bits() + 7) / 8;
    let two = BigUint::from(2u32);
    let n_minus_two = n - &two;
    loop {
        let mut buf = vec![0u8; byte_len as usize];
        rng.fill_bytes(&mut buf);
        let candidate = (BigUint::from_bytes_be(&buf) % &n_minus_two) + &two;
        if candidate.gcd(n) == BigUint::one() {
            return candidate;
        }
    }
}

pub fn blind(m: &BigUint, r: &BigUint, e: &BigUint, n: &BigUint) -> BigUint {
    let r_pow_e = r.modpow(e, n);
    (m * r_pow_e) % n
}

pub fn unblind(s_blind: &BigUint, r: &BigUint, n: &BigUint) -> Result<BigUint, CryptoError> {
    let r_inv = modinv(r, n)?;
    Ok((s_blind * r_inv) % n)
}

pub fn verify(m: &BigUint, sig: &BigUint, e: &BigUint, n: &BigUint) -> bool {
    let chk = sig.modpow(e, n);
    chk == *m
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

const LOCK_MARK: &str = "|lock=";

/// Parse the optional `|lock=<ed25519 pubkey hex>` suffix of a token secret.
/// The lock is part of the blind-signed secret, so it cannot be stripped or
/// rewritten after issuance without breaking the mint signature.
pub fn lock_of(secret: &str) -> Result<Option<[u8; 32]>, CryptoError> {
    match secret.find(LOCK_MARK) {
        None => Ok(None),
        Some(i) => {
            let bytes = hex_decode(&secret[i + LOCK_MARK.len()..])
                .ok_or_else(|| CryptoError::InvalidLock("not hex".into()))?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| CryptoError::InvalidLock("pubkey must be 32 bytes".into()))?;
            Ok(Some(arr))
        }
    }
}

/// New secret locked to `lock_pub_hex` (ed25519 public key, hex).
pub fn generate_locked_secret(lock_pub_hex: &str) -> Result<String, CryptoError> {
    let key = hex_decode(lock_pub_hex)
        .filter(|b| b.len() == 32)
        .ok_or_else(|| CryptoError::InvalidLock("pubkey must be 32 bytes of hex".into()))?;
    Ok(format!("{}{}{}", generate_secret(), LOCK_MARK, hex_encode(&key)))
}

/// Returns (secret_key_hex, public_key_hex) for a fresh ed25519 claim key.
pub fn generate_claim_keypair() -> (String, String) {
    let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    (hex_encode(&sk.to_bytes()), hex_encode(sk.verifying_key().as_bytes()))
}

/// hex ed25519 signature over arbitrary bytes by a hex secret key.
pub fn sign_bytes(secret_key_hex: &str, msg: &[u8]) -> Result<String, CryptoError> {
    use ed25519_dalek::Signer;
    let sk: [u8; 32] = hex_decode(secret_key_hex)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| CryptoError::InvalidLock("key must be 32 bytes of hex".into()))?;
    let sk = ed25519_dalek::SigningKey::from_bytes(&sk);
    Ok(hex_encode(&sk.sign(msg).to_bytes()))
}

/// hex ed25519 signature over the secret bytes: the proof of ownership a
/// locked token needs at settlement.
pub fn claim_signature(secret_key_hex: &str, secret: &str) -> Result<String, CryptoError> {
    sign_bytes(secret_key_hex, secret.as_bytes())
}

/// Public key (hex) for a secret key (hex).
pub fn public_key_of(secret_key_hex: &str) -> Result<String, CryptoError> {
    let sk: [u8; 32] = hex_decode(secret_key_hex)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| CryptoError::InvalidLock("key must be 32 bytes of hex".into()))?;
    let sk = ed25519_dalek::SigningKey::from_bytes(&sk);
    Ok(hex_encode(sk.verifying_key().as_bytes()))
}

/// Exactly what a device signs to request one proof (must match the kiosk's DeviceSignMessage).
pub fn device_sign_message(device_hex: &str, seq: u64, amount: u64, blinded_b64: &str) -> String {
    format!("fupi-blind-sign-v1|{device_hex}|{seq}|{amount}|{blinded_b64}")
}

/// SHA-256 of the modulus bytes, hex: what a human compares out-of-band when pinning a keyset.
pub fn modulus_fingerprint(n_b64: &str) -> Result<String, CryptoError> {
    Ok(hex_encode(&Sha256::digest(b64_decode(n_b64)?)))
}

pub fn generate_secret() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let hex_str: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    format!("fupi-{}", hex_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_b64_roundtrip() {
        let original = b"fupi-vault-test-secret-value";
        let enc = b64_encode(original);
        let dec = b64_decode(&enc).unwrap();
        assert_eq!(original.to_vec(), dec);
    }

    #[test]
    fn test_biguint_b64_roundtrip() {
        let val = BigUint::from(12345678901234567890u128);
        let enc = biguint_to_b64(&val);
        let dec = b64_to_biguint(&enc).unwrap();
        assert_eq!(val, dec);
    }

    #[test]
    fn test_hash_to_scalar_range() {
        let n = BigUint::from(1000000007u32);
        let m = hash_to_scalar(b"test-secret", &n);
        assert!(m >= BigUint::from(2u32));
        assert!(m < n);
    }

    #[test]
    fn test_modinv() {
        let a = BigUint::from(3u32);
        let m = BigUint::from(11u32);
        let inv = modinv(&a, &m).unwrap();
        assert_eq!(inv, BigUint::from(4u32));
        assert_eq!((&a * &inv) % &m, BigUint::one());
    }

    #[test]
    fn test_blind_unblind_verify_mock() {
        // Mock small RSA key: p=61, q=53 -> n=3233, phi=3120, e=17, d=2753
        let n = BigUint::from(3233u32);
        let e = BigUint::from(17u32);
        let d = BigUint::from(2753u32);

        let secret = b"unit-test-proof";
        let m = hash_to_scalar(secret, &n);

        let mut rng = rand::rngs::OsRng;
        let r = random_blinder(&mut rng, &n);

        // Blinding
        let m_blind = blind(&m, &r, &e, &n);
        assert_ne!(m_blind, m);

        // Mint signs blind message
        let s_blind = m_blind.modpow(&d, &n);

        // Unblinding
        let sig = unblind(&s_blind, &r, &n).unwrap();

        // Verification
        assert!(verify(&m, &sig, &e, &n));
    }

    #[test]
    fn test_lock_roundtrip_and_claim_signature() {
        let (sk, pk) = generate_claim_keypair();
        let secret = generate_locked_secret(&pk).unwrap();
        assert_eq!(lock_of(&secret).unwrap().unwrap().to_vec(), hex_decode(&pk).unwrap());
        let sig = claim_signature(&sk, &secret).unwrap();
        assert_eq!(hex_decode(&sig).unwrap().len(), 64);
        assert!(lock_of("fupi-plain").unwrap().is_none());
        assert!(lock_of("fupi-x|lock=zz").is_err());
        assert!(lock_of("fupi-x|lock=abcd").is_err());
        assert!(generate_locked_secret("abcd").is_err());
    }

    #[test]
    fn test_device_signature_matches_kiosk_message_format() {
        use ed25519_dalek::{Signature, VerifyingKey};
        let (sk, pk) = generate_claim_keypair();
        assert_eq!(public_key_of(&sk).unwrap(), pk);
        let msg = device_sign_message(&pk, 7, 50, "AbCd");
        assert_eq!(msg, format!("fupi-blind-sign-v1|{pk}|7|50|AbCd"));
        let sig = sign_bytes(&sk, msg.as_bytes()).unwrap();
        let vk = VerifyingKey::from_bytes(&hex_decode(&pk).unwrap().try_into().unwrap()).unwrap();
        let sig = Signature::from_slice(&hex_decode(&sig).unwrap()).unwrap();
        assert!(vk.verify_strict(msg.as_bytes(), &sig).is_ok());
        assert!(vk.verify_strict(b"other", &sig).is_err());
    }

    #[test]
    fn test_b64_standard_and_url_safe() {
        // [1, 2, 3, 251] in standard base64 is "AQID+w=="
        let standard = "AQID+w==";
        let dec = b64_decode(standard).expect("standard base64 must decode");
        assert_eq!(dec, vec![1, 2, 3, 251]);

        // In URL-safe base64 is "AQID-w"
        let url_safe = "AQID-w";
        let dec_url = b64_decode(url_safe).expect("url-safe base64 must decode");
        assert_eq!(dec_url, vec![1, 2, 3, 251]);
    }
}
