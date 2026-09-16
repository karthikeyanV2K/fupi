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
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::Base64DecodeError(e) => write!(f, "Base64 decode error: {e}"),
            CryptoError::NoModularInverse => write!(f, "No modular inverse exists (gcd != 1)"),
            CryptoError::VerificationFailed => write!(f, "Signature verification failed"),
            CryptoError::InvalidExponent => write!(f, "Invalid RSA public exponent"),
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
