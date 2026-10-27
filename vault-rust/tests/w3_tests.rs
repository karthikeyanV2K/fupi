//! W3 merchant terminal: offline acceptance rules. Settlement against a live kiosk is
//! covered by kiosk-go/e2e_https_rust_vault_test.py.

use fupi_vault::crypto::{b64_encode, biguint_to_b64, hash_to_scalar};
use fupi_vault::storage::FlashStorage;
use fupi_vault::types::{Keyset, Proof};
use fupi_vault::vault::{Vault, VaultError};
use num_bigint::BigUint;

fn n() -> BigUint { BigUint::from(3233u32) }
fn d() -> BigUint { BigUint::from(2753u32) }

fn proof(id: &str, secret: &str) -> Proof {
    let m = hash_to_scalar(secret.as_bytes(), &n());
    Proof {
        secret: secret.into(),
        sig: biguint_to_b64(&m.modpow(&d(), &n())),
        n: biguint_to_b64(&n()),
        e: 17,
        keyset_id: Some(id.into()),
        p2pk: None,
        claimer: None,
    }
}

fn token(ps: &[Proof]) -> String {
    b64_encode(&serde_json::to_vec(ps).unwrap())
}

fn merchant() -> (Vault, FlashStorage) {
    let f = std::env::temp_dir().join(format!("fupi_w3_{}.json", rand::random::<u64>()));
    let storage = FlashStorage::new(&f);
    let mut v = Vault::new(storage.clone(), None).unwrap();
    let ks: Vec<Keyset> = ["go-mvp-d5", "go-mvp-d20"]
        .iter()
        .map(|id| Keyset { keyset_id: (*id).into(), n: biguint_to_b64(&n()), e: 17 })
        .collect();
    v.cache_keysets(&ks).unwrap();
    (v, storage)
}

#[test]
fn accepts_valid_payment_and_writes_receipt() {
    let (mut m, storage) = merchant();
    let tok = token(&[proof("go-mvp-d20", "fupi-a"), proof("go-mvp-d5", "fupi-b")]);
    let r = m.accept_payment(&tok, Some("order-7".into()), Some(25)).unwrap();
    assert_eq!((r.id, r.amount, r.secrets.len()), (1, 25, 2));
    assert_eq!(m.balance(), 25);
    let r2 = m.accept_payment(&token(&[proof("go-mvp-d5", "fupi-c")]), None, None).unwrap();
    assert_eq!(r2.id, 2);
    // Receipts and held proofs survive a restart.
    let again = Vault::new(storage, None).unwrap();
    assert_eq!(again.receipts().len(), 2);
    assert_eq!(again.receipts()[0].invoice.as_deref(), Some("order-7"));
    assert_eq!(again.balance(), 30);
}

#[test]
fn replay_and_duplicates_are_refused_and_store_nothing() {
    let (mut m, _) = merchant();
    let tok = token(&[proof("go-mvp-d5", "fupi-x")]);
    m.accept_payment(&tok, None, None).unwrap();
    assert!(matches!(m.accept_payment(&tok, None, None), Err(VaultError::DuplicateToken)));
    // Same secret twice inside one token.
    let p = proof("go-mvp-d5", "fupi-dup");
    assert!(matches!(
        m.accept_payment(&token(&[p.clone(), p]), None, None),
        Err(VaultError::DuplicateToken)
    ));
    // A token that overlaps an earlier one is refused whole, not half-taken.
    let mix = token(&[proof("go-mvp-d20", "fupi-new"), proof("go-mvp-d5", "fupi-x")]);
    assert!(matches!(m.accept_payment(&mix, None, None), Err(VaultError::DuplicateToken)));
    assert_eq!((m.balance(), m.receipts().len()), (5, 1));
}

#[test]
fn wrong_amount_forgery_and_unpinned_store_nothing() {
    let (mut m, _) = merchant();
    let tok = token(&[proof("go-mvp-d20", "fupi-w")]);
    assert!(matches!(
        m.accept_payment(&tok, Some("o".into()), Some(25)),
        Err(VaultError::WrongAmount { expected: 25, got: 20 })
    ));
    // Relabelled up to a keyset that is not pinned, and a corrupted signature.
    assert!(m.accept_payment(&token(&[proof("go-mvp-d500", "fupi-f")]), None, None).is_err());
    let mut bad = proof("go-mvp-d5", "fupi-g");
    bad.sig = biguint_to_b64(&BigUint::from(12u32));
    assert!(m.accept_payment(&token(&[bad]), None, None).is_err());
    assert_eq!((m.balance(), m.receipts().len()), (0, 0));

    // A merchant with nothing pinned trusts nothing.
    let f = std::env::temp_dir().join(format!("fupi_w3u_{}.json", rand::random::<u64>()));
    let mut bare = Vault::new(FlashStorage::new(&f), None).unwrap();
    assert!(bare.accept_payment(&tok, None, None).is_err());
}

#[test]
fn settle_all_needs_an_atm() {
    let (mut m, _) = merchant();
    m.accept_payment(&token(&[proof("go-mvp-d5", "fupi-s")]), None, None).unwrap();
    assert!(m.settle_all(None).is_err());
    assert_eq!(m.balance(), 5, "a failed settle run must keep everything");
}
