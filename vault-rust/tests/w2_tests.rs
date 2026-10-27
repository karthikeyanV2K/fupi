//! W2 vault tests: denominated balance, exact-change selection, per-denomination keyset
//! pinning/verification, device key, and swap recovery state. Tiny RSA keys keep these fast;
//! the real kiosk interop is covered by kiosk-go/e2e_https_rust_vault_test.py.

use fupi_vault::crypto::{biguint_to_b64, hash_to_scalar};
use fupi_vault::storage::FlashStorage;
use fupi_vault::types::{Keyset, PendingOut, PendingSwap, Proof};
use fupi_vault::vault::{Vault, VaultError};
use num_bigint::BigUint;

struct Rsa {
    n: BigUint,
    e: u64,
    d: BigUint,
}

fn key_a() -> Rsa {
    Rsa { n: BigUint::from(3233u32), e: 17, d: BigUint::from(2753u32) }
}
fn key_b() -> Rsa {
    // p=67, q=71, phi=4620, e=13, d=13^-1 mod 4620
    Rsa { n: BigUint::from(4757u32), e: 13, d: BigUint::from(1777u32) }
}

fn keyset(id: &str, k: &Rsa) -> Keyset {
    Keyset { keyset_id: id.into(), n: biguint_to_b64(&k.n), e: k.e }
}

fn proof(id: &str, secret: &str, k: &Rsa) -> Proof {
    let m = hash_to_scalar(secret.as_bytes(), &k.n);
    Proof {
        secret: secret.into(),
        sig: biguint_to_b64(&m.modpow(&k.d, &k.n)),
        n: biguint_to_b64(&k.n),
        e: k.e,
        keyset_id: Some(id.into()),
        p2pk: None,
        claimer: None,
    }
}

fn vault_with(proofs: Vec<Proof>) -> (Vault, FlashStorage) {
    let f = std::env::temp_dir().join(format!("fupi_w2_{}.json", rand::random::<u64>()));
    let storage = FlashStorage::new(&f);
    let mut st = storage.load().unwrap();
    st.proofs = proofs;
    storage.save(&st).unwrap();
    (Vault::new(storage.clone(), None).unwrap(), storage)
}

fn coins(a: &Rsa) -> Vec<Proof> {
    [(200u64, "c200"), (20, "c20"), (10, "c10"), (5, "c5"), (2, "c2")]
        .iter()
        .map(|(d, s)| proof(&format!("go-mvp-d{d}"), &format!("fupi-{s}"), a))
        .collect()
}

#[test]
fn balance_is_money_not_proof_count() {
    let (v, _) = vault_with(coins(&key_a()));
    assert_eq!(v.proof_count(), 5);
    assert_eq!(v.balance(), 237);
    assert_eq!(v.breakdown(), vec![(200, 1), (20, 1), (10, 1), (5, 1), (2, 1)]);
}

#[test]
fn exact_payment_picks_the_right_coins_and_keeps_the_rest() {
    let a = key_a();
    let (mut v, _) = vault_with(coins(&a));
    let tok = v.make_payment(37, None).unwrap(); // 20 + 10 + 5 + 2
    assert_eq!(v.balance(), 200);
    let sent = Vault::decode_token(&tok).unwrap();
    let sum: usize = sent
        .iter()
        .map(|p| p.keyset_id.as_deref().unwrap().trim_start_matches("go-mvp-d").parse::<usize>().unwrap())
        .sum();
    assert_eq!(sum, 37);
    assert_eq!(v.outbox(), &[tok]);
}

#[test]
fn payment_needing_change_is_reported_not_overspent() {
    let a = key_a();
    let (mut v, _) = vault_with(vec![proof("go-mvp-d200", "fupi-big", &a)]);
    match v.make_payment(40, None) {
        Err(VaultError::NeedChange { requested: 40, have: 200 }) => {}
        other => panic!("want NeedChange, got {other:?}"),
    }
    assert_eq!(v.balance(), 200, "a refused payment must not spend anything");
    assert!(matches!(
        v.make_payment(300, None),
        Err(VaultError::InsufficientFunds { have: 200, requested: 300 })
    ));
    // Without an ATM client the auto-change path cannot run, and still spends nothing.
    assert!(v.pay(40, None).is_err());
    assert_eq!(v.balance(), 200);
    assert!(!v.has_pending_swap());
}

#[test]
fn proofs_verify_against_the_keyset_they_name_only() {
    let (a, b) = (key_a(), key_b());
    let ks = vec![keyset("go-mvp-d5", &a), keyset("go-mvp-d10", &b)];
    let p5 = proof("go-mvp-d5", "fupi-five", &a);
    let p10 = proof("go-mvp-d10", "fupi-ten", &b);
    let tok = fupi_vault::crypto::b64_encode(&serde_json::to_vec(&vec![p5.clone(), p10.clone()]).unwrap());
    assert_eq!(Vault::verify_offline_set(&tok, &ks).unwrap().len(), 2);

    // A proof signed under key A but labelled as denomination 10 must fail (value inflation).
    let mut lie = p5.clone();
    lie.keyset_id = Some("go-mvp-d10".into());
    let tok = fupi_vault::crypto::b64_encode(&serde_json::to_vec(&vec![lie]).unwrap());
    assert!(Vault::verify_offline_set(&tok, &ks).is_err());

    // A keyset id that was never pinned is refused.
    let mut unknown = p5;
    unknown.keyset_id = Some("go-mvp-d500".into());
    let tok = fupi_vault::crypto::b64_encode(&serde_json::to_vec(&vec![unknown]).unwrap());
    assert!(matches!(
        Vault::verify_offline_set(&tok, &ks),
        Err(VaultError::KeysetMismatch { .. })
    ));
    assert!(Vault::verify_offline_set(&tok, &[]).is_err());
}

#[test]
fn keyset_set_pinning_rules() {
    let (a, b) = (key_a(), key_b());
    let d5 = keyset("go-mvp-d5", &a);
    let d10 = keyset("go-mvp-d10", &b);
    // First use pins everything.
    assert!(Vault::check_keyset_set(&[], &[d5.clone(), d10.clone()], false).is_ok());
    // Same set again is fine.
    assert!(Vault::check_keyset_set(&[d5.clone(), d10.clone()], &[d10.clone(), d5.clone()], false).is_ok());
    // A swapped modulus under a pinned id is refused, even with allow_new.
    let swapped = keyset("go-mvp-d5", &b);
    assert!(Vault::check_keyset_set(&[d5.clone()], &[swapped.clone()], true).is_err());
    // A new id is refused unless explicitly allowed.
    assert!(Vault::check_keyset_set(&[d5.clone()], &[d5.clone(), d10.clone()], false).is_err());
    assert!(Vault::check_keyset_set(&[d5.clone()], &[d5, d10], true).is_ok());
    assert!(Vault::check_keyset_set(&[], &[], false).is_err());
}

#[test]
fn device_key_is_created_once_and_survives_restart() {
    let (mut v, storage) = vault_with(vec![]);
    let pk1 = v.device_public_key().unwrap();
    assert_eq!(pk1.len(), 64);
    assert_eq!(v.device_public_key().unwrap(), pk1);
    let mut v2 = Vault::new(storage, None).unwrap();
    assert_eq!(v2.device_public_key().unwrap(), pk1);
}

#[test]
fn unfinished_swap_holds_value_and_can_be_abandoned() {
    let a = key_a();
    let (v0, storage) = vault_with(vec![proof("go-mvp-d5", "fupi-keep", &a)]);
    drop(v0);
    let held = proof("go-mvp-d200", "fupi-held", &a);
    let mut st = storage.load().unwrap();
    st.pending_swap = Some(PendingSwap {
        inputs: vec![held],
        outputs: vec![PendingOut {
            secret: "fupi-new".into(),
            r: "Aw".into(),
            blinded: "Ag".into(),
            amount: 200,
            keyset_id: "go-mvp-d200".into(),
        }],
    });
    storage.save(&st).unwrap();

    let mut v = Vault::new(storage.clone(), None).unwrap();
    assert!(v.has_pending_swap());
    assert_eq!(v.balance(), 5, "value inside an unfinished swap is not spendable");
    // No ATM client: recovery fails and the pending record is kept.
    assert!(v.recover().is_err());
    assert!(v.has_pending_swap());
    assert!(v.topup(5).is_err());
    assert!(v.pay(5, None).is_err());
    assert_eq!(v.balance(), 5);

    assert!(v.abandon_pending().unwrap());
    assert!(!v.has_pending_swap());
    assert_eq!(v.balance(), 205);
    assert!(!Vault::new(storage, None).unwrap().has_pending_swap(), "abandon is persisted");
}
