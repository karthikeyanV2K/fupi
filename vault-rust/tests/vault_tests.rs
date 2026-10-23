use fupi_vault::crypto::{
    b64_encode, biguint_to_b64, blind, claim_signature, generate_claim_keypair,
    generate_locked_secret, generate_secret, hash_to_scalar, hex_decode, lock_of,
    random_blinder, unblind, verify,
};
use fupi_vault::storage::FlashStorage;
use fupi_vault::types::{Keyset, Proof};
use fupi_vault::vault::Vault;
use num_bigint::BigUint;

#[test]
fn test_vault_offline_lifecycle_and_verification() {
    let temp_dir = std::env::temp_dir();
    let flash_file = temp_dir.join(format!("fupi_test_v_{}.json", rand::random::<u64>()));
    let storage = FlashStorage::new(&flash_file);

    // Mock RSA-2048 keypair (or small RSA for ultra-fast unit testing)
    // p=61, q=53 -> n=3233, phi=3120, e=17, d=2753
    let n = BigUint::from(3233u32);
    let e = BigUint::from(17u32);
    let d = BigUint::from(2753u32);

    let keyset = Keyset {
        keyset_id: "mock-keyset-01".to_string(),
        n: biguint_to_b64(&n),
        e: 17,
    };

    let vault = Vault::new(storage.clone(), None).expect("failed to init vault");
    assert_eq!(vault.balance(), 0);

    // Receiver (Alice) owns an ed25519 claim key; the first 2 proofs are locked to it.
    let (alice_sk, alice_pk) = generate_claim_keypair();

    // Simulate 5 topup operations directly using crypto primitives
    let mut rng = rand::rngs::OsRng;
    for i in 0..5 {
        let secret = if i < 2 {
            generate_locked_secret(&alice_pk).unwrap()
        } else {
            generate_secret()
        };
        let m = hash_to_scalar(secret.as_bytes(), &n);
        let r = random_blinder(&mut rng, &n);
        let m_blind = blind(&m, &r, &e, &n);

        // Mock ATM signs blind message
        let s_blind = m_blind.modpow(&d, &n);
        let sig = unblind(&s_blind, &r, &n).unwrap();
        assert!(verify(&m, &sig, &e, &n));

        let proof = Proof {
            secret,
            sig: biguint_to_b64(&sig),
            n: keyset.n.clone(),
            e: keyset.e,
            keyset_id: Some(keyset.keyset_id.clone()),
            p2pk: None,
            claimer: None,
        };

        // Store into state manually for offline test
        let mut state = storage.load().unwrap();
        state.proofs.push(proof);
        state.journal.push(format!("topup +1 (balance {})", state.proofs.len()));
        storage.save(&state).unwrap();
    }

    // Reload vault from flash
    let mut vault = Vault::new(storage.clone(), None).unwrap();
    assert_eq!(vault.balance(), 5);

    // Spend the 2 proofs locked to Alice's key
    let token_alice = vault
        .make_payment(2, Some(alice_pk.clone()))
        .expect("payment should succeed");
    assert_eq!(vault.balance(), 3);

    // Receiver (Alice) verifies tokens OFFLINE without any network connection
    let verified_proofs = Vault::verify_offline(&token_alice, Some(&keyset))
        .expect("offline verification must pass for genuine tokens");
    assert_eq!(verified_proofs.len(), 2);
    let alice_pub_bytes: [u8; 32] = hex_decode(&alice_pk).unwrap().try_into().unwrap();
    for p in &verified_proofs {
        // The lock lives inside the blind-signed secret, not in a strippable field.
        assert_eq!(lock_of(&p.secret).unwrap(), Some(alice_pub_bytes));
        // Only Alice's key can produce a valid claim signature for it.
        let sig_hex = claim_signature(&alice_sk, &p.secret).unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&hex_decode(&sig_hex).unwrap()).unwrap();
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&alice_pub_bytes).unwrap();
        assert!(vk.verify_strict(p.secret.as_bytes(), &sig).is_ok());
    }
    // The outbox kept the emitted token, saved atomically with the removal of the proofs.
    assert_eq!(vault.outbox().len(), 1);
    assert_eq!(vault.outbox()[0], token_alice);
    // Spend 3 remaining tokens
    let token_bob = vault.make_payment(3, None).unwrap();
    assert_eq!(vault.balance(), 0);

    let bob_proofs = Vault::verify_offline(&token_bob, Some(&keyset)).unwrap();
    assert_eq!(bob_proofs.len(), 3);

    // Attempt spending when balance is 0
    let err = vault.make_payment(1, None).unwrap_err();
    match err {
        fupi_vault::VaultError::InsufficientFunds { have, requested } => {
            assert_eq!(have, 0);
            assert_eq!(requested, 1);
        }
        _ => panic!("unexpected error variant: {:?}", err),
    }

    // Wipe vault
    vault.wipe().unwrap();
    assert_eq!(vault.balance(), 0);
    assert!(!flash_file.exists());
}

#[test]
fn test_tampered_token_rejection() {
    let n = BigUint::from(3233u32);
    let d = BigUint::from(2753u32);

    let secret = "fupi-original-valid-secret";
    let m = hash_to_scalar(secret.as_bytes(), &n);
    let sig = m.modpow(&d, &n); // valid RSA sig

    let keyset = Keyset {
        keyset_id: "test-00".to_string(),
        n: biguint_to_b64(&n),
        e: 17,
    };
    let mut proof = Proof {
        secret: secret.to_string(),
        sig: biguint_to_b64(&sig),
        n: biguint_to_b64(&n),
        e: 17,
        keyset_id: Some("test-00".to_string()),
        p2pk: None,
        claimer: None,
    };

    // Valid token passes against the pinned keyset
    let valid_token = b64_encode(&serde_json::to_vec(&vec![proof.clone()]).unwrap());
    assert!(Vault::verify_offline(&valid_token, Some(&keyset)).is_ok());

    // Tamper 1: modify secret (signature no longer matches hash)
    proof.secret = "fupi-altered-tampered-secret".to_string();
    let tampered_token_1 = b64_encode(&serde_json::to_vec(&vec![proof.clone()]).unwrap());
    assert!(Vault::verify_offline(&tampered_token_1, Some(&keyset)).is_err());

    // Tamper 2: corrupt signature bytes
    proof.secret = secret.to_string();
    proof.sig = biguint_to_b64(&(&sig + BigUint::from(1u32)));
    let tampered_token_2 = b64_encode(&serde_json::to_vec(&vec![proof]).unwrap());
    assert!(Vault::verify_offline(&tampered_token_2, Some(&keyset)).is_err());
}

#[test]
fn test_peer_to_peer_offline_payment_and_receive() {
    let temp_dir = std::env::temp_dir();
    let alice_file = temp_dir.join(format!("fupi_test_alice_{}.json", rand::random::<u64>()));
    let bob_file = temp_dir.join(format!("fupi_test_bob_{}.json", rand::random::<u64>()));

    let alice_storage = FlashStorage::new(&alice_file);
    let bob_storage = FlashStorage::new(&bob_file);

    let n = BigUint::from(3233u32);
    let d = BigUint::from(2753u32);
    let keyset = Keyset {
        keyset_id: "test-mint-01".to_string(),
        n: biguint_to_b64(&n),
        e: 17,
    };

    // 1. Fund Alice's vault with 3 proofs
    let mut alice_state = alice_storage.load().unwrap();
    alice_state.trusted_keyset = Some(keyset.clone());
    for i in 0..3 {
        let secret = format!("fupi-alice-proof-{}", i);
        let m = hash_to_scalar(secret.as_bytes(), &n);
        let sig = m.modpow(&d, &n);
        alice_state.proofs.push(Proof {
            secret,
            sig: biguint_to_b64(&sig),
            n: keyset.n.clone(),
            e: keyset.e,
            keyset_id: Some(keyset.keyset_id.clone()),
            p2pk: None,
            claimer: None,
        });
    }
    alice_storage.save(&alice_state).unwrap();

    let mut alice_vault = Vault::new(alice_storage, None).unwrap();
    assert_eq!(alice_vault.balance(), 3);

    let mut bob_vault = Vault::new(bob_storage, None).unwrap();
    bob_vault.cache_keyset(keyset.clone()).unwrap();
    assert_eq!(bob_vault.balance(), 0);

    // 2. Alice pays 2 tokens to Bob offline
    let token_to_bob = alice_vault.make_payment(2, None).unwrap();
    assert_eq!(alice_vault.balance(), 1);

    // 3. Bob receives the 2 tokens into his vault offline
    let received = bob_vault.receive_token(&token_to_bob, Some(&keyset)).unwrap();
    assert_eq!(received, 2);
    assert_eq!(bob_vault.balance(), 2);

    // 4. Duplicate receive of the exact same token should be rejected
    let dup_err = bob_vault.receive_token(&token_to_bob, Some(&keyset));
    assert!(dup_err.is_err());

    // 5. Bob spends 1 token to Charlie offline
    let token_to_charlie = bob_vault.make_payment(1, None).unwrap();
    assert_eq!(bob_vault.balance(), 1);

    let charlie_proofs = Vault::verify_offline(&token_to_charlie, Some(&keyset)).unwrap();
    assert_eq!(charlie_proofs.len(), 1);

    // Clean up
    let _ = alice_vault.wipe();
    let _ = bob_vault.wipe();
}

#[test]
fn test_forged_token_with_custom_modulus_rejected() {
    // Trusted mint key: N=3233, e=17, d=2753
    let trusted_n = BigUint::from(3233u32);
    let trusted_keyset = Keyset {
        keyset_id: "trusted-mint".to_string(),
        n: biguint_to_b64(&trusted_n),
        e: 17,
    };

    // Attacker Eve creates her own custom RSA key: p=11, q=13 -> N_fake=143, e=7, d_fake=103
    let n_fake = BigUint::from(143u32);
    let d_fake = BigUint::from(103u32);
    let secret = "fupi-counterfeit-cash-001";
    let m_fake = hash_to_scalar(secret.as_bytes(), &n_fake);
    let sig_fake = m_fake.modpow(&d_fake, &n_fake);

    let fake_proof = Proof {
        secret: secret.to_string(),
        sig: biguint_to_b64(&sig_fake),
        n: biguint_to_b64(&n_fake), // Attacker injected her own modulus
        e: 7,
        keyset_id: Some("trusted-mint".to_string()),
        p2pk: None,
        claimer: None,
    };

    let fake_token = b64_encode(&serde_json::to_vec(&vec![fake_proof]).unwrap());

    // Offline verify against the trusted keyset MUST fail and detect forgery!
    let verify_res = Vault::verify_offline(&fake_token, Some(&trusted_keyset));
    assert!(verify_res.is_err());
    let err_str = verify_res.unwrap_err().to_string();
    assert!(err_str.contains("forgery detected") || err_str.contains("failed"));
}

fn big_odd_modulus() -> BigUint {
    (BigUint::from(1u32) << 2047usize) + BigUint::from(12345u32) * 2u32 + 1u32
}

#[test]
fn test_e_equals_one_forgery_rejected() {
    // Regression: the old verifier took `e` from the token. With e=1 and sig=m anyone
    // can "sign" without the private key. The pinned keyset's e/n are now authoritative.
    let n = big_odd_modulus();
    let ks = Keyset { keyset_id: "go-mvp-00".into(), n: biguint_to_b64(&n), e: 65537 };
    let secret = "fupi-forged-0001";
    let m = hash_to_scalar(secret.as_bytes(), &n);
    let json = format!(r#"[{{"secret":"{}","sig":"{}","e":1}}]"#, secret, biguint_to_b64(&m));
    let tok = b64_encode(json.as_bytes());
    assert!(Vault::verify_offline(&tok, Some(&ks)).is_err());
    // Even if the forger also claims the right keyset id and modulus.
    let json = format!(
        r#"[{{"secret":"{}","sig":"{}","n":"{}","e":1,"keyset_id":"go-mvp-00"}}]"#,
        secret, biguint_to_b64(&m), ks.n
    );
    let tok = b64_encode(json.as_bytes());
    assert!(Vault::verify_offline(&tok, Some(&ks)).is_err());
}

#[test]
fn test_no_pinned_keyset_means_no_trust() {
    // Regression: with no keyset, a token carrying its own (n, e) used to verify.
    let p = BigUint::from(3233u32);
    let secret = "fupi-own-key";
    let m = hash_to_scalar(secret.as_bytes(), &p);
    let sig = m.modpow(&BigUint::from(2753u32), &p);
    let json = format!(
        r#"[{{"secret":"{}","sig":"{}","n":"{}","e":17}}]"#,
        secret, biguint_to_b64(&sig), biguint_to_b64(&p)
    );
    let tok = b64_encode(json.as_bytes());
    assert!(Vault::verify_offline(&tok, None).is_err());

    // receive_token on a vault with nothing pinned must also refuse.
    let f = std::env::temp_dir().join(format!("fupi_test_nopin_{}.json", rand::random::<u64>()));
    let mut v = Vault::new(FlashStorage::new(&f), None).unwrap();
    assert!(v.receive_token(&tok, None).is_err());
    assert_eq!(v.balance(), 0);
    let _ = v.wipe();
}

#[test]
fn test_keyset_pin_refuses_change() {
    let a = Keyset { keyset_id: "k1".into(), n: biguint_to_b64(&BigUint::from(3233u32)), e: 17 };
    let same = a.clone();
    let other_n = Keyset { n: biguint_to_b64(&BigUint::from(143u32)), ..a.clone() };
    let other_id = Keyset { keyset_id: "k2".into(), ..a.clone() };
    let bad_e = Keyset { e: 2, ..a.clone() };

    assert!(Vault::check_keyset_pin(None, &a).is_ok()); // first use pins
    assert!(Vault::check_keyset_pin(Some(&a), &same).is_ok());
    assert!(Vault::check_keyset_pin(Some(&a), &other_n).is_err()); // swapped modulus
    assert!(Vault::check_keyset_pin(Some(&a), &other_id).is_err()); // swapped id
    assert!(Vault::check_keyset_pin(None, &bad_e).is_err()); // degenerate exponent
}

#[test]
fn test_payment_selects_only_matching_lock_and_keeps_outbox() {
    let f = std::env::temp_dir().join(format!("fupi_test_sel_{}.json", rand::random::<u64>()));
    let storage = FlashStorage::new(&f);
    let n = BigUint::from(3233u32);
    let d = BigUint::from(2753u32);
    let (_sk, pk) = generate_claim_keypair();
    let (_sk2, other_pk) = generate_claim_keypair();

    let mut st = storage.load().unwrap();
    for secret in [
        "fupi-plain-1".to_string(),
        generate_locked_secret(&pk).unwrap(),
        generate_locked_secret(&other_pk).unwrap(),
    ] {
        let m = hash_to_scalar(secret.as_bytes(), &n);
        st.proofs.push(Proof {
            secret,
            sig: biguint_to_b64(&m.modpow(&d, &n)),
            n: biguint_to_b64(&n),
            e: 17,
            keyset_id: Some("t".into()),
            p2pk: None,
            claimer: None,
        });
    }
    storage.save(&st).unwrap();
    let mut v = Vault::new(storage.clone(), None).unwrap();

    // Unlocked payments never touch locked proofs: only 1 plain proof exists.
    assert!(v.make_payment(2, None).is_err());
    assert_eq!(v.balance(), 3);
    // A lock that matches nothing fails; the vault is untouched.
    let (_s3, nobody) = generate_claim_keypair();
    assert!(v.make_payment(1, Some(nobody)).is_err());
    assert_eq!(v.balance(), 3);

    let tok = v.make_payment(1, Some(pk.clone())).unwrap();
    assert_eq!(v.balance(), 2);

    // Crash safety: a fresh vault reloaded from flash still has the token in its outbox.
    let mut reloaded = Vault::new(storage, None).unwrap();
    assert_eq!(reloaded.balance(), 2);
    assert_eq!(reloaded.outbox(), &[tok]);
    assert!(reloaded.ack_outbox(1).unwrap());
    assert!(reloaded.outbox().is_empty());
    assert!(!reloaded.ack_outbox(1).unwrap());
    let _ = reloaded.wipe();
}
