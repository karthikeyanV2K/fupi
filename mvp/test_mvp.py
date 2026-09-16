"""FUPI MVP test suite — run from X:\\fupi\\mvp:  python test_mvp.py

Covers: blind-signature math, blinding unlinkability, reserve 1:1 rule,
P2PK lock enforcement, double-spend rejection, offline verification.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto import MintKeypair, hash_to_int, modinv  # noqa: E402

PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}")


def test_blind_signature_roundtrip():
    kp = MintKeypair(bits=512)
    secret = "fupi-test-secret-0001"
    m = hash_to_int(secret.encode(), kp.n)
    r = MintKeypair.random_blinder(kp.n)
    s_blind = kp.sign(kp.blind(m, r))
    s = kp.unblind(s_blind, r)
    check("signature verifies after unblind", kp.verify(m, s))
    check("kiosk never saw m", kp.blind(m, r) != m)


def test_blinding_unlinkability():
    """Blinding randomizes the KIOSK'S VIEW, not the final signature:
    same message -> identical unblinded sig (deterministic RSA), but the
    blinded values the kiosk signs are all different and unlinkable."""
    kp = MintKeypair(bits=512)
    m = hash_to_int(b"unlink-test", kp.n)
    blinded_views, unblinded = [], []
    for _ in range(4):
        r = MintKeypair.random_blinder(kp.n)
        b = kp.blind(m, r)
        blinded_views.append(b)
        unblinded.append(kp.unblind(kp.sign(b), r))
    check("kiosk sees different blinded values each time",
          len(set(blinded_views)) == len(blinded_views))
    check("unblinded sigs are all valid for m",
          all(kp.verify(m, s) for s in unblinded))
    check("blinded view differs from raw message",
          all(b != m for b in blinded_views))


def test_kiosk_rules():
    from kiosk import Kiosk
    k = Kiosk()
    n, e = k.keypair.n, k.keypair.e

    k.credit_reserve(2)
    try:
        k.sign_blinded(12345, 3)
        check("1:1 reserve rule blocks overissue", False)
    except ValueError:
        check("1:1 reserve rule blocks overissue", True)

    m = hash_to_int(b"proof-a", n)
    r = MintKeypair.random_blinder(n)
    s = k.keypair.unblind(k.sign_blinded(k.keypair.blind(m, r), 1), r)
    proof = {"secret": "proof-a", "sig": s, "n": n, "e": e}
    check("settle accepts genuine proof", k.settle(proof))
    check("settle rejects replay (double-spend)", not k.settle(proof))

    m2 = hash_to_int(b"forged", n)
    bad = {"secret": "forged", "sig": (s + 1) % n, "n": n, "e": e}
    check("settle rejects bad signature", not k.settle(bad))

    m3 = hash_to_int(b"locked", n)
    r3 = MintKeypair.random_blinder(n)
    s3 = k.keypair.unblind(k.sign_blinded(k.keypair.blind(m3, r3), 1), r3)
    locked = {"secret": "locked", "sig": s3, "n": n, "e": e, "p2pk": "shop"}
    check("P2PK rejects wrong claimer", not k.settle(dict(locked, claimer="thief")))
    check("P2PK accepts right claimer", k.settle(dict(locked, claimer="shop")))


def test_vault_flow():
    from kiosk import Kiosk
    from vault import Vault
    v = Vault(flash=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  "test_flash.json"))
    v.wipe_flash()
    k = Kiosk()
    k.credit_reserve(10)
    v.topup(k, 10)
    check("vault balance after topup", v.balance() == 10)
    tok = v.make_payment(3, p2pk="friend")
    proofs = Vault.decode_token(tok)
    check("token decodes to 3 proofs", len(proofs) == 3)
    check("p2pk lock carried on proofs", all(p.get("p2pk") == "friend" for p in proofs))
    check("offline verify passes", Vault.verify_offline(proofs, {**k.pubkey}))
    check("vault balance after spend", v.balance() == 7)
    try:
        v.make_payment(100)
        check("spend blocked when over balance", False)
    except AssertionError:
        check("spend blocked when over balance", True)
    v.wipe_flash()


print("=== FUPI MVP test suite ===")
test_blind_signature_roundtrip()
test_blinding_unlinkability()
test_kiosk_rules()
test_vault_flow()
print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
