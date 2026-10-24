r"""End-to-end integration test: Go HTTPS ATM <-> Rust Vault over real TLS.

Build first:
  (cd kiosk-go && go build -o kiosk-go .)
  (cd vault-rust && cargo build)
Run:
  python kiosk-go/e2e_https_rust_vault_test.py

Covers the hardened flow:
   1. Kiosk boots with a credit secret; vault trusts ONLY the pinned TLS fingerprint
   2. TLS: strict default and a wrong pin are both refused for the self-signed kiosk
   3. Reserve funding is HMAC-authenticated; replayed reference and missing secret are refused
   4. Device identity: unallocated device refused; operator allocates quota; denominated top-up
   4b. Exact payment, and change-making through /v1/swap when the coins do not add up
   5. P2PK locks are real: claim signature required, wrong key / no key / stripped lock refused
   6. Offline verify, replay (double-spend) rejection, token outbox
   7. Peer-to-peer offline receive, forged tokens (e=1, fake modulus) rejected
   8. 5-way concurrent settle race: exactly one winner
"""

import base64
import concurrent.futures
import json
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

PORT = 8896
ATM_URL = f"https://127.0.0.1:{PORT}"
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EXE = ".exe" if os.name == "nt" else ""
KIOSK_EXE = os.path.join(ROOT_DIR, "kiosk-go", "kiosk-go" + EXE)
VAULT_EXE = os.path.join(ROOT_DIR, "vault-rust", "target", "debug", "fupi-vault" + EXE)
TEST_STATE = os.path.join(ROOT_DIR, "test_atm_state_e2e.json")
FLASH = {
    "alice": os.path.join(ROOT_DIR, "test_vault_flash_alice_e2e.json"),
    "bob": os.path.join(ROOT_DIR, "test_vault_flash_bob_e2e.json"),
}
CREDIT_SECRET = "e2e-credit-secret-not-for-production"

# Only used to READ the kiosk fingerprint on localhost; the vault itself pins it.
INSECURE_CTX = ssl.create_default_context()
INSECURE_CTX.check_hostname = False
INSECURE_CTX.verify_mode = ssl.CERT_NONE

PIN = None  # set once the kiosk is up


def cleanup():
    for base in [TEST_STATE] + list(FLASH.values()):
        for ext in ["", ".tmp", ".bak"]:
            try:
                os.remove(base + ext)
            except OSError:
                pass
        stem = os.path.splitext(base)[0]
        for ext in [".tmp", ".bak"]:
            try:
                os.remove(stem + ext)
            except OSError:
                pass


def http_json(path):
    with urllib.request.urlopen(ATM_URL + path, timeout=3, context=INSECURE_CTX) as r:
        return json.loads(r.read().decode())


def wait_for_atm(proc, timeout=90):
    start = time.time()
    while time.time() - start < timeout:
        if proc.poll() is not None:
            raise RuntimeError(f"kiosk exited early with code {proc.returncode}")
        try:
            http_json("/v1/info")
            return True
        except Exception:
            time.sleep(0.15)
    return False


def vault(who, *args, tls="pin", env=None, check=True):
    cmd = [VAULT_EXE] + list(args) + ["--atm", ATM_URL, "--flash", FLASH[who]]
    if tls == "pin":
        cmd += ["--pin-tls", PIN]
    elif tls == "badpin":
        cmd += ["--pin-tls", "00" * 32]
    elif tls == "insecure":
        cmd += ["--insecure"]
    # tls == "strict": no TLS flag at all (default must refuse a self-signed cert)
    e = dict(os.environ)
    e.pop("FUPI_CREDIT_SECRET", None)
    if env:
        e.update(env)
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=e)
    if check and res.returncode != 0:
        print(f"FAILED cmd: {' '.join(cmd)}\nSTDOUT: {res.stdout}\nSTDERR: {res.stderr}")
        raise RuntimeError(f"vault command failed with code {res.returncode}")
    return res


def last_line(res):
    return res.stdout.strip().splitlines()[-1]


def keygen():
    out = vault("alice", "keygen").stdout
    pk = re.search(r"public_key=([0-9a-f]{64})", out).group(1)
    sk = re.search(r"secret_key=([0-9a-f]{64})", out).group(1)
    return sk, pk


def token_value(tok):
    """Face value of a token = sum of the denominations named by its keyset ids."""
    proofs = json.loads(base64.urlsafe_b64decode(tok + "=" * (-len(tok) % 4)))
    total = 0
    for p in proofs:
        kid = p["keyset_id"]
        total += 1 if kid == "go-mvp-00" else int(kid.rsplit("d", 1)[1])
    return total


def step(n, title):
    print(f"\n[Step {n}] {title}")


def main():
    global PIN
    print("=" * 65)
    print("  FUPI End-to-End Test: Go HTTPS ATM <-> Rust Vault (hardened)")
    print("=" * 65)
    for exe in (KIOSK_EXE, VAULT_EXE):
        if not os.path.exists(exe):
            sys.exit(f"missing binary {exe}; see build instructions at the top of this file")
    cleanup()

    step(1, f"Booting kiosk on :{PORT} with TLS and a credit secret...")
    env = dict(os.environ, FUPI_CREDIT_SECRET=CREDIT_SECRET)
    kiosk = subprocess.Popen(
        [KIOSK_EXE, "-port", str(PORT), "-tls=true", "-state", TEST_STATE, "-save-cert=false"],
        cwd=os.path.join(ROOT_DIR, "kiosk-go"), env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        if not wait_for_atm(kiosk):
            raise RuntimeError("kiosk did not come up")
        PIN = http_json("/v1/info")["tls_fingerprint_sha256"]
        print(f"  -> kiosk up; TLS fingerprint {PIN[:16]}...")

        step(2, "TLS trust: strict default and a wrong pin must both be REFUSED")
        assert vault("alice", "info", tls="strict", check=False).returncode != 0, \
            "strict TLS accepted a self-signed certificate"
        assert vault("alice", "info", tls="badpin", check=False).returncode != 0, \
            "a wrong pin was accepted"
        res = vault("alice", "info")
        assert "TLS Active: true" in res.stdout
        print("  -> only the pinned certificate is trusted")

        step(3, "Reserve funding is authenticated and idempotent")
        assert vault("alice", "bank", "100", "--ref", "UTR-1", check=False).returncode != 0, \
            "credit without FUPI_CREDIT_SECRET should fail client-side"
        assert vault("alice", "bank", "100", "--ref", "UTR-1",
                     env={"FUPI_CREDIT_SECRET": "wrong"}, check=False).returncode != 0, \
            "credit with the wrong secret was accepted"
        good = {"FUPI_CREDIT_SECRET": CREDIT_SECRET}
        assert "100.00" in vault("alice", "bank", "100", "--ref", "UTR-1", env=good).stdout
        assert vault("alice", "bank", "100", "--ref", "UTR-1", env=good, check=False).returncode != 0, \
            "replayed bank reference was credited twice"
        rc = http_json("/v1/reconcile")
        assert rc["reserve"] == 100.0 and rc["deposit_count"] == 1, rc
        print(f"  -> reserve stays 100.00 after replay; reconcile: {rc}")

        step(4, "Device identity: no quota => no proofs; operator allocates; denominated top-up")
        assert vault("alice", "credit-dummy", check=False).returncode != 0  # unknown subcommand
        assert vault("alice", "bank", "400", "--ref", "UTR-2", env=good).returncode == 0
        pk_dev = re.search(r"device_public_key=([0-9a-f]{64})", vault("alice", "device").stdout).group(1)
        assert vault("alice", "topup", "10", check=False).returncode != 0, \
            "a device with no allocation got proofs"
        assert vault("alice", "allocate", pk_dev, "300", "--ref", "ALLOC-1", check=False).returncode != 0, \
            "allocation without the operator secret was accepted"
        assert vault("alice", "allocate", pk_dev, "300", "--ref", "ALLOC-1", env=good).returncode == 0
        assert vault("alice", "allocate", pk_dev, "300", "--ref", "ALLOC-1", env=good, check=False).returncode != 0, \
            "replayed allocation ref was accepted"
        assert vault("alice", "allocate", pk_dev, "9999", "--ref", "ALLOC-2", env=good, check=False).returncode != 0, \
            "allocation above the reserve was accepted"
        assert "topup +237" in vault("alice", "topup", "237").stdout
        assert int(vault("alice", "balance").stdout.strip()) == 237
        assert "go-mvp-d200" in json.dumps(http_json("/v1/keysets"))
        rc = http_json("/v1/reconcile")
        assert rc["issued_outstanding"] == 237 and rc["fully_backed"] and rc["ledger_consistent"], rc
        print("  -> 237 loaded as 200+20+10+5+2; reconcile counts money, not proofs")

        step("4b", "Exact payment, then change-making via /v1/swap")
        tok37 = last_line(vault("alice", "pay", "37"))
        assert token_value(tok37) == 37
        assert int(vault("alice", "balance").stdout.strip()) == 200
        tok40 = last_line(vault("alice", "pay", "40"))  # only a 200 left: must swap
        assert token_value(tok40) == 40
        assert int(vault("alice", "balance").stdout.strip()) == 160
        assert "PENDING" not in vault("alice", "status").stdout
        res = vault("bob", "receive", tok37)
        assert "received +4 proofs" in res.stdout, res.stdout
        assert vault("bob", "settle", tok37).stdout.count("SETTLED OK") == 4
        assert vault("alice", "settle", tok40).stdout.count("SETTLED OK") == 2
        rc = http_json("/v1/reconcile")
        assert rc["issued_outstanding"] == 160 and rc["fully_backed"], rc
        print("  -> paid 37 exactly, paid 40 after swapping the 200; issued fell by what was settled")
        vault("bob", "wipe")

        step(5, "Real P2PK: proofs locked to Charlie's ed25519 key at issuance")
        sk_charlie, pk_charlie = keygen()
        assert "topup +2" in vault("alice", "topup", "2", "--lock", pk_charlie).stdout
        assert int(vault("alice", "balance").stdout.strip()) == 162
        token_charlie = last_line(vault("alice", "pay", "2", "--p2pk", pk_charlie))
        assert int(vault("alice", "balance").stdout.strip()) == 160
        res = vault("alice", "verify", token_charlie)
        assert "VERIFIED: 1 valid proof(s)" in res.stdout and pk_charlie in res.stdout
        print("  -> offline verify OK, lock visible inside the secret")

        # No claim key / the wrong key: refused. The lock cannot be stripped or relabelled.
        r = vault("alice", "settle", token_charlie, check=False)
        assert r.returncode != 0 and "SETTLE REJECTED" in r.stdout, r.stdout
        sk_thief, _ = keygen()
        r = vault("alice", "settle", token_charlie, "--claim-key", sk_thief, check=False)
        assert r.returncode != 0 and "SETTLE REJECTED" in r.stdout, r.stdout
        proofs = json.loads(base64.urlsafe_b64decode(token_charlie + "=" * (-len(token_charlie) % 4)))
        for p in proofs:  # attacker deletes lock fields / swaps in labels: nothing changes
            p.pop("p2pk", None)
            p["claimer"] = pk_charlie
            p["p2pk"] = pk_charlie
        relabelled = base64.urlsafe_b64encode(json.dumps(proofs).encode()).decode().rstrip("=")
        r = vault("alice", "settle", relabelled, check=False)
        assert r.returncode != 0 and "SETTLE REJECTED" in r.stdout, r.stdout
        # Value inflation: relabel a 2-proof as a 500 keyset => signature check must fail.
        for p in proofs:
            p["keyset_id"] = "go-mvp-d500"
        inflated = base64.urlsafe_b64encode(json.dumps(proofs).encode()).decode().rstrip("=")
        assert vault("alice", "verify", inflated, check=False).returncode != 0, "denomination relabel accepted"
        print("  -> no key / wrong key / relabelled / inflated token all REJECTED")

        res = vault("alice", "settle", token_charlie, "--claim-key", sk_charlie)
        assert res.stdout.count("SETTLED OK") == 1, res.stdout
        print("  -> Charlie's claim signature settles it")

        step(6, "Double-spend replay rejected; outbox keeps the emitted tokens")
        r = vault("alice", "settle", token_charlie, "--claim-key", sk_charlie, check=False)
        assert r.returncode != 0 and "SETTLE REJECTED" in r.stdout
        out = vault("alice", "outbox").stdout
        assert token_charlie in out, "emitted token missing from outbox"
        assert "outbox entry 1 acknowledged" in vault("alice", "ack", "1").stdout
        print("  -> replay blocked; token was recoverable from the outbox until acked")

        step(7, "Peer-to-peer offline hand-over to Bob")
        vault("alice", "topup", "1")
        token_to_bob = last_line(vault("alice", "pay", "1"))
        # Bob has no pinned keyset yet: receive pins it from the (TLS-pinned) kiosk.
        assert "received +1 proofs" in vault("bob", "receive", token_to_bob).stdout
        assert int(vault("bob", "balance").stdout.strip()) == 1
        assert "SETTLED OK" in vault("bob", "settle", token_to_bob).stdout
        print("  -> Bob received offline and settled")

        step(8, "Forged tokens are rejected (fake modulus, e=1)")
        def forge(**kw):
            base = {"secret": "fupi-counterfeit-cash-e2e", "sig": "AQIDBAU=", "e": 65537,
                    "keyset_id": "go-mvp-00"}
            base.update(kw)
            return base64.urlsafe_b64encode(json.dumps([base]).encode()).decode().rstrip("=")
        assert vault("alice", "verify", forge(n="FAKE_MODULUS_N"), check=False).returncode != 0
        assert vault("alice", "verify", forge(e=1), check=False).returncode != 0
        print("  -> forged tokens rejected")

        step(9, "5 concurrent settles of one token: exactly one winner")
        vault("alice", "topup", "1")
        race = last_line(vault("alice", "pay", "1"))
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
            results = list(ex.map(lambda _: vault("alice", "settle", race, check=False), range(5)))
        ok = sum(1 for r in results if r.returncode == 0)
        assert ok == 1, f"expected exactly 1 winner, got {ok}"
        print("  -> exactly 1 winner, 4 rejected")

        rc = http_json("/v1/reconcile")
        assert rc["fully_backed"] and rc["ledger_consistent"], rc
        assert rc["issued_outstanding"] == 160, rc  # what Alice still holds
        print(f"\nFinal reconcile: {rc}")
        print("\n" + "=" * 65)
        print("  ALL E2E STEPS PASSED")
        print("=" * 65)
    finally:
        kiosk.terminate()
        try:
            kiosk.wait(timeout=3)
        except Exception:
            kiosk.kill()
        cleanup()


if __name__ == "__main__":
    main()
