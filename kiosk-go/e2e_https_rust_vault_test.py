r"""End-to-end integration test: Self-Contained Go HTTPS ATM <-> Lightweight Rust Vault.

Tests the full FUPI payment lifecycle over real TLS / HTTPS:
  1. Inbound fiat reserve funding at Go HTTPS ATM
  2. Public keyset retrieval over TLS
  3. Chaum blind-signing (RSA-2048) over HTTPS
  4. Rust vault unblinding, on-chip signature verification, and atomic flash persistence
  5. Bearer token spending and P2PK key locking
  6. Recipient offline verification (zero network needed)
  7. Final settlement at Go HTTPS ATM over TLS
  8. Replay attack rejection (double-spend protection, HTTP 409)
  9. Unauthorized P2PK claimer rejection (HTTP 409)
 10. Legitimate P2PK settlement (HTTP 200)
"""

import os
import ssl
import subprocess
import sys
import time
import urllib.request

PORT = 8896
ATM_URL = f"https://127.0.0.1:{PORT}"
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
KIOSK_EXE = os.path.join(ROOT_DIR, "kiosk-go", "kiosk-go.exe")
VAULT_EXE = os.path.join(ROOT_DIR, "vault-rust", "target", "debug", "fupi-vault.exe")
TEST_STATE = os.path.join(ROOT_DIR, "test_atm_state_e2e.json")
TEST_FLASH = os.path.join(ROOT_DIR, "test_vault_flash_e2e.json")
TEST_FLASH_BOB = os.path.join(ROOT_DIR, "test_vault_flash_bob_e2e.json")

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


def cleanup():
    stems = [
        TEST_STATE, TEST_FLASH, TEST_FLASH_BOB,
        os.path.splitext(TEST_STATE)[0],
        os.path.splitext(TEST_FLASH)[0],
        os.path.splitext(TEST_FLASH_BOB)[0],
    ]
    for s in stems:
        for ext in ["", ".json", ".tmp", ".bak"]:
            f = s + ext
            if os.path.exists(f):
                try:
                    os.remove(f)
                except Exception:
                    pass


def wait_for_atm(proc, timeout=10):
    start = time.time()
    while time.time() - start < timeout:
        if proc.poll() is not None:
            raise RuntimeError(f"Go HTTPS ATM process exited prematurely with code {proc.returncode}")
        try:
            req = urllib.request.Request(f"{ATM_URL}/v1/info")
            with urllib.request.urlopen(req, timeout=1, context=SSL_CTX) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.15)
    return False


def run_vault(*args, check=True):
    cmd = [VAULT_EXE] + list(args) + [
        "--atm", ATM_URL,
        "--flash", TEST_FLASH,
        "--insecure",
    ]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if check and res.returncode != 0:
        print(f"FAILED cmd: {' '.join(cmd)}")
        print(f"STDOUT: {res.stdout}")
        print(f"STDERR: {res.stderr}")
        raise RuntimeError(f"Vault command failed with code {res.returncode}")
    return res


def run_vault_bob(*args, check=True):
    cmd = [VAULT_EXE] + list(args) + [
        "--atm", ATM_URL,
        "--flash", TEST_FLASH_BOB,
        "--insecure",
    ]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if check and res.returncode != 0:
        print(f"FAILED cmd: {' '.join(cmd)}")
        print(f"STDOUT: {res.stdout}")
        print(f"STDERR: {res.stderr}")
        raise RuntimeError(f"Bob's Vault command failed with code {res.returncode}")
    return res


def main():
    print("=================================================================")
    print("  FUPI End-to-End Test: Go HTTPS ATM <-> Lightweight Rust Vault  ")
    print("=================================================================")
    cleanup()

    # 1. Start Go HTTPS ATM
    print(f"\n[Step 1] Booting Go HTTPS ATM on port {PORT} with self-contained TLS...")
    kiosk_proc = subprocess.Popen(
        [KIOSK_EXE, "-port", str(PORT), "-tls=true", "-state", TEST_STATE, "-save-cert=false"],
        cwd=os.path.join(ROOT_DIR, "kiosk-go"),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        if not wait_for_atm(kiosk_proc):
            raise RuntimeError("Go HTTPS ATM failed to start or respond to TLS handshake")
        print("  -> Go HTTPS ATM is live and serving TLS!")

        # 2. Query ATM info via Rust Vault
        print("\n[Step 2] Querying ATM status & TLS fingerprint via Rust vault...")
        res = run_vault("info")
        print(res.stdout.strip())
        assert "TLS Active: true" in res.stdout
        assert "FUPI Self-Contained Go HTTPS ATM" in res.stdout

        # 3. Fund ATM reserve (bank rail simulation)
        print("\n[Step 3] Funding ATM fiat reserve (+100.00)...")
        res = run_vault("bank", "100")
        print(res.stdout.strip())
        assert "100.00" in res.stdout

        # 4. Topup: withdraw 5 blind-signed proofs
        print("\n[Step 4] Withdrawing 5 blind-signed bearer proofs (Chaum RSA-2048)...")
        res = run_vault("topup", "5")
        print(res.stdout.strip())
        assert "topup +5 proofs" in res.stdout

        # 5. Check vault balance
        print("\n[Step 5] Checking Rust vault bearer balance...")
        res = run_vault("balance")
        bal = int(res.stdout.strip())
        print(f"  -> Active bearer balance: {bal}")
        assert bal == 5

        # 6. Make payment of 2 tokens locked to 'merchant-charlie'
        print("\n[Step 6] Spending 2 tokens locked to P2PK key 'merchant-charlie'...")
        res = run_vault("pay", "2", "--p2pk", "merchant-charlie")
        token_charlie = res.stdout.strip().splitlines()[-1]
        print(f"  -> Generated Bearer Token: {token_charlie[:40]}... (length {len(token_charlie)})")

        res_bal = run_vault("balance")
        assert int(res_bal.stdout.strip()) == 3
        print(f"  -> Remaining vault balance: 3")

        # 7. Recipient verifies token OFFLINE (zero network)
        print("\n[Step 7] Recipient verifies token OFFLINE (zero network access)...")
        res_verify = run_vault("verify", token_charlie)
        print(res_verify.stdout.strip())
        assert "VERIFIED: 2 valid proof(s)" in res_verify.stdout
        assert "merchant-charlie" in res_verify.stdout

        # 8. Settle token at Go HTTPS ATM (legitimate claimer)
        print("\n[Step 8] Settling token at Go HTTPS ATM with claimer 'merchant-charlie'...")
        res_settle = run_vault("settle", token_charlie, "--claimer", "merchant-charlie")
        print(res_settle.stdout.strip())
        assert "SETTLED OK" in res_settle.stdout

        # 9. Double-spend / replay attack rejection
        print("\n[Step 9] Testing Double-Spend Rejection (replay attack)...")
        res_replay = run_vault("settle", token_charlie, "--claimer", "merchant-charlie", check=False)
        print(f"  Exit code: {res_replay.returncode} (expected error code 2)")
        print(f"  Output: {res_replay.stdout.strip()}")
        assert res_replay.returncode != 0
        assert "SETTLE REJECTED" in res_replay.stdout
        print("  -> Double-spend successfully BLOCKED by Go ATM (HTTP 409)!")

        # 10. Test P2PK theft protection
        print("\n[Step 10] Testing P2PK theft protection...")
        res_p2pk = run_vault("pay", "1", "--p2pk", "legitimate-owner")
        token_p2pk = res_p2pk.stdout.strip().splitlines()[-1]

        # Thief tries to claim it
        res_thief = run_vault("settle", token_p2pk, "--claimer", "thief", check=False)
        print(f"  Thief claim exit code: {res_thief.returncode}")
        print(f"  Thief claim output: {res_thief.stdout.strip()}")
        assert res_thief.returncode != 0
        assert "SETTLE REJECTED" in res_thief.stdout

        # Legitimate owner claims it
        res_owner = run_vault("settle", token_p2pk, "--claimer", "legitimate-owner")
        print(f"  Legitimate claim: {res_owner.stdout.strip()}")
        assert "SETTLED OK" in res_owner.stdout

        # 11. Peer-to-peer offline transfer and receive into Bob's vault
        print("\n[Step 11] Testing Peer-to-Peer Offline Transfer -> Bob's Vault Receive...")
        # Topup 1 more token into Alice's vault
        run_vault("topup", "1")
        res_alice_pay = run_vault("pay", "1")
        token_to_bob = res_alice_pay.stdout.strip().splitlines()[-1]

        # Bob receives the token into Bob's flash vault offline
        res_bob_recv = run_vault_bob("receive", token_to_bob)
        print(f"  Bob receive output: {res_bob_recv.stdout.strip()}")
        assert "received +1 proofs" in res_bob_recv.stdout

        res_bob_bal = run_vault_bob("balance")
        assert int(res_bob_bal.stdout.strip()) == 1
        print("  -> Bob's offline vault balance confirmed: 1")

        # Bob now settles his received token at the Go HTTPS ATM
        res_bob_settle = run_vault_bob("settle", token_to_bob)
        print(f"  Bob settle output: {res_bob_settle.stdout.strip()}")
        assert "SETTLED OK" in res_bob_settle.stdout

        # 12. Forged token with counterfeit modulus rejection
        print("\n[Step 12] Testing Forged Token Rejection (counterfeit modulus)...")
        import base64
        import json
        fake_proof = [{
            "secret": "fupi-counterfeit-cash-e2e",
            "sig": "AQIDBAU=",
            "n": "FAKE_MODULUS_N",
            "e": 65537,
            "keyset_id": "go-mvp-00",
        }]
        fake_token = base64.urlsafe_b64encode(json.dumps(fake_proof).encode()).decode().rstrip("=")
        res_fake = run_vault("verify", fake_token, check=False)
        print(f"  Fake token verify exit code: {res_fake.returncode}")
        assert res_fake.returncode != 0
        print("  -> Forged token with fake modulus successfully rejected!")

        # 13. Concurrency double-spend stress test over HTTPS
        print("\n[Step 13] Testing Concurrent Double-Spend Settlement Race (5 parallel HTTPS threads)...")
        run_vault("topup", "1")
        res_race_token = run_vault("pay", "1")
        race_token = res_race_token.stdout.strip().splitlines()[-1]

        import concurrent.futures

        def attempt_settle():
            return run_vault("settle", race_token, check=False)

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(attempt_settle) for _ in range(5)]
            results = [f.result() for f in futures]

        settled_ok = [r for r in results if r.returncode == 0]
        settled_rej = [r for r in results if r.returncode != 0]
        print(f"  Concurrent settlements: {len(settled_ok)} OK, {len(settled_rej)} REJECTED")
        assert len(settled_ok) == 1, f"Expected exactly 1 OK, got {len(settled_ok)}"
        assert len(settled_rej) == 4, f"Expected 4 rejected, got {len(settled_rej)}"
        print("  -> Concurrent double-spend race test PASSED: strictly 1 winner!")

        print("\n=================================================================")
        print("  ALL 13 TESTS PASSED: Go HTTPS ATM <-> Rust Vault Interop Verified! ")
        print("=================================================================\n")

    finally:
        kiosk_proc.terminate()
        try:
            kiosk_proc.wait(timeout=3)
        except Exception:
            kiosk_proc.kill()
        cleanup()


if __name__ == "__main__":
    main()
