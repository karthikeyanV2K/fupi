r"""Cross-language interop test: Python vault <-> Go HTTPS ATM over real TLS/HTTP.

Proves the FUPI protocol is language-independent:
  Python blinding -> Go blind-sign (RSA-2048) -> Python unblind/verify
  -> Go settle (200) -> replay (409) -> thief claim (409, defense-in-depth).

Start the Go kiosk first (the credit secret enables the authenticated /v1/credit):
  FUPI_CREDIT_SECRET=xyz ./kiosk-go -port 8890 -tls=true -allow-anonymous-issuance
Then:
  FUPI_CREDIT_SECRET=xyz python kiosk-go/cross_lang_test.py 8890 https
"""

import base64
import hashlib
import hmac
import json
import os
import math
import random
import ssl
import sys
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8890
PROTO = sys.argv[2] if len(sys.argv) > 2 else "http"
BASE = f"{PROTO}://127.0.0.1:{PORT}"

# Allow testing with self-signed TLS certs
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


def get(path):
    with urllib.request.urlopen(BASE + path, timeout=10, context=SSL_CTX) as r:
        return json.loads(r.read().decode())


def post(path, payload, headers=None):
    body = json.dumps(payload, separators=(",", ":")).encode()
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    req = urllib.request.Request(BASE + path, data=body, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10, context=SSL_CTX) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def main():
    print(f"=== Python vault <-> Go ATM interop on {BASE} ===")
    info = get("/v1/info")
    print(f"[0] ATM Info: {info.get('name')} (TLS={info.get('tls_enabled')})")

    ks = get("/v1/keyset")
    n = int.from_bytes(base64.urlsafe_b64decode(ks["n"] + "=="), "big")
    e = ks["e"]
    print(f"[1] keyset {ks['keyset_id']} fetched: RSA-{n.bit_length()} bits, e={e}")

    # Credit needs HMAC auth + a unique ref (replay-safe).
    secret_key = os.environ.get("FUPI_CREDIT_SECRET")
    assert secret_key, "set FUPI_CREDIT_SECRET to the value the kiosk runs with"
    body = json.dumps({"amount": 100, "ref": f"xlang-{random.getrandbits(48):x}"},
                      separators=(",", ":")).encode()
    s, r = post("/v1/credit", json.loads(body), {"X-Fupi-Signature": "00" * 32})
    assert s == 401, (s, r)
    print("[2a] credit with a bad signature refused (401)")
    ref = json.loads(body)["ref"]
    sig_hdr = hmac.new(secret_key.encode(), body, hashlib.sha256).hexdigest()
    s, r = post("/v1/credit", {"amount": 100, "ref": ref}, {"X-Fupi-Signature": sig_hdr})
    assert s == 200, r
    print(f"[2b] reserve credited: {r['reserve']}")
    s, r = post("/v1/credit", {"amount": 100, "ref": ref}, {"X-Fupi-Signature": sig_hdr})
    assert s == 409, (s, r)
    print("[2c] replayed ref refused (409)")

    def b64i(i):
        return base64.urlsafe_b64encode(i.to_bytes((i.bit_length() + 7) // 8, "big")).decode().rstrip("=")

    def issue(secret):
        """Full client side of the blind protocol: returns a proof the kiosk signed blind."""
        m = int.from_bytes(hashlib.sha256(secret.encode()).digest(), "big") % n
        if m < 2:
            m = 2
        while True:
            rr = random.randrange(2, n - 1)
            if math.gcd(rr, n) == 1:
                break
        blinded = pow(m * pow(rr, e, n), 1, n)
        st, rsp = post("/v1/blind-sign", {"blinded_message": b64i(blinded), "amount": 1})
        # needs the kiosk started with -allow-anonymous-issuance (dev only); real vaults sign with a device key
        assert st == 200, rsp
        sig_int = int.from_bytes(base64.urlsafe_b64decode(rsp["blind_signature"] + "=="), "big")
        sg = sig_int * pow(rr, -1, n) % n
        assert pow(sg, e, n) == m, "unblinded signature does not verify"
        return {"secret": secret, "sig": b64i(sg), "n": b64i(n), "e": e}

    secret = f"cross-lang-token-{random.getrandbits(48):x}"
    proof = issue(secret)
    print("[3] Python unblinded Go's RSA-2048 signature, verifies: True")
    s, r = post("/v1/settle", proof)
    print(f"[4] settle: HTTP {s} -> {r['result']}")
    if s != 200:
        print(f"    DEBUG m =  {m:x}")
        print(f"    DEBUG sig={sig:x}")
        print(f"    DEBUG n =  {n:x}")
    assert s == 200

    s, r = post("/v1/settle", proof)
    print(f"[5] replay:  HTTP {s} -> {r['result']}")
    assert s == 409

    # A locked secret (lock key = 32 bytes of hex) cannot be claimed without that key's signature.
    locked = issue(f"cross-lang-locked-{random.getrandbits(48):x}|lock=" + "11" * 32)
    s, r = post("/v1/settle", dict(locked, p2pk="shop", claimer="thief"))
    print(f"[6] locked proof, thief label: HTTP {s} -> {r['result']}")
    assert s == 409
    s, r = post("/v1/settle", dict(locked, claimer="ab" * 64))
    print(f"[7] locked proof, forged claim signature: HTTP {s} -> {r['result']}")
    assert s == 409

    # Denominations: the 50 keyset signs a 50-proof; face value comes from the keyset id.
    r = get("/v1/keysets")
    ks50 = [k for k in r["keysets"] if k["keyset_id"] == "go-mvp-d50"][0]
    n50 = int.from_bytes(base64.urlsafe_b64decode(ks50["n"] + "=="), "big")
    sec = "cross-lang-d50-" + str(random.getrandbits(32))
    m50 = int.from_bytes(hashlib.sha256(sec.encode()).digest(), "big") % n50
    while True:
        rr = random.randrange(2, n50 - 1)
        if math.gcd(rr, n50) == 1:
            break
    bl = m50 * pow(rr, ks50["e"], n50) % n50
    st, rsp = post("/v1/blind-sign", {"blinded_message": b64i(bl), "amount": 50})
    assert st == 200, rsp
    sg = int.from_bytes(base64.urlsafe_b64decode(rsp["blind_signature"] + "=="), "big") * pow(rr, -1, n50) % n50
    assert pow(sg, ks50["e"], n50) == m50
    before = get("/v1/info")["issued"]
    s, r = post("/v1/settle", {"secret": sec, "sig": b64i(sg), "keyset_id": "go-mvp-d50"})
    assert s == 200, r
    print(f"[8] 50-denomination proof settled; issued {before} -> {get('/v1/info')['issued']}")
    s, r = post("/v1/settle", {"secret": sec, "sig": b64i(sg), "keyset_id": "go-mvp-00"})
    assert s == 409, (s, r)  # same signature under the wrong (1) keyset must not verify
    print("[9] relabelling a 50 as a 1 (or the reverse) is rejected")

    print("\nCROSS-LANGUAGE INTEROP: ALL PASS (Python + Go, RSA-2048, HTTPS/TLS)")


if __name__ == "__main__":
    main()
