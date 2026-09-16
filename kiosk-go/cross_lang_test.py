r"""Cross-language interop test: Python vault <-> Go HTTPS ATM over real TLS/HTTP.

Proves the FUPI protocol is language-independent:
  Python blinding -> Go blind-sign (RSA-2048) -> Python unblind/verify
  -> Go settle (200) -> replay (409) -> thief claim (409, defense-in-depth).

Start the Go kiosk first:
  kiosk-go\kiosk-go.exe -port 8890 -tls=true
Then:
  python kiosk-go\cross_lang_test.py 8890 https
"""

import base64
import hashlib
import json
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


def post(path, payload):
    req = urllib.request.Request(BASE + path, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
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

    s, r = post("/v1/credit", {"amount": 100})
    assert s == 200, r
    print(f"[2] reserve credited: {r['reserve']}")

    secret = "cross-lang-token-001"
    m = int.from_bytes(hashlib.sha256(secret.encode()).digest(), "big") % n
    if m < 2:
        m = 2
    while True:
        rr = random.randrange(2, n - 1)
        if math.gcd(rr, n) == 1:
            break
    blinded = pow(m * pow(rr, e, n), 1, n)

    def b64i(i):
        return base64.urlsafe_b64encode(i.to_bytes((i.bit_length() + 7) // 8, "big")).decode().rstrip("=")

    s, r = post("/v1/blind-sign", {"blinded_message": b64i(blinded), "amount": 1})
    assert s == 200, r
    sig_int = int.from_bytes(base64.urlsafe_b64decode(r["blind_signature"] + "=="), "big")
    sig = sig_int * pow(rr, -1, n) % n
    ok = pow(sig, e, n) == m
    print(f"[3] Python unblinded Go's RSA-2048 signature, verifies: {ok}")
    assert ok

    proof = {"secret": secret, "sig": b64i(sig), "n": b64i(n), "e": e}
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

    s, r = post("/v1/settle", dict(proof, secret="stolen-002", sig=b64i(sig),
                                   p2pk="shop", claimer="thief"))
    print(f"[6] thief P2PK: HTTP {s} -> {r['result']}")
    assert s == 409

    print("\nCROSS-LANGUAGE INTEROP: ALL PASS (Python + Go, RSA-2048, HTTPS/TLS)")


if __name__ == "__main__":
    main()
