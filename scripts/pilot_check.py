#!/usr/bin/env python3
"""FUPI pilot daily check: does the kiosk's own bookkeeping still add up?

Run once a day (and after any incident):
  FUPI_CREDIT_SECRET=... python3 scripts/pilot_check.py --atm https://127.0.0.1:8890 \
      --pin-tls <sha256> --bank-balance 4820.00 --max-total 5000

Exit code 0 = all checks passed (warnings allowed), 1 = at least one FAIL: stop issuing
until it is explained. Every run appends one JSON line to --log, which is the pilot's
audit trail and the baseline for the next day's rollback / tamper checks.
"""

import argparse
import hashlib
import hmac
import http.client
import json
import os
import ssl
import sys
import time
import urllib.parse

FAIL, WARN, OK = "FAIL", "WARN", "ok"
EPS = 0.005


def evaluate(rc, prev=None, bank=None, max_total=None, report=None):
    """Pure function: returns [(level, message)]. rc = /v1/reconcile, prev = last logged rc."""
    out = []

    def add(level, msg):
        out.append((level, msg))

    issued, owed = rc["issued_outstanding"], rc.get("owed_total", 0)
    reserve = rc["reserve"]

    # 1. The kiosk's own invariants.
    add(OK if rc["fully_backed"] else FAIL, f"fully_backed (reserve {reserve} >= issued {issued} + owed {owed})")
    add(OK if rc["ledger_consistent"] else FAIL, "ledger_consistent (deposits - payouts == reserve)")
    if reserve + EPS < issued + owed:
        add(FAIL, "reserve is below issued + owed")
    if min(issued, owed, rc.get("settled_total", 0), rc.get("paid_total", 0)) < 0:
        add(FAIL, "a total is negative")
    if rc.get("paid_total", 0) > rc.get("settled_total", 0):
        add(FAIL, "paid_total exceeds settled_total")
    if rc.get("devices_loaded", 0) > rc.get("devices_allocated", 0) + EPS:
        add(FAIL, f"devices loaded {rc['devices_loaded']} > allocated {rc['devices_allocated']}")

    # 2. The real bank account is the source of truth for the reserve.
    if bank is not None:
        if bank + EPS < reserve:
            add(FAIL, f"bank balance {bank:.2f} is BELOW reserve {reserve:.2f}: tokens are not fully backed in cash")
        elif bank > reserve + EPS:
            add(WARN, f"bank balance {bank:.2f} is above reserve {reserve:.2f}: an unrecorded deposit (credit it with its UTR)")
        else:
            add(OK, f"bank balance matches reserve ({reserve:.2f})")
    else:
        add(WARN, "no --bank-balance given: reserve was not compared with the real bank")

    # 3. Pilot-wide cap.
    if max_total is not None:
        used = rc.get("devices_allocated", 0)
        add(OK if used <= max_total + EPS else FAIL, f"allocated {used} within pilot cap {max_total}")

    # 4. Day-over-day: things that may only grow must not shrink (state rollback / tampering).
    if prev:
        for key in ("deposits_total", "deposit_count", "settled_count", "settled_total", "paid_total",
                    "devices_allocated", "devices_loaded"):
            if rc.get(key, 0) + EPS < prev.get(key, 0):
                add(FAIL, f"{key} went DOWN ({prev.get(key)} -> {rc.get(key)}): state rolled back?")
        d_res = reserve - prev["reserve"]
        d_exp = (rc["deposits_total"] - prev["deposits_total"]) - (rc.get("paid_total", 0) - prev.get("paid_total", 0))
        if abs(d_res - d_exp) > EPS:
            add(FAIL, f"reserve moved {d_res:+.2f} but deposits-payouts explain {d_exp:+.2f}")
        else:
            add(OK, f"reserve change since last run explained ({d_res:+.2f})")
    else:
        add(OK, "first run: baseline recorded")

    # 5. The settlement log must add up to what reconcile says (needs the operator secret).
    if report is not None:
        logged = sum(e["amount"] for e in report.get("entries", []))
        if len(report.get("entries", [])) < 1000:  # full history returned
            add(OK if logged == rc.get("settled_total", 0) else FAIL,
                f"settlement log sums to {logged}, reconcile says settled_total {rc.get('settled_total', 0)}")
        for m in report.get("merchants", []):
            if m["owed"] < 0 or m["owed"] != m["settled"] - m["paid"]:
                add(FAIL, f"merchant {m['merchant']} balance is inconsistent: {m}")
        owed_sum = sum(m["owed"] for m in report.get("merchants", []))
        if owed_sum != owed:
            add(FAIL, f"merchant balances sum to {owed_sum}, reconcile owed_total is {owed}")
    else:
        add(WARN, "no FUPI_CREDIT_SECRET: settlement log not cross-checked")
    return out


def fetch(base, uri, pin=None, insecure=False, headers=None):
    u = urllib.parse.urlparse(base)
    if u.scheme == "https":
        ctx = ssl.create_default_context()
        if pin or insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(u.hostname, u.port or 443, context=ctx, timeout=10)
    else:
        conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=10)
    conn.connect()
    if pin:  # trust ONLY this certificate
        der = conn.sock.getpeercert(binary_form=True)
        if hashlib.sha256(der).hexdigest() != pin.lower().replace(":", ""):
            conn.close()
            raise SystemExit("TLS certificate does not match --pin-tls: refusing to talk to this server")
    conn.request("GET", uri, headers=headers or {})
    resp = conn.getresponse()
    body = resp.read().decode()
    conn.close()
    if resp.status != 200:
        raise SystemExit(f"{uri}: HTTP {resp.status} {body[:200]}")
    return json.loads(body)


def last_log_entry(path):
    try:
        with open(path) as f:
            lines = [ln for ln in f.read().splitlines() if ln.strip()]
        return json.loads(lines[-1])["reconcile"] if lines else None
    except FileNotFoundError:
        return None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--atm", required=True)
    ap.add_argument("--pin-tls", help="SHA-256 of the kiosk certificate (recommended)")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification (localhost dev only)")
    ap.add_argument("--bank-balance", type=float, help="current balance of the reserve bank account")
    ap.add_argument("--max-total", type=float, help="pilot-wide cap on allocated quota")
    ap.add_argument("--log", default="pilot_log.jsonl")
    args = ap.parse_args(argv)

    rc = fetch(args.atm, "/v1/reconcile", args.pin_tls, args.insecure)
    report = None
    secret = os.environ.get("FUPI_CREDIT_SECRET")
    if secret:
        uri = "/v1/settlements?since=0&limit=1000"
        sig = hmac.new(secret.encode(), uri.encode(), hashlib.sha256).hexdigest()
        report = fetch(args.atm, uri, args.pin_tls, args.insecure, {"X-Fupi-Signature": sig})

    results = evaluate(rc, last_log_entry(args.log), args.bank_balance, args.max_total, report)
    for level, msg in results:
        print(f"[{level:>4}] {msg}")
    failed = any(level == FAIL for level, _ in results)
    with open(args.log, "a") as f:
        f.write(json.dumps({"ts": int(time.time()), "reconcile": rc, "bank_balance": args.bank_balance,
                            "failed": failed, "results": results}) + "\n")
    print("RESULT:", "FAIL - stop issuing and investigate" if failed else "PASS")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
