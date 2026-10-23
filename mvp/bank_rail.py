"""FUPI real-bank rails: plug REAL money into the kiosk reserve.

The kiosk and vault never talk to a bank directly — they only see on_credit(amount).
These are the pluggable bank rails for that socket:

 1) WebhookBank       real HTTP server. Point Razorpay / Cashfree / Stripe /
                      your bank's corporate API callback at POST /webhook.
                      Verifies HMAC-SHA256 signature header per gateway spec
                      (Razorpay: X-Razorpay-Signature = hex HMAC of raw body).
 2) StatementBank     import REAL statement CSV exports (no API, no keys).
 3) LightningMintRail real cdk-mintd with CLN/LND/LDK backend: poll a mint
                      quote; when PAID -> credit reserve (README §9 sequence).

Nothing else in FUPI changes. demo_phase1.py supports --mode csv|webhook|lightning.
"""

import argparse
import csv
import hashlib
import hmac
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class _Rail:
    """Shared credit plumbing. A rail reports every inbound payment as
    (amount, ref). `ref` is the external payment reference (bank UTR, gateway
    order id, LN quote id): it is what makes a credit idempotent, because the
    same payment can be reported twice (webhook retries, re-imported statements).

    Bind either `on_credit(amount)` (in-process kiosk) or
    `on_credit_ref(amount, ref)` (kiosk over HTTP, which dedupes by ref)."""

    def __init__(self):
        self.on_credit = None
        self.on_credit_ref = None
        self.seen_refs = set()   # in-process replay guard (the kiosk also dedupes)

    def bind(self, fn):
        self.on_credit = fn

    def bind_ref(self, fn):
        self.on_credit_ref = fn

    def _emit(self, amount, ref):
        """Credit once per ref. Returns True if credited, False if it was a replay."""
        if not ref:
            raise ValueError("every credit needs a unique external reference")
        if ref in self.seen_refs:
            return False
        if self.on_credit_ref:
            self.on_credit_ref(amount, ref)
        elif self.on_credit:
            self.on_credit(amount)
        self.seen_refs.add(ref)
        return True


class WebhookBank(_Rail):
    """Receives REAL gateway/bank webhooks over HTTP with signature checks.

    The signing secret must be configured (FUPI_WEBHOOK_SECRET or `secret=`);
    there is no built-in default. `allow_dev_secret=True` exists only for the selftest.
    Webhooks without a unique `order_id`/`ref` are rejected, and a repeated ref is
    answered 409 without crediting again (gateways retry deliveries)."""

    DEV_SECRET = "dev-secret-selftest-only"
    MAX_BODY = 65536

    def __init__(self, secret=None, port=8787, allow_dev_secret=False):
        super().__init__()
        chosen = secret or os.environ.get("FUPI_WEBHOOK_SECRET")
        if not chosen:
            if not allow_dev_secret:
                raise ValueError("set FUPI_WEBHOOK_SECRET (the secret configured in your gateway)")
            chosen = self.DEV_SECRET
        self.secret = chosen.encode()
        self.port = port
        self.log = []
        self._server = None

    def verify_signature(self, body: bytes, signature: str) -> bool:
        if not signature:
            return False
        mac = hmac.new(self.secret, body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(mac, signature.strip())

    def _handler(self):
        bank = self

        class H(BaseHTTPRequestHandler):
            def _reply(self, code, body=b""):
                self.send_response(code)
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                try:
                    length = int(self.headers.get("Content-Length", 0))
                except ValueError:
                    return self._reply(400, b'{"error":"bad length"}')
                if length < 0 or length > bank.MAX_BODY:
                    return self._reply(413, b'{"error":"body too large"}')
                body = self.rfile.read(length)
                sig = (self.headers.get("X-Razorpay-Signature")
                       or self.headers.get("X-Fupi-Signature") or "")
                if not bank.verify_signature(body, sig):
                    return self._reply(401, b'{"error":"bad signature"}')
                try:
                    data = json.loads(body or b"{}")
                    amount = int(data.get("amount", 0))  # MINOR units (paise/cents)
                except (ValueError, TypeError, AttributeError):
                    return self._reply(400, b'{"error":"bad payload"}')
                ref = data.get("order_id") or data.get("ref")
                if amount <= 0:
                    return self._reply(400, b'{"error":"amount<=0"}')
                if not ref:
                    return self._reply(400, b'{"error":"order_id/ref required"}')
                major = amount / 100.0
                try:
                    credited = bank._emit(major, str(ref))
                except Exception as ex:  # kiosk refused / unreachable: tell the gateway to retry
                    print(f"  [bank:webhook] credit FAILED ref={ref}: {ex}")
                    return self._reply(502, b'{"error":"kiosk credit failed"}')
                if not credited:
                    print(f"  [bank:webhook] replay ignored ref={ref}")
                    return self._reply(409, b'{"error":"duplicate ref"}')
                bank.log.append({"ref": ref, "amount": major})
                print(f"  [bank:webhook] CREDIT {major:.2f} ref={ref} (signature OK)")
                self._reply(200, b'{"ok":true}')

            def log_message(self, *args):
                pass

        return H

    def start_background(self):
        self._server = ThreadingHTTPServer(("0.0.0.0", self.port), self._handler())
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def stop(self):
        if self._server:
            self._server.shutdown()

    def serve_forever(self):
        ThreadingHTTPServer(("0.0.0.0", self.port), self._handler()).serve_forever()

class StatementBank(_Rail):
    """Import REAL bank statement CSVs (HDFC/ICICI/SBI/Chase export format).
    No API, no keys: download statement CSV from net-banking, feed it here.

    Only DEPOSIT (credit) rows count. A withdrawal/debit is money leaving the
    account and is never a top-up. Each row gets a reference = hash of the whole
    row (statements carry a running balance, which makes rows unique), so
    re-importing the same or an overlapping statement does not credit twice.
    Use `narration_match` (e.g. "FUPI-") so unrelated deposits such as salary
    are not treated as kiosk top-ups."""

    def __init__(self, csv_path, kiosk_account=None, narration_match=None):
        super().__init__()
        self.csv_path = csv_path
        self.kiosk_account = kiosk_account
        self.narration_match = (narration_match or "").lower()
        self.log = []

    def import_statement(self):
        """Auto-detects columns: date/description/withdrawal/deposit/balance.
        Accepts headers like: deposit, credit, credit amount, deposits, amount(+)."""
        total = 0.0
        with open(self.csv_path, newline="", encoding="utf-8-sig") as f:
            sample = f.read(4096)
            f.seek(0)
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
            except csv.Error:
                # tiny samples defeat the Sniffer: fall back to comma, then tab
                dialect = csv.excel if sample.count(",") >= sample.count("\t") \
                    else csv.excel_tab
            reader = csv.DictReader(f, dialect=dialect)
            cols = {c.strip().lower(): c for c in (reader.fieldnames or [])}

            normed = [(re.sub(r"[^a-z0-9 ]", " ", c.strip().lower()).strip(), c)
                      for c in (reader.fieldnames or [])]

            def pick(*stems):
                """First column whose normalized name STARTS WITH a stem.
                'Deposit Amt.' -> 'deposit amt' matches stem 'deposit'."""
                for stem in stems:
                    for n, orig in normed:
                        if n.startswith(stem):
                            return orig
                return None

            deposit_col = pick("deposit", "credit")
            withdraw_col = pick("withdrawal", "withdrawl", "debit")
            amount_col = pick("amount")   # last resort: single Amount column
            desc_col = pick("narration", "description", "particulars",
                            "remarks", "detail")
            acct_col = pick("account")
            for row in reader:
                amount = 0.0
                if deposit_col:
                    amount = self._parse_amount(row.get(deposit_col))
                if not amount and amount_col and not withdraw_col:
                    amount = self._parse_amount(row.get(amount_col), signed=True)
                if not amount:
                    continue  # debits / withdrawals are never credited
                if self.kiosk_account and acct_col:
                    if self.kiosk_account not in (row.get(acct_col) or ""):
                        continue  # credit to a different account, skip
                desc = (row.get(desc_col) or "") if desc_col else ""
                if self.narration_match and self.narration_match not in desc.lower():
                    continue  # not addressed to the kiosk
                ref = "csv:" + hashlib.sha256(
                    json.dumps(row, sort_keys=True).encode()).hexdigest()[:32]
                if not self._emit(amount, ref):
                    print(f"  [bank:csv] SKIP already-credited row ({desc[:60]})")
                    continue
                total += amount
                self.log.append({"amount": amount, "desc": desc, "ref": ref})
                print(f"  [bank:csv] CREDIT {amount:.2f}  ({desc[:60]})")
        print(f"  [bank:csv] imported total {total:.2f} from {self.csv_path}")
        return total

    @staticmethod
    def _parse_amount(v, signed=False):
        """Parse '1,234.50', 'Rs. 50', '50.00 Cr'. Debits ('-50', '50 DR') return 0.
        With signed=True a single Amount column is used and only positive values count."""
        if not v:
            return 0.0
        s = str(v).replace(",", "").replace("Rs.", "").replace("INR", "").replace("\u20b9", "").strip()
        up = s.upper()
        if up.endswith("DR") or s.startswith("-") or (s.startswith("(") and s.endswith(")")):
            return 0.0
        s = re.sub(r"(?i)\s*(cr|dr)\.?$", "", s).strip("+ ")
        try:
            x = float(s)
        except ValueError:
            return 0.0
        return x if x > 0 else 0.0


class LightningMintRail(_Rail):
    """Real cdk-mintd (Rust) reserve source: NO bank license needed.
    Run:  cdk-mintd  (configure lightning backend: CLN/LND/LDK)
    Then poll a mint quote until PAID -> reserve credited. This is the README
    §9 sequence with a real mint instead of the mock."""

    def __init__(self, mint_url, poll_secs=2.0):
        super().__init__()
        self.mint_url = mint_url.rstrip("/")
        self.poll_secs = poll_secs
        self.log = []

    def _post(self, path, payload):
        req = urllib.request.Request(
            self.mint_url + path,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode())

    def _get(self, path):
        with urllib.request.urlopen(self.mint_url + path, timeout=10) as r:
            return json.loads(r.read().decode())

    def wait_for_topup(self, amount_minor=5000, unit="sat", timeout=600):
        """Create quote, print bolt11, block until PAID, credit reserve."""
        desc = "FUPI kiosk reserve top-up"
        q = self._post("/v1/mint/quote/bolt11",
                       {"amount": amount_minor, "unit": unit, "description": desc})
        quote_id, invoice = q["quote"], q.get("request") or q.get("invoice")
        print(f"  [mint] quote {quote_id}")
        print(f"  [mint] PAY THIS INVOICE (real money, real Lightning):")
        print(f"         {invoice}")
        deadline = time.time() + timeout
        while time.time() < deadline:
            st = self._get(f"/v1/mint/quote/bolt11/{quote_id}")
            if st.get("state") in ("PAID", "ISSUED", 2, 3):
                amt = amount_minor / (100.0 if unit in ("usd", "eur") else 1.0)
                print(f"  [mint] PAID -> reserve +{amt} {unit}")
                self.log.append({"quote": quote_id, "amount": amt, "unit": unit})
                self._emit(amt, "ln:" + str(quote_id))
                return amt
            time.sleep(self.poll_secs)
        raise TimeoutError("invoice not paid in time")

def demo_webhook_bank(kiosk, port=8787, wait_secs=120):
    """Run the real webhook server. Point your gateway at:
    http://YOUR-IP:8787/webhook  (set FUPI_WEBHOOK_SECRET to the same secret
    in the gateway dashboard). Then send a test payment from your bank app."""
    from kiosk import Kiosk  # noqa: F401  (type hint only)
    bank = WebhookBank(port=port)  # requires FUPI_WEBHOOK_SECRET
    bank.bind(kiosk.credit_reserve)
    print(f"\n=== REAL BANK MODE: webhook server on :{port} ===")
    print("  POST /webhook   JSON {\"amount\": <minor units>, \"order_id\": \"ref\"}")
    print("  Header X-Fupi-Signature (or X-Razorpay-Signature) = HMAC-SHA256")
    print(f"  waiting up to {wait_secs}s for a REAL payment ... (Ctrl+C to stop)")
    bank.serve_forever()


def main():
    ap = argparse.ArgumentParser(description="FUPI real-bank rails")
    ap.add_argument("--mode", choices=["webhook", "csv", "lightning", "selftest"],
                    default="selftest")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--csv", help="path to real bank statement CSV (SBI/HDFC/ICICI)")
    ap.add_argument("--mint", help="cdk-mintd base URL, e.g. http://127.0.0.1:3338")
    ap.add_argument("--atm", help="Go HTTPS ATM URL to credit (e.g. https://127.0.0.1:8890). "
                    "Needs FUPI_CREDIT_SECRET (same value the kiosk runs with)")
    ap.add_argument("--atm-cert", help="PEM of the ATM's (self-signed) certificate to trust, e.g. kiosk_cert.pem")
    ap.add_argument("--insecure", action="store_true",
                    help="DANGEROUS: do not verify the ATM's TLS certificate (local dev only)")
    ap.add_argument("--match", help="csv mode: only deposits whose narration contains this text (e.g. FUPI-)")
    ap.add_argument("--amount", type=int, default=5000,
                    help="minor units for lightning quote (sats)")
    args = ap.parse_args()

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from kiosk import Kiosk

    def credit_atm(amt, ref):
        """POST /v1/credit with an HMAC-SHA256 signature over the body and a unique ref."""
        if not args.atm:
            return
        import ssl
        secret = os.environ.get("FUPI_CREDIT_SECRET")
        if not secret:
            raise SystemExit("set FUPI_CREDIT_SECRET to credit the ATM")
        if args.insecure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx = ssl.create_default_context(cafile=args.atm_cert) if args.atm_cert \
                else ssl.create_default_context()
        body = json.dumps({"amount": float(amt), "ref": ref}, separators=(",", ":")).encode()
        sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        url = args.atm.rstrip("/") + "/v1/credit"
        req = urllib.request.Request(
            url, data=body, method="POST",
            headers={"Content-Type": "application/json", "X-Fupi-Signature": sig})
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
                res = json.loads(r.read().decode())
                print(f"  [bank -> atm] credited ref={ref}. New reserve: {res.get('reserve'):.2f}")
        except urllib.error.HTTPError as e:
            if e.code == 409:
                print(f"  [bank -> atm] ref={ref} was already credited (duplicate ignored)")
            else:
                raise RuntimeError(f"ATM refused credit ({e.code}): {e.read().decode()[:120]}")

    if args.mode == "selftest":
        print("=== bank_rail selftest (no real money moves) ===")
        b = WebhookBank(allow_dev_secret=True)
        body = json.dumps({"amount": 5000, "order_id": "test-1"}).encode()
        good = hmac.new(b.secret, body, hashlib.sha256).hexdigest()
        check_sig = b.verify_signature(body, good)
        check_bad = b.verify_signature(body, "deadbeef") is False
        print(f"  webhook signature accept/reject: {check_sig}/{check_bad}")
        csv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "sample_statement.csv")
        with open(csv_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["Date", "Narration", "Withdrawal Amt.", "Deposit Amt."])
            w.writerow(["01-09-2026", "UPI/RAZORPAY/KIOSK-TOPUP/1234", "", "5,000.00"])
            w.writerow(["02-09-2026", "UPI/RAZORPAY/KIOSK-TOPUP/1235", "", "2,500.50"])
            w.writerow(["03-09-2026", "SALARY", "", "75,000.00"])
        k = Kiosk()
        sb = StatementBank(csv_path, narration_match="KIOSK-TOPUP")
        sb.bind(k.credit_reserve)
        total = sb.import_statement()
        again = sb.import_statement()  # re-import must not credit again
        print(f"  kiosk reserve after import: {k.reserve} (imported {total}, re-import {again})")
        ok = (check_sig and check_bad and again == 0 and k.reserve == 5000 + 2500.50)
        print("  SELFTEST " + ("PASS" if ok else "FAIL"))
        os.remove(csv_path)
        sys.exit(0 if ok else 1)

    if args.mode == "webhook":
        if args.atm:
            wb = WebhookBank(port=args.port)
            wb.bind_ref(credit_atm)
            print(f"\n=== REAL BANK MODE: webhook server on :{args.port} -> Go ATM {args.atm} ===")
            wb.serve_forever()
        else:
            k = Kiosk.load() if os.path.exists(Kiosk.STATE_FILE) else Kiosk()
            k.__class__.STATE_FILE = Kiosk.STATE_FILE
            kiosk = k
            demo_webhook_bank(kiosk, port=args.port)

    if args.mode == "csv":
        if not args.csv:
            print("usage: python bank_rail.py --mode csv --csv statement.csv [--atm https://127.0.0.1:8890]")
            sys.exit(2)
        sb = StatementBank(args.csv, narration_match=args.match)
        if args.atm:
            sb.bind_ref(credit_atm)
            total = sb.import_statement()
            print(f"  SBI statement imported total: {total:.2f} credited to Go ATM {args.atm}")
        else:
            k = Kiosk.load() if os.path.exists(Kiosk.STATE_FILE) else Kiosk()
            sb.bind(k.credit_reserve)
            total = sb.import_statement()
            k.save()
            print(f"  kiosk state saved; reserve now {k.reserve} (+{total})")

    if args.mode == "lightning":
        if not args.mint:
            print("usage: python bank_rail.py --mode lightning --mint http://127.0.0.1:3338")
            sys.exit(2)
        k = Kiosk.load() if os.path.exists(Kiosk.STATE_FILE) else Kiosk()
        rail = LightningMintRail(args.mint)
        if args.atm:
            rail.bind_ref(credit_atm)
        else:
            rail.bind(k.credit_reserve)
        amt = rail.wait_for_topup(amount_minor=args.amount)
        if not args.atm:
            k.save()
        print(f"  kiosk reserve now (+{amt})")


if __name__ == "__main__":
    main()


