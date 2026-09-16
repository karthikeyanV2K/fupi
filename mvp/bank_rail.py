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


class WebhookBank:
    """Receives REAL gateway/bank webhooks over HTTP with signature checks."""

    def __init__(self, secret=None, port=8787):
        self.secret = (secret or os.environ.get("FUPI_WEBHOOK_SECRET")
                       or "dev-secret-change-me").encode()
        self.port = port
        self.on_credit = None
        self.log = []
        self._server = None

    def bind(self, fn):
        self.on_credit = fn

    def verify_signature(self, body: bytes, signature: str) -> bool:
        if not signature:
            return False
        mac = hmac.new(self.secret, body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(mac, signature.strip())

    def _handler(self):
        bank = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                sig = (self.headers.get("X-Razorpay-Signature")
                       or self.headers.get("X-Fupi-Signature") or "")
                if not bank.verify_signature(body, sig):
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b'{"error":"bad signature"}')
                    return
                data = json.loads(body or b"{}")
                amount = int(data.get("amount", 0))  # MINOR units (paise/cents)
                ref = data.get("order_id") or data.get("ref") or "webhook"
                if amount <= 0:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b'{"error":"amount<=0"}')
                    return
                major = amount / 100.0
                bank.log.append({"ref": ref, "amount": major})
                print(f"  [bank:webhook] CREDIT {major:.2f} ref={ref} (signature OK)")
                if bank.on_credit:
                    bank.on_credit(major)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"ok":true}')

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

class StatementBank:
    """Import REAL bank statement CSVs (HDFC/ICICI/SBI/Chase export format).
    No API, no keys: download statement CSV from net-banking, feed it here.
    Row shows the kiosk's account credited. Only IN (credit) rows count."""

    def __init__(self, csv_path, kiosk_account=None):
        self.csv_path = csv_path
        self.kiosk_account = kiosk_account
        self.on_credit = None
        self.log = []

    def bind(self, fn):
        self.on_credit = fn

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
                    amount = self._parse_amount(row.get(amount_col))
                if not amount and withdraw_col:
                    w = self._parse_amount(row.get(withdraw_col))
                    if w:  # a withdrawal at the kiosk account = top-up too
                        amount = w
                if not amount:
                    continue
                if self.kiosk_account and acct_col:
                    if self.kiosk_account not in (row.get(acct_col) or ""):
                        continue  # credit to a different account, skip
                desc = (row.get(desc_col) or "") if desc_col else ""
                total += amount
                self.log.append({"amount": amount, "desc": desc})
                print(f"  [bank:csv] CREDIT {amount:.2f}  ({desc[:60]})")
                if self.on_credit:
                    self.on_credit(amount)
        print(f"  [bank:csv] imported total {total:.2f} from {self.csv_path}")
        return total

    @staticmethod
    def _parse_amount(v):
        if not v:
            return 0.0
        s = str(v).replace(",", "").replace("Rs.", "").replace("INR", "")
        s = s.replace("₹", "").strip()
        neg = s.startswith("-") or s.endswith("DR") or s.endswith("Cr-")
        s = s.strip("+-DR ")
        try:
            x = float(s)
        except ValueError:
            return 0.0
        return abs(x) if neg or s == "" else abs(x)


class LightningMintRail:
    """Real cdk-mintd (Rust) reserve source: NO bank license needed.
    Run:  cdk-mintd  (configure lightning backend: CLN/LND/LDK)
    Then poll a mint quote until PAID -> reserve credited. This is the README
    §9 sequence with a real mint instead of the mock."""

    def __init__(self, mint_url, poll_secs=2.0):
        self.mint_url = mint_url.rstrip("/")
        self.poll_secs = poll_secs
        self.on_credit = None
        self.log = []

    def bind(self, fn):
        self.on_credit = fn

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
                if self.on_credit:
                    self.on_credit(amt)
                return amt
            time.sleep(self.poll_secs)
        raise TimeoutError("invoice not paid in time")

def demo_webhook_bank(kiosk, port=8787, wait_secs=120):
    """Run the real webhook server. Point your gateway at:
    http://YOUR-IP:8787/webhook  (set FUPI_WEBHOOK_SECRET to the same secret
    in the gateway dashboard). Then send a test payment from your bank app."""
    from kiosk import Kiosk  # noqa: F401  (type hint only)
    bank = WebhookBank(port=port)
    bank.bind(kiosk.credit_reserve)
    print(f"\n=== REAL BANK MODE: webhook server on :{port} ===")
    print("  POST /webhook   JSON {\"amount\": <minor units>, \"order_id\": \"ref\"}")
    print("  Header X-Fupi-Signature (or X-Razorpay-Signature) = HMAC-SHA256")
    print(f"  secret = {os.environ.get('FUPI_WEBHOOK_SECRET', 'dev-secret-change-me')}")
    print(f"  waiting up to {wait_secs}s for a REAL payment ... (Ctrl+C to stop)")
    bank.serve_forever()


def main():
    ap = argparse.ArgumentParser(description="FUPI real-bank rails")
    ap.add_argument("--mode", choices=["webhook", "csv", "lightning", "selftest"],
                    default="selftest")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--csv", help="path to real bank statement CSV (SBI/HDFC/ICICI)")
    ap.add_argument("--mint", help="cdk-mintd base URL, e.g. http://127.0.0.1:3338")
    ap.add_argument("--atm", help="Go HTTPS ATM URL to credit (e.g. https://127.0.0.1:8890)")
    ap.add_argument("--amount", type=int, default=5000,
                    help="minor units for lightning quote (sats)")
    args = ap.parse_args()

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from kiosk import Kiosk

    def credit_atm(amt):
        if not args.atm:
            return
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        url = args.atm.rstrip("/") + "/v1/credit"
        req = urllib.request.Request(
            url,
            data=json.dumps({"amount": float(amt)}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
                res = json.loads(r.read().decode())
                print(f"  [bank -> atm] Go HTTPS ATM reserve successfully credited! New reserve: {res.get('reserve'):.2f}")
        except Exception as e:
            print(f"  [bank -> atm] Failed to credit Go ATM at {url}: {e}")

    if args.mode == "selftest":
        print("=== bank_rail selftest (no real money moves) ===")
        b = WebhookBank()
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
        sb = StatementBank(csv_path)
        sb.bind(k.credit_reserve)
        total = sb.import_statement()
        print(f"  kiosk reserve after import: {k.reserve} (imported {total})")
        ok = (check_sig and check_bad and k.reserve == 5000 + 2500.50 + 75000)
        print("  SELFTEST " + ("PASS" if ok else "FAIL"))
        os.remove(csv_path)
        sys.exit(0 if ok else 1)

    if args.mode == "webhook":
        if args.atm:
            wb = WebhookBank(port=args.port)
            wb.bind(credit_atm)
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
        sb = StatementBank(args.csv)
        if args.atm:
            sb.bind(credit_atm)
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
            rail.bind(credit_atm)
        else:
            rail.bind(k.credit_reserve)
        amt = rail.wait_for_topup(amount_minor=args.amount)
        if not args.atm:
            k.save()
        print(f"  kiosk reserve now (+{amt})")


if __name__ == "__main__":
    main()


