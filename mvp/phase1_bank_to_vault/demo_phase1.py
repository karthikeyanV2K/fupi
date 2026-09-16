r"""PHASE 1 DEMO: bank transfer -> kiosk reserve -> blind-signed tokens -> vault.

Plugs into real bank rails from bank_rail.py (StatementBank CSV import, WebhookBank, or Lightning).

Run:  python phase1_bank_to_vault/demo_phase1.py   (from X:\fupi\mvp)
"""

import argparse
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bank_rail import StatementBank, WebhookBank, LightningMintRail  # noqa: E402
from kiosk import Kiosk  # noqa: E402
from vault import Vault  # noqa: E402

AMOUNT = 50
DEFAULT_CSV = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bank_statement.csv")


def ensure_statement(path, amount):
    """Ensure a statement CSV exists with a deposit record for the kiosk."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Date", "Narration", "Withdrawal Amt.", "Deposit Amt."])
        w.writerow(["15-09-2026", "ATM WITHDRAWAL / KIOSK TOP-UP", "", f"{amount:.2f}"])


def main():
    parser = argparse.ArgumentParser(description="FUPI Phase 1 Demo: Bank -> Vault")
    parser.add_argument("--mode", choices=["csv", "webhook", "lightning"], default="csv",
                        help="Bank rail mode to use (default: csv)")
    parser.add_argument("--csv", help="Path to bank statement CSV export (HDFC/ICICI/SBI/etc.)")
    parser.add_argument("--port", type=int, default=8787, help="Port for webhook server")
    parser.add_argument("--mint", help="cdk-mintd URL for Lightning rail (e.g. http://127.0.0.1:3338)")
    parser.add_argument("--amount", type=int, default=AMOUNT, help="Top-up amount in units (default: 50)")
    args = parser.parse_args()

    vault = Vault()
    vault.wipe_flash()  # fresh vault for the demo
    kiosk = Kiosk()

    print("=== FUPI PHASE 1: bank -> vault (digital ATM) ===")

    if args.mode == "csv":
        csv_path = args.csv or DEFAULT_CSV
        if not args.csv:
            ensure_statement(csv_path, args.amount)
        print(f"\n[1] bank rail (Statement CSV): importing {csv_path}")
        bank = StatementBank(csv_path)
        bank.bind(kiosk.credit_reserve)
        bank.import_statement()

    elif args.mode == "webhook":
        print(f"\n[1] bank rail (Webhook): starting server on port {args.port}...")
        bank = WebhookBank(port=args.port)
        bank.bind(kiosk.credit_reserve)
        bank.start_background()
        print(f"  Awaiting webhook payment to credit reserve...")

    elif args.mode == "lightning":
        if not args.mint:
            print("Error: --mint <url> required for Lightning mode")
            sys.exit(1)
        print(f"\n[1] bank rail (Lightning): requesting invoice from {args.mint}...")
        rail = LightningMintRail(args.mint)
        rail.bind(kiosk.credit_reserve)
        rail.wait_for_topup(amount_minor=args.amount)

    load_amount = min(args.amount, int(kiosk.reserve)) if kiosk.reserve >= args.amount else int(kiosk.reserve)
    if load_amount <= 0:
        print("No reserve credited. Exiting.")
        sys.exit(1)

    print(f"\n[2] kiosk reserve now {kiosk.reserve:.2f}; blind top-up {load_amount} proofs")
    vault.topup(kiosk, load_amount)

    print(f"\n[3] DONE. bank's job is finished.")
    print(f"    vault balance: {vault.balance()} bearer proofs")
    print(f"    kiosk issued={kiosk.issued} reserve={kiosk.reserve:.2f} (1:1 OK)")
    print(f"    flash file: {vault.flash}")
    kiosk.save()
    print("    kiosk state saved (keys + reserve + spent-set)")


if __name__ == "__main__":
    main()
