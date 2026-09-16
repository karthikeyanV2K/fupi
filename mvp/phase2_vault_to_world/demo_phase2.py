"""PHASE 2 DEMO: vault pays friend / shop / website directly. No middleman.

Run:  python phase2_vault_to_world/demo_phase2.py   (from X:\\fupi\\mvp)
Requires: run demo_phase1 first (needs a loaded vault_flash.json).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kiosk import Kiosk  # noqa: E402
from vault import Vault  # noqa: E402

SHOP_P2PK = "shop-terminal-key-001"


def main():
    kiosk = Kiosk.load()  # SAME keys + reserve + spent-set as Phase 1

    vault = Vault()  # loads vault_flash.json from Phase 1
    if vault.balance() == 0:
        print("vault empty — run demo_phase1.py first")
        return

    print(f"loading kiosk state: {Kiosk.STATE_FILE}")

    print("=== FUPI PHASE 2: vault -> world (no middleman) ===")
    print(f"vault starts with {vault.balance()} bearer proofs\n")

    # ---- 10.1 friend: QR string, offline verify, settle ----
    print("[10.1] vault -> friend (5, over 'QR')")
    token = vault.make_payment(5)
    print(f"  QR payload (truncated): {token[:60]}...")
    friend_proofs = Vault.decode_token(token)
    ok = Vault.verify_offline(friend_proofs, {**kiosk.pubkey})
    print(f"  friend offline-verify vs cached keyset: {ok}")
    for p in friend_proofs:
        kiosk.settle(p)
    print(f"  vault balance: {vault.balance()}\n")

    # ---- 10.2 shop: NUT-18 style request, P2PK-locked ----
    print("[10.2] vault -> shop (12, P2PK-locked to shop key)")
    print(f"  shop request: amount=12 p2pk={SHOP_P2PK} (NUT-18 style)")
    token = vault.make_payment(12, p2pk=SHOP_P2PK)
    shop_proofs = Vault.decode_token(token)
    ok = Vault.verify_offline(shop_proofs, {**kiosk.pubkey})
    print(f"  shop offline-verify: {ok}")
    print("  [ATTACK] thief sniffs the token, tries to claim it as theirs")
    for p in shop_proofs:
        kiosk.settle(dict(p, claimer="thief-key-666"))  # P2PK lock rejects ALL
    print("  shop claims with its own key:")
    for p in shop_proofs:
        kiosk.settle(dict(p, claimer=SHOP_P2PK))  # shop claims with its key
    print(f"  vault balance: {vault.balance()}\n")

    # ---- 10.3 website: HTTP 402 + X-Cashu mock ----
    print("[10.3] vault -> website (3, HTTP 402 + X-Cashu)")
    print("  site -> 402 Payment Required, X-Cashu: amount=3")
    token = vault.make_payment(3)
    site_proofs = Vault.decode_token(token)
    for p in site_proofs:
        kiosk.settle(p)
    print("  site: 200 OK, article unlocked. No card rail, no gateway cut.")
    print(f"  vault balance: {vault.balance()}\n")

    # ---- double-spend demo: copy of an old token loses ----
    print("[ATTACK] copy of the friend token is settled AGAIN by a thief")
    for p in friend_proofs:
        kiosk.settle(p)  # all rejected
    print(f"\nDONE. vault balance: {vault.balance()}")
    print("bank saw ZERO of these payments (it only ever saw the Phase-1 load)")
    kiosk.save()  # persist spent-set so replayed tokens stay dead


if __name__ == "__main__":
    main()
