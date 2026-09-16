"""FUPI MVP vault: the bearer-cash wallet logic (sim of the hardware vault).

Holds proofs in an encrypted-at-rest JSON "flash" file. Generates secrets,
blinds -> kiosk signs -> unblinds -> verifies -> stores. Spends by handing a
proof over (QR string). Same logic is mirrored in pico_w/main.py.
"""

import base64
import json
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto import MintKeypair, modinv, hash_to_int  # noqa: E402

FLASH_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "vault_flash.json")


class Vault:
    def __init__(self, flash=FLASH_FILE):
        self.flash = flash
        self.proofs = []  # each: {secret, sig, n, e, keyset_id, p2pk?}
        self.journal = []
        self.load_flash()

    # ---- flash (sim of encrypted ESP32 flash) ----
    def load_flash(self):
        if os.path.exists(self.flash):
            with open(self.flash) as f:
                data = json.load(f)
            self.proofs = data.get("proofs", [])
            self.journal = data.get("journal", [])

    def save_flash(self):
        with open(self.flash, "w") as f:
            json.dump({"proofs": self.proofs, "journal": self.journal}, f, indent=1)

    def wipe_flash(self):
        self.proofs, self.journal = [], []
        if os.path.exists(self.flash):
            os.remove(self.flash)

    # ---- load: blind top-up against the kiosk ----
    def topup(self, kiosk, amount):
        """Request `amount` fresh proofs; kiosk blind-signs (never sees secrets)."""
        pub = kiosk.pubkey
        n, e = pub["n"], pub["e"]
        for _ in range(amount):
            secret = "fupi-" + secrets.token_hex(16)
            m = hash_to_int(secret.encode(), n)
            r = MintKeypair.random_blinder(n)
            m_blind = (m * pow(r, e, n)) % n
            s_blind = kiosk.sign_blinded(m_blind, 1)
            # unblind via modular inverse of r:
            s = (s_blind * modinv(r, n)) % n
            assert pow(s, e, n) == m, "vault: signature verify failed"
            self.proofs.append({"secret": secret, "sig": s, "n": n, "e": e,
                                "keyset_id": pub["keyset_id"]})
        self.journal.append(f"topup +{amount} (balance {self.balance()})")
        self.save_flash()
        print(f"  [vault] loaded +{amount} proofs (balance {self.balance()})")

    def balance(self):
        return len(self.proofs)

    # ---- spend: hand a bearer proof over (the money itself moves) ----
    def make_payment(self, amount, p2pk=None):
        assert self.balance() >= amount, "vault: insufficient bearer cash"
        chosen = self.proofs[:amount]
        del self.proofs[:amount]
        if p2pk:
            # NUT-11 style lock: only the holder of p2pk's key can settle these
            chosen = [dict(p, p2pk=p2pk) for p in chosen]
        token = base64.b64encode(json.dumps(chosen).encode()).decode()
        self.journal.append(f"spent {amount} (balance {self.balance()})")
        self.save_flash()
        return token

    @staticmethod
    def decode_token(token):
        return json.loads(base64.b64decode(token.encode()).decode())

    @staticmethod
    def verify_offline(token_proofs, pubkey):
        """Receiver-side offline check: signature + keyset, no network."""
        n, e = pubkey["n"], pubkey["e"]
        for p in token_proofs:
            if p.get("keyset_id") != pubkey.get("keyset_id"):
                return False
            m = hash_to_int(p["secret"].encode(), n)
            if pow(p["sig"], e, n) != m:
                return False
        return True
