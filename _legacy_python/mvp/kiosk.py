"""FUPI MVP kiosk (mini mint): reserve, keyset, blind-sign, melt, settle.

Models README §12: a kiosk, not a bank. It blind-signs tokens against its
reserve 1:1 and settles tokens handed to it. It never sees token serials at
issue time (blind) and blocks double-spends at settle time.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto import MintKeypair, hash_to_int  # noqa: E402


class Kiosk:
    KEYSET_ID = "mvp-00"

    def __init__(self):
        self.keypair = MintKeypair(bits=512)
        self.reserve = 0      # fiat/LN backing credited via bank webhook
        self.issued = 0       # tokens outstanding (must stay <= reserve)
        self.spent = set()    # spent secrets -> double-spend guard
        self.log = []

    @property
    def pubkey(self):
        return {"keyset_id": self.KEYSET_ID, **self.keypair.pub()}

    # ---- persistence: same keys + reserve + spent-set across demo runs ----
    STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "kiosk_state.json")

    def save(self, path=None):
        path = path or self.STATE_FILE
        with open(path, "w") as f:
            json.dump({"n": self.keypair.n, "e": self.keypair.e,
                       "d": self.keypair.d, "reserve": self.reserve,
                       "issued": self.issued, "spent": sorted(self.spent)}, f)

    @classmethod
    def load(cls, path=None):
        path = path or cls.STATE_FILE
        with open(path) as f:
            data = json.load(f)
        k = cls.__new__(cls)
        kp = MintKeypair.__new__(MintKeypair)
        kp.n, kp.e, kp.d = data["n"], data["e"], data["d"]
        k.keypair = kp
        k.reserve, k.issued = data["reserve"], data["issued"]
        k.spent = set(data["spent"])
        k.log = []
        return k

    # ---- reserve side (bank webhook hits this) ----
    def credit_reserve(self, amount):
        self.reserve += amount
        self.log.append(f"reserve +{amount} (total {self.reserve})")

    # ---- issue side: blind-sign, never sees the secret ----
    def sign_blinded(self, m_blind, amount=1):
        if self.issued + amount > self.reserve:
            raise ValueError("kiosk: insufficient reserve (1:1 rule)")
        s_blind = self.keypair.sign(m_blind)
        self.issued += amount
        return s_blind

    # ---- settle side: melt/swap/accept, first-to-settle-wins ----
    def settle(self, proof, amount=1):
        secret, s = proof["secret"], proof["sig"]
        if secret in self.spent:
            print("  [kiosk] REJECTED: double-spend (already settled)")
            return False
        n, e = proof["n"], proof["e"]
        m = hash_to_int(secret.encode(), n)
        if pow(s, e, n) != m:
            print("  [kiosk] REJECTED: bad signature")
            return False
        if proof.get("p2pk") and proof.get("p2pk") != proof.get("claimer"):
            print("  [kiosk] REJECTED: P2PK lock (not the owner)")
            return False
        self.spent.add(secret)
        self.issued -= amount
        self.log.append(f"settled {amount} (issued now {self.issued})")
        print("  [kiosk] settled OK (first-to-settle-wins)")
        return True
