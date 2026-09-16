"""FUPI MVP crypto: real Chaum-style RSA blind signatures, stdlib only.

Flow:  vault picks secret -> m = hash(secret) -> blinds with r -> kiosk signs
blind -> vault unblinds -> (m, s) is a bearer proof anyone can verify.
The kiosk NEVER sees m or the secret. Demo keys are RSA-512 (fast, NOT secure).
Production: RSA-2048+ / secp256k1 per Cashu NUT-00.
"""

import hashlib
import math
import random


def _egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = _egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def modinv(a, m):
    g, x, _ = _egcd(a % m, m)
    if g != 1:
        raise ValueError("no modular inverse")
    return x % m


def _is_probable_prime(n, rounds=10):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits):
    while True:
        c = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(c):
            return c


def hash_to_int(data: bytes, n: int) -> int:
    """Map arbitrary bytes to an integer in [2, n)."""
    v = int.from_bytes(hashlib.sha256(data).digest(), "big") % n
    return v if v > 1 else 2


class MintKeypair:
    """Kiosk signing key. 'd' never leaves the kiosk. Vault only gets (n, e)."""

    def __init__(self, bits=512):
        p = _gen_prime(bits // 2)
        q = _gen_prime(bits // 2)
        while q == p:
            q = _gen_prime(bits // 2)
        self.n = p * q
        phi = (p - 1) * (q - 1)
        self.e = 65537
        self.d = modinv(self.e, phi)

    def pub(self):
        return {"n": self.n, "e": self.e}

    def blind(self, m, r):
        return (m * pow(r, self.e, self.n)) % self.n

    @staticmethod
    def random_blinder(n):
        while True:
            r = random.randrange(2, n - 1)
            if math.gcd(r, n) == 1:
                return r

    def sign(self, m_blind):
        return pow(m_blind, self.d, self.n)

    def unblind(self, s_blind, r):
        return (s_blind * modinv(r, self.n)) % self.n

    def verify(self, m, s):
        return pow(s, self.e, self.n) == m
