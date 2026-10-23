# FUPI Lightweight Rust Vault (`fupi-vault`)

Lightweight, memory-safe offline digital cash vault for **Raspberry Pi** (Linux SBCs), embedded devices, and cross-platform desktop/server.

Holds mint-signed bearer proofs in power-loss resilient atomic flash memory. Implements Chaum blind signatures over RSA-2048, receiver-side offline verification (zero network needed), and native TLS connections to the FUPI Go HTTPS ATM.

---

## 1. Why Rust for the Vault Tier?

- **Zero Garbage Collection on Money Paths:** No GC pauses, deterministic execution times.
- **Atomic Flash Journaling:** Uses `.tmp` writes followed by atomic rename to prevent state corruption on unexpected Raspberry Pi power cuts.
- **On-Chip Verification:** Verifies RSA blind signatures locally before any proof is committed to flash.
- **Offline Pay & Verification:** Emits self-contained bearer tokens (Base64 JSON) that any recipient can verify mathematically with zero network access.
- **Pure-Rust TLS:** Uses `rustls` (no OpenSSL C dependency). Seamlessly connects to self-contained Go HTTPS ATMs.

---

## 2. Quickstart & Build

```powershell
# Build release binary (lean, statically linkable)
cd X:\fupi\vault-rust
cargo build --release

# Run unit and integration tests
cargo test
```

Binary output: `target/release/fupi-vault.exe` (or `target/release/fupi-vault` on Linux/RPi).

---

## 3. CLI Commands

TLS is **strict by default**. The kiosk's self-signed certificate is trusted by pinning its SHA-256
fingerprint (shown in the kiosk log and by `info`/the dashboard); `--insecure` exists for local development only.

```bash
ATM=https://127.0.0.1:8890
PIN=<sha256 fingerprint printed by the kiosk>

# 1. Pin the ATM's signing keyset once (compare the printed modulus fingerprint out-of-band).
#    After pinning, a changed keyset is refused unless you run `pin --force`.
fupi-vault pin --atm $ATM --pin-tls $PIN

# 2. OPERATOR: credit the ATM reserve for a verified bank payment (unique --ref per payment)
FUPI_CREDIT_SECRET=... fupi-vault bank 100 --ref UTR-123 --atm $ATM --pin-tls $PIN

# 3. Withdraw 5 blind-signed bearer proofs (optionally locked to a payee's ed25519 key)
fupi-vault topup 5 --atm $ATM --pin-tls $PIN
fupi-vault topup 2 --lock <payee_pubkey_hex> --atm $ATM --pin-tls $PIN

# 4. Check active bearer balance
fupi-vault balance

# 5. Spend 2 proofs (unlocked ones; or --p2pk <pubkey> to spend proofs locked to that key).
#    The token is also kept in the outbox until you `ack` it, so a lost screen never loses money.
fupi-vault pay 2
fupi-vault outbox
fupi-vault ack 1

# 6. Receiver verifies OFFLINE against the pinned keyset (zero network). No pinned keyset = refuse.
fupi-vault verify <token_string>

# 7. Receiver imports the token into its flash vault OFFLINE
fupi-vault receive <token_string>

# 8. Payee creates a claim key once, then settles locked proofs with it
fupi-vault keygen
fupi-vault settle <token_string> --claim-key <secret_key_hex> --atm $ATM --pin-tls $PIN

# 9. Vault status and journal / wipe (duress or tamper)
fupi-vault status
fupi-vault wipe
```

---

## 4. Interactive REPL Mode (Raspberry Pi Serial / SSH)

Run:
```powershell
fupi-vault repl --atm https://127.0.0.1:8890 --pin-tls <fingerprint>
```

Matches the Raspberry Pi Pico W console commands:
```text
fupi-vault> TOPUP 5
fupi-vault> PAY 2 [lock-pubkey-hex]
fupi-vault> VERIFY <token>
fupi-vault> SETTLE <token> [claim-key-hex]
fupi-vault> STATUS
fupi-vault> WIPE
```

---

## 5. Security & Verification Record

- **Chaum Blinding Math:** `m = SHA256(secret) % N`, `m_blind = (m * r^e) % N`, `sig = (s_blind * r^-1) % N`.
- **Verification uses the pinned keyset only:** `n` and `e` are never taken from a token. A token that repeats them must match the pinned values; with no pinned keyset nothing verifies (this closes the `e = 1` and own-modulus forgeries).
- **Keyset pinning:** first use pins; any later change (modulus or id) is refused until `pin --force`.
- **TLS:** strict by default; `--pin-tls <sha256>` trusts exactly one certificate; `--insecure` is explicit and warns.
- **Double-Spend Protection:** First-to-settle-wins; replay attempts return HTTP 409 Conflict.
- **P2PK lock enforcement:** the lock is an ed25519 public key inside the blind-signed secret; settlement needs a signature by that key (`--claim-key`). Locks can only be set at issuance (`topup --lock`).
- **No lost tokens:** `pay` stores the emitted token in the `outbox` in the same atomic save that removes the proofs.

Known limits: flash is plaintext JSON (no encryption / PIN / secure element yet), no seed restore, 1 proof = 1 unit. See `docs/CODE_PLAN.md`.
