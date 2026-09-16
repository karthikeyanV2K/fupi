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

```powershell
# 1. Inspect ATM status and TLS certificate fingerprint over HTTPS
fupi-vault info --atm https://127.0.0.1:8890 --insecure

# 2. Fund ATM reserve (bank deposit simulation)
fupi-vault bank 100 --atm https://127.0.0.1:8890 --insecure

# 3. Withdraw 5 blind-signed bearer proofs from the ATM (blind topup)
fupi-vault topup 5 --atm https://127.0.0.1:8890 --insecure

# 4. Check active bearer balance
fupi-vault balance

# 5. Spend 2 tokens (emits bearer payment string, deducts from flash)
fupi-vault pay 2 --p2pk merchant-bob

# 6. Recipient verifies token OFFLINE (ZERO network required, checks trusted keyset)
fupi-vault verify <token_string>

# 7. Recipient receives token into flash vault OFFLINE (increases balance, zero network)
fupi-vault receive <token_string>

# 8. Settle token at Go HTTPS ATM
fupi-vault settle <token_string> --claimer merchant-bob --atm https://127.0.0.1:8890 --insecure

# 9. View vault status and journal history
fupi-vault status

# 10. Wipe vault memory (duress / tamper event)
fupi-vault wipe
```

---

## 4. Interactive REPL Mode (Raspberry Pi Serial / SSH)

Run:
```powershell
fupi-vault repl --atm https://127.0.0.1:8890
```

Matches the Raspberry Pi Pico W console commands:
```text
fupi-vault> TOPUP 5
fupi-vault> PAY 2 merchant-bob
fupi-vault> VERIFY <token>
fupi-vault> SETTLE <token> merchant-bob
fupi-vault> STATUS
fupi-vault> WIPE
```

---

## 5. Security & Verification Record

- **Chaum Blinding Math:** `m = SHA256(secret) % N`, `m_blind = (m * r^e) % N`, `sig = (s_blind * r^-1) % N`.
- **Local Verification:** `pow(sig, e, n) == m`. Tested against Go ATM mint keys.
- **Double-Spend Protection:** First-to-settle-wins; replay attempts return HTTP 409 Conflict.
- **P2PK Lock Enforcement:** Only the specified claimer can settle locked tokens.
