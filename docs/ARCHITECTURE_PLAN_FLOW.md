# FUPI System Architecture & Execution Flow Plan
## Lightweight Rust Vault & Self-Contained Go HTTPS ATM

> **Document Version:** 1.0.0  
> **Target Platforms:** Raspberry Pi (Raspberry Pi OS / Linux SBC), Raspberry Pi Pico W (MicroPython), Cross-Platform Desktop/Server.  
> **Security Baseline:** Chaum Blind Signatures (RSA-2048), Native TLS 1.2/1.3, Atomic Flash Storage, Zero-Middleman Bearer Payments.

---

## 1. System Topology & Architecture

```
                          ┌─────────────────────────────────────────────────────────┐
                          │         FUPI SELF-CONTAINED HTTPS ATM ("kiosk-go")      │
                          │                                                         │
   BANK RAIL (1 load)     │  ┌─────────────────┐  ┌──────────────────────────────┐  │
   NEFT / IMPS / LN       │  │  1:1 Cash       │  │  Chaum Blind Signer          │  │
   ══════════════════════►│  │  Reserve Vault  │◄─┤  RSA-2048 (e=65537)          │  │
   salary deposit /       │  │  (Audited)      │  │  (Never sees token secrets)  │  │
   ATM funding            │  └────────┬────────┘  └──────────────┬───────────────┘  │
                          │           │                          │                  │
                          │  ┌────────▼──────────────────────────▼───────────────┐  │
                          │  │  Self-Contained Native TLS HTTPS Server           │  │
                          │  │  • Auto-generated X.509 certificate on boot       │  │
                          │  │  • cdk-mintd compatible REST API (/v1/*)          │  │
                          │  │  • Live Web Terminal Dashboard (/)               │  │
                          │  └───────────────────────┬───────────────────────────┘  │
                          └──────────────────────────┼──────────────────────────────┘
                                                     │
                                                     │ HTTPS (TLS 1.2/1.3)
                                                     ▼
                  ┌───────────────────────────────────────────────────────────────┐
                  │          LIGHTWEIGHT RUST VAULT ("vault-rust / fupi-vault")   │
                  │              (Raspberry Pi Linux / SBC / Embedded Core)       │
                  │                                                               │
                  │  ┌───────────────────────┐   ┌─────────────────────────────┐  │
                  │  │  Chaum Blind Engine   │   │  Atomic Flash Storage       │  │
                  │  │  • SHA-256 scalar map │   │  • vault_flash.json (.tmp)  │  │
                  │  │  • Random blinder (r) │   │  • Power-loss resilient     │  │
                  │  │  • Unblind (r^-1 mod N│   │  • Bearer proofs & journal  │  │
                  │  │  • On-chip RSA verify │   │  • P2PK lock attribution    │  │
                  │  └───────────┬───────────┘   └──────────────┬──────────────┘  │
                  │              │                              │                 │
                  │  ┌───────────▼──────────────────────────────▼──────────────┐  │
                  │  │  Vault Wallet Engine & RPi CLI / REPL Interface         │  │
                  │  │  Commands: TOPUP, PAY, BANK, SETTLE, VERIFY, STATUS     │  │
                  │  └───────────────────────────┬─────────────────────────────┘  │
                  └──────────────────────────────┼────────────────────────────────┘
                                                 │
                                                 │ Bearer Payment Transfer (Token Handover)
                                                 │ (QR code / BLE / Local File / Airgap)
                                                 ▼
                  ┌───────────────────────────────────────────────────────────────┐
                  │                 RECIPIENT / MERCHANT DEVICE                   │
                  │   (Another RPi Vault, Phone Wallet, or Pico W Display)        │
                  │                                                               │
                  │  1. Receives base64-encoded bearer token                      │
                  │  2. OFFLINE VERIFICATION: verifies signature vs cached keyset │
                  │     ==> ZERO NETWORK REQUIRED. Money is authentic on receipt. │
                  │  3. Settles at Go HTTPS ATM later (first-to-settle-wins)      │
                  └───────────────────────────────────────────────────────────────┘
```

---

## 2. Core Cryptographic Primitives & Specifications

| Component | Standard / Spec | Implementation | Role |
|---|---|---|---|
| **Mint Signing Key** | RSA-2048 ($e=65537, N=p \cdot q$) | Go `crypto/rsa` | High-security blind minting |
| **Scalar Mapping** | $m = \text{SHA256}(\text{secret}) \pmod N$ (min 2) | Go, Rust (`sha2`), MicroPython | Maps arbitrary token secret to RSA scalar |
| **Blinding Factor** | Random $r \in [2, N)$ such that $\gcd(r, N)=1$ | Cryptographic PRNG (`OsRng`) | Blinds message so mint cannot link load to spend |
| **Blind Message** | $m_{\text{blind}} = (m \cdot r^e) \pmod N$ | Pure Rust `num_bigint` | Transmitted to ATM over HTTPS |
| **Blind Signature** | $s_{\text{blind}} = (m_{\text{blind}})^d \pmod N$ | Go `big.Int.Exp` | Signed by ATM without knowing $m$ or secret |
| **Unblind Signature** | $s = (s_{\text{blind}} \cdot r^{-1}) \pmod N$ | Extended Euclidean algorithm | Unblinded client-side on RPi |
| **Signature Verification** | $s^e \pmod N \stackrel{?}{=} m$ | On-chip client & receiver check | Verifies signature validity offline |
| **Double-Spend Ledger** | Spent secret hash set + disk state | Go `map[string]struct{}` + JSON | Enforces first-to-settle-wins rule |
| **Transport Security** | Native TLS 1.2 / TLS 1.3 | Go `crypto/tls` + Rust `rustls` | Mutual encryption, self-contained certificates |

---

## 3. End-to-End Execution Flows

### Flow 1: Inbound Bank Deposit (ATM Reserve Funding)
1. User makes a standard bank transfer (NEFT, IMPS, or LN deposit) into the ATM reserve.
2. The bank sees **one ordinary ATM withdrawal/deposit transaction**. The bank's job is finished here.
3. ATM credits reserve: `POST /v1/credit {"amount": 100}` &rarr; reserve becomes 100.00.
4. **The 1:1 rule:** The ATM strictly enforces `issued + amount <= reserve`. No unbacked tokens can ever be minted.

### Flow 2: Keyset Discovery & Authentication
1. RPi Rust Vault connects to the ATM: `GET /v1/keyset` over HTTPS.
2. ATM responds with:
   ```json
   {
     "keyset_id": "go-mvp-00",
     "n": "<base64url-encoded-2048-bit-modulus>",
     "e": 65537
   }
   ```
3. The vault pins the keyset ID and caches $(N, e)$.

### Flow 3: Blind Top-Up (ATM Withdrawal)
```
  RUST VAULT (RPi)                           GO HTTPS ATM (kiosk-go)
        │                                               │
        │ 1. secret = "fupi-" + random_hex(16)          │
        │ 2. m = SHA256(secret) % N                     │
        │ 3. Pick random r where gcd(r, N) == 1         │
        │ 4. m_blind = (m * r^e) % N                    │
        │                                               │
        │ 5. POST /v1/blind-sign ──────────────────────►│
        │    {"blinded_message": b64(m_blind),          │ 6. Check reserve >= issued+1
        │     "amount": 1}                              │ 7. s_blind = (m_blind)^d % N
        │                                               │ 8. issued += 1
        │◄── 200 {"blind_signature": b64(s_blind)} ─────│
        │                                               │
        │ 9.  r_inv = modinv(r, N)                      │
        │ 10. sig = (s_blind * r_inv) % N               │
        │ 11. Assert (sig^e % N == m) [On-Chip Check]   │
        │ 12. Save proof to vault_flash.json            │
```
**Privacy Guarantee:** The ATM only saw $m_{\text{blind}}$, which is mathematically independent of $m$. The ATM never saw the secret, never saw $m$, and cannot link this topup to future spending.

### Flow 4: Bearer Payment Transfer (Handover)
1. Payer runs `fupi-vault pay 2 [--p2pk <recipient_pubkey>]`.
2. The vault checks its balance, extracts 2 proofs, and deducts them from flash.
3. If P2PK is specified, the recipient's public key is attached to the proof:
   ```json
   [
     {
       "secret": "fupi-a33720f25e4bba933c4b4f9841dd2ea2",
       "sig": "...",
       "n": "...",
       "e": 65537,
       "keyset_id": "go-mvp-00",
       "p2pk": "merchant-charlie"
     }
   ]
   ```
4. The token is serialized as a URL-safe or standard Base64 string.
5. The token is handed over to the receiver (via QR code, BLE packet, Nostr message, or local file).

### Flow 5: Recipient Offline Verification (Zero Network)
1. Recipient receives the token string.
2. Recipient runs `fupi-vault verify <token>`.
3. For each proof:
   - Derives $m = \text{SHA256}(\text{secret}) \pmod N$.
   - Verifies $(s^e \pmod N) == m$.
   - **Forgery Guard:** Strictly validates that the proof's modulus $N$ and `keyset_id` match the trusted ATM keyset. Tokens signed under an attacker's custom modulus are instantly rejected.
4. If valid, the recipient accepts the payment with 100% mathematical certainty that the mint signed it. **No internet connection, cellular service, or switch is required.**

### Flow 6: Peer-to-Peer Offline Cash Receipt & Vault Import
1. Recipient imports verified tokens into their own flash vault: `fupi-vault receive <token>`.
2. The vault verifies each proof against the trusted keyset offline.
3. The vault checks for duplicate secrets, preventing self-replay.
4. Verified proofs are atomically added to `vault_flash.json` (`.tmp` sync + `.bak` snapshot).
5. The recipient's active balance increases immediately offline. They can now re-spend these tokens offline to a third party or settle them later at an ATM.

### Flow 7: Settlement at ATM (Online)
1. When convenient, the holder settles the token at the ATM: `POST /v1/settle`.
2. The ATM verifies:
   - Secret has not been spent before: `spent[secret] == nil`.
   - RSA signature matches: $(s^e \pmod N) == \text{SHA256}(\text{secret}) \pmod N$.
   - P2PK lock check: If `p2pk` is set, `claimer` must match in constant time (`subtle.ConstantTimeCompare`).
3. ATM records `spent[secret] = struct{}{}`, decrements `issued`, and returns `200 settled OK`.

### Flow 8: Double-Spend / Replay Protection & Concurrency
1. If anyone attempts to settle the exact same secret again, the ATM finds `secret` in its spent set.
2. ATM immediately returns `409 Conflict: REJECTED: double-spend (already settled)`.
3. First-to-settle-wins rule guarantees physical cash semantics.
4. Under concurrent race conditions (e.g. 50 parallel requests), `k.mu` mutex serialization guarantees strictly one settlement succeeds and all 49 replays are blocked.

---

## 4. Hardware & Software Profiles

### Raspberry Pi (RPi 3, 4, 5 & Linux SBCs)
- **Runtime:** Native Rust binary (`fupi-vault`), zero runtime dependencies.
- **Storage:** Power-loss resilient atomic flash journaling (`.tmp` write &rarr; `file.sync_all()` &rarr; `.bak` snapshot &rarr; rename to `vault_flash.json`). Automatically recovers from incomplete writes or truncated 0-byte states without losing money.
- **Interface:** CLI subcommands (`topup`, `pay`, `receive`, `verify`, `settle`, `balance`, `bank`, `info`, `status`, `wipe`) + interactive terminal REPL for SSH or local serial console.
- **Network:** Pure Rust TLS (`rustls`) client with support for self-signed development certificates (`--insecure`) and custom CA roots.

### Raspberry Pi Pico W (RP2040 MicroPython)
- **Runtime:** MicroPython with socket HTTP client and SSD1306 OLED display driver.
- **Hardware Wiring:** 4 wires only (3V3, GND, SDA on GP4, SCL on GP5).
- **Crypto:** Pure Python bignums for RSA-2048 Chaum blinding.
- **ATM Interop:** Interfaces directly with the Go ATM in HTTP mode (`kiosk-go -tls=false -port 8890`).

### Self-Contained Go HTTPS ATM
- **Binary:** Statically linked single Go executable (`kiosk-go.exe` / `kiosk-go`).
- **TLS Engine:** Native Go `crypto/tls` + `crypto/x509` with automatic self-signed certificate generation on boot and persistent certificate reuse to prevent TLS fingerprint churn across restarts.
- **Resilience:** Atomic state writes (`.tmp` &rarr; sync &rarr; rename) preventing reserve or spent-set corruption on power loss. Safe Base64 decoding eliminating panics on malformed client requests.
- **Web Dashboard:** Embedded HTML terminal accessible at `https://<ip>:8890/` displaying real-time 1:1 reserve, issued tokens, and settlement telemetry.

---

## 5. Verification & Test Matrix

| Test Suite | File | Coverage | Result |
|---|---|---|---|
| **Go ATM Unit & Concurrency Tests** | `kiosk-go/settle_test.go` | In-process blinding math, signature verification, settlement, double-spend replay prevention, invalid Base64 input resilience, and 50-goroutine parallel race serialization | **PASS** |
| **Go ATM TLS Tests** | `kiosk-go/tls_test.go` | Self-signed TLS cert generation, HTTPS listener boot, custom CA client verification, HTTPS endpoints | **PASS** |
| **Rust Vault Unit Tests** | `vault-rust/src/crypto.rs` | Base64 URL & Standard decoding, scalar hashing, extended Euclidean inverse, blinding, unblinding, mock RSA verify | **PASS** (8/8) |
| **Rust Flash Resilience Tests** | `vault-rust/src/storage.rs` | Atomic file write, sync_all, rename, persistence reload, wipe, and power-loss recovery from corrupted/truncated primary files via `.bak` | **PASS** (2/2) |
| **Rust Vault Tests** | `vault-rust/tests/vault_tests.rs` | Vault balance tracking, payment token generation, offline recipient verification, tampered token rejection, peer-to-peer offline receive, and counterfeit modulus rejection | **PASS** (4/4) |
| **Python <-> Go TLS Interop** | `kiosk-go/cross_lang_test.py` | Python blinding & unblinding &rarr; Go HTTPS ATM signing & settle over TLS with certificate reuse | **PASS** |
| **End-to-End System Test** | `kiosk-go/e2e_https_rust_vault_test.py` | Full 13-step workflow: Go HTTPS ATM boot &rarr; Reserve credit &rarr; Rust Vault blind topup &rarr; Spend &rarr; Offline verify &rarr; Settle &rarr; Replay reject &rarr; P2PK theft reject &rarr; Peer-to-peer offline receive &rarr; Counterfeit modulus reject &rarr; 5-thread parallel settle race | **PASS** (13/13) |
| **MVP Reference Test** | `mvp/test_mvp.py` | 17 reference bank rail and Chaum blinding tests | **PASS** (17/17) |
