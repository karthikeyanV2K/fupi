# kiosk-go — the FUPI Self-Contained Go HTTPS ATM & Mint

Same protocol as `mvp/kiosk.py`, rebuilt in **Go** as a self-contained HTTPS ATM and blind-signature cash mint.

| Tier | Language | Why |
|---|---|---|
| **ATM / Mint (this server)** | **Go** | Native HTTPS/TLS without nginx, goroutine-per-conn concurrency, single static binary deploy, GC memory safety |
| **Vault Core (RPi / embedded)** | **Rust** (`vault-rust`) | No GC pauses, atomic flash persistence, const-eval safety, panics = safe reboots |
| **Hardware Prototype** | **MicroPython** (`pico_w/`) | 4-wire hardware proof on Raspberry Pi Pico W + 0.96" OLED |
| **Protocol Research / Rails** | **Python** (`mvp/`) | Fastest to verify math; bank rail simulation |

## Capabilities

1. **Self-Contained Native HTTPS:** Automatically generates modern X.509 TLS certificates in-memory on boot (or writes to `kiosk_cert.pem`/`kiosk_key.pem`). Supports custom certificates via `-cert` and `-key`. No reverse proxy needed.
2. **Chaum Blind Signatures (RSA-2048):** Textbook RSA on blinded scalars ($e=65537$). The mint never sees token preimages or serial numbers.
3. **1:1 Reserve Rule:** Minting strictly blocked if `issued + amount > reserve`. The reserve only grows through `/v1/credit`, which requires an HMAC signature and a unique bank reference.
4. **First-to-Settle-Wins:** Double-spend replay protection immediately returns `409 Conflict`.
5. **Real P2PK Locks:** A lock is an ed25519 public key embedded *inside* the blind-signed secret (`<secret>|lock=<pubkey hex>`). Settling needs an ed25519 claim signature over the secret by that key. The lock cannot be stripped or relabelled without invalidating the mint's signature.
6. **Deposit ledger + reconcile:** every credit is an append-only `{ref, amount, at}` entry; a repeated reference is rejected (409). `GET /v1/reconcile` reports whether outstanding tokens are covered and whether the ledger sums to the reserve.
7. **Crash-safe state:** state is written `.tmp` (fsync) -> `.bak` (last good) -> rename. If state files exist but none is valid the kiosk **refuses to start** rather than generating a new key over them.
8. **ATM Web Dashboard:** Terminal dashboard served at `/` and `/atm` showing live 1:1 reserve, issued tokens, and TLS telemetry.

## Status

```bash
go build -o kiosk-go .                       # Static binary, zero C dependencies
go vet ./...                                 # Clean
go test -race ./...                          # Settle math, TLS, credit auth, ledger, locks, crash recovery
FUPI_CREDIT_SECRET=xyz ./kiosk-go -port 8895 &
FUPI_CREDIT_SECRET=xyz python cross_lang_test.py 8895 https   # Python <-> Go HTTPS interop
python e2e_https_rust_vault_test.py          # Go kiosk <-> Rust vault (build both binaries first)
```

## HTTP / HTTPS API (`/v1/*`)

```http
GET  /                    -> ATM Web Terminal Dashboard (HTML)
GET  /v1/info             -> {"name":"...","version":"0.2.0","tls_enabled":true,"reserve":100,...}
GET  /v1/keyset           -> {"keyset_id":"go-mvp-00","n":"<b64url>","e":65537}
GET  /v1/reconcile        -> {"reserve":..,"issued_outstanding":..,"deposits_total":..,
                              "deposit_count":..,"settled_count":..,"fully_backed":true,"ledger_consistent":true}
POST /v1/credit           <- {"amount": 100, "ref": "<unique bank reference>"}
                             header X-Fupi-Signature: hex(HMAC-SHA256(credit secret, raw body))
                          -> 200 {"reserve":..} | 401 bad signature | 409 duplicate ref
                             | 400 bad ref/amount | 503 no credit secret configured
POST /v1/blind-sign       <- {"blinded_message":"<b64url>","amount":1}     # amount must be 1 (one proof = one unit)
                          -> {"blind_signature":"<b64url>"} (402 if reserve exceeded)
POST /v1/settle           <- {"secret":"...","sig":"<b64url>","n":"...","e":65537,
                              "claimer":"<hex ed25519 signature over secret, locked proofs only>"}
                          -> 200 settled | 409 rejected (double-spend / bad sig / lock)
```

The old unauthenticated credit and the free-text `p2pk`/`claimer` labels are gone: they allowed anyone
to print reserve or to "claim" a locked proof by repeating its label.

## Running the ATM

```powershell
# Run with self-contained HTTPS (default, auto-generates TLS certificate).
# The credit secret authenticates the bank rail; without it /v1/credit is DISABLED.
# Prefer the env var (flags are visible in `ps`).
export FUPI_CREDIT_SECRET="$(openssl rand -hex 32)"
./kiosk-go -port 8890 -tls=true -state kiosk_go_state.json

# Run with plain HTTP (e.g. for MicroPython Pico W on a trusted LAN ONLY: traffic is cleartext)
./kiosk-go -port 8890 -tls=false -state kiosk_go_state.json

# Run with custom TLS certificate
./kiosk-go -port 8890 -tls=true -cert mycert.pem -key mykey.pem
```

## Known limits (tracked in docs/CODE_PLAN.md)

- Every proof is worth exactly 1 unit; denominations are planned (W2).
- The signing key is stored in the state file (mode 0600) in plaintext; use disk encryption / an HSM before real money.
- State is rewritten in full on every sign/settle (O(n)); fine for pilots, not for scale.
- The reserve is a number in a file. Real money needs the bank-side reconciliation described in docs/CODE_PLAN.md.

## W2: denominations, devices, swap

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /v1/keysets` | none | public key per denomination (`go-mvp-00` = 1, `go-mvp-d<N>` = N) |
| `POST /v1/allocate` | HMAC (`X-Fupi-Signature`) + unique `ref` | give a device (ed25519 pubkey) issuance quota; total allocations <= reserve |
| `POST /v1/blind-sign` | device signature (`device`, `seq`, `device_sig`) | issue one proof of `amount` (a supported denomination); `-allow-anonymous-issuance` disables the check (dev only) |
| `POST /v1/swap` | the proofs themselves | unlocked proofs in, same-total blind outputs out; idempotent |

Device signature message: `fupi-blind-sign-v1|<device hex>|<seq>|<amount>|<blinded b64>`, ed25519, `seq` strictly increasing.
