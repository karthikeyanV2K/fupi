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
3. **1:1 Reserve Rule:** Minting strictly blocked if `issued + amount > reserve`. Inbound fiat funded via `/v1/credit`.
4. **First-to-Settle-Wins:** Double-spend replay protection immediately returns `409 Conflict`.
5. **P2PK Locks:** Enforces receiver public key ownership before releasing settlement.
6. **ATM Web Dashboard:** Terminal dashboard served at `/` and `/atm` showing live 1:1 reserve, issued tokens, and TLS telemetry.

## Status (All Verified)

```powershell
go build -o kiosk-go.exe .                   # Static binary, zero C dependencies
go vet ./...                                 # Clean
go test -v ./...                             # PASS: Settle math + Self-Signed TLS Server
python cross_lang_test.py 8895 https         # PASS: Python <-> Go HTTPS interop
python e2e_https_rust_vault_test.py          # PASS: Full 10-step Go ATM <-> Rust Vault test
```

## HTTP / HTTPS API (`/v1/*`)

```http
GET  /                    -> ATM Web Terminal Dashboard (HTML)
GET  /v1/info             -> {"name":"...","version":"0.2.0","tls_enabled":true,"reserve":100}
GET  /v1/keyset           -> {"keyset_id":"go-mvp-00","n":"<b64url>","e":65537}
POST /v1/credit           <- {"amount": 100}         # Bank rails credit reserve
POST /v1/blind-sign       <- {"blinded_message":"<b64url>","amount":1}
                          -> {"blind_signature":"<b64url>"} (402 if reserve exceeded)
POST /v1/settle           <- {"secret":"...","sig":"<b64url>","n":"...","e":65537,
                              "p2pk":"pubkey?","claimer":"pubkey?"}
                          -> 200 settled | 409 rejected (double-spend / bad sig / P2PK)
```

## Running the ATM

```powershell
# Run with self-contained HTTPS (default, auto-generates TLS certificate)
.\kiosk-go.exe -port 8890 -tls=true -state kiosk_go_state.json

# Run with plain HTTP (e.g. for MicroPython Pico W)
.\kiosk-go.exe -port 8890 -tls=false -state kiosk_go_state.json

# Run with custom TLS certificate
.\kiosk-go.exe -port 8890 -tls=true -cert mycert.pem -key mykey.pem
```
