# _legacy_python — archived Python (superseded by Go/Rust ports)

Everything in this directory is RETIRED from the active codebase. Every check,
rail and harness here was ported faithfully into native Go (and the vault into
Rust), and the Go suite passes on the same expectations:

| Archived file                              | Native replacement |
|--------------------------------------------|--------------------|
| `mvp/test_mvp.py` (17 checks)              | `kiosk-go/mvp_suite_test.go` (`go test -run TestMvp -v ./...`) |
| `mvp/kiosk.py`, `mvp/crypto.py`, `mvp/vault.py` | the Go `Kiosk` (`kiosk-go/main.go`, `settlements.go`) + wallet math re-proven by the ported tests |
| `mvp/bank_rail.py` (StatementBank / WebhookBank / LightningMintRail) | `kiosk-go/rails.go` (+ `kiosk-go/webhook.go`), covered by `kiosk-go/rails_test.go` |
| `kiosk-go/e2e_https_rust_vault_test.py` (12 steps) | `kiosk-go/e2e_vault_test.go` (`go test -run TestE2EHttpsRustVaultHardened -v ./...`) |
| `kiosk-go/cross_lang_test.py`              | the Go/Rust interoperability is now exercised continuously by `e2e_vault_test.go` (real kiosk ⇄ real vault binary over TLS) |
| `scripts/pilot_check.py`                   | `kiosk-go/pilot/main.go` (`go run ./pilot`), driven live as step 12 of the e2e |
| `scripts/test_pilot_check.py`              | the pilot's verdict logic runs against a live kiosk inside `e2e_vault_test.go` step 12 (PASS / day-over-day / below-reserve FAIL / wrong-pin refuse) |

Nothing here is buildable or runnable as part of FUPI anymore; it is kept only
as reference for the port reviewers (demos from mvp/phase1_*, phase2_* included).

The only Python allowed to remain in the repository is `pico_w/` — that is
MicroPython FIRMWARE for the Raspberry Pi Pico W client device itself. It is
not part of the G/dev toolchain and cannot be replaced with Go/Rust without
rewriting the Pico client in C/IDF (planned Tier-1 work).
