# FUPI Code Plan: from prototype to a real-world pilot

> Goal: a working, auditable loop on real (small) money **before** any pitch or licensing step.
> The spend path (load, pay, verify, settle) has no switch in it. Banks are needed only at the two
> ends: money in, and money out.

## 1. Real-world money workflow

```
 (1) FUND          (2) RECORD            (3) LOAD               (4) PAY
 user -> BANK      ledger entry:         vault key-signed       vault --QR/BLE/NFC--> merchant device
 reserve account   {ref, amount, who}    request -> kiosk       offline both sides    verifies vs pinned keyset
 (IMPS/NEFT/cash)  sets issue quota      blind-signs proofs
                                         into the vault
                                                                      |
 (7) RECONCILE <-- (6) CASH-OUT <------------------------------ (5) SETTLE
 daily: bank bal   operator pays the      merchant device online later:
 >= tokens out     merchant's bank acct   kiosk marks proofs spent,
                   from the settlement    credits the merchant ledger
                   report
```

| Step | Touches a bank? | Touches UPI / a payment switch? |
|---|---|---|
| (1) fund, (6) cash-out | yes (ordinary transfers) | the transfer rail may be IMPS/NEFT |
| (3) load, (4) pay, (5) settle | no | **no** |
| (7) reconcile | read-only statement | no |

The bank holds the money. The vault holds *claims* on it. The kiosk's job is to keep
`tokens outstanding <= money in the bank` and to prove it.

## 2. Phases

| Phase | Deliverable | Status |
|---|---|---|
| **W0** | Fix the critical findings from the repo review | **done** (this PR) |
| **W1** | Deposit-authorised issuance and an append-only ledger | **done** (this PR) |
| **W2** | Denominations (1,2,5,10,20,50,100,200,500), one signing key per denomination, device identity (signed load requests), change-making | **done** |
| **W3** | Merchant terminal: verify-only device, accumulates, settles later | **done** |
| **W4** | Cash-out: settlement report first (operator pays by bank app), payout automation later | **done** (report + payout ledger; automation not started) |
| **W5** | Field pilot: 5-10 known people, own funds, tiny cap, written consent, daily reconciliation | **tooling + runbook done**; the 30-day run itself is yours |

### W0: what was fixed

| # | Finding | Fix | Test |
|---|---|---|---|
| 1 | `/v1/credit` was unauthenticated: anyone could print reserve | HMAC-SHA256 over the body (`X-Fupi-Signature`), endpoint disabled without a secret | `TestCreditRequiresAuthAndUniqueRef`, e2e step 3 |
| 2 | Offline verify took `e` from the token (`e=1` forgery) | `n`/`e` come only from the pinned keyset; mismatching repeats are rejected | `test_e_equals_one_forgery_rejected` |
| 3 | P2PK was an unauthenticated label (strip it, or copy it into `claimer`) | ed25519 lock **inside** the blind-signed secret; claim signature required | `TestLockedProofNeedsClaimSignature`, e2e step 5 |
| 4 | No pinned keyset => token's own modulus was trusted | refuse to verify without a pinned keyset | `test_no_pinned_keyset_means_no_trust` |
| 5 | TLS verification off by default; keyset overwritten on every top-up | strict TLS by default, `--pin-tls <sha256>`; keyset change refused until `pin --force` | `test_keyset_pin_refuses_change`, e2e step 2 |
| 6 | `pay` removed proofs before the token was saved anywhere | token written to the `outbox` in the same atomic save | `test_payment_selects_only_matching_lock_and_keeps_outbox` |
| 7 | Corrupt Go state silently created a new key; no `.bak` | `.bak` + refuse to start on unreadable state; signature released only after state is persisted | `TestCorruptStateNeverRegeneratesKey` |
| 8 | No server timeouts / body limits; secrets logged in debug | timeouts, 64 KB body cap, debug logging removed | (build + e2e) |
| 9 | `blind-sign amount=N` counted N units but signed one proof | amount must be a supported denomination; face value comes from the keyset | `TestBlindSignRejectsUnsupportedDenominations` |
| 10 | `bank_rail.py`: default secret, no webhook replay guard, withdrawals counted as top-ups, re-importing a CSV doubled the reserve | no default secret, `ref`-based dedupe, deposits only, `--match` narration filter | `bank_rail.py --mode selftest` |

### W1: deposit-authorised issuance

* `POST /v1/credit {amount, ref}`: signed, `ref` unique (bank UTR, gateway order id, LN quote id).
* Append-only ledger in the state file; `GET /v1/reconcile` returns reserve, outstanding tokens,
  deposit total/count, settled count, `fully_backed`, `ledger_consistent`.
* `bank_rail.py` passes a `ref` for every rail and refuses replays on its own side as well.
* Old state files get a `legacy-opening-balance` ledger entry so reconcile stays consistent.

## 3. Next: W2 to W5 in code terms

### W2: denominations + device identity (done)

| Piece | Design | Test |
|---|---|---|
| Keysets | one RSA key per denomination; ids `go-mvp-00` (1, legacy) and `go-mvp-d<N>`; `GET /v1/keysets` | `TestKeysetMapping`, cross_lang [8][9] |
| Face value | derived from the keyset the signature verifies under, never from a client field; `issued` is money | `TestDenominatedIssueAndSettle` |
| Device identity | vault holds an ed25519 key; operator allocates quota (`POST /v1/allocate`, HMAC + unique ref, total <= reserve); each request signed over `device|seq|amount|blinded`, seq strictly increasing | `TestDevice*`, e2e step 4 |
| Anonymous issuance | off unless `-allow-anonymous-issuance` (dev only) | `TestHTTPBlindSignNeedsDevice` |
| Change-making | `POST /v1/swap`: unlocked proofs in, same-total blind outputs out; idempotent (same request returns the same signatures) | `TestSwap*`, e2e step 4b |
| Vault | balance in money; exact-subset payment (`NeedChange` if coins do not add up); `pay` swaps automatically; write-ahead `pending_swap` + `recover`/`recover --abandon` | `tests/w2_tests.rs` |

Operator flow: `bank` (credit reserve) -> `allocate <device-pubkey> <amount>` -> vault `topup <amount>`.

### W3: merchant terminal (done)

| Command | Behaviour |
|---|---|
| `accept <token> [--invoice ID] [--expect N]` | verify OFFLINE against pinned keysets only; refuse wrong amount, replays, duplicate secrets, unpinned/forged keys; nothing is stored unless the whole token passes; receipt written in the same atomic save |
| `receipts` | audit log: id, time, invoice, amount, settled, rejected, pending |
| `settle-all [--claim-key]` | settles held proofs one by one, saving after each answer; a rejected proof (customer double-spent) is dropped from the held total and shown as `rejected` on its receipt; a network error stops the run and keeps unanswered proofs |

Risk the terminal cannot remove: until `settle-all` succeeds, an offline token is only as good as
first-to-settle-wins. Mitigations are the offline cap per device and settling often.
Tests: `vault-rust/tests/w3_tests.rs`, e2e step 10.

### W4: cash-out (done)

```
merchant --settle--> kiosk: settlement log {seq, time, payee label, amount, keyset, proof tag}
operator: report  -> owed per merchant -> pays from the bank app -> payout <merchant> <amt> --ref <UTR>
kiosk:    payout  -> owed falls, reserve falls (the bank balance fell by the same amount)
```

| Piece | Behaviour | Test |
|---|---|---|
| Log | every accepted settlement is appended in the same save that marks the proof spent; rejected ones are not logged | `TestSettlementLogGroupsByMerchantAndSanitisesLabels` |
| Payee label | `X-Fupi-Merchant` header (`--merchant`); sanitised, unlabeled if absent. It says who to PAY, it is not authentication: a bearer proof is cash | same |
| `GET /v1/settlements?since=&merchant=` | operator-only; HMAC over the request URI so a signed query can't be replayed as another | `TestSettlementEndpointsNeedOperatorAuth` |
| `POST /v1/payout {merchant, amount, ref}` | operator-only; unique bank ref; amount <= owed; lowers reserve | `TestPayoutLowersOwedAndReserveAndIsReplaySafe` |
| Backing rule | `reserve >= issued + owed`; **issuance now counts merchant claims**, so the kiosk cannot hand out money already promised to a merchant | `TestOwedMoneyCountsAgainstIssuance` |
| Ledger | `deposits - payouts == reserve` (`ledger_consistent`) | restart + reconcile tests, e2e step 11 |

Operator CLI: `report [--since N] [--merchant M]`, `payout <merchant> <amount> --ref <UTR>`.
Automation (bank payout API) stays out until a licensed entity is in the loop.

### W5: pilot (tooling done)

* `docs/PILOT_RUNBOOK.md`: parameters, roles, day-0 setup, daily routine, incidents, wind-down, pass/fail.
* `docs/PILOT_CONSENT.md`: participant consent template (have it reviewed).
* `scripts/pilot_check.py`: daily check (exit 1 = stop issuing). Verifies fully-backed / ledger invariants,
  **bank balance vs reserve**, pilot cap, day-over-day monotonic totals (state rollback or tampering), every
  reserve change explained by a deposit or payout, and the settlement log summing to reconcile. Appends an
  audit line to `pilot_log.jsonl`. Tests: `scripts/test_pilot_check.py`, e2e step 12.
* Success criteria: reconcile matches to the rupee for 30 days; zero lost tokens; every failure recoverable
  from the outbox/journal.

## 4. Known limits (not fixed in this PR)

| Area | Limit |
|---|---|
| Vault storage | plaintext JSON; no PIN, flash encryption, secure element or seed restore |
| Kiosk key | signing key in the state file (0600); needs disk encryption / HSM for real money |
| Kiosk scale | full-state rewrite on every sign/settle; one global mutex |
| Blinding | hash-to-scalar is 256 bits in a 2048-bit modulus (not full-domain-hash); fine for a pilot, review before scale |
| Offline double-spend | bounded only by the offline cap; first-to-settle-wins |
| Pico client | plain HTTP only; no locks, claim signatures, denominations or device key yet |
| Lost response | if a blind-sign response is lost after the kiosk signed, that proof is lost (quota consumed); swap has write-ahead recovery, top-up does not yet |
| Swap refusals | the kiosk answers all swap errors with 409, so a refused swap needs an explicit `recover --abandon` after a retry |
| Reserve | a number in a file; the bank balance is not checked automatically, and payouts are recorded by the operator after the bank transfer (no link to the bank) |
| Settlement log | settlements made before W4 are not in the log (owed starts at 0); payee labels are unauthenticated, so the operator confirms who to pay out of band; the log is a full rewrite per save like the rest of the state |
| Legal | none of this is licensed for public use; see the approval paths discussed separately |

## 5. How to run everything

```bash
(cd kiosk-go   && go vet ./... && go test -race ./... && go build -o kiosk-go .)
(cd vault-rust && cargo test && cargo build)
python3 mvp/test_mvp.py
python3 mvp/bank_rail.py --mode selftest
python3 scripts/test_pilot_check.py
python3 kiosk-go/e2e_https_rust_vault_test.py
```
