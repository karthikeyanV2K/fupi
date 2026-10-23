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
| W2 | Denominations (1,2,5,10,20,50,100,200,500), one signing key per denomination, device identity (signed load requests) | todo |
| W3 | Merchant terminal: verify-only device, accumulates, settles later | todo |
| W4 | Cash-out: settlement report first (operator pays by bank app), payout automation later | todo |
| W5 | Field pilot: 5-10 known people, own funds, tiny cap, written consent, daily reconciliation | todo |

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
| 9 | `blind-sign amount=N` counted N units but signed one proof | amount must be 1 | `TestBlindSignAmountMustBeOne` |
| 10 | `bank_rail.py`: default secret, no webhook replay guard, withdrawals counted as top-ups, re-importing a CSV doubled the reserve | no default secret, `ref`-based dedupe, deposits only, `--match` narration filter | `bank_rail.py --mode selftest` |

### W1: deposit-authorised issuance

* `POST /v1/credit {amount, ref}`: signed, `ref` unique (bank UTR, gateway order id, LN quote id).
* Append-only ledger in the state file; `GET /v1/reconcile` returns reserve, outstanding tokens,
  deposit total/count, settled count, `fully_backed`, `ledger_consistent`.
* `bank_rail.py` passes a `ref` for every rail and refuses replays on its own side as well.
* Old state files get a `legacy-opening-balance` ledger entry so reconcile stays consistent.

## 3. Next: W2 to W5 in code terms

**W2: denominations + device identity**
* Kiosk: keyset per denomination (`keyset_id = go-mvp-<denom>`), `blind-sign` takes the denomination;
  `issued` is tracked in money, not proof count. `Proof` gains `amount`.
* Vault: coin selection (greedy with change via a `/v1/swap` that re-issues blind), balance in money.
* Device identity: each vault has an ed25519 key; `blind-sign` requests are signed; kiosk keeps a
  per-device issue quota tied to its deposits.

**W3: merchant terminal**
* A verify-only mode (`fupi-vault merchant`): pinned keyset, running total, QR scan input,
  batched `settle` when online, local receipt log.

**W4: cash-out**
* `GET /v1/settlements?since=` report (merchant, amount, time, proof count) for the operator.
* Manual payout first; automation (bank API / payout rail) only after a licensed issuer is in the loop.

**W5: pilot**
* Own funds, closed group, written consent, a hard per-device cap, daily `reconcile` log kept.
* Success criteria: reconcile matches to the rupee for 30 days; zero lost tokens; every failure
  recoverable from the outbox/journal.

## 4. Known limits (not fixed in this PR)

| Area | Limit |
|---|---|
| Vault storage | plaintext JSON; no PIN, flash encryption, secure element or seed restore |
| Kiosk key | signing key in the state file (0600); needs disk encryption / HSM for real money |
| Kiosk scale | full-state rewrite on every sign/settle; one global mutex |
| Blinding | hash-to-scalar is 256 bits in a 2048-bit modulus (not full-domain-hash); fine for a pilot, review before scale |
| Offline double-spend | bounded only by the offline cap; first-to-settle-wins |
| Pico client | plain HTTP only; no locks / claim signatures yet |
| Reserve | a number in a file; the bank balance is not checked automatically |
| Legal | none of this is licensed for public use; see the approval paths discussed separately |

## 5. How to run everything

```bash
(cd kiosk-go   && go vet ./... && go test -race ./... && go build -o kiosk-go .)
(cd vault-rust && cargo test && cargo build)
python3 mvp/test_mvp.py
python3 mvp/bank_rail.py --mode selftest
python3 kiosk-go/e2e_https_rust_vault_test.py
```
