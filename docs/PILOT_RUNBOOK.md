# FUPI field pilot runbook (W5)

Goal: 30 days on real, tiny money with a closed group, and prove the books never drift.
Not legal advice. As far as I know, running this as a public payment instrument needs an
RBI authorisation (PPI / PA path); a closed pilot of consenting friends, own funds, no fees,
no public merchants, is the safest shape. Get a lawyer or CA to confirm before day 1.

## 0. Pilot parameters (suggested defaults; you decide)

| Parameter | Suggested | Why |
|---|---|---|
| People | 5-10, all known personally | consent and recourse are personal |
| Merchants | 1-2 you control (a friend's shop, a canteen) | no stranger gets a bearer token |
| Pilot-wide cap | Rs 5,000 total allocated | loss is bounded by what you can absorb |
| Per-device quota | Rs 500 (`allocate`) | the kiosk enforces it |
| Funds | your own, in a separate bank account used only for this | the reserve must equal that account's balance |
| Duration | 30 days, then wind-down (section 6) | |
| Fees | none | avoids looking like a commercial payment business |

## 1. Roles

- **Operator** (you): holds `FUPI_CREDIT_SECRET`, runs the kiosk, credits the reserve, allocates quota, pays merchants, runs the daily check.
- **Participants**: each has a vault (`fupi-vault`); signed the consent form.
- **Merchant**: runs the terminal (`accept`, `settle-all --merchant <label>`).

Keep the credit secret off the kiosk's shell history (env var or file with mode 0600), never in chat.

## 2. Day 0 setup

```bash
# kiosk (operator machine). Disk encryption on; state file backed up nightly.
FUPI_CREDIT_SECRET=$(cat ~/.fupi_secret) ./kiosk-go -port 8890 -tls=true -state /var/fupi/state.json
# note the TLS fingerprint printed at start; hand it to participants on paper / in person.

# each participant, once
fupi-vault pin  --atm https://KIOSK:8890 --pin-tls <fingerprint>   # compare the modulus hashes with the operator
fupi-vault device                                                    # send the public key to the operator

# operator, per participant (one bank transfer = one unique ref)
fupi-vault bank 500 --ref <bank UTR>
fupi-vault allocate <device-pubkey> 500 --ref ALLOC-<name>-1
# participant
fupi-vault topup 200
```

Never start the pilot with `-allow-anonymous-issuance`. Reserve is credited only after the money
is visible in the bank account, with its UTR as the `ref`.

## 3. Daily routine (10 minutes)

1. Read the bank balance of the pilot account.
2. `python3 scripts/pilot_check.py --atm https://KIOSK:8890 --pin-tls <fp> --bank-balance <balance> --max-total 5000 --log pilot_log.jsonl` (with `FUPI_CREDIT_SECRET` set).
3. Exit 0: file the output. Exit 1: **stop the line** (section 5), do not issue or pay anything until explained.
4. Merchant: `settle-all --merchant <label>` at the end of each trading day; any `rejected` is investigated the same day.
5. Operator: `report`; pay merchants from the bank app weekly (or when owed exceeds Rs 500), then `payout <merchant> <amt> --ref <UTR>`. Pay first, record second, same day.
6. Copy `state.json` and `pilot_log.jsonl` to a second location.

What the check proves each day: tokens out + merchant claims are covered by the reserve; the reserve equals the
bank balance; the ledger (deposits - payouts) equals the reserve; nothing that should only grow has shrunk
(a restored old backup or edited state fails here); every reserve change is explained by a deposit or payout;
the settlement log sums to reconcile.

## 4. Weekly vault hygiene (each participant)

- `fupi-vault status`: no `PENDING SWAP`. If there is: `fupi-vault recover`.
- `fupi-vault outbox`: every token you handed over is `ack`ed once the receiver confirms; unacknowledged tokens older than a day are chased.
- Keep the vault file (and its backup) private: it **is** the money. No PIN or encryption exists yet (known limit).

## 5. Incidents

| Symptom | Action |
|---|---|
| `pilot_check` FAIL | stop issuing (stop the kiosk), snapshot `state.json`, find the cause from `report` + bank statement before restarting |
| bank balance below reserve | treat as a loss event: stop, reconcile every deposit UTR and payout UTR against the statement |
| bank balance above reserve | an uncredited deposit: credit it with its UTR, rerun the check |
| lost phone / vault file | the tokens are gone (bearer cash). Cap exposure by quota; no recovery is promised in the consent form |
| a token delivered but not accepted | `outbox` still has it: re-show and resend; the merchant `accept` refuses replays safely |
| interrupted change swap | `fupi-vault recover`; if the kiosk refused it, `recover --abandon` |
| merchant `rejected` on settle | the payer spent the same token elsewhere first: record it, settle it between the two people, count it as a pilot failure metric |
| kiosk crash mid-write | it refuses to start on unreadable state and falls back to `.bak`; never delete state files to "fix" it |
| kiosk key suspected stolen | stop, announce, wind down (section 6): all tokens are redeemed for bank refunds |

## 6. Wind-down (day 30, or any stop-the-line you cannot explain)

1. Announce the end date; no new top-ups.
2. Participants and merchants settle everything (`settle-all`, or `settle <token>`).
3. Operator pays every merchant the owed balance (`payout ... --ref UTR`).
4. Participants whose tokens are unspent: each settles to a payee label with their own name; operator pays that out from the bank like a merchant.
5. Run `pilot_check`: `issued_outstanding` and `owed_total` must both be 0. Bank balance must then equal `reserve` (0 plus any unrecorded deposits). Return the remainder to yourself.
6. Archive `state.json`, `pilot_log.jsonl`, bank statement.

## 7. Pass / fail

The pilot **passes** only if all hold for 30 consecutive days:

- [ ] `pilot_check` exits 0 every day; the bank balance equals the reserve to the rupee
- [ ] zero lost tokens: every token ever issued was settled, or is provably held in a named vault
- [ ] every failure (rejected settle, pending swap, mismatch) was explained from the logs within one day
- [ ] no operator action outside the CLI (no hand-edited state files)
- [ ] every participant completed at least 3 payments and 1 merchant settlement without help
- [ ] wind-down reaches `issued_outstanding = 0` and `owed_total = 0`

It **fails** (stop, fix, restart the 30 days) on any unexplained mismatch, any double-spend that
the merchant could not settle, or any evidence the state file was rolled back.

Metrics to record weekly: payments, average payment, offline-to-settle delay, rejected settlements,
recoveries needed, support questions per participant.

## 8. Known limits to tell participants honestly

Vault files are unencrypted; a lost phone is lost money. Offline tokens are first-to-settle-wins until
the merchant settles. The kiosk is one machine with one signing key (no HSM). Payouts are recorded by hand
after a bank transfer. Settlements before W4 are not in the log. This is an experiment, not a bank.
