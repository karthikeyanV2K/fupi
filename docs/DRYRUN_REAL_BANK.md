# Real-bank dry run: prove money in = money out, to the same bank and to another bank

Purpose: before any pilot participant, prove with YOUR OWN rupees and a bank statement that
(1) only money actually transferred in can ever be cashed out, (2) it can be cashed out to the
same bank and to a different bank, (3) the books match the bank to the rupee at every step.
Not legal advice; use only your own funds. Keep every amount at Rs 100-200.

What the code does and does not know about banks: nothing. The kiosk only has a number
(`reserve`). "Cash out to bank X" means YOU send an ordinary IMPS/NEFT transfer from the pilot
account to any account at any bank, then record its UTR with `payout`. The proof is the bank
statement lining up with the kiosk's ledger, not anything the code does to a bank.

## Accounts

| Name | What | Notes |
|---|---|---|
| **PILOT** | a separate account used only for this (Bank X) | never mix with your own money |
| **SRC** | the account you fund PILOT from | can be your normal account |
| **OUT-X** | an account at the same bank as PILOT (your own) | tests same-bank cash-out |
| **OUT-Y** | an account at a different bank (your own) | tests other-bank cash-out |

Payee labels used in the kiosk: `out-x` and `out-y` (they only tell you who to pay).

## Setup (real machine, real network, real phone/laptop for the vaults)

```bash
export FUPI_CREDIT_SECRET=$(cat ~/.fupi_secret)      # operator secret, mode 0600 file
./kiosk-go -port 8890 -tls=true -state ./dryrun_state.json      # note the TLS fingerprint it prints
export ATM=https://<kiosk-ip>:8890  PIN=<fingerprint>
v() { fupi-vault "$@" --atm "$ATM" --pin-tls "$PIN" --flash "$FLASH"; }
FLASH=alice.json v pin ; FLASH=alice.json v device        # customer vault; note the device pubkey
FLASH=shop.json  v pin                                    # a second vault acting as the merchant
```

## The run (record the evidence column at every step)

| # | Action | Expected | Evidence to keep |
|---|---|---|---|
| 1 | Transfer Rs 200 SRC -> PILOT | PILOT balance 200 | bank statement line, UTR `D1` |
| 2 | `v bank 200 --ref D1` | reserve 200 | kiosk output |
| 3 | `python3 scripts/pilot_check.py --atm $ATM --pin-tls $PIN --bank-balance 200 --log dryrun_log.jsonl` | PASS, "bank balance matches reserve" | check output |
| 4 | `FLASH=alice.json v allocate <alice-pubkey> 200 --ref A1` | quota 200 | output |
| 5 | **Negative:** `FLASH=alice.json v topup 300` | REFUSED (quota/reserve) | error text. You cannot issue more than was paid in. |
| 6 | `FLASH=alice.json v topup 200` | balance 200 | output |
| 7 | **Negative:** `v allocate <alice-pubkey> 9999 --ref A2` | REFUSED (over reserve) | error text |
| 8 | Pay 100 to the shop vault: `FLASH=alice.json v pay 100` -> hand the token to the shop: `FLASH=shop.json v accept <token> --invoice X1 --expect 100` | receipt #1, alice balance 100 | outputs |
| 9 | **Negative:** `FLASH=shop.json v accept <same token>` | REJECTED (replay) | error text |
| 10 | Pay another 100 (`out-y`): `FLASH=alice.json v pay 100`, then `FLASH=yshop.json v accept ...` (third vault file) | receipt, alice balance 0 | outputs |
| 11 | `FLASH=shop.json v settle-all --merchant out-x` and `FLASH=yshop.json v settle-all --merchant out-y` | settled 100 each | outputs |
| 12 | **Negative:** settle the step-8 token again from alice's saved copy | REJECTED (double-spend) | error text |
| 13 | `v report` | `out-x OWED=100`, `out-y OWED=100`, reserve 200 | report text |
| 14 | Send Rs 100 PILOT -> **OUT-X (same bank)** by IMPS | statement shows debit, UTR `P1` | statement line |
| 15 | `v payout out-x 100 --ref P1` | owed out-x 0, reserve 100 | output |
| 16 | Send Rs 100 PILOT -> **OUT-Y (other bank)** by IMPS/NEFT | statement debit, UTR `P2` | statement line |
| 17 | `v payout out-y 100 --ref P2` | owed out-y 0, reserve 0 | output |
| 18 | **Negative:** `v payout out-x 100 --ref P3` | REFUSED (exceeds owed) | error text |
| 19 | **Negative:** `v payout out-x 1 --ref P1` | REFUSED (duplicate ref) | error text |
| 20 | PILOT balance should now be 0; `pilot_check ... --bank-balance 0` | PASS; reserve 0, issued 0, owed 0 | check output + `dryrun_log.jsonl` |

Run `pilot_check` (with the real bank balance) after steps 2, 6, 11, 15 and 17 as well. Each run must
PASS and the log must show the reserve changes explained by deposits/payouts.

## What this proves, and what it does not

| Claim | Proved by | Not proved |
|---|---|---|
| Can't cash out more than was transferred in | steps 5, 7, 18, 20 | |
| Cash-out works to the same bank | step 14-15, statement UTR matches `payout` ref | automation: it is a manual transfer |
| Cash-out works to another bank | step 16-17 | same |
| Books equal the bank | `pilot_check` PASS with typed bank balance at each stage | the code never reads the bank; a wrong typed balance defeats it |
| No double-cash | steps 9, 12 | offline double-spend before settlement (known limit) |

Pass = every row behaves as expected, every `pilot_check` passes, and the final state is
reserve 0 / issued 0 / owed 0 / PILOT balance 0 (minus any bank fee: record it, and credit the
reserve difference explicitly so the books still equal the bank).

Watch for: IMPS fees and daily limits, NEFT settling in batches (the credit may arrive hours
later: record the UTR only when it shows on the statement), and the bank asking questions about
a new account receiving small transfers (answer truthfully; do not split amounts to dodge limits).

Archive the statement PDF, `dryrun_state.json`, `dryrun_log.jsonl` and every command output.
Do not start the pilot (docs/PILOT_RUNBOOK.md) until this has passed twice.
