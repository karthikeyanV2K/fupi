# FUPI × Real-World Bank — System Architecture & Workflows

> Status: architecture spec, Nov 2026. Companion to `ARCHITECTURE_PLAN_FLOW.md`.
> Scope: **full tech + workflow only** — how a real bank recognizes FUPI hardware,
> how hardware pays hardware, and how hardware money deposits back to the bank.

---

## 0. The model in one paragraph

A centralized wallet (Amazon Pay, PhonePe, Razorpay Wallet) is **three things**:
a **ledger** (who owns what inside the wallet), an **escrow account at a sponsor
bank** (the real ₹ behind every wallet rupee), and a **recognition rail** (the
bank + payment networks telling the wallet "money arrived, credit user X").
FUPI has exactly the same three things: `kiosk_state.json` is the ledger, the
bank account you transfer into is the escrow, and the CSV/webhook/Lightning
rails are the recognition rail. The FUPI hardware difference: **the ledger lives
in a box you own, and money can move offline between boxes** — which no
centralized wallet can do.

```
        CENTRALIZED WALLET (Amazon Pay / PhonePe)          FUPI
┌──────────────────────────────────────────────┐   ┌──────────────────────────────────────┐
│ User's bank ──IMPS/UPI──► ESCROW ACCT        │   │ User's bank ──IMPS/NEFT──► escrow    │
│  (per-user reference / virtual account)      │   │  acct (FUPI remark = reference)      │
│      │ bank host matches VA → callback       │   │      │ CSV / webhook / LN = callback │
│      ▼                                       │   │      ▼                               │
│ WALLET LEDGER (company DB)                   │   │ KIOSK LEDGER (kiosk_state.json)      │
│      │ spend = online API call               │   │      │ issue = RSA blind signature   │
│      ▼                                       │   │      ▼                               │
│ Merchant wallet (online, same DB)            │   │ Merchant DEVICE (offline bearer      │
│                                              │   │ proofs — works with ZERO network)    │
└──────────────────────────────────────────────┘   └──────────────────────────────────────┘
        money exits: unload → bank                    money exits: settle → payout → bank
```

---

## 1. How a real bank "recognizes" a wallet — the actual mechanism

There is no magic. Banks recognize wallets by **pre-agreed account references
plus a machine callback**. Three real-world patterns, in order of automation:

1. **Reference matching (manual reconciliation)** — every deposit carries a
   code in the narration (each wallet company uses its own scheme; the exact
   formats below are *illustrative, unverified*).
   The wallet company downloads statements and matches refs. *This is exactly
   FUPI's CSV rail with `-match FUPI` — Level 0.*
2. **Virtual Accounts (VA / UVA)** — the bank issues the wallet company a
   **bank account per user/device**. Any IMPS/UPI to that VA is auto-matched
   by the **bank's host** (amount + VA number = unambiguous identity), and the
   bank **pushes a callback/API event** to the wallet server. No CSV ever.
   *(Structure is how bank–wallet partnerships work; account-number formats
   are illustrative. Confirm exact VA formats, callback schemas, fees and
   onboarding requirements with a specific bank or VA provider — e.g.
   RazorpayX — before relying on them.)*
   *This is the real "bank recognizes the hardware" answer — Level 2.*
3. **Gateway webhooks** — Razorpay/Cashfree hold the bank relationship, do VA
   matching on your behalf, and POST `payment.captured` to your server.
   *FUPI's `POST /v1/webhook` is this endpoint — Level 1 (needs the flat-payload
   adapter per gateway; gateway pricing/KYC terms are per-provider, verify
   before quoting numbers).*

**The invariant that makes any bank trust the box:** the escrow balance must
equal the sum of issued-and-unsettled device money, checked daily.
Amazon does this with an escrow recon team. FUPI does it with:
`pilot --bank-balance` (bank ≥ reserve ⇒ fully_backed), append-only ledger,
unique refs, first-to-settle-wins. Those four invariants **are** the audit
a sponsor bank would demand.

---

## 2. Recognition levels for FUPI hardware (what to build next)

| Level | Bank cooperation | Tech needed | Status |
|---|---|---|---|
| **L0 — remark + CSV** | none (dumb courier) | built: `-import-csv -match FUPI`, identity refs (`utr:<token>`) — *see §7 fixes* | ✅ running, manual |
| **L1 — gateway webhook** | merchant KYC + provider fees (per-provider; verify) | built: `POST /v1/webhook` (HMAC, replay-safe); needs **payload adapter** per gateway + public HTTPS (Cloudflare Tunnel) | ✅ endpoint live, adapter missing |
| **L2 — bank Virtual Accounts** | sponsor-bank partnership (several Indian banks offer corporate VA APIs; also VA-as-a-service providers) | kiosk consumes bank callback (`X-Fupi-Signature` HMAC already specified); **VA number ↔ device pubkey mapping table** added to kiosk state | 📐 designed here (§2 example is illustrative, not a real bank schema) |
| **L3 — licensed PPI wallet** | RBI PPI authorization, company + net-worth + compliance | FUPI kiosk = issuer core; interop with UPI/other wallets via licensed PSP | 🚫 out of scope for a personal pilot (net-worth/compliance thresholds: verify against the current RBI PPI Master Direction) |

**L2 design (the real answer to "how will the bank recognize the hardware") — illustrative schema, not a real bank's:**

```
Sponsor bank issues:  VA-1 = kiosk escrow VA   (bulk top-ups)
                      VA-2..N = per-device VAs (one per device pubkey)
Bank host: IMPS credit to VA-2, ref "FUPI-<UTR>"  →  POST https://kiosk/v1/webhook
           body: {va:"VA-2", device:"fea2cc80…", amount_minor:100000, utr:"SBINR26…"}
Kiosk:      VA→device pubkey lookup  →  credit reserve + auto-allocate to that device
            ref = "utr:SBINR26…"     →  bank-replay-proof by construction
```

The VA number *is* the hardware's identity at the bank; the UTR is the deposit's
identity; `Deposit(ref="utr:<UTR>")` makes double-credit impossible by design
(the dedupe key is the bank's own receipt number).

---

## 3. Full tech stack — component mapping

| Layer | FUPI component (exists today) | Real-world equivalent |
|---|---|---|
| Escrow ledger | `kiosk_state.json` (append-only, atomic tmp+rename+bak, 0600) | wallet company ledger DB |
| Real money | your SBI account | nodal/escrow account at sponsor bank |
| Issuer keys | kiosk RSA-2048, **one key per denomination** (`main.go:229-239`) | issuer HSM keyset |
| Money ingest | CSV rail / webhook rail / Lightning rail | VA callback / gateway webhook / acquirer push |
| User wallet | `vault-rust` flash file (offline, self-verifying) | wallet app balance row (online-only) |
| Peer payment | bearer blind-signature proofs, offline | — *(centralized wallets have no offline mode — this is FUPI's edge)* |
| Settlement | `settle-all` → kiosk spent-set (first-to-settle-wins) | acquirer batch settlement |
| Unload to bank | `payout --ref UTR` (unique UTR, owed-decremented) | nodal sweep / UPI P2P payout |
| Daily audit | `go run ./pilot --atm … --pin-tls … --bank-balance` | escrow reconciliation report |

---

## 4. Workflow A — Top-up: bank → hardware

```
STEP   ACTOR      ACTION
────────────────────────────────────────────────────────────────────────────
A1     user       YONO/branch: IMPS/NEFT ₹X → escrow acct, remark "FUPI-<UTR>"
A2     bank       credits account; narration carries remark + UTR   (dumb courier)
A3     kiosk      RECOGNITION (per level):
                  L0: operator exports statement CSV → stop kiosk →
                      ./kiosk-go -state … -import-csv sbi_statement.csv -match FUPI
                      ref = "utr:<token from narration>"   ← §7 fix makes this safe
                  L1: gateway POSTs /v1/webhook (HMAC body, amount minor units)
                      ref = order_id → 409 on replay
                  L2: bank posts VA callback → ref = "utr:<UTR>" → auto-allocated
A4     kiosk      reserve += X; depositRefs += ref; fully_backed re-checked
A5     operator   vault allocate <device-pubkey> X --ref alloc-<n>
                  vault topup X   → blinded request → RSA blind sign → unblind
                  device now holds bearer notes (d500/d100/d20/d5/d1)
────────────────────────────────────────────────────────────────────────────
INVARIANT: no A3 ⇒ no A5. Issuance guard: issued + owed + amount ≤ reserve (main.go:427).
```

## 5. Workflow B — Hardware → hardware (offline payment + settlement)

```
SAME ISSUER (both devices pinned to the same kiosk keyset — today's reality):

STEP   ACTOR      ACTION
────────────────────────────────────────────────────────────────────────────
B1     payer      vault pay 150  → denom selection (d100+d20+d20+d5+d5)
                  → proofs = (secret, kiosk-RSA-sig) leave the flash into outbox
B2     payer      transport: QR / NFC / USB / file  ← NO network anywhere
B3     merchant   vault accept INV-7 --expect 150   (OFFLINE)
                  verifies sig^e mod n == SHA256(secret) under PINNED keyset
                  checks own receipts (local replay), stores proof + receipt
B4     merchant   later, any connectivity: vault settle-all --merchant cafe-1
                  → POST proofs → kiosk verifies, first-to-settle-wins:
                     first proof wins (spent-set += serial, owed += value)
                     duplicate → REJECTED double-spend (merchant ate the loss —
                     inherent to offline ecash; there is NO expiry window, §7-3)
────────────────────────────────────────────────────────────────────────────

DIFFERENT ISSUER (device pinned to kiosk-α, merchant to kiosk-β) — interop sketch:

   ┌─── payer device (α-signed proof) ──► merchant device (β keyset pinned) ───┐
   │  α and β run a CLEARING AGREEMENT (modeled on how wallet issuers clear
   │  between themselves — e.g. RBI's interop arrangements; sketch only,
   │  NOT implemented in this repo):│
   │  B5  β accepts α-signed proof only if β has α's pinned keyset (fingerprint│
   │      exchange = the "interop directory")                                  │
   │  B6  β settles to β-kiosk as usual                                        │
   │  B7  nightly: α↔β exchange clearing files of each other's settled proofs  │
   │      → net position → single IMPS transfer α→β (or reverse) covers it     │
   │  Each kiosk only ever pays/collects the NET, banks stay dumb.             │
   └───────────────────────────────────────────────────────────────────────────┘
```

## 6. Workflow C — Hardware deposit to bank (unload / cash-out)

```
STEP   ACTOR      ACTION
────────────────────────────────────────────────────────────────────────────
C1     merchant   proofs settled (Workflow B) → kiosk report shows OWED
C2     operator   vault payout --merchant cafe-1 --ref <IMPS-ref>  (or kiosk API)
                  guard: amount ≤ owed (recomputed from full ledger, same lock)
                  guard: ref unique → ErrDupPayout (UTR can never pay twice)
C3     kiosk      owed -= X; reserve -= X; payout record + append-only ledger
C4     bank leg   operator IMPS/NEFT ₹X from escrow acct → merchant's real acct
                  (L2 future: kiosk calls sponsor-bank payout API with the same
                   unique ref; the bank's UTR comes back and is recorded)
C5     nightly    pilot --bank-balance <actual> → bank ≥ reserve? PASS
                  (this is the escrow recon that keeps the kiosk honest —
                   escrow can NEVER go below outstanding device money)
────────────────────────────────────────────────────────────────────────────
```

## 7. Gate before real ₹ at L1/L2 (from the 4-agent validation, Nov 2026)

1. **Identity refs** — CSV/VA refs = `"utr:<token>"` extracted from narration,
   not row-content hash (closes 2 probe-proven double-credit paths).
2. **One-shot rails require the credit secret** — `-import-csv` /
   `-lightning-mint` must fail closed without `FUPI_CREDIT_SECRET`.
3. **Document honestly**: offline accept = local-trust only; double-spend is
   caught at settlement, no expiry window exists.
4. Dir-fsync after state rename (power-loss settle-replay window).
5. Per-gateway webhook payload adapter (Razorpay nested `payment.captured`).
6. `receive`/`verify` auto-pin must go through the pinned-keyset checks (TOFU).

## 8. Legal reality (do not skip)

Moving **your own money** through your own box = a personal pilot, fine.
Letting **other people** load and spend = you are operating a Prepaid Payment
Instrument: in India that means an RBI PPI authorization (company, minimum
net-worth, escrow with a sponsor bank, KYC, audit) **or** operating through an
already-licensed issuer/gateway (Level 1/2 above). The FUPI protocol is the
easy part — the license is the moat Amazon/PhonePe paid for.

---
*Validation basis: 4-agent full-codebase review (core / rails / vault / docs),
Nov 2026. Vault verdict: no forgery without the kiosk private key.*
