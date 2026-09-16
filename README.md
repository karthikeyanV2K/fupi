# FUPI — Fuck UPI (Offline Vault Payment Infrastructure)

> Pronounced "foo-pee". The name is a statement of purpose: **everything UPI does
> to your money — route it through a switch, watch both sides, block it, reverse
> it — FUPI refuses to do.** No switch, no bank, no processor sits inside your
> payment. A bank loads your vault once (like an ATM); after that the token itself
> IS the money, and the token itself moves.
>
> *Status: design document (code-free), v2. Written 2026-09-15. Apache-2.0.*
> *All technical and regulatory claims were verified live against public sources
> (§15). Re-verify before relying on fast-moving law.*

## Table of Contents

1. [What is FUPI?](#1-what-is-fupi)
2. [60-Second Concept Course](#2-60-second-concept-course)
3. [System Architecture (ASCII)](#3-system-architecture)
4. [From Your Bank to Your Vault (the digital ATM)](#4-from-your-bank-to-your-vault)
5. [The No-Middleman Guarantee — FUPI vs UPI-style](#5-the-no-middleman-guarantee)
6. [Hardware: ESP32-C6 vs Pico W](#6-hardware-esp32-c6-vs-pico-w)
7. [Tech Stack](#7-tech-stack)
8. [Ownership & Custody](#8-ownership--custody)
9. [Top-Up Flow — From Main Node to Vault](#9-top-up-flow)
10. [Payment Flows (All Rails)](#10-payment-flows-all-rails)
11. [Offline Mode — The Honest Model](#11-offline-mode--the-honest-model)
12. [The Main Node — Kiosk, Not Bank](#12-the-main-node--kiosk-not-bank)
13. [Threat Model](#13-threat-model)
14. [Legality & Compliance](#14-legality--compliance)
15. [Roadmap](#15-roadmap)
16. [Glossary](#16-glossary)
17. [Sources (verified live)](#17-sources-verified-live)
18. [MVP: Working Phases 1 & 2](mvp/README.md) — run it today
19. [kiosk-go: Self-Contained HTTPS ATM in Go](kiosk-go/README.md) — production-tier mint
20. [vault-rust: Lightweight RPi Rust Vault](vault-rust/README.md) — memory-safe offline cash
21. [Architecture Plan & Execution Flow](docs/ARCHITECTURE_PLAN_FLOW.md) — detailed technical specification


## 1. What is FUPI?

FUPI is a **hardware offline digital-cash vault** (ESP32-C6 production, Pico W
prototype) fed from a self-hosted ecash mint. You load value **once** — from your
bank, from Lightning, from any rail — and from then on you pay **anyone, anywhere,
with nothing in between**:

```
 LOAD ONCE (bank's job)              PAY ANYWHERE (nobody's job but yours)
 ┌──────┐   one transfer   ┌───────┐   YOUR VAULT ──token──► ANYONE
 │ BANK │ ── like an ATM ─►│ VAULT │     │
 │salary│    withdrawal    │ chip  │     └── no bank, no switch, no app,
 └──────┘                  └───────┘         no processor, no middleman
```

Four pillars:

1. **Bearer tokens, not ledger entries.** Money is an object you hold (a mint-
   signed proof), not a record a bank edits on your behalf. Possession = ownership.
2. **Blind signatures (Chaum 1983, via Cashu).** Even the mint that signed your
   tokens cannot link your load to your spends.
3. **A chip that answers to nobody.** ESP32-C6 secure boot + encrypted flash +
   secure element: stolen vault = encrypted brick.
4. **A kiosk, not a bank.** The main node exchanges outside money for bearer
   tokens 1:1 and holds reserves. It is not a bank, takes no deposits, pays no
   yield, promises nothing.

| | Bank account + UPI-style rails | App wallet | Crypto on-chain | FUPI vault |
|---|---|---|---|---|
| Money form | Ledger entry the bank edits | Database row in their cloud | UTXO on public ledger | Bearer proof on YOUR chip |
| Needs a middleman per payment | Always (switch + banks) | Always (their server) | No, but chain is public | **No — token moves directly** |
| Who can block a payment | Switch / bank | The company | Nobody, but all see it | **Nobody** |
| Privacy from the operator | None | None | Pseudonymous, graph-visible | Blind: mint can't link load→spend |
| Works with no network | No | No | No | Bounded offline (§11) |
| Lose device = lose money | No (bank recovers) | No (account recovers) | Yes (without seed) | Yes — like cash (seed restores) |

## 2. 60-Second Concept Course

| Term | Meaning in one line |
|---|---|
| **Bearer token** | Whoever holds it owns it — like a banknote, no account needed |
| **Mint** | Server holding 1:1 backing; blind-signs tokens, settles them |
| **Blind signature** | Mint signs your token without seeing its serial (Chaum 1983) |
| **DLEQ (NUT-12)** | Proof the mint's signature is genuine — anyone can verify |
| **P2PK (NUT-11)** | Token locked to a public key — only that key's owner can spend |
| **Melt** | Redeem tokens at the mint for an external payment (LN invoice etc.) |
| **Keyset** | Mint's set of denomination signing keys, identified by ID |
| **Rail** | A backing/payment channel: bank transfer, Lightning, on-chain, licensed fiat |

## 3. System Architecture

```
                        ┌──────────────── FUPI WORLD ────────────────┐
                        │                                            │
  YOUR BANK             │  MAIN NODE ("kiosk", cdk-mintd)            │   THE WORLD
  (loads once)          │  1:1 reserve, blind signer                 │   (paid directly)
   salary ──transfer──► │  ┌────────┐  ┌─────────┐  ┌────────────┐    │  friend/shop/site
   like ATM             │  │ reserve│  │  mint   │  │ transparency│   │  ▲
   withdrawal           │  │ vault  │◄─┤ signer  ├─►│ feed (DLEQ) │   │  │ token moves
                        │  └────────┘  └────┬────┘  └────────────┘    │  │ nothing between
                        └───────────────────┼────────────────────────┘  │
                                            │ blind top-up (once)
                                            ▼
                                     ┌──────────────┐  token   ┌──────────┐
                                     │ YOUR VAULT   │ ────────►│ RECEIVER │
                                     │ ESP32-C6 chip│  QR/BLE  │ anyone   │
                                     │ encrypted    │  Nostr   │          │
                                     │ flash        │  NUT-18  │          │
                                     └──────────────┘          └──────────┘
```

Layer map (L0–L6):

```
 L0 silicon : ESP32-C6 (secure boot RSA-3072, AES-XTS flash, DS/HMAC, TEE)
              + ATECC608B secure element | Pico W for prototype only
 L1 token   : Cashu NUTs — bearer proofs, blind sigs, P2PK, DLEQ, seed, QR
 L2 wallet  : vault engine — balance, journal, P2PK keys, keyset cache
 L3 mint    : cdk-mintd (Rust) — signer, reserve, melt/swap endpoints
 L4 rails   : bank transfer / Lightning (CLN/LND/LDK) / on-chain / licensed fiat
 L5 pay UX  : QR (animated NUT-16), BLE, Nostr, NUT-18 requests, HTTP 402 X-Cashu
 L6 audit   : DLEQ proofs + transparency feed + reconciliation
```

Trust map: bank sees ONE load. Mint signs blind, settles what it's handed.
Nobody sees both sides of a payment. The vault's OLED is the trusted display.

## 4. From Your Bank to Your Vault (the digital ATM)

> FUPI is a digital ATM in your pocket. You "withdraw" once from the bank — that
> one load transaction is visible to the bank exactly like an ATM withdrawal — and
> from that moment the money is cash-style YOURS. No bank, no UPI switch, no
> payment processor exists anywhere in your spending path.

```
 YOUR BANK             BRIDGE / KIOSK (the "ATM")        YOUR VAULT
 (where your           holds fiat reserve 1:1,           (ESP32-C6)
  salary lands)        issues bearer tokens)
 ─────────             ─────────────────────────         ─────────────
 [1] NEFT / IMPS / card transfer: "top up my kiosk"
 ─────────────────────►  bank sees ONE ordinary payment
                         to the kiosk/bridge — same as
                         an ATM withdrawal record
                         [2] bridge credits your bridge
                             wallet with the fiat unit
                             [3] vault requests blind
                                 top-up (§9 sequence)
                                 ── blinded messages ──►
                                 ◄─ blind signatures ───
                                                    [4] unblind → proofs
                                                        stored in encrypted
                                                        flash. VAULT = loaded.

 YOU NOW HOLD DIGITAL CASH. THE BANK'S JOB IS FINISHED.
```

| Who | What they know | What they NEVER know |
|---|---|---|
| Your bank | You moved money to your kiosk once (like an ATM withdrawal) | Which tokens exist, where you spend, whom you pay |
| Bridge/kiosk operator | Load amount, current reserve | Token serials (blind), your future spends, your payees |
| Any payment network | **Nothing — there is no payment network in your spending** | — |

Nothing about your spending ever flows back through the bank or any switch.
The bank rail is used **once, inbound, by you** — the same direction and dignity
as taking cash out of a machine. After that, the vault answers to nobody.

## 5. The No-Middleman Guarantee — FUPI vs UPI-style

> **"Crypto" in FUPI means one thing: the token itself is the money, and the token
> itself moves.** Not a message *about* money. Not an instruction to move money.
> Value and transport are the same object — a mint-signed bearer proof.

```
 HOW UPI-STYLE SYSTEMS MOVE MONEY (a switch sits inside EVERY payment)

 your phone ──► PSP app ──► CENTRAL SWITCH ──► payee's bank ──► payee
               (middleman) (the BIG middleman:    (middleman)
                            routes every payment,
                            sees both sides, can
                            block / reverse / flag)

 money never moves between you two — two ledger entries at two banks get
 flipped, in real time, by the hub. The hub is a mandatory party to every
 single payment. Both banks online + switch online, or nothing happens.
 The hub holds: your identity, payee identity, amount, time, device, pattern.

 HOW FUPI MOVES MONEY (a bearer token physically travels — like a banknote)

 YOUR VAULT ........ token ........►  RECEIVER
 (ESP32-C6)     mint-signed bearer      (their wallet)
                proofs — the money
                itself
                     └── NOTHING in between. No app server, no switch,
                         no bank, no processor, no "payment interface".
                         A QR code / BLE hop is just the paper the note
                         travels on — it is not a party to the payment.
```

| Property | UPI-style switch | FUPI bearer flow |
|---|---|---|
| Who must be online at pay-time | Both banks + the switch | Nobody (P2P) — receiver only for instant settle |
| Who can block or censor a payment | Switch / banks | Nobody at pay-time; mint only settles what it is handed |
| Who sees both parties | The switch | Nobody (blind signatures — mint can't link load→spend) |
| Reversal / freeze from the hub | Possible | Impossible — bearer, final at handover |
| Payer's bank needed per payment | Always | Never (bank used once, to LOAD — §4) |
| Any network needed at all | Always | No (§11 State C, bounded) |
| What a "payment" is | A ledger instruction | The money itself moving |

**One-line rule:** *in UPI-style systems, money is a record that gets edited.
In FUPI, money is an object that gets handed over.*

**Honest footnote:** a receiver who wants instant back-to-fiat settles tokens at
*their own* mint/bridge. That settlement is **their** business, between them and
their operator — like a shop depositing cash at its bank after closing. It is not
a middleman inside your payment; your payment finished when the token left your hand.

## 6. Hardware: ESP32-C6 vs Pico W

> **Verdict: ESP32-C6 = the production vault. Pico W = the cheap prototype.**
> The deciding factors are all security silicon Pico W lacks: secure boot,
> encrypted flash, key-isolation peripherals, TEE, official secure-element support.

| Spec | ESP32-C6 | Pico W (RP2040) |
|---|---|---|
| Core | RISC-V 160 MHz + LP core | Dual Cortex-M0+ 133 MHz |
| Radio | WiFi 6 + BLE 5 + 802.15.4 | WiFi 4 + BLE (CYW43439) |
| RAM / flash | 512 KB SRAM / 4–8 MB ext. | 264 KB SRAM / 2 MB ext. |
| Secure boot | RSA-3072, rollback-protected | None |
| Flash encryption | AES-128/256-XTS | None |
| Key isolation | DS + HMAC peripherals, TEE | None |
| Secure element support | ATECC608B via esp-cryptoauthlib | Possible over I2C, no official flow |
| Crypto accelerators | AES/SHA/RSA/ECC/RNG | None (software only) |
| Dev stack | ESP-IDF / Arduino / esp-rs | C/C++ SDK, MicroPython, UF2 BOOTSEL |
| Price | ~$3–5 module | ~$6 board |

Three build tiers:

```
 Tier 0 "PAPER" (~$10)    Pico W + 0.96" OLED + 3 buttons + LiPo.
                          Proves flows on a desk. No security claims.
 Tier 1 "PROTO" (~$15-20) Pico W + ATECC608B on I2C + display + buzzer.
                          Real rails, real phone interop. Still no secure boot.
 Tier 2 "VAULT" (~$20-35) ESP32-C6 + ATECC608B + OLED + tamper loop + metal shell.
                          Secure boot ON, flash encryption ON, keys never leave SE.
                          THE build this document describes.
```

Wiring (Tier 2):

```
 ESP32-C6 ──I2C──► ATECC608B (SDA/SCL + 4k7 pullups)
          ──SPI──► 0.96" OLED (SCLK/MOSI/CS/DC/RST)
          ──GPIO─► 3 buttons (UP/DOWN/OK, INPUT_PULLUP)
          ──GPIO─► tamper loop (case switch → wipe on open)
          ──VBAT─► LiPo + charger + fuel gauge
```

## 7. Tech Stack

Everything below is **verified open-source**. No proprietary dependency anywhere.

```
 YOUR VAULT (firmware)         MAIN NODE (server)            PHONE / WEB (bridge)
 Cashu wallet engine           cdk-mintd (Rust)              Nutshell / Cashu.me
 NUT-11 P2PK, NUT-12 DLEQ      CLN / LND / LDK / fake rail   NUT-16 animated QR
 NUT-13 seed, NUT-16 QR        SQLite → Postgres             Nostr client (NUT-17)
 ESP-IDF / esp-rs              cdk-axum REST                 ERC-4337 smart-account
 ATECC608B via                 NUT-18 requests               bridge for fiat/HTTP402
 esp-cryptoauthlib             NUT-24 HTTP 402 X-Cashu
```

| Component | Project | License |
|---|---|---|
| Token protocol | Cashu NUTs (00–30) | MIT |
| Mint server | Cashu CDK `cdk-mintd` (Rust) | MIT / Apache-2.0 |
| Kiosk (this repo, Go port) | `kiosk-go/` — stdlib-only, cross-lang tested | Apache-2.0 |
| Wallet ref / interop | Nutshell (Python) | MIT |
| Vault firmware base | ESP-IDF | Apache-2.0 |
| Vault firmware (Rust alt) | esp-rs | MIT / Apache-2.0 |
| Secure element driver | esp-cryptoauthlib (ATECC608B) | Apache-2.0 |
| Privacy precedent | GNU Taler (payer-private, merchant-taxable) | GPLv3+ / GFDL docs |
| Federation future | Fedimint | MIT |
| Web-bridge accounts | ERC-4337 tooling | MIT |

Per-device: vault = ESP-IDF/esp-rs + Cashu wallet engine + display/QR stack.
Kiosk = `cdk-mintd` + one rail backend + transparency feed. Bridge phone app =
any NUT-compatible wallet (Nutshell/Cashu.me class).

Language per tier (full argument + benchmarks in [kiosk-go/README.md](kiosk-go/README.md)):
kiosk = **Go** (goroutine-per-connection, stdlib TLS, single static binary),
vault core = **Rust** via esp-rs (no GC on the money path, `no_std`, panics
reboot instead of exploit), protocol tests = **Python** (fast math iteration +
cross-language interop client). C never touches a money path.

## 8. Ownership & Custody

> **"How does the vault hold my money?"** Ownership is a **signature**, not an
> account. One token = one secret only you know + one mint signature on it + one
> DLEQ proof it's genuine. Flash holds ciphertext; the SE holds the keys.

Anatomy of one token:

```
 ┌─ YOUR SECRET (random, blinded at load — mint never saw it)
 │   ┌─ MINT SIGNATURE (blind-signed at load, verifiable by anyone)
 │   │   ┌─ DLEQ PROOF (mint proves the signature is genuine)
 │   │   │   ┌─ DENOMINATION + KEYSET ID (which keys signed it)
 ▼   ▼   ▼   ▼
 [secret | C_blind | DLEQ | 8 sat | keyset 0x00ab..]
```

Three keys on the vault: (1) NUT-13 seed → all token secrets (restorable from
words); (2) P2PK receive key → lives in ATECC608B, never leaves; (3) PIN key →
unlocks flash, 3 fails = wipe. Keyset IDs are pinned — a signature from an
unknown keyset is rejected on sight.

Flash layout: `[PIN slot][seed (enc)][P2PK pubkey][proof store (enc)][journal]`.
Lifecycle: load (blind-sign → store) → hold (encrypted, offline) → spend (hand
token over) → settle (receiver redeems) → restore (seed re-derives secrets).

## 9. Top-Up Flow — From Main Node to Vault

Online Lightning top-up (the full sequence; bank-fiat loads in §4 reuse it
with the bridge standing in for the LN rail):

```
 VAULT              MAIN NODE (cdk-mintd)           RAIL (LN / bridge)
  │ quote request   │                               │
  │────────────────►│────── invoice request ────────►│
  │◄────────────────│◄───── invoice ─────────────────│
  │ pay invoice (external wallet / bank-paid bridge)│
  │────────────────►│────── settle check ───────────►│ paid ✓
  │ blinded msgs    │                               │
  │────────────────►│ (mint signs BLIND — never     │
  │◄── signatures ──│  sees token serials)          │
  │ unblind → proofs stored in encrypted flash      │
```

Trust notes: mint can't link load→spend (blind). Vault verifies every signature
+ DLEQ before storing. Keyset IDs pinned. Amount split across denominations.

Airgapped QR top-up: vault shows no network at all — blinded messages ride as
animated QR (NUT-16) via a phone camera; signatures ride back the same way.
Fiat rail: the ONLY fiat issuance happens at a LICENSED operator; your kiosk
only swaps that unit 1:1 against reserves (§14).

## 10. Payment Flows (All Rails)

> One token, six destinations. In every flow the token moves directly from vault
> to receiver — no switch, no processor, no middleman.

```
 [10.1 FRIEND]  vault ──QR/BLE/Nostr──► friend's wallet. Done. Nobody online.
 [10.2 SHOP]    shop shows NUT-18 request → vault scans → token locked to
                shop's P2PK key → shop settles at its mint later. Shop offline OK.
 [10.3 WEBSITE] site answers 402 + `X-Cashu` (NUT-24) → vault/bridge pays token
                → site settles. No card rail, no gateway cut.
 [10.4 LIGHTNING] vault melts token at mint → mint pays any LN invoice.
                (Receiver-side settle — the only online flow, and it's yours.)
 [10.5 ON-CHAIN] mint pays a BTC address from reserve (NUT-30 style).
 [10.6 CROSS-MINT] melt at mint A → fresh invoice at mint B → blind-mint at B.
                Value hops kiosks without any of them seeing the full path.
```

- Tokens can be sent to your **P2PK key** any time (NUT-11) — you collect them
  when you next connect, batched in one swap.

## 11. Offline Mode — The Honest Model

> "Digital cash offline" has a 40-year-old catch: **if both sides are offline,
> nobody can check whether the token was already spent.** FUPI doesn't lie about
> this — it gives you three honest states:

```
 STATE A — RECEIVER OFFLINE (final)     STATE B — YOU OFFLINE (final)
 shop's terminal down, you online       your vault offline, shop online
 → pay P2PK-locked token to shop's key  → show QR from encrypted store
 → shop verifies DLEQ vs cached keyset  → shop settles live at mint
 → shop settles when back online        → final at handover

 STATE C — BOTH OFFLINE (bounded, cash-like)
 vault ──token──► receiver, nobody checks anything — EXACTLY like paper cash.
 Risk = double-spend of that token. Bound by: offline purse CAP (small),
 P2PK lock (only receiver can settle), spend JOURNAL (evidence), first-to-
 settle-wins rule. A copied token is a forged note: possible, bounded, visible.
```

| Capability | Online | Receiver-offline | Fully-offline |
|---|---|---|---|
| Pay friend/shop/site | Yes | Yes (P2PK+DLEQ) | Yes (State C, capped) |
| Double-spend check | Live | Deferred (first-settle-wins) | None (cap bounds loss) |
| Needs network | Vault or receiver | Neither at pay-time | Neither |
| Finality | Instant settle | At receiver's settle | At handover (trust/cap) |

## 12. The Main Node — Kiosk, Not Bank

> "Bank as main node — like bank but NOT bank." Precisely: a **kiosk**. It
> exchanges outside money for its own bearer tokens, and that's ALL it does.

```
 KIOSK IS                              KIOSK IS NOT
 ─────────────────────────────         ─────────────────────────────
 blind signer (never sees serials)     account keeper (no accounts exist)
 1:1 reserve holder (published)        fractional lender (no lending)
 melt/swap endpoint (settles handed    payment switch (no routing, no
 tokens, no questions)                 blocking, no reversing)
 transparency feed (DLEQ, keysets)     credit bureau (no identities kept)
```

Topologies: (a) self-kiosk — your Pi at home, your rules; (b) community kiosk —
one operator, published reserves; (c) licensed-issuer wrap — fiat unit comes from
a permitted issuer, kiosk only custodies 1:1. Reserve rule: **issued tokens ≤
audited reserve, always, published always.** Users vote with feet — that exit is
the kiosk model's self-check.

## 13. Threat Model

```
 THREAT                            MITIGATION (already in design)
 ───────────────────────────────── ─────────────────────────────────
 Device stolen                     AES-XTS flash encryption; PIN-gated unlock;
                                   P2PK receive key in SE can't be read out
 Firmware swapped for thief build  RSA-3072 secure boot; rollback protection
 Token copied (backup leak)        First-to-settle-wins; P2PK locks; offline cap
 Mint prints extra tokens          DLEQ makes rogue keys detectable by any wallet
 Mint insolvency / rug             1:1 reserve + attestations; small per-mint balances
 Mint learns payment graph         Blind signatures break issue→spend linkage
 Coerced PIN ($5 wrench)           Duress PIN → decoy/wipe (design note)
 Case opened, bus probed           ATECC608B: keys never leave SE; tamper-loop wipe
 Seed photographed at restore     One-screen hold-to-reveal; wipe on 3 fails
 Malicious board (supply chain)    Flash own keys; verify secure-boot pubkeys
 Quantum (future)                  Keyset-based protocol → post-quantum NUT migration
```

NOT protected: losing device AND seed (cash is gone); a mint running away with
reserves (same trust as choosing a bank branch); legal seizure of a reserve;
malware on your phone bridge (the vault's OLED is the trusted display).

## 14. Legality & Compliance

> The software is legal everywhere; operating value issuance is regulated
> somewhere. FUPI keeps every actor on the most defensible side of that line —
> in the same shape regulators already know: anonymous payer, taxable merchant
> (GNU Taler's core compliance principle).

```
 ACTOR            BURDEN                          FUPI RESPONSE
 ───────────────  ──────────────────────────────  ─────────────────────────────
 Vault holder     Holding own cash/token:         Self-custody. No yield, no
 (you)            normally none                   interest. Like banknotes.
 Mint operator    Running issuance/redemption     (a) BTC/LN rail (lighter regime);
 (kiosk owner)    can be EMI/MSP/MSB-adjacent     (b) fiat: wrap a LICENSED
                                                  issuer's unit, kiosk only
                                                  custodies 1:1 + publishes
 Merchant         Ordinary commerce duties        Income TRANSPARENT (settles via
 (shop/site)      (tax etc.)                      mint) — payer stays private
```

Stablecoin-law reality (verified 2025–2026): **USA GENIUS Act** (Pub. L. 119-27,
signed 2025-07-18) — payment stablecoins need permitted issuers + 1:1 reserves.
**EU MiCA** — e-money-token issuance needs authorization. Hence: fiat issuance
only at a licensed operator; the kiosk wraps, never issues. No native token, no
yield, DLEQ self-audit, 1:1 reserves — legit-friendly by construction.

## 15. Roadmap

```
 PHASE       GOAL                             HARDWARE    DELIVERABLE
 ──────────  ───────────────────────────────  ──────────  ─────────────────────
 M0 "Paper"  Flows on a desk (fake rail)      Pico W      Balance, top-up, P2P QR
 M1 "Proto"  Real rail + phone interop        Pico W      Real LN melt, NUT-18 shop
 M2 "Vault"  Secure port: PIN, journal, DLEQ  ESP32-C6    Secure boot + enc ON,
              on-device, SE custody                       pen-test checklist
 M3 "Offline" P2PK offline + capped purse     ESP32-C6    Offline purse, evidence
 M4 "Kiosk"  Operator-grade node + feed       Pi/VPS      Transparency, rotation
```

Every phase is independently useful. Protocol stays 100% within existing NUTs.

---

## 16. Glossary

| Term | Definition |
|---|---|
| **Bearer instrument** | Possession = ownership (banknote, FUPI token) |
| **Blind signature** | Signed hidden, unblinded later, still valid (Chaum 1983) |
| **Cashu** | Open Chaumian ecash protocol in "NUTs" (MIT) |
| **cdk-mintd** | Rust mint server from the Cashu Development Kit (MIT/Apache-2.0) |
| **DLEQ** | Proof the mint's signature is genuine (NUT-12) |
| **Keyset** | Mint's denomination signing keys, by ID (NUT-01/02) |
| **Melt** | Redeem tokens for an external payment (LN invoice etc.) |
| **Mint** | 1:1-backed server issuing/blind-signing bearer tokens |
| **NUT** | "Notation, Usage, and Terminology" — one Cashu spec doc |
| **P2PK** | Pay-to-Public-Key lock — only key owner spends (NUT-11) |
| **Proof** | Atomic unit: secret + signature (+DLEQ) worth a denomination |
| **Rail** | Backing/payment channel: bank, Lightning, on-chain, licensed fiat |
| **Seed (NUT-13)** | One seed restores all token secrets |
| **Secure element** | Chip (ATECC608B) holding keys that can't be read out |
| **Swap** | Exchange proofs for fresh proofs (change, privacy) |
| **Vault** | FUPI hardware wallet: proofs in encrypted flash |

## 17. Sources (verified live at writing time)

| # | Claim used in this doc | Source |
|---|---|---|
| 1 | Cashu = open Chaumian ecash; bearer tokens vs Lightning; blind sigs; MIT | cashu.space |
| 2 | NUTs 00–30: NUT-11 P2PK offline-receiver, NUT-12 DLEQ, NUT-13 seeds, NUT-16 animated QR, NUT-18 requests, NUT-24 HTTP 402, NUT-30 on-chain | github.com/cashubtc/nuts |
| 3 | CDK: Rust, MIT/Apache-2.0; cdk-mintd, CLN/LND/LDK backends, fake-wallet, axum, sqlite/postgres | github.com/cashubtc/cdk |
| 4 | GNU Taler: blind sigs, no chain, payer anonymous + merchant taxable, user-bears-loss cash model | taler.net, docs.taler.net |
| 5 | Fedimint: federated guardians + ecash + LN gateways | fedimint.org |
| 6 | ESP32-C6: RISC-V 160 MHz, RSA-3072 secure boot, AES-XTS flash, DS/HMAC, TEE, WiFi6/BLE5/15.4 | espressif.com (ESP32-C6) |
| 7 | esp-cryptoauthlib: official ATECC608A/B component for ESP-IDF incl. C6 | github.com/espressif/esp-cryptoauthlib |
| 8 | Pico W / RP2040: dual M0+ 133 MHz, 264 KB SRAM, UF2, no crypto silicon | raspberrypi.com documentation |
| 9 | ERC-4337: smart accounts, paymasters, session keys, passkeys | docs.erc4337.io |
| 10 | GENIUS Act: Pub. L. 119-27, signed 2025-07-18, 1:1 reserves, permitted issuers | congress.gov |

> Fetched and read live while writing (2026-09-15). Re-verify regulatory points.

---

## License & Colophon

- This document and the FUPI design: **Apache-2.0**.
- Upstream: Cashu NUTs (MIT), CDK (MIT/Apache-2.0), Nutshell (MIT), ESP-IDF
  (Apache-2.0), esp-rs (MIT/Apache-2.0), esp-cryptoauthlib (Apache-2.0),
  GNU Taler (GPLv3+/GFDL docs).
- Diagrams: hand-drawn ASCII, kept in-repo so they diff like code.

*FUPI — Fuck UPI. Your money, your chip, your rules. Load once from the bank,
pay anyone, anywhere, with nothing in between.*
