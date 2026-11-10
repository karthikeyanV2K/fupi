# FUPI MVP — Build Plan

> FUPI = Fuck UPI. Two phases, two demos. No middleman inside any payment.

```
 PHASE 1 "LOAD"  bank transfer → kiosk → blind-signed bearer tokens → ESP32 vault
 PHASE 2 "SPEND" ESP32 vault ──token (the money itself)──► friend / shop / website
```

## Layout

```
 X:\fupi\mvp\
   README.md                  <- this file
   crypto.py                  <- real Chaum RSA blind signatures (stdlib only)
   bank_rail.py               <- REAL BANK RAILS (Webhook, CSV import, Lightning)
   kiosk.py                   <- mini mint: reserve, keyset, blind-sign, settle
   vault.py                   <- vault logic (shared by sim + ESP32 spec)
   test_mvp.py                <- 17 checks: crypto, rules, flows
   phase1_bank_to_vault\
     demo_phase1.py           <- RUN THIS: bank → vault end-to-end
   phase2_vault_to_world\
     demo_phase2.py           <- RUN THIS: vault → friend/shop/website
  X:\fupi\pico_w\
    main.py                    <- Raspberry Pi Pico W vault firmware (MicroPython)
    ssd1306.py                 <- I2C OLED driver
```

## Run it (Python 3.10+, NO pip install needed — stdlib only)

```powershell
 cd X:\fupi\mvp
 python test_mvp.py                           # 17 checks: crypto + rules + flow
 python phase1_bank_to_vault\demo_phase1.py   # Phase 1: load 50 from bank to vault
 python phase2_vault_to_world\demo_phase2.py  # Phase 2: pay friend + shop + site
```

## What Phase 1 proves

1. Bank transfer credits the kiosk's reserve via bank_rail.py (Statement CSV, Webhook, or Lightning).
2. The bank rail tells the kiosk "reserve +50".
3. Vault generates secrets, blinds them, kiosk blind-signs (never sees serials).
4. Vault unblinds, verifies, stores proofs in `vault_flash.json` (sim of ESP32 flash).
5. Bank's job is FINISHED. Vault holds bearer cash.

## What Phase 2 proves

1. Vault → friend: token string over "QR" (printed string), friend verifies offline
   with cached keyset + settles at kiosk. No switch, no bank, no server in path.
2. Vault → shop: NUT-18 style payment request → P2PK-locked token → shop settles.
3. Vault → website: HTTP 402 + X-Cashu mock → site accepts token.
4. Double-spend demo: same token paid twice → kiosk rejects second settle.
   First-to-settle-wins, exactly like the README §11 model.

## Honest MVP limits (vs full README)

- RSA-512 demo keys (fast, NOT secure) — swap to 2048+ / secp256k1 NUT-00 in prod.
- Single 1-unit denomination (real Cashu uses powers of 2).
- Kiosk is function calls, not HTTP — ESP32 sketch shows the HTTP shape.
- No PIN / flash-encryption / SE in the sim — on-device vault lives in `pico_w/main.py`.

## Real money — the actual bank transaction (you do this)

The kiosk itself only knows `on_credit(amount)` — `bank_rail.py` plugs rails into that socket
(the production Go HTTP kiosk — RSA-2048, cross-language tested — lives in
`../kiosk-go/`):

```
 RAIL A — Gateway/bank webhook  (real money, needs a merchant/gateway account)
   1. set secret:   setx FUPI_WEBHOOK_SECRET "your-long-random-secret"
   2. start server: python bank_rail.py --mode webhook --port 8787
   3. in your Razorpay/Cashfree/Stripe dashboard (or bank corporate API),
      point the payment-captured webhook at:
        http://YOUR-IP:8787/webhook
      body: {"amount": <paise/cents>, "order_id": "ref-123"}
      signature header: X-Razorpay-Signature or X-Fupi-Signature
                        = HMAC-SHA256(raw body, secret)
   4. pay REALLY from your bank app / card / UPI-to-gateway.
   5. server verifies HMAC -> credits kiosk reserve -> then:
        python phase1_bank_to_vault\demo_phase1.py   (vault loads against it)

 RAIL B — Statement CSV import  (real money already moved, no API/keys at all)
   1. net-banking -> download statement CSV (HDFC/ICICI/SBI/any)
   2. python bank_rail.py --mode csv --csv my_statement.csv
   3. every credit row to the kiosk account becomes reserve. Done.

 RAIL C — Real cdk-mintd + Lightning  (no bank license needed, README §9)
   1. install + run cdk-mintd (CLN/LND/LDK backend)
   2. python bank_rail.py --mode lightning --mint http://127.0.0.1:3338 --amount 10000
   3. pay the printed bolt11 invoice from any real Lightning wallet
   4. on PAID the reserve credits; vault tops up against it

 Verify the plumbing without money:  python bank_rail.py --mode selftest
```

Regulatory note (README §14): Rail A/C settle the kiosk's reserve — the kiosk
wraps value 1:1 and issues bearer tokens against it. Keep the reserve published;
fiat-unit issuance at scale belongs to a licensed issuer.
