use fupi_vault::client::{AtmClient, TlsMode};
use fupi_vault::crypto::{generate_claim_keypair, lock_of, modulus_fingerprint};
use fupi_vault::storage::FlashStorage;
use fupi_vault::vault::Vault;
use std::env;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

fn print_usage() {
    println!(
        r#"
FUPI Lightweight Rust Vault (for Raspberry Pi & Desktop)
Zero-middleman offline digital cash. The token itself IS the money.

Usage:
  fupi-vault <subcommand> [options]

Subcommands:
  pin [--force]        Pin the ATM's denomination keysets (prints fingerprints to verify out-of-band)
  device               Print this vault's device public key (the operator allocates quota to it)
  allocate <pubkey> <amount>
                       OPERATOR: give a device an issuance quota (needs FUPI_CREDIT_SECRET; --ref <unique id>)
  topup <amount>       Withdraw <amount> of value as denominated proofs (--lock <pubkey> to lock them)
  pay <amount>         Pay exactly <amount>, making change via the ATM if needed; --p2pk <pubkey> spends proofs locked to that key
  accept <token>       MERCHANT: verify offline, store, write a receipt (--invoice <id>, --expect <amount>)
  receipts             MERCHANT: list accepted payments and their settlement status
  settle-all           MERCHANT: settle every held proof at the ATM when online (--claim-key for locked proofs)
  recover [--abandon]  Finish an interrupted change-making swap (--abandon restores its inputs if the ATM refused it)
  outbox               List emitted tokens not yet acknowledged (never lose a token you generated)
  ack <n>              Drop token #n from the outbox once the receiver has it
  receive <token>      Receive/import verified bearer tokens into vault (OFFLINE)
  balance              Show spendable value (sum of denominations)
  verify <token>       Verify a received token locally (OFFLINE, zero network)
  settle <token>       Settle/redeem a bearer token at the ATM (--claim-key <hex> for locked proofs)
  keygen               Generate an ed25519 claim keypair for P2PK-locked proofs
  bank <amount>        OPERATOR: credit the ATM reserve (needs FUPI_CREDIT_SECRET; --ref <unique id>)
  info                 Query ATM status and TLS certificate fingerprint
  status               Display detailed vault balance, journal, and flash path
  wipe                 Wipe all proofs and journal from flash memory
  repl                 Enter interactive terminal REPL

Flags:
  --atm <url>          ATM endpoint (default: https://127.0.0.1:8890)
  --flash <file>       Flash storage path (default: vault_flash.json)
  --pin-tls <sha256>   Trust ONLY the ATM TLS certificate with this SHA-256 fingerprint (self-signed kiosk)
  --insecure           DANGEROUS: accept any TLS certificate (local development only)
  --p2pk <pubkey>      (pay) spend proofs locked to this ed25519 public key (hex)
  --lock <pubkey>      (topup) lock new proofs to this ed25519 public key (hex)
  --claim-key <hex>    (settle) ed25519 secret key that signs claims for locked proofs
  --invoice <id>       (accept) invoice / order id to record on the receipt\n  --expect <amount>    (accept) refuse the token unless it is worth exactly this\n  --ref <id>           (bank) unique payment reference; replays are rejected
  --force              (pin) replace an already pinned keyset
"#
    );
}

struct Config {
    subcommand: String,
    args: Vec<String>,
    atm_url: String,
    flash_path: PathBuf,
    p2pk: Option<String>,
    lock: Option<String>,
    claim_key: Option<String>,
    pin_tls: Option<String>,
    reference: Option<String>,
    force: bool,
    abandon: bool,
    invoice: Option<String>,
    expect: Option<u64>,
    insecure: bool,
}

fn parse_cli() -> Option<Config> {
    let raw_args: Vec<String> = env::args().skip(1).collect();
    if raw_args.is_empty()
        || raw_args[0] == "-h"
        || raw_args[0] == "--help"
        || raw_args[0] == "help"
    {
        print_usage();
        return None;
    }

    let mut subcommand = String::new();
    let mut positional = Vec::new();
    let mut atm_url = "https://127.0.0.1:8890".to_string();
    let mut flash_path = PathBuf::from("vault_flash.json");
    let mut p2pk = None;
    let mut lock = None;
    let mut claim_key = None;
    let mut pin_tls = None;
    let mut reference = None;
    let mut force = false;
    let mut abandon = false;
    let mut invoice = None;
    let mut expect = None;
    let mut insecure = false; // strict TLS unless explicitly relaxed

    let mut i = 0;
    while i < raw_args.len() {
        let arg = &raw_args[i];
        if arg == "--atm" && i + 1 < raw_args.len() {
            atm_url = raw_args[i + 1].clone();
            i += 2;
        } else if arg == "--flash" && i + 1 < raw_args.len() {
            flash_path = PathBuf::from(&raw_args[i + 1]);
            i += 2;
        } else if arg == "--p2pk" && i + 1 < raw_args.len() {
            p2pk = Some(raw_args[i + 1].clone());
            i += 2;
        } else if arg == "--lock" && i + 1 < raw_args.len() {
            lock = Some(raw_args[i + 1].clone());
            i += 2;
        } else if arg == "--claim-key" && i + 1 < raw_args.len() {
            claim_key = Some(raw_args[i + 1].clone());
            i += 2;
        } else if arg == "--pin-tls" && i + 1 < raw_args.len() {
            pin_tls = Some(raw_args[i + 1].clone());
            i += 2;
        } else if arg == "--ref" && i + 1 < raw_args.len() {
            reference = Some(raw_args[i + 1].clone());
            i += 2;
        } else if arg == "--invoice" && i + 1 < raw_args.len() {
            invoice = Some(raw_args[i + 1].clone());
            i += 2;
        } else if arg == "--expect" && i + 1 < raw_args.len() {
            expect = raw_args[i + 1].parse().ok();
            if expect.is_none() {
                eprintln!("--expect needs a whole number");
                return None;
            }
            i += 2;
        } else if arg == "--abandon" {
            abandon = true;
            i += 1;
        } else if arg == "--force" {
            force = true;
            i += 1;
        } else if arg == "--insecure" {
            insecure = true;
            i += 1;
        } else if arg == "--strict-tls" {
            insecure = false;
            i += 1;
        } else if arg == "--help" || arg == "-h" {
            print_usage();
            std::process::exit(0);
        } else if arg.starts_with("--") {
            eprintln!("Unknown flag: {arg}");
            return None;
        } else {
            if subcommand.is_empty() {
                subcommand = arg.clone();
            } else {
                positional.push(arg.clone());
            }
            i += 1;
        }
    }

    Some(Config {
        subcommand,
        args: positional,
        atm_url,
        flash_path,
        p2pk,
        lock,
        claim_key,
        pin_tls,
        reference,
        force,
        abandon,
        invoice,
        expect,
        insecure,
    })
}

/// Operator-only: credit the reserve for a verified inbound payment.
fn do_credit(client: &AtmClient, amount: f64, reference: Option<String>) -> Result<f64, String> {
    let secret = std::env::var("FUPI_CREDIT_SECRET")
        .map_err(|_| "set FUPI_CREDIT_SECRET (same value the kiosk was started with)".to_string())?;
    let reference = reference.unwrap_or_else(|| {
        let ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("cli-{ns}")
    });
    client.credit_reserve(amount, &reference, &secret).map_err(|e| e.to_string())
}

fn run_repl(mut vault: Vault, atm_url: String, insecure: bool) {
    println!("\n=======================================================");
    println!("  FUPI LIGHTWEIGHT RUST VAULT (RPi & Linux Edition)");
    println!("  ATM Target: {atm_url} (TLS Insecure: {insecure})");
    println!("=======================================================");
    println!("Commands:");
    println!("  TOPUP <n>          -> Withdraw <n> blind-signed tokens from ATM");
    println!("  PAY <n> [p2pk]     -> Spend <n> tokens (emits bearer token)");
    println!("  BANK <amount>      -> Credit ATM reserve with bank transfer test");
    println!("  SETTLE <token>     -> Settle a spent token at the ATM");
    println!("  VERIFY <token>     -> Offline verify token authenticity");
    println!("  STATUS             -> Show current balance, flash path & journal");
    println!("  WIPE               -> Reset vault and clear flash memory");
    println!("  EXIT / QUIT        -> Exit REPL");
    println!("=======================================================\n");

    let stdin = io::stdin();
    let mut reader = stdin.lock();

    loop {
        print!("fupi-vault> ");
        let _ = io::stdout().flush();
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        let cmd = parts[0].to_uppercase();

        match cmd.as_str() {
            "TOPUP" => {
                if parts.len() < 2 {
                    println!("Usage: TOPUP <amount>");
                    continue;
                }
                let amount: usize = match parts[1].parse() {
                    Ok(a) => a,
                    Err(_) => {
                        println!("Invalid amount");
                        continue;
                    }
                };
                match vault.topup(amount) {
                    Ok((v, n)) => println!("TOPUP SUCCESS: loaded +{v} in {n} proofs (balance {})", vault.balance()),
                    Err(e) => println!("TOPUP FAILED: {e}"),
                }
            }
            "PAY" => {
                if parts.len() < 2 {
                    println!("Usage: PAY <amount> [lock-pubkey-hex]");
                    continue;
                }
                let amount: usize = match parts[1].parse() {
                    Ok(a) => a,
                    Err(_) => {
                        println!("Invalid amount");
                        continue;
                    }
                };
                let p2pk = if parts.len() >= 3 {
                    Some(parts[2].to_string())
                } else {
                    None
                };
                match vault.pay(amount, p2pk) {
                    Ok(tok) => {
                        println!("\n=== FUPI PAYMENT TOKEN (BEARER TRANSFER) ===");
                        println!("{tok}");
                        println!("============================================\n");
                        println!("Paid {amount} token(s). New balance: {}", vault.balance());
                    }
                    Err(e) => println!("PAYMENT FAILED: {e}"),
                }
            }
            "BANK" => {
                if parts.len() < 2 {
                    println!("Usage: BANK <amount>");
                    continue;
                }
                let amount: f64 = match parts[1].parse() {
                    Ok(a) => a,
                    Err(_) => {
                        println!("Invalid amount");
                        continue;
                    }
                };
                if let Some(client) = vault.client() {
                    match do_credit(client, amount, None) {
                        Ok(res) => println!("BANK CREDIT SUCCESS: reserve = {res:.2}"),
                        Err(e) => println!("BANK CREDIT FAILED: {e}"),
                    }
                } else {
                    println!("No ATM client configured");
                }
            }
            "SETTLE" => {
                if parts.len() < 2 {
                    println!("Usage: SETTLE <token> [claim-key-hex]");
                    continue;
                }
                let token = parts[1];
                let claim_key = if parts.len() >= 3 {
                    Some(parts[2].to_string())
                } else {
                    None
                };
                match vault.settle_token(token, claim_key) {
                    Ok(res) => {
                        for (sec, ok, msg) in res {
                            println!("[SETTLE] secret={} success={} msg={}", sec, ok, msg);
                        }
                    }
                    Err(e) => println!("SETTLE FAILED: {e}"),
                }
            }
            "RECEIVE" => {
                if parts.len() < 2 {
                    println!("Usage: RECEIVE <token>");
                    continue;
                }
                let token = parts[1];
                match vault.receive_token(token, None) {
                    Ok(n) => println!("RECEIVE SUCCESS: +{n} proofs stored into flash (balance {})", vault.balance()),
                    Err(e) => println!("RECEIVE FAILED: {e}"),
                }
            }
            "VERIFY" => {
                if parts.len() < 2 {
                    println!("Usage: VERIFY <token>");
                    continue;
                }
                let token = parts[1];
                match vault.verify_token(token) {
                    Ok(proofs) => println!("OFFLINE VERIFY PASS: {} genuine proofs confirmed!", proofs.len()),
                    Err(e) => println!("OFFLINE VERIFY FAILED: {e}"),
                }
            }
            "STATUS" => {
                println!("VAULT STATUS:");
                println!("  Flash Path: {:?}", vault.storage_path());
                println!("  Bearer Balance: {}", vault.balance());
                println!("  Journal Entries: {}", vault.journal().len());
                for (idx, entry) in vault.journal().iter().rev().take(5).enumerate() {
                    println!("    [{}] {}", idx + 1, entry);
                }
            }
            "WIPE" => {
                match vault.wipe() {
                    Ok(_) => println!("VAULT WIPED. Flash cleared, balance = 0"),
                    Err(e) => println!("WIPE FAILED: {e}"),
                }
            }
            "EXIT" | "QUIT" => break,
            "HELP" => {
                println!("Available commands: TOPUP, PAY, RECEIVE, BANK, SETTLE, VERIFY, STATUS, WIPE, EXIT");
            }
            _ => println!("Unknown command '{}'. Type HELP for options.", parts[0]),
        }
    }
}

fn main() {
    let cfg = match parse_cli() {
        Some(c) => c,
        None => return,
    };

    let tls = if let Some(fp) = cfg.pin_tls.clone() {
        TlsMode::Pinned(fp)
    } else if cfg.insecure {
        eprintln!("[warn] --insecure: TLS certificate is NOT being verified");
        TlsMode::Insecure
    } else {
        TlsMode::Strict
    };
    let client = match AtmClient::with_tls(&cfg.atm_url, tls) {
        Ok(c) => Some(c),
        Err(e) => {
            eprintln!("[warn] could not build ATM client: {e}");
            None
        }
    };
    let storage = FlashStorage::new(&cfg.flash_path);
    let mut vault = match Vault::new(storage, client) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to initialize vault: {e}");
            std::process::exit(1);
        }
    };

    match cfg.subcommand.as_str() {
        "balance" => {
            println!("{}", vault.balance());
        }
        "status" => {
            println!("FUPI Vault Status");
            println!("  Flash path: {:?}", vault.storage_path());
            println!("  Bearer Balance: {}", vault.balance());
            for (d, c) in vault.breakdown() {
                println!("    {c} x {d}");
            }
            if vault.has_pending_swap() {
                println!("  PENDING SWAP: run `recover`");
            }
            println!("  Journal (last 5 entries):");
            for j in vault.journal().iter().rev().take(5) {
                println!("    - {j}");
            }
        }
        "topup" => {
            if cfg.args.is_empty() {
                eprintln!("Usage: fupi-vault topup <amount>");
                std::process::exit(1);
            }
            let amount: usize = cfg.args[0].parse().unwrap_or_else(|_| {
                eprintln!("Invalid topup amount: {}", cfg.args[0]);
                std::process::exit(1);
            });
            match vault.topup_locked(amount, cfg.lock.clone()) {
                Ok((v, n)) => {
                    println!("[vault] topup +{v} in {n} proofs (balance {})", vault.balance());
                }
                Err(e) => {
                    eprintln!("Topup failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        "pay" => {
            if cfg.args.is_empty() {
                eprintln!("Usage: fupi-vault pay <amount> [--p2pk <pubkey-hex>]");
                std::process::exit(1);
            }
            let amount: usize = cfg.args[0].parse().unwrap_or_else(|_| {
                eprintln!("Invalid payment amount: {}", cfg.args[0]);
                std::process::exit(1);
            });
            match vault.pay(amount, cfg.p2pk) {
                Ok(token) => {
                    println!("{token}");
                    eprintln!("[vault] token saved in outbox; run `outbox` to re-show it, `ack <n>` once delivered");
                }
                Err(e) => {
                    eprintln!("Payment failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        "receive" => {
            if cfg.args.is_empty() {
                eprintln!("Usage: fupi-vault receive <token>");
                std::process::exit(1);
            }
            if vault.pinned_keysets().is_empty() {
                if let Ok(list) = vault.fetch_keysets() {
                    let _ = vault.cache_keysets(&list);
                }
            }
            let token = &cfg.args[0];
            match vault.receive_token(token, None) {
                Ok(n) => {
                    println!("[vault] received +{n} proofs (balance {})", vault.balance());
                }
                Err(e) => {
                    eprintln!("Receive failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        "verify" => {
            if cfg.args.is_empty() {
                eprintln!("Usage: fupi-vault verify <token>");
                std::process::exit(1);
            }
            if vault.pinned_keysets().is_empty() {
                if let Ok(list) = vault.fetch_keysets() {
                    let _ = vault.cache_keysets(&list);
                }
            }
            let token = &cfg.args[0];
            match vault.verify_token(token) {
                Ok(proofs) => {
                    println!("VERIFIED: {} valid proof(s)", proofs.len());
                    for (i, p) in proofs.iter().enumerate() {
                        let lock_info = match lock_of(&p.secret) {
                            Ok(Some(pk)) => format!(" [P2PK locked to: {}]", fupi_vault::crypto::hex_encode(&pk)),
                            _ => "".into(),
                        };
                        println!("  Proof #{}: secret={}{}", i + 1, p.secret, lock_info);
                    }
                }
                Err(e) => {
                    eprintln!("Verification FAILED: {e}");
                    std::process::exit(1);
                }
            }
        }
        "settle" => {
            if cfg.args.is_empty() {
                eprintln!("Usage: fupi-vault settle <token> [--claim-key <hex>]");
                std::process::exit(1);
            }
            let token = &cfg.args[0];
            match vault.settle_token(token, cfg.claim_key.clone()) {
                Ok(results) => {
                    let mut any_failed = false;
                    for (sec, ok, msg) in results {
                        if ok {
                            println!("SETTLED OK: secret={sec} ({msg})");
                        } else {
                            println!("SETTLE REJECTED: secret={sec} ({msg})");
                            any_failed = true;
                        }
                    }
                    if any_failed {
                        std::process::exit(2);
                    }
                }
                Err(e) => {
                    eprintln!("Settle error: {e}");
                    std::process::exit(1);
                }
            }
        }
        "bank" => {
            if cfg.args.is_empty() {
                eprintln!("Usage: fupi-vault bank <amount>");
                std::process::exit(1);
            }
            let amount: f64 = cfg.args[0].parse().unwrap_or_else(|_| {
                eprintln!("Invalid bank amount: {}", cfg.args[0]);
                std::process::exit(1);
            });
            if let Some(client) = vault.client() {
                match do_credit(client, amount, cfg.reference.clone()) {
                    Ok(reserve) => println!("ATM Reserve credited: {reserve:.2}"),
                    Err(e) => {
                        eprintln!("Bank credit failed: {e}");
                        std::process::exit(1);
                    }
                }
            } else {
                eprintln!("No ATM client configured");
                std::process::exit(1);
            }
        }
        "keygen" => {
            let (sk, pk) = generate_claim_keypair();
            println!("public_key={pk}   (give this to whoever issues you locked proofs: topup --lock)");
            println!("secret_key={sk}   (KEEP PRIVATE: settle --claim-key)");
        }
        "pin" => {
            let offered = vault.fetch_keysets().unwrap_or_else(|e| {
                eprintln!("Could not fetch keysets: {e}");
                std::process::exit(1);
            });
            if let Err(e) = Vault::check_keyset_set(&vault.pinned_keysets(), &offered, cfg.force) {
                if !cfg.force {
                    eprintln!("Refusing to change pinned keysets: {e}");
                    std::process::exit(1);
                }
            }
            if let Err(e) = vault.cache_keysets(&offered) {
                eprintln!("Could not save keysets: {e}");
                std::process::exit(1);
            }
            for k in &offered {
                let fp = modulus_fingerprint(&k.n).unwrap_or_default();
                println!("Pinned keyset '{}' (e={}) modulus SHA-256: {fp}", k.keyset_id, k.e);
            }
            println!("  Compare these with the values shown by the kiosk operator before trusting them.");
        }
        "device" => match vault.device_public_key() {
            Ok(pk) => println!("device_public_key={pk}"),
            Err(e) => {
                eprintln!("device key error: {e}");
                std::process::exit(1);
            }
        },
        "allocate" => {
            if cfg.args.len() < 2 {
                eprintln!("Usage: fupi-vault allocate <device-pubkey-hex> <amount> [--ref <id>]");
                std::process::exit(1);
            }
            let amount: f64 = cfg.args[1].parse().unwrap_or_else(|_| {
                eprintln!("Invalid amount: {}", cfg.args[1]);
                std::process::exit(1);
            });
            let secret = std::env::var("FUPI_CREDIT_SECRET").unwrap_or_else(|_| {
                eprintln!("set FUPI_CREDIT_SECRET (same value the kiosk was started with)");
                std::process::exit(1);
            });
            let reference = cfg.reference.clone().unwrap_or_else(|| {
                let ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);
                format!("alloc-{ns}")
            });
            let client = vault.client().unwrap_or_else(|| {
                eprintln!("No ATM client configured");
                std::process::exit(1);
            });
            match client.allocate(&cfg.args[0], amount, &reference, &secret) {
                Ok(total) => println!("Device allocation is now {total:.2}"),
                Err(e) => {
                    eprintln!("Allocate failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        "accept" => {
            let token = cfg.args.first().unwrap_or_else(|| {
                eprintln!("Usage: fupi-vault accept <token> [--invoice <id>] [--expect <amount>]");
                std::process::exit(1);
            });
            if vault.pinned_keysets().is_empty() {
                eprintln!("No pinned keysets: run `pin` first (a merchant must never trust keys from a token)");
                std::process::exit(1);
            }
            match vault.accept_payment(token, cfg.invoice.clone(), cfg.expect) {
                Ok(r) => println!(
                    "ACCEPTED receipt #{} amount={} proofs={} held_total={}",
                    r.id, r.amount, r.secrets.len(), vault.balance()
                ),
                Err(e) => {
                    println!("REJECTED: {e}");
                    std::process::exit(2);
                }
            }
        }
        "receipts" => {
            if vault.receipts().is_empty() {
                println!("(no receipts)");
            }
            for r in vault.receipts() {
                println!(
                    "#{} ts={} invoice={} amount={} settled={} rejected={} pending={}",
                    r.id, r.ts, r.invoice.as_deref().unwrap_or("-"), r.amount, r.settled, r.rejected,
                    r.amount - r.settled - r.rejected
                );
            }
        }
        "settle-all" => match vault.settle_all(cfg.claim_key.clone()) {
            Ok((ok, bad, held)) => {
                println!("SETTLED value={ok} rejected={bad} still_held={held}");
                if bad > 0 {
                    std::process::exit(2);
                }
            }
            Err(e) => {
                eprintln!("settle-all stopped: {e} (unanswered proofs are still held)");
                std::process::exit(1);
            }
        },
        "recover" => {
            if cfg.abandon {
                match vault.abandon_pending() {
                    Ok(true) => println!("pending swap abandoned; inputs restored (balance {})", vault.balance()),
                    Ok(false) => println!("nothing pending"),
                    Err(e) => {
                        eprintln!("abandon failed: {e}");
                        std::process::exit(1);
                    }
                }
            } else {
                match vault.recover() {
                    Ok(true) => println!("pending swap completed (balance {})", vault.balance()),
                    Ok(false) => println!("nothing pending"),
                    Err(e) => {
                        eprintln!("recover failed: {e}");
                        std::process::exit(1);
                    }
                }
            }
        }
        "outbox" => {
            if vault.outbox().is_empty() {
                println!("(outbox empty)");
            }
            for (i, t) in vault.outbox().iter().enumerate() {
                println!("[{}] {}", i + 1, t);
            }
        }
        "ack" => {
            let n: usize = cfg.args.first().and_then(|a| a.parse().ok()).unwrap_or_else(|| {
                eprintln!("Usage: fupi-vault ack <n>");
                std::process::exit(1);
            });
            match vault.ack_outbox(n) {
                Ok(true) => println!("outbox entry {n} acknowledged"),
                Ok(false) => {
                    eprintln!("no such outbox entry");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("ack failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        "info" => {
            if let Some(client) = vault.client() {
                match client.get_info() {
                    Ok(info) => {
                        println!("ATM Information:");
                        println!("  Name: {}", info.name);
                        println!("  Version: {}", info.version);
                        println!("  Keyset ID: {}", info.keyset_id);
                        println!("  1:1 Reserve: {:.2}", info.reserve);
                        println!("  Issued Tokens: {}", info.issued);
                        println!("  Settled Proofs: {}", info.spent_count);
                        println!("  TLS Active: {}", info.tls_enabled);
                        if let Some(fp) = info.tls_fingerprint_sha256 {
                            println!("  TLS SHA-256 Fingerprint: {fp}");
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to query ATM: {e}");
                        std::process::exit(1);
                    }
                }
            } else {
                eprintln!("No ATM client configured");
                std::process::exit(1);
            }
        }
        "wipe" => match vault.wipe() {
            Ok(_) => println!("Vault flash wiped successfully."),
            Err(e) => {
                eprintln!("Wipe failed: {e}");
                std::process::exit(1);
            }
        },
        "repl" => {
            run_repl(vault, cfg.atm_url, cfg.insecure);
        }
        _ => {
            eprintln!("Unknown subcommand: {}", cfg.subcommand);
            print_usage();
            std::process::exit(1);
        }
    }
}
