use fupi_vault::client::AtmClient;
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
  topup <amount>       Withdraw <amount> blind-signed bearer proofs from ATM
  pay <amount>         Spend <amount> tokens (emits bearer payment token)
  receive <token>      Receive/import verified bearer tokens into vault (OFFLINE)
  balance              Show current active bearer token count
  verify <token>       Verify a received token locally (OFFLINE, zero network)
  settle <token>       Settle/redeem a bearer token at the Go HTTPS ATM
  bank <amount>        Fund the ATM fiat reserve (inbound bank rail simulation)
  info                 Query ATM status and TLS security certificate metadata
  status               Display detailed vault balance, journal, and flash path
  wipe                 Wipe all proofs and journal from flash memory
  repl                 Enter interactive terminal REPL (matches Pico W commands)

Flags:
  --atm <url>          ATM endpoint (default: https://127.0.0.1:8890)
  --flash <file>       Flash storage path (default: vault_flash.json)
  --p2pk <pubkey>      Lock payment to a specific recipient public key
  --claimer <pubkey>   Specify claimer identity when settling P2PK-locked tokens
  --insecure           Accept self-signed TLS certificates from local/RPi ATM (default: true)
"#
    );
}

struct Config {
    subcommand: String,
    args: Vec<String>,
    atm_url: String,
    flash_path: PathBuf,
    p2pk: Option<String>,
    claimer: Option<String>,
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
    let mut claimer = None;
    let mut insecure = true; // default true for self-contained local ATM

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
        } else if arg == "--claimer" && i + 1 < raw_args.len() {
            claimer = Some(raw_args[i + 1].clone());
            i += 2;
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
        claimer,
        insecure,
    })
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
                    Ok(n) => println!("TOPUP SUCCESS: loaded +{n} proofs (balance {})", vault.balance()),
                    Err(e) => println!("TOPUP FAILED: {e}"),
                }
            }
            "PAY" => {
                if parts.len() < 2 {
                    println!("Usage: PAY <amount> [p2pk]");
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
                match vault.make_payment(amount, p2pk) {
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
                    match client.credit_reserve(amount) {
                        Ok(res) => println!("BANK CREDIT SUCCESS: reserve = {res:.2}"),
                        Err(e) => println!("BANK CREDIT FAILED: {e}"),
                    }
                } else {
                    println!("No ATM client configured");
                }
            }
            "SETTLE" => {
                if parts.len() < 2 {
                    println!("Usage: SETTLE <token> [claimer]");
                    continue;
                }
                let token = parts[1];
                let claimer = if parts.len() >= 3 {
                    Some(parts[2].to_string())
                } else {
                    None
                };
                match vault.settle_token(token, claimer) {
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

    let client = AtmClient::new(&cfg.atm_url, cfg.insecure).ok();
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
            match vault.topup(amount) {
                Ok(n) => {
                    println!("[vault] topup +{n} proofs (balance {})", vault.balance());
                }
                Err(e) => {
                    eprintln!("Topup failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        "pay" => {
            if cfg.args.is_empty() {
                eprintln!("Usage: fupi-vault pay <amount> [--p2pk <recipient>]");
                std::process::exit(1);
            }
            let amount: usize = cfg.args[0].parse().unwrap_or_else(|_| {
                eprintln!("Invalid payment amount: {}", cfg.args[0]);
                std::process::exit(1);
            });
            match vault.make_payment(amount, cfg.p2pk) {
                Ok(token) => {
                    println!("{token}");
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
            if vault.trusted_keyset().is_none() {
                if let Some(client) = vault.client() {
                    if let Ok(ks) = client.get_keyset() {
                        let _ = vault.cache_keyset(ks);
                    }
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
            if vault.trusted_keyset().is_none() {
                if let Some(client) = vault.client() {
                    if let Ok(ks) = client.get_keyset() {
                        let _ = vault.cache_keyset(ks);
                    }
                }
            }
            let token = &cfg.args[0];
            match vault.verify_token(token) {
                Ok(proofs) => {
                    println!("VERIFIED: {} valid proof(s)", proofs.len());
                    for (i, p) in proofs.iter().enumerate() {
                        let lock_info = if let Some(ref pk) = p.p2pk {
                            format!(" [P2PK locked to: {pk}]")
                        } else {
                            "".into()
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
                eprintln!("Usage: fupi-vault settle <token> [--claimer <name>]");
                std::process::exit(1);
            }
            let token = &cfg.args[0];
            match vault.settle_token(token, cfg.claimer) {
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
                match client.credit_reserve(amount) {
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
