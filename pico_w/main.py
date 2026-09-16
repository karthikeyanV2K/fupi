# FUPI Vault Firmware for Raspberry Pi Pico W
# (Offline Digital-Cash Vault in MicroPython)
#
# WIRING (Only 4 Wires — Zero Button / D-Pins):
# ─────────────────────────────────────────────────────────────
#  OLED Pin  │ Raspberry Pi Pico W Pin
# ─────────────────────────────────────────────────────────────
#  VCC       │ 3V3 (Pin 36)
#  GND       │ GND (Pin 38 or Pin 3 or Pin 8)
#  SDA       │ GP4 / I2C0 SDA (Pin 6)
#  SCL       │ GP5 / I2C0 SCL (Pin 7)
# ─────────────────────────────────────────────────────────────

import hashlib
import json
import math
import network
import select
import socket
import sys
import time
import ubinascii
import uos
from machine import Pin, I2C
from ssd1306 import SSD1306_I2C

# --- Configuration ---
WIFI_SSID = "YOUR_WIFI_SSID"
WIFI_PASS = "YOUR_WIFI_PASSWORD"
KIOSK_URL = "http://192.168.1.50:8890"  # Kiosk server IP / URL
FLASH_FILE = "vault_flash.json"

# --- Initialize Hardware ---
i2c = I2C(0, sda=Pin(4), scl=Pin(5), freq=400000)
oled = SSD1306_I2C(128, 64, i2c, addr=0x3C)


def show_oled(l1, l2="", l3="", bal=None):
    if bal is None:
        bal = get_balance()
    oled.fill(0)
    oled.text("=== FUPI VAULT ===", 0, 0)
    oled.text(str(l1)[:16], 0, 14)
    oled.text(str(l2)[:16], 0, 26)
    oled.text(str(l3)[:16], 0, 38)
    oled.text("BEARER BAL: " + str(bal), 0, 52)
    oled.show()
    print("[OLED] %s | %s | %s | BAL=%d" % (l1, l2, l3, bal))


# --- Flash Storage ---
def load_vault():
    try:
        with open(FLASH_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {"proofs": [], "journal": []}


def save_vault(data):
    with open(FLASH_FILE, "w") as f:
        json.dump(data, f)


def get_balance():
    return len(load_vault().get("proofs", []))


def wipe_vault():
    save_vault({"proofs": [], "journal": []})
    show_oled("WIPED", "All proofs deleted", "Clean vault", 0)


# --- Wi-Fi Connection ---
wlan = network.WLAN(network.STA_IF)


def connect_wifi():
    wlan.active(True)
    if not wlan.isconnected():
        show_oled("Connecting WiFi...", WIFI_SSID)
        wlan.connect(WIFI_SSID, WIFI_PASS)
        timeout = 20
        while not wlan.isconnected() and timeout > 0:
            time.sleep(0.5)
            timeout -= 1

    if wlan.isconnected():
        ip = wlan.ifconfig()[0]
        show_oled("WiFi CONNECTED!", ip, "Kiosk: " + KIOSK_URL)
        print("Connected to Wi-Fi! IP:", ip)
    else:
        show_oled("WiFi FAILED", "Check credentials", WIFI_SSID)
        print("Failed to connect to Wi-Fi.")


# --- HTTP Client Helper (Socket-based, zero extra dependencies) ---
def http_request(method, url, json_payload=None, timeout=5):
    # Parse url: http://host:port/path
    url = url.replace("http://", "")
    parts = url.split("/", 1)
    host_port = parts[0]
    path = "/" + (parts[1] if len(parts) > 1 else "")

    if ":" in host_port:
        host, port = host_port.split(":")
        port = int(port)
    else:
        host = host_port
        port = 80

    body = json.dumps(json_payload) if json_payload is not None else ""

    addr = socket.getaddrinfo(host, port)[0][-1]
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect(addr)
        req = "%s %s HTTP/1.1\r\nHost: %s\r\n" % (method, path, host)
        req += "Connection: close\r\n"
        if body:
            req += "Content-Type: application/json\r\n"
            req += "Content-Length: %d\r\n" % len(body)
        req += "\r\n"
        if body:
            req += body
        s.send(req.encode())

        resp = b""
        while True:
            chunk = s.recv(512)
            if not chunk:
                break
            resp += chunk

        head_body = resp.split(b"\r\n\r\n", 1)
        status_line = head_body[0].split(b"\r\n")[0].decode()
        status_code = int(status_line.split(" ")[1])
        body_text = head_body[1].decode() if len(head_body) > 1 else ""
        return status_code, body_text
    finally:
        s.close()


# --- Base64URL Helpers ---
def b64url_encode(b):
    s = ubinascii.b2a_base64(b).decode().strip()
    return s.replace("+", "-").replace("/", "_").rstrip("=")


def b64url_decode(s):
    s = s.replace("-", "+").replace("_", "/")
    while len(s) % 4 != 0:
        s += "="
    return ubinascii.a2b_base64(s)


def int_to_b64(i):
    b = i.to_bytes((i.bit_length() + 7) // 8, "big")
    return b64url_encode(b)


def b64_to_int(s):
    return int.from_bytes(b64url_decode(s), "big")


# --- Cryptographic Math (Pure Python bignums on RP2040) ---
def _egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = _egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def modinv(a, m):
    g, x, _ = _egcd(a % m, m)
    if g != 1:
        raise ValueError("no modular inverse")
    return x % m


def random_blinder(n):
    bytes_len = (n.bit_length() + 7) // 8
    while True:
        r = int.from_bytes(uos.urandom(bytes_len), "big") % n
        if r >= 2 and math.gcd(r, n) == 1:
            return r


def hash_to_scalar(secret_str, n):
    h = hashlib.sha256(secret_str.encode()).digest()
    m = int.from_bytes(h, "big") % n
    return m if m >= 2 else 2


# --- Blind Top-Up (The ATM Withdrawal) ---
def topup_one(kiosk_url):
    code, text = http_request("GET", kiosk_url + "/v1/keyset")
    if code != 200:
        print("Failed to fetch keyset:", code, text)
        return False
    ks = json.loads(text)
    n = b64_to_int(ks["n"])
    e = int(ks.get("e", 65537))
    keyset_id = ks["keyset_id"]

    secret = "fupi-pico-" + ubinascii.hexlify(uos.urandom(16)).decode()
    m = hash_to_scalar(secret, n)
    r = random_blinder(n)
    blinded = (m * pow(r, e, n)) % n

    payload = {"blinded_message": int_to_b64(blinded), "amount": 1}
    code, text = http_request("POST", kiosk_url + "/v1/blind-sign", payload)
    if code != 200:
        print("Blind sign rejected:", code, text)
        return False

    resp = json.loads(text)
    s_blind = b64_to_int(resp["blind_signature"])

    # Unblind
    sig = (s_blind * modinv(r, n)) % n

    # Verify on-chip
    if pow(sig, e, n) != m:
        print("Signature verify FAILED!")
        return False

    proof = {
        "secret": secret,
        "sig": int_to_b64(sig),
        "n": ks["n"],
        "e": e,
        "keyset_id": keyset_id,
    }

    vault = load_vault()
    vault["proofs"].append(proof)
    vault["journal"].append("topup +1 (bal %d)" % len(vault["proofs"]))
    save_vault(vault)
    return True


def handle_topup(amount):
    if not wlan.isconnected():
        show_oled("WIFI ERROR", "Connect WiFi first", "")
        return
    show_oled("TOP-UP IN PROGRESS", "Blinding %d tokens" % amount, "Calling Kiosk...")
    loaded = 0
    for _ in range(amount):
        if topup_one(KIOSK_URL):
            loaded += 1
        else:
            break

    if loaded > 0:
        show_oled("TOP-UP SUCCESS!", "+%d verified" % loaded, "Stored in Flash")
        print("Loaded %d proofs. Balance = %d" % (loaded, get_balance()))
    else:
        show_oled("TOP-UP FAILED", "Check Kiosk Reserve", "")


# --- Payment Flow (Pay) ---
def handle_pay(amount):
    vault = load_vault()
    proofs = vault.get("proofs", [])
    if len(proofs) < amount:
        show_oled("PAYMENT BLOCKED", "Insufficient cash", "Have: %d" % len(proofs))
        print("Insufficient cash: requested %d, have %d" % (amount, len(proofs)))
        return

    chosen = proofs[:amount]
    vault["proofs"] = proofs[amount:]
    vault["journal"].append("spent %d (bal %d)" % (amount, len(vault["proofs"])))
    save_vault(vault)

    token_b64 = b64url_encode(json.dumps(chosen).encode())
    print("\n=== FUPI PAYMENT TOKEN (BEARER TRANSFER) ===")
    print(token_b64)
    print("============================================\n")

    show_oled("PAID %d TOKEN(S)" % amount, "Token emitted", "No bank in path")


# --- Settle against Kiosk ---
def handle_settle(token_str):
    try:
        raw = b64url_decode(token_str).decode()
        proofs = json.loads(raw)
        for p in proofs:
            code, text = http_request("POST", KIOSK_URL + "/v1/settle", p)
            print("[SETTLE]", code, text)
            show_oled("SETTLE AT MINT", "HTTP %d" % code, text[:16])
    except Exception as ex:
        print("Settle error:", ex)


# --- Bank Credit Simulation ---
def handle_bank(amount):
    if not wlan.isconnected():
        print("Connect Wi-Fi first")
        return
    code, text = http_request("POST", KIOSK_URL + "/v1/credit", {"amount": float(amount)})
    print("[BANK CREDIT]", code, text)
    show_oled("BANK RESERVE +", str(amount), "Credited to Kiosk")


# --- Main Loop & REPL Commands ---
def main():
    show_oled("FUPI VAULT BOOT", "Raspberry Pi Pico W", "Zero D-Pins")
    time.sleep(1)
    connect_wifi()

    print("\n=======================================================")
    print("  FUPI VAULT READY (Raspberry Pi Pico W Edition)")
    print("=======================================================")
    print("Commands:")
    print("  TOPUP <n>          -> Withdraw <n> blind-signed tokens from Kiosk")
    print("  PAY <n>            -> Spend <n> tokens (emits bearer token, updates OLED)")
    print("  BANK <amount>      -> Credit Kiosk reserve with bank transfer test")
    print("  SETTLE <tokenB64>  -> Settle a spent token at the Kiosk")
    print("  STATUS             -> Show current status on OLED & Serial")
    print("  WIPE               -> Reset vault and clear flash")
    print("=======================================================\n")

    poller = select.poll()
    poller.register(sys.stdin, select.POLLIN)

    while True:
        if poller.poll(100):
            line = sys.stdin.readline().strip()
            if not line:
                continue

            if line.startswith("TOPUP "):
                amt = int(line.split(" ")[1])
                handle_topup(amt)
            elif line.startswith("PAY "):
                amt = int(line.split(" ")[1])
                handle_pay(amt)
            elif line.startswith("BANK "):
                amt = float(line.split(" ")[1])
                handle_bank(amt)
            elif line.startswith("SETTLE "):
                handle_settle(line.split(" ", 1)[1])
            elif line == "STATUS":
                ip = wlan.ifconfig()[0] if wlan.isconnected() else "No WiFi"
                show_oled("STATUS", ip, "Kiosk: " + KIOSK_URL)
            elif line == "WIPE":
                wipe_vault()


if __name__ == "__main__":
    main()
