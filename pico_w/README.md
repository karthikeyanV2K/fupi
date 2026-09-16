# FUPI Vault for Raspberry Pi Pico W

Complete offline digital cash vault running natively on **Raspberry Pi Pico W** using MicroPython.

---

## 1. Wiring (Only 4 Wires — Zero Button / D-Pins)

Connect your 0.96" I2C OLED display (SSD1306 128x64) directly to the Pico W:

```
  OLED (SSD1306)              Raspberry Pi Pico W
 ┌──────────────┐            ┌─────────────────────┐
 │ VCC          │ ──────────►│ Pin 36 (3V3 Out)    │
 │ GND          │ ──────────►│ Pin 38 (GND)        │
 │ SDA          │ ──────────►│ Pin 6  (GP4 / I2C0) │
 │ SCL          │ ──────────►│ Pin 7  (GP5 / I2C0) │
 └──────────────┘            └─────────────────────┘
```

*No push-buttons, resistors, or digital pins needed. All actions are commanded via the USB Serial / REPL interface.*

---

## 2. Flash MicroPython onto Pico W (1-Minute Setup)

1. Unplug the Pico W.
2. Hold down the white **BOOTSEL** button on the Pico W while plugging it into your PC via USB.
3. A USB drive named **`RPI-RP2`** will appear in Windows File Explorer.
4. Download the official Pico W MicroPython UF2:
   - [Official MicroPython for Pico W Download](https://micropython.org/download/RPI_PICO_W/)
5. Drag and drop the `.uf2` file into the `RPI-RP2` drive. The Pico W will reboot automatically into MicroPython.

---

## 3. Upload Code to Pico W

The easiest tool is **Thonny IDE** (free at [thonny.org](https://thonny.org/)):

1. Open **Thonny**.
2. In the bottom right corner, click the interpreter and choose:
   **`MicroPython (Raspberry Pi Pico)`**.
3. Open [`X:\fupi\pico_w\ssd1306.py`](file:///X:/fupi/pico_w/ssd1306.py) in Thonny &rarr; Click **File** &rarr; **Save as...** &rarr; select **Raspberry Pi Pico** &rarr; name it `ssd1306.py`.
4. Open [`X:\fupi\pico_w\main.py`](file:///X:/fupi/pico_w/main.py) in Thonny &rarr; Click **File** &rarr; **Save as...** &rarr; select **Raspberry Pi Pico** &rarr; name it `main.py`.
5. Press **F5** (or click the green Play icon) to run!

---

## 4. Testing Bank Transfers and Top-Ups

1. Make sure your Kiosk is running on your PC:
   ```powershell
   cd X:\fupi\kiosk-go
   .\kiosk-go.exe -port 8890
   ```
2. On Thonny's Shell / Serial console, you will see:
   ```text
   === FUPI VAULT ===
   WiFi CONNECTED!
   192.168.29.X
   Kiosk: http://192.168.29.86:8890
   ```
   And your OLED screen will light up!

3. **Simulate a bank transfer to the Kiosk**:
   Type in the Shell:
   ```text
   BANK 50
   ```
4. **Top up the Pico W Vault (ATM withdrawal)**:
   Type in the Shell:
   ```text
   TOPUP 5
   ```
   The Pico W blinds tokens, talks to the Kiosk over Wi-Fi, unblinds the RSA-2048 signatures, verifies them on-chip, and stores them in `vault_flash.json`!
   OLED will show: `BEARER BAL: 5`.

5. **Spend bearer cash (peer-to-peer handover)**:
   ```text
   PAY 1
   ```
   The Pico W emits the bearer token string and updates the OLED to `BEARER BAL: 4`.
