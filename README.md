# wifi_distortion

RSSI-based Wi-Fi sensing on Linux. Two tools in one crate:

1. **Radio fingerprinting** (`map` / `track`) — record RSSI signatures per location and locate yourself later.
2. **Gesture-to-keystroke bridge** (`gesture-*`) — an ESP32 sniffs RSSI, a Rust classifier recognizes hand gestures, and xdotool turns them into keystrokes for a focused terminal (e.g. driving an opencode choice menu).

---

## Radio fingerprinting

```bash
# record a location (stand still for 5s)
sudo ./target/release/wifi_distortion map "Desk"

# track your current location
sudo ./target/release/wifi_distortion track

# list / clear the radio map
wifi_distortion list
wifi_distortion clear
```

---

## Gesture-to-keystroke bridge

### Architecture

```
ESP32 (firmware, Rust no_std)          Laptop (wifi_distortion host bridge)
┌─────────────────────────────┐ USB   ┌─────────────────────────────────────────────┐
│ promiscuous Sniffer         │ ────► │ serial → time-window buffer → per-AP        │
│ rx_cntl.rssi + timestamp    │ UART  │ features (9 TD + 4 FFT) → z-score →         │
│ filter rx_state != 0        │       │ RandomForest/KNN → margin gate → xdotool   │
└─────────────────────────────┘       └─────────────────────────────────────────────┘
```

Firmware prints `timestamp_us,MAC,RSSI` lines at 115200 baud.

### 1. Flash the ESP32 firmware

```bash
cd firmware/rssi_sniffer
export PATH="$HOME/.rustup/toolchains/esp/xtensa-esp-elf/esp-15.2.0_20250920/xtensa-esp-elf/bin:$PATH"
export LIBCLANG_PATH="$HOME/.rustup/toolchains/esp/xtensa-esp32-elf-clang/esp-20.1.1_20250829/esp-clang/lib"
cargo run --release   # or: cargo build --release && espflash flash target/xtensa-esp32-none-elf/release/rssi_sniffer
```

- Check the `SNIFFER_CHANNEL` constant matches your router's channel (`iw dev`).
- Default UART pins: GPIO1 (TX), GPIO3 (RX) — the board's USB-serial chip.
- Verify the stream: `cat /dev/ttyUSB0` should print `timestamp,MAC,RSSI` lines.

### 2. Record gestures

```bash
# grants serial access once (logout/relogin after)
sudo usermod -aG dialout $USER

# record ~3s of each gesture (repeat several times for good coverage)
wifi_distortion gesture-record still --seconds 3
wifi_distortion gesture-record swipe-up --seconds 3
wifi_distortion gesture-record swipe-down --seconds 3
wifi_distortion gesture-record push --seconds 3
```

### 3. Train

```bash
wifi_distortion gesture-train
# logs held-out accuracy for RandomForest and KNN; saves gesture_model.json
```

### 4. Run

```bash
wifi_distortion gesture-run
# focus the terminal running opencode; gesture to control the choice menu
```

| Gesture | Key | opencode action |
|---------|-----|-----------------|
| swipe-up | Up | move up |
| swipe-down | Down | move down |
| push | Return | accept / confirm |

`still` and low-confidence readings are ignored by the margin gate.

### Configuration (env vars)

| Var | Default | Meaning |
|-----|---------|---------|
| `SERIAL_PORT` | `/dev/ttyUSB0` | ESP32 serial device |
| `SERIAL_BAUD` | `115200` | serial baud |
| `WINDOW_MS` | `1000` | sliding window length |
| `AP_COUNT` | `3` | strongest APs used as parallel streams |
| `RATIO` | `0.3` | min margin `(best-2nd)/best` to emit |
| `DEBOUNCE_K` | `3` | consecutive windows required |
| `COOLDOWN_MS` | `400` | min gap between emissions |

---

## Requirements

- Linux with `pcap`/`radiotap` deps, X11 (`xdotool` for key injection)
- ESP32 (original) + `esp-rs` toolchain (`espup`, `espflash`) for the firmware
- Rust toolchain for the host crate
