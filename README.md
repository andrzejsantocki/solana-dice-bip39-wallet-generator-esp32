# Wallet Local Dice Generator ESP32 — Cardputer ADV

![Cardputer ADV dice wallet firmware](assets/cardputer-adv-dice-wallet-hero.png)

Launcher-ready PlatformIO firmware for M5Stack Cardputer/Cardputer ADV.

Current firmware is a safe offline dice-entropy UI:

- colorful 240x135 Cardputer-sized display UI
- accepts physical d6 rolls: keys `1`..`6`
- enforces Von Neumann extraction from roll pairs
- requires at least 256 Von Neumann bits before hashing
- no fixed roll-count gate; fair dice typically need about 615 rolls for 256 VN bits, but the firmware trusts the actual VN-bit count
- `Enter` validates + computes SHA-256(VN 32-byte entropy)
- up/down arrows navigate result pages
- `Del` erases last roll; after result screen, `Del` clears
- writes `/dice_wallet/report.txt` on SD card when available

Security note: dice transcript is secret wallet material. Report intentionally does not save raw rolls. This firmware currently shows entropy hash only; it does not yet display a BIP39 mnemonic or private key.

## Build

```bash
pio run
```

Output:

```text
.pio/build/cardputer_adv_launcher/firmware.bin
```

Rename for Launcher if desired:

```text
DiceWallet-cardputer-adv.bin
```

## Run via Launcher

1. Install M5Launcher/Cardputer ADV Launcher on device.
2. Copy `firmware.bin` to FAT32 SD card or upload via Launcher WebUI.
3. Launcher → SD/WUI → select binary → install.
4. Reboot → app launches.

## Target

`platformio.ini` uses `esp32-s3-devkitc-1` + `M5Cardputer` library because Cardputer ADV support is in the M5Cardputer Arduino library.
