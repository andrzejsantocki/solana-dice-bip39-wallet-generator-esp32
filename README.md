# Solana Dice BIP39 Wallet Generator ESP32 — Cardputer ADV

![Cardputer ADV dice entropy firmware](assets/cardputer-adv-dice-wallet-hero.png)

Launcher-ready PlatformIO firmware for M5Stack Cardputer/Cardputer ADV.

Dice-entropy BIP39 wallet generator: physical d6 rolls → Von Neumann extraction → 256-bit entropy → BIP39 mnemonic → seed → Solana keypair at m/44'/501'/0'/0'.

## Current scope

- colorful 240x135 Cardputer ADV UI
- physical d6 input uses a strict press-release FSM: one complete keypress = one roll; dice-key chords are ignored
- Von Neumann extraction from roll pairs:
  - equal pair: discarded
  - first < second: bit 0
  - first > second: bit 1
- hard gate: at least 256 accepted VN bits
- no fixed roll-count gate; fair d6 usually needs about 615 rolls, but actual VN bit count wins
- SHA-256 audit fingerprint display, split into large readable numbered lines
- BIP39 mnemonic generation (24 words, English wordlist, 256-bit ENT)
- BIP39 passphrase input with NFKD normalization (empty passphrase = default)
- SLIP-0010 Ed25519 derivation (hardened-only), Solana path m/44'/501'/0'/0'
- Solana address derivation and display (base58 ed25519 pubkey)
- result pages for fingerprint, mnemonic (3 words per page), passphrase status, address, sanity checks, and SD audit
- SD report at `/dice_wallet/report.txt` when available
- startup disables Wi-Fi and Bluetooth; `RADIOS OFF` is shown only when the firmware sees radios disabled

## Not implemented yet

- private-key export (intentional: the address is displayed; raw key material stays on-device)

The firmware never exports or displays the raw private key or seed. The mnemonic is displayed for backup — that is the key material.

## Crypto contract

```text
physical d6 rolls
→ Von Neumann extraction
→ rawEntropy[32]
→ BIP39 ENT (24 words + 8-bit checksum)
→ PBKDF2-HMAC-SHA512("mnemonic" || NFKD(passphrase), 2048 rounds) = seed[64]
→ SLIP-0010 Ed25519 m/44'/501'/0'/0'
→ ed25519 pubkey → base58 = Solana address
```

The displayed SHA-256 value is an audit fingerprint only:

```text
SHA256("DiceWallet audit v1" || rawEntropy[32])
```

The SD report must not store raw rolls, raw entropy, mnemonic, passphrase, seed, or private keys. Runtime roll storage uses a fixed buffer that is overwritten on clear/delete instead of Arduino `String`. The mnemonic and passphrase live in fixed buffers that are wiped on clear-all.

Core derivation logic (`lib/wallet_core`) is verified against official test vectors — see `tests/` (host-compiled harness vs. Python reference: BIP39 trezor vectors, SLIP-0010 spec vectors, Solana address cross-check).

## Controls

- `1`..`6`: enter die roll
- `1`..`6` on result page: return to input and record the roll
- `Enter`: validate; with >= 256 VN bits opens the passphrase screen
- `Enter` on passphrase screen: confirm and generate mnemonic + address
- Up/Left or `W/A`: previous result page
- Down/Right or `S/D`: next result page
- `Del` on input page: remove last roll
- `Del` on passphrase screen: backspace (or cancel when empty)
- `Del` on result page: arm modal clear-all confirmation
- `Y`: confirm clear-all
- `N`: cancel clear-all
- while clear is armed, all other input is ignored

## Build

```bash
python -m platformio run
```

Output:

```text
.pio/build/cardputer_adv_launcher/firmware.bin
```

Release binary name:

```text
DiceWallet-cardputer-adv.bin
```

## Run via Launcher

1. Install M5Launcher/Cardputer ADV Launcher on device.
2. Copy `DiceWallet-cardputer-adv.bin` to FAT32 SD card or upload via Launcher WebUI.
3. Launcher → SD/WUI → select binary → install.
4. Reboot.

## Target

`platformio.ini` pins:

- `espressif32@6.4.0`
- `M5Cardputer@1.1.1`
- `M5Unified@0.2.20`
- `M5GFX@0.2.27`
- `IRremote@4.7.1`

The project uses `esp32-s3-devkitc-1` because Cardputer ADV support is provided by the M5Cardputer Arduino library.

## Release integrity

CI builds firmware artifacts on every push. For version tags, GitHub Actions publishes release assets directly from the CI-built `.pio/build/cardputer_adv_launcher/firmware.bin` plus `DiceWallet-cardputer-adv.bin.sha256`. Local committed binaries are convenience artifacts, not the root of trust.

## Vendored libraries

- `lib/ed25519` — orlp/ed25519 (public domain / CC0)
- `lib/utf8proc` — JuliaStrings utf8proc v2.10.0 (MIT)
- `lib/bip39` — BIP39 English wordlist (MIT, bitcoin/bips)
