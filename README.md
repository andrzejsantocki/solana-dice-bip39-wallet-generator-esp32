# Solana Dice BIP39 Wallet Generator ESP32 — Cardputer ADV

![Cardputer ADV dice entropy firmware](assets/cardputer-adv-dice-wallet-hero.png)

Launcher-ready PlatformIO firmware for M5Stack Cardputer/Cardputer ADV.

Dice-entropy BIP39 wallet generator: physical d6 rolls → Von Neumann extraction → 256-bit entropy → BIP39 mnemonic → seed → Solana keypair at m/44'/501'/0'/0'.

## Current scope

- colorful 240x135 Cardputer ADV UI
- boot fork: select entropy mode with arrows — Von Neumann (unbiased, ~615 rolls) or raw dice (fast, 86 rolls, bias kept)
- physical d6 input uses a strict press-release FSM: one complete keypress = one roll; dice-key chords are ignored
- typed input (passphrase, backup check) uses per-key edge detection: overlapping/chorded keys are rejected with an explicit warning, never silently merged or dropped
- Von Neumann extraction from roll pairs:
  - equal pair: discarded
  - first < second: bit 0
  - first > second: bit 1
- raw dice mode: each roll contributes 3 bits directly (1..6 → 0..5); physical dice bias is NOT removed — the UI warns before selection
- hard gate: at least 256 accepted VN bits (Von Neumann mode) or 86 rolls (raw mode)
- no fixed roll-count gate; fair d6 usually needs about 615 rolls, but actual VN bit count wins
- SHA-256 audit fingerprint display, split into large readable numbered lines
- BIP39 mnemonic generation (24 words, English wordlist, 256-bit ENT)
- BIP39 passphrase, entered twice with constant-time comparison (empty passphrase = default), ASCII-only input (0x20–0x7E), NFKD-normalized
- SLIP-0010 Ed25519 derivation (hardened-only), Solana path m/44'/501'/0'/0'
- Solana address derivation and display (base58 ed25519 pubkey)
- mnemonic backup verification quiz: 4 random positions must be typed back correctly before the address page unlocks
- fail-closed radios: wallet generation is blocked if Wi-Fi/Bluetooth state cannot be verified as off
- result pages for fingerprint, mnemonic (3 words per page), passphrase status, address (gated on backup verification), sanity checks, and SD audit
- SD report at `/dice_wallet/report.txt` when available
- startup disables Wi-Fi and Bluetooth; `RADIOS OFF` is shown only when the firmware sees radios disabled

## Not implemented yet

- private-key export (intentional: the address is displayed; raw key material stays on-device)

The firmware never exports or displays the raw private key or seed. The mnemonic is displayed for backup — that is the key material.

## Crypto contract

```text
physical d6 rolls
→ Von Neumann extraction (default) OR raw dice extraction (3 bits/roll, bias kept)
→ rawEntropy[32]
→ BIP39 ENT (24 words + 8-bit checksum)
→ PBKDF2-HMAC-SHA512("mnemonic" || NFKD(passphrase), 2048 rounds) = seed[64]
→ SLIP-0010 Ed25519 m/44'/501'/0'/0'
→ ed25519 pubkey → base58 = Solana address
```

At boot the device asks which extraction to use, with a short explanation of each.
Von Neumann removes physical dice bias (equal pairs are dropped, ~615 rolls
typical). Raw mode feeds dice values straight into entropy (86 rolls) and keeps
any bias of the physical dice — the UI marks it "Not recommended".

The displayed SHA-256 value is an audit fingerprint only:

```text
SHA256("DiceWallet audit v1" || rawEntropy[32])
```

## Wallet compatibility

- Empty BIP39 passphrase: m/44'/501'/0'/0' is Phantom's documented path — restore with the 24 words alone is expected to work in Phantom/Solflare.
- Non-empty BIP39 passphrase: Phantom/Solflare restore flows do not document an additional passphrase field. Restore support for the passphrase case has NOT been verified against those wallets — test with a small amount first, and confirm your wallet app restores the same address.

## Controls

- `1`..`6`: enter die roll
- `1`..`6` on result page: return to input and record the roll
- `Enter`: validate; with >= 256 VN bits and verified radios-off, opens the passphrase screen
- `Enter` on passphrase screen: confirm entry (non-empty passphrase must be entered twice; mismatch restarts)
- `Enter` on mnemonic pages: start backup verification quiz (type 4 prompted words, one at a time; 4/4 correct unlocks the address page)
- Up/Left or `W/A`: previous result page
- Down/Right or `S/D`: next result page
- `Del` on input page: remove last roll
- `Del` on passphrase screen: backspace (or cancel/edit on empty)
- `Del` on quiz screen: backspace (or cancel quiz on empty)
- `Del` on result page: arm modal clear-all confirmation
- `Y`: confirm clear-all
- `N`: cancel clear-all
- while clear is armed, all other input is ignored

## Testing

Host-side verification (`tests/`) compiles the exact on-device `lib/wallet_core` and checks it against official vectors:

- BIP39: trezor python-mnemonic vectors (8×, 256-bit ENT)
- SLIP-0010: official ed25519 spec vectors (3×)
- Solana: m/44'/501'/0'/0' addresses cross-checked between PyNaCl and cryptography (8×)
- NFKD: NFD vs NFC passphrase forms produce identical seeds
- Von Neumann pipeline: fixed 700-roll transcript → entropy → fingerprint → mnemonic → seed → address, end-to-end
- contracts: wc_nfkd never truncates (overflow → false), base58 bounds rejection

```bash
python reference.py                 # regenerate tests/reference_vectors.json (dev machines with pynacl + cryptography)
python gen_test_vectors.py          # regenerate tests/host_test/vectors.inc
bash tests/build_host_test.sh       # portable: w64devkit (Windows) or system gcc/g++ (CI)
./tests/host_test/host_test         # .exe suffix on Windows
```

CI runs the host tests on every push/PR and publishes tag releases only after both host tests and the firmware build pass.

Hardware-in-the-loop (scripted ~615-roll replay, fingerprint reproducibility) has not been performed — no device available.

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

CI builds firmware artifacts on every push. For version tags, GitHub Actions publishes release assets directly from the CI-built `.pio/build/cardputer_adv_launcher/firmware.bin` plus `DiceWallet-cardputer-adv.bin.sha256`, and only after the host crypto/vector tests pass. Local committed binaries are convenience artifacts, not the root of trust.

## Vendored libraries

- `lib/ed25519` — orlp/ed25519 (public domain / CC0)
- `lib/utf8proc` — JuliaStrings utf8proc v2.10.0 (MIT)
- `lib/bip39` — BIP39 English wordlist (MIT, bitcoin/bips)
