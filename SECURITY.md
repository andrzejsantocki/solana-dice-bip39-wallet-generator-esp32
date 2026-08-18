# Security

## Current scope

- Cardputer ADV dice-entry firmware
- Von Neumann extraction from physical d6 rolls
- 256 accepted comparison bits
- SHA-256 audit fingerprint display
- BIP39 mnemonic generation (24 words, 256-bit ENT)
- BIP39 passphrase input with NFKD normalization
- SLIP-0010 Ed25519 derivation, Solana path m/44'/501'/0'/0'
- Solana address derivation (base58 ed25519 pubkey)
- SD sanity report that intentionally excludes roll transcript, raw entropy, mnemonic, passphrase, and seed

## Not implemented yet

- private-key export (intentional)

## Key-material handling

- The mnemonic is displayed on-device for backup. Treat it as the wallet's private key.
- The raw private key and seed are never displayed, exported, or written to SD.
- Roll storage uses a fixed buffer overwritten on clear/delete; no Arduino `String` in the secret path.
- Mnemonic, passphrase, normalized passphrase, entropy, and seed buffers are wiped (volatile write) on clear-all.
- The SD report contains only: sanity verdict, counters, face histogram, audit fingerprint, public address, and explicit `*_saved=false` flags.

## Verification

`lib/wallet_core` (mnemonic generation, PBKDF2, SLIP-0010, ed25519 pubkey, base58, NFKD) is the exact code that runs on-device, host-compiled and tested against:

- official BIP39 vectors (trezor python-mnemonic, 256-bit ENT)
- official SLIP-0010 ed25519 test vectors
- Solana m/44'/501'/0'/0' addresses cross-checked between two independent implementations
- NFKD equivalence tests (NFD vs NFC passphrase forms)

Run:

```bash
python reference.py          # regenerates tests/reference_vectors.json
bash tests/build_host_test.sh && ./tests/host_test/host_test.exe
```

Hardware-in-the-loop tests (scripted 615-roll replay, fingerprint reproducibility) have not been performed; run them before relying on this firmware for real funds.

## Reporting issues

Open a GitHub issue for non-secret bug reports.

Never paste dice transcripts, mnemonics, passphrases, private keys, or wallet seed material into an issue, chat, screenshot, or cloud document.
