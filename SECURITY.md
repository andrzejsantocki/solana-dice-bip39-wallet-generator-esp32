# Security

This project is not ready for real-money wallet generation.

Current scope:

- Cardputer ADV dice-entry firmware
- Von Neumann extraction from physical d6 rolls
- 256 accepted comparison bits
- SHA-256 audit fingerprint display
- SD sanity report that intentionally excludes roll transcript and raw entropy

Not implemented yet:

- BIP39 mnemonic generation
- BIP39 passphrase input / NFKD normalization
- SLIP-0010 Ed25519 derivation
- Solana address derivation
- private-key export

Do not use generated or displayed values as a private key. Do not fund wallets from this firmware until BIP39/Solana derivation and independent test vectors exist.

## Reporting issues

Open a GitHub issue for non-secret bug reports.

Never paste dice transcripts, mnemonics, passphrases, private keys, or wallet seed material into an issue, chat, screenshot, or cloud document.
