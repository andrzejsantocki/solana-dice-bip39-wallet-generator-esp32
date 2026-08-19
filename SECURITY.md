# Security

## Current scope

- Cardputer ADV dice-entry firmware
- entropy mode fork at boot: Von Neumann extraction (default, bias removed) or raw dice (3 bits/roll, bias kept)
- Von Neumann extraction from physical d6 rolls
- 256 accepted comparison bits
- SHA-256 audit fingerprint display
- BIP39 mnemonic generation (24 words, 256-bit ENT)
- BIP39 passphrase (ASCII-only input, entered twice, NFKD-normalized)
- SLIP-0010 Ed25519 derivation, Solana path m/44'/501'/0'/0'
- Solana address derivation (base58 ed25519 pubkey)
- backup verification quiz (4 typed words) gating the address page
- fail-closed radio checks: wallet generation is blocked unless Wi-Fi and Bluetooth are verified off
- SD sanity report that intentionally excludes roll transcript, raw entropy, mnemonic, passphrase, and seed

## Not implemented yet

- private-key export (intentional)

## Key-material handling

- The mnemonic is displayed on-device for backup. Treat it as the wallet's private key.
- The raw private key and seed are never displayed, exported, or written to SD.
- No Arduino `String` exists in any path carrying roll/entropy/mnemonic/passphrase/address data — fixed buffers and `snprintf` slices only. The address page stays locked until the 4-word backup quiz passes.
- All secret-bearing temporaries in `lib/wallet_core` (HMAC pads, PBKDF2 U/T blocks, SLIP-0010 intermediate keys and chaincodes, the ed25519 private-key temporary, UTF-8 normalization buffers, entropy and seed copies) are wiped with volatile writes (`wc_secure_zero`) before they leave scope or are freed.
- Firmware wipes rolls, passphrase (both entries), normalized passphrase, mnemonic, and address buffers on clear-all.
- `wc_nfkd` never truncates: oversized normalized output returns failure, and the firmware re-prompts instead of deriving with a silently truncated passphrase.
- The SD report contains only: sanity verdict, counters, face histogram, audit fingerprint, public address, passphrase-set flag (not the passphrase), backup-verified flag, and explicit `*_saved=false` flags.

## Passphrase input

- ASCII-only (0x20–0x7E), accepted one key at a time via per-key edge detection; chorded/overlapping keys are rejected with a visible warning, never silently merged or dropped.
- Non-empty passphrases are entered twice; entries are compared in full with a constant-time no-early-exit XOR (wc_ct_equal) before any derivation runs. BIP39 has no passphrase checksum — double-entry is the only typo defense.
- Empty passphrase (default) skips confirmation.
- Typed-input modes (passphrase, quiz) ignore the keypress that opened them until it is fully released — a held Enter can never double as the first confirmation.
- Passphrase, its confirmation copy, and the normalized copy are wiped immediately after seed derivation; only the set/empty flag survives.

## Entropy mode fork

At boot the device offers two extraction modes:

- Von Neumann (default): roll pairs with equal values are dropped, the rest
  produce unbiased bits. Recommended. ~615 rolls typical for 256 bits.
- Raw dice: 100 rolls -> X in [0, 6^100); L = 5·2^256. X >= L: whole batch
  rejected (~11.4% of batches, UI says re-roll). X < L: entropy = X mod 2^256
  — exactly uniform for fair independent dice (5 preimages per output), and
  dice bias is NOT corrected by any part of this path. The UI marks raw mode
  "Not recommended" and the sanity page flags it. The SD report records the
  chosen mode (`entropy_mode=`) plus mode-specific fields (VN: `vn_bits`,
  `ties`, `used_vn_bits`, `surplus_vn_bits`; raw: `raw_dice_rolls=100`,
  conversion method, acceptance probability, fair-d6 contract).

## Radio posture

- Wi-Fi and Bluetooth are disabled at boot, and state is re-verified: once after initialization, again immediately before passphrase entry, and again inside wallet derivation. Any failed verification shows `RADIO STATE ERROR` and blocks generation (fail closed).

## Compatibility caveat

- Empty-passphrase wallets follow Phantom's documented m/44'/501'/0'/0' path.
- Non-empty-passphrase restore has NOT been verified against Phantom/Solflare flows. The device UI warns about this on the address page. Verify restore in your wallet app with a small amount before depositing.

## Verification

`lib/wallet_core` (VN extraction, mnemonic generation, PBKDF2, SLIP-0010, ed25519 pubkey, base58, NFKD) is the exact code that runs on-device, host-compiled and tested against:

- official BIP39 vectors (trezor python-mnemonic, 256-bit ENT)
- official SLIP-0010 ed25519 test vectors
- Solana m/44'/501'/0'/0' addresses cross-checked between two independent implementations
- NFKD equivalence tests (NFD vs NFC passphrase forms)
- a fixed 700-roll transcript run end-to-end: rolls → entropy → fingerprint → mnemonic → seed → address

Run:

```bash
python tools/reference.py        # regenerates tests/reference_vectors.json
python tools/gen_test_vectors.py # regenerates tests/host_test/vectors.inc
bash tests/build_host_test.sh && ./tests/host_test/host_test
```

CI executes the host tests on every push and PR; tag releases publish only after host tests and the firmware build both pass.

Hardware-in-the-loop tests (scripted 615-roll replay, fingerprint reproducibility) have not been performed; run them before relying on this firmware for real funds.

## Reporting issues

Open a GitHub issue for non-secret bug reports.

Never paste dice transcripts, mnemonics, passphrases, private keys, or wallet seed material into an issue, chat, screenshot, or cloud document.
