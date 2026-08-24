# Security

## Current scope

- Cardputer ADV dice-entry firmware
- entropy mode fork at boot: Von Neumann extraction (default, bias removed), fair-d6 raw conversion (bias kept), or Dice + HWRNG
- Von Neumann extraction from physical d6 rolls
- 256 accepted comparison bits
- SHA-256 audit fingerprint display
- BIP39 mnemonic generation (24 words, 256-bit ENT)
- fixed empty BIP39 passphrase; restore is intentionally based on the 24 words alone
- SLIP-0010 Ed25519 derivation, Solana path m/44'/501'/0'/0'
- Solana address derivation (base58 ed25519 pubkey)
- backup verification quiz (4 typed words) gating the address page
- fail-closed radio checks: wallet generation is blocked unless Wi-Fi and Bluetooth are verified off
- SD sanity report that intentionally excludes roll transcript, raw entropy, mnemonic, and seed

## Not implemented yet

- private-key export (intentional)

## Key-material handling

- The mnemonic is displayed on-device for backup. Treat it as the wallet's private key.
- The raw private key and seed are never displayed, exported, or written to SD.
- No Arduino `String` exists in any path carrying roll/entropy/mnemonic/address data — fixed buffers and `snprintf` slices only. The address page stays locked until the 4-word backup quiz passes.
- All secret-bearing temporaries in `lib/wallet_core` (HMAC pads, PBKDF2 U/T blocks, SLIP-0010 intermediate keys and chaincodes, the ed25519 private-key temporary, UTF-8 normalization buffers, entropy and seed copies) are wiped with volatile writes (`wc_secure_zero`) before they leave scope or are freed.
- Firmware wipes rolls, mnemonic, and address buffers on clear-all.
- The SD report contains only: sanity verdict, counters, face histogram, audit fingerprint, public address, fixed-empty-passphrase metadata, backup-verified flag, and explicit `*_saved=false` flags.

## BIP39 passphrase policy

- The optional BIP39 passphrase is always the empty string. The firmware has no passphrase entry screen or passphrase state.
- The 24-word mnemonic alone determines the BIP39 seed used by this firmware. Users who need a separate passphrase-based wallet must derive and verify it on another trusted signing device.
- Backup-quiz input still uses per-key edge detection; chorded or overlapping keys are rejected visibly.

## Entropy mode fork

At boot the device offers three extraction modes:

- Von Neumann (default): roll pairs with equal values are dropped, the rest
  produce unbiased bits. Recommended. ~615 rolls typical for 256 bits.
- Raw dice: 100 rolls -> X in [0, 6^100); L = 5·2^256. X >= L: whole batch
  rejected (~11.4% of batches, UI says re-roll). X < L: entropy = X mod 2^256
  — exactly uniform for fair independent dice (5 preimages per output), and
  dice bias is NOT corrected by any part of this path. The UI marks raw mode
  "Not recommended" and the sanity page flags it.
- Dice + HWRNG: ENT = SHA256("DiceWallet hybrid hwrng v1" || 512 HWRNG
  bytes) XOR SHA256("DiceWallet hybrid dice v1" || u16be(100) || 100-entry
  transcript).
  Domain separation keeps both digests non-interchangeable with other
  SHA-256 uses. The HWRNG (ESP32-S3 SAR entropy source, enabled only inside
  the critical section, disabled unconditionally after) is the primary
  source; the dice transcript is an auxiliary hedge — it is never claimed to
  be random, and 111111... or 161616... are legitimate inputs. A predictable
  dice transcript cannot weaken an independent uniformly random hardware
  value (XOR argument). A good unpredictable dice transcript can hedge an
  undetected HWRNG failure. Detected catastrophic HWRNG failure (all 16
  32-byte chunks identical) BLOCKS generation — no silent fallback to dice.
  HWRNG is collected at the last possible moment (after entropy entry and
  radio verification), never at boot or mode selection. The SD report
  records metadata only (mode, rolls, conditioner, sample bytes, combiner,
  domain version) — never transcripts, digests, or HWRNG samples.

## Radio posture

- Wi-Fi and Bluetooth are disabled at boot, and state is re-verified after initialization, immediately before derivation, and again inside hybrid wallet derivation. Any failed verification shows `RADIO STATE ERROR` and blocks generation (fail closed).

## Device trust / firmware integrity

Build provenance answers one question only: does this binary correspond to
this source? (boot screen shows `firmware_version git-sha`, rebuild + hash
comparison is documented in the README). It does NOT answer: can
unauthorized firmware run on this physical device?

Current position (deliberate, open-verifiable-device model):

- No Secure Boot, no flash encryption. Any USB-connected computer can
  reflash the device; this is how users install verified builds.
- No JTAG/debug lockdown. The USB-CDC console and flashing interface stay
  open by design.
- Consequence: a device left unattended is reflashable by anyone with
  physical + USB access. Physical access is assumed to be game over.

If this device is to guard substantial funds, the following need explicit
decisions, not defaults:

1. Secure Boot (signed app + trusted bootloader): prevents unauthenticated
   firmware from booting, at the cost of making "flash your own build"
   depend on signing keys.
2. Flash encryption: hides firmware at rest; complicates the
   open/verifiable-device model and brick-recovery.
3. JTAG/console policy: efuse-level disable vs. open debugging.
4. Firmware update trust: who may flash, and how updates are authenticated
   (currently: manual, user-driven, verified-by-hash).
5. Bootloader trust: the stock bootloader is not independently audited
   here.

Until these are decided, treat the device as a signing appliance you
personally control — not as tamper-evident hardware.

## Compatibility caveat

- Wallets use an empty BIP39 passphrase and m/44'/501'/0'/0'. Solflare can import a recovery phrase and offers derivation-path selection in its advanced import flow.
- Verify that the restored address exactly matches the address displayed by this device before depositing funds.

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

Never paste dice transcripts, mnemonics, private keys, or wallet seed material into an issue, chat, screenshot, or cloud document.
