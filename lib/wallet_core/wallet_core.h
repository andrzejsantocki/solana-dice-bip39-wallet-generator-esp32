#pragma once
#include <stddef.h>
#include <stdint.h>

#define WC_MNEMONIC_MAX_LEN 240
#define WC_PASSPHRASE_MAX_LEN 64
#define WC_ADDRESS_MAX_LEN 45

// Platform hooks (provided by src/wc_platform_esp.cpp or tests host stub).
extern "C" void wc_sha256(const uint8_t* data, size_t len, uint8_t out[32]);
extern "C" void wc_sha512(const uint8_t* data, size_t len, uint8_t out[64]);

// Constant-time-ish overwrite via volatile writes. Wipe anything secret
// before it goes out of scope / is freed.
void wc_secure_zero(void* p, size_t n);

// Von Neumann extraction shared with firmware: consumes roll pairs
// ('1'..'6'), equal pairs discarded, a<b -> 0, a>b -> 1, up to 256 bits.
// Returns number of bits written (max 256).
size_t wc_vn_extract(const char* rolls, size_t roll_count, uint8_t out[32]);

// Raw dice extraction (bias NOT removed): exact base-6 to binary conversion
// of 100 rolls (6^100 > 2^256), top 32 bytes taken. Fair dice: ~258.5 bits
// of source entropy for 256 output bits. Returns 256 on success, 0 if fewer
// than 100 valid rolls.
size_t wc_raw_extract(const char* rolls, size_t roll_count, uint8_t out[32]);

// Deterministic backup-quiz positions: 4 distinct indices 0..23 from
// hash bytes (candidate index always advances — cannot loop forever).
void wc_quiz_positions(const uint8_t hash[32], uint8_t pos[4]);

// ---- keyboard edge parsing (shared with firmware UI, host-tested) ----
// Printable ASCII 0x20..0x7E needs 4x32-bit buckets (0x7E >> 5 == 3).
#define WC_ASCII_BUCKETS 4
struct WcKeyEdges {
  char added[8];
  uint8_t addedCount;
  bool chord, enter, del;
};
// Per-update edge detection: chars newly present vs the persistent mask are
// "added"; >1 new char = chord. enter/del are edge-triggered. Callers reset
// mask/prev flags on full release.
void wc_key_edges(const uint8_t* word, size_t word_len, bool enter, bool del,
                  uint32_t mask[WC_ASCII_BUCKETS], bool* prevEnter,
                  bool* prevDel, WcKeyEdges* out);

// Constant-time equality (volatile reads, no early exit).
bool wc_ct_equal(const void* a, const void* b, size_t n);

// BIP39: 256-bit entropy -> 24-word mnemonic in out (WC_MNEMONIC_MAX_LEN).
void wc_mnemonic_from_entropy(const uint8_t ent[32], char* out);

// PBKDF2-HMAC-SHA512, 2048 rounds, salt "mnemonic" || passphrase_nfkd.
void wc_seed_from_mnemonic(const char* mnemonic, const char* passphrase_nfkd,
                           uint8_t seed[64]);

// NFKD normalization. Returns false if input is invalid UTF-8 or the
// normalized output does not fit out_cap (including NUL) — never truncates.
bool wc_nfkd(const char* in, char* out, size_t out_cap);

// ---- SLIP-0010 ed25519 (hardened-only, as used by Solana) ----
void wc_slip10_master(const uint8_t* seed, size_t seed_len, uint8_t kL[32],
                      uint8_t chaincode[32]);
// index is the raw child index; 0x80000000 is OR-ed in internally.
// out buffers may alias the input buffers.
void wc_slip10_child(const uint8_t kL[32], const uint8_t chaincode[32],
                     uint32_t index, uint8_t out_kL[32], uint8_t out_cc[32]);

// ed25519 public key from a 32-byte secret scalar.
void wc_ed25519_pubkey(const uint8_t kL[32], uint8_t pub[32]);

// SLIP-0010 m/44'/501'/0'/0' private scalar from a BIP39 seed (kL wiped by callers).
void wc_solana_private_seed(const uint8_t seed[64], uint8_t kL[32]);

// base58 encode. Returns false (no output) if len > 40 or the encoded
// form does not fit out_cap (including NUL).
bool wc_base58_encode(const uint8_t* data, size_t len, char* out,
                      size_t out_cap);

// Solana keypair: seed -> SLIP-0010 m/44'/501'/0'/0' -> ed25519 pubkey
// -> base58 address. Internal temporaries are wiped before return.
void wc_solana_address(const uint8_t seed[64], char addr[WC_ADDRESS_MAX_LEN]);
