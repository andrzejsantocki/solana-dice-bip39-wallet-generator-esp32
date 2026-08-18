#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WC_MNEMONIC_MAX_LEN 240    // 24 words <=9 chars + 23 spaces
#define WC_PASSPHRASE_MAX_LEN 64   // firmware input cap (normalized)
#define WC_ADDRESS_MAX_LEN 45      // base58 ed25519 pubkey <= 44 chars + NUL

// ---- hash primitives (platform layer) ----
void wc_sha256(const uint8_t* data, size_t len, uint8_t out[32]);
void wc_sha512(const uint8_t* data, size_t len, uint8_t out[64]);

// ---- BIP39 ----
// entropy[32] -> 24-word mnemonic, space separated, NUL terminated.
// Buffer must hold at least WC_MNEMONIC_MAX_LEN bytes.
void wc_mnemonic_from_entropy(const uint8_t ent[32], char* out);

// seed = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic"||passphrase, 2048, 64).
// passphrase must already be NFKD-normalized (see wc_nfkd).
// mnemonic is the ASCII sentence produced by wc_mnemonic_from_entropy;
// the English wordlist is ASCII, so NFKD on the sentence is the identity.
void wc_seed_from_mnemonic(const char* mnemonic, const char* passphrase_nfkd,
                           uint8_t seed[64]);

// ---- NFKD ----
// utf8proc compat decomposition, no recomposition (BIP39 NFKD).
// Returns false on invalid UTF-8 or if output does not fit out_cap.
bool wc_nfkd(const char* in, char* out, size_t out_cap);

// ---- SLIP-0010 ed25519 (hardened-only, as used by Solana) ----
void wc_slip10_master(const uint8_t* seed, size_t seed_len, uint8_t kL[32],
                      uint8_t chaincode[32]);
// index is the raw child index; 0x80000000 is OR-ed in internally.
// out buffers may alias the input buffers.
void wc_slip10_child(const uint8_t kL[32], const uint8_t chaincode[32],
                     uint32_t index, uint8_t out_kL[32], uint8_t out_cc[32]);

// ---- Solana ----
// m/44'/501'/0'/0' private seed from BIP39 seed.
void wc_solana_private_seed(const uint8_t seed[64], uint8_t kL[32]);

// ed25519 pubkey from 32-byte private seed (orlp/ed25519, clamps internally).
void wc_ed25519_pubkey(const uint8_t kL[32], uint8_t pub[32]);

// base58 (Bitcoin alphabet).
void wc_base58_encode(const uint8_t* data, size_t len, char* out);

// Solana address = base58(pubkey) for m/44'/501'/0'/0'.
void wc_solana_address(const uint8_t seed[64], char addr[WC_ADDRESS_MAX_LEN]);

#ifdef __cplusplus
}
#endif
