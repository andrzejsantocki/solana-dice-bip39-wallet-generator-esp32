#include "wallet_core.h"
#include <string.h>
#include "../bip39/wordlist.h"
#include "../utf8proc/utf8proc.h"
#include "../ed25519/ed25519.h"

// ---------------- HMAC-SHA512 ----------------
static void hmac_sha512(const uint8_t* key, size_t keylen,
                        const uint8_t* data, size_t datalen,
                        uint8_t out[64]) {
  uint8_t k[128];
  size_t klen = keylen;
  if (keylen > 128) {
    uint8_t h[64];
    wc_sha512(key, keylen, h);
    memcpy(k, h, 64);
    klen = 64;
  } else {
    memcpy(k, key, keylen);
  }
  uint8_t ipad[128], opad[128];
  for (int i = 0; i < 128; ++i) { ipad[i] = 0x36; opad[i] = 0x5c; }
  for (size_t i = 0; i < klen; ++i) { ipad[i] ^= k[i]; opad[i] ^= k[i]; }

  uint8_t inner[128 + 128];
  memcpy(inner, ipad, 128);
  memcpy(inner + 128, data, datalen);
  uint8_t h[64];
  wc_sha512(inner, 128 + datalen, h);
  memcpy(inner, opad, 128);
  memcpy(inner + 128, h, 64);
  wc_sha512(inner, 192, out);
}

// ---------------- BIP39 ----------------
void wc_mnemonic_from_entropy(const uint8_t ent[32], char* out) {
  uint8_t cs[32];
  wc_sha256(ent, 32, cs);
  uint8_t bits[33];
  memcpy(bits, ent, 32);
  bits[32] = cs[0];  // 8 checksum bits for 256-bit ENT

  size_t pos = 0;
  for (int w = 0; w < 24; ++w) {
    uint32_t bitoff = (uint32_t)w * 11;
    uint16_t idx = 0;
    for (int b = 0; b < 11; ++b) {
      uint32_t bo = bitoff + (uint32_t)b;
      idx = (uint16_t)((idx << 1) | ((bits[bo >> 3] >> (7 - (bo & 7))) & 1));
    }
    const char* word = bip39_word_ptr(idx);
    for (const char* p = word; *p; ++p) out[pos++] = *p;
    if (w != 23) out[pos++] = ' ';
  }
  out[pos] = 0;
}

// PBKDF2-HMAC-SHA512, single block (dkLen=64 == SHA512 block size).
void wc_seed_from_mnemonic(const char* mnemonic, const char* passphrase_nfkd,
                           uint8_t seed[64]) {
  size_t mlen = strlen(mnemonic);
  size_t plen = strlen(passphrase_nfkd);
  uint8_t salt[8 + WC_PASSPHRASE_MAX_LEN + 4];
  memcpy(salt, "mnemonic", 8);
  memcpy(salt + 8, passphrase_nfkd, plen);
  size_t slen = 8 + plen;
  salt[slen] = 0; salt[slen + 1] = 0; salt[slen + 2] = 0; salt[slen + 3] = 1;

  uint8_t U[64], T[64];
  hmac_sha512((const uint8_t*)mnemonic, mlen, salt, slen + 4, U);
  memcpy(T, U, 64);
  for (uint32_t i = 1; i < 2048; ++i) {
    hmac_sha512((const uint8_t*)mnemonic, mlen, U, 64, U);
    for (int j = 0; j < 64; ++j) T[j] ^= U[j];
  }
  memcpy(seed, T, 64);
}

// ---------------- NFKD ----------------
bool wc_nfkd(const char* in, char* out, size_t out_cap) {
  utf8proc_uint8_t* res = NULL;
  utf8proc_ssize_t n = utf8proc_map(
      (const utf8proc_uint8_t*)in, 0, &res,
      (utf8proc_option_t)(UTF8PROC_NULLTERM | UTF8PROC_STABLE |
                          UTF8PROC_DECOMPOSE | UTF8PROC_COMPAT));
  if (n < 0) { if (res) free(res); return false; }
  size_t copy = (size_t)n;
  if (copy >= out_cap) copy = out_cap - 1;
  memcpy(out, res, copy);
  out[copy] = 0;
  free(res);
  return true;
}

// ---------------- SLIP-0010 ----------------
void wc_slip10_master(const uint8_t* seed, size_t seed_len, uint8_t kL[32],
                      uint8_t chaincode[32]) {
  uint8_t I[64];
  hmac_sha512((const uint8_t*)"ed25519 seed", 12, seed, seed_len, I);
  memcpy(kL, I, 32);
  memcpy(chaincode, I + 32, 32);
}

void wc_slip10_child(const uint8_t kL[32], const uint8_t chaincode[32],
                     uint32_t index, uint8_t out_kL[32], uint8_t out_cc[32]) {
  uint8_t data[37];
  data[0] = 0;
  memcpy(data + 1, kL, 32);
  uint32_t i = index | 0x80000000u;
  data[33] = (uint8_t)(i >> 24);
  data[34] = (uint8_t)(i >> 16);
  data[35] = (uint8_t)(i >> 8);
  data[36] = (uint8_t)i;
  uint8_t I[64];
  hmac_sha512(chaincode, 32, data, 37, I);
  memcpy(out_kL, I, 32);
  memcpy(out_cc, I + 32, 32);
}

// ---------------- Solana ----------------
void wc_solana_private_seed(const uint8_t seed[64], uint8_t kL[32]) {
  uint8_t cc[32];
  wc_slip10_master(seed, 64, kL, cc);
  static const uint32_t path[4] = {44, 501, 0, 0};
  for (int i = 0; i < 4; ++i) {
    uint8_t nkL[32], ncc[32];
    wc_slip10_child(kL, cc, path[i], nkL, ncc);
    memcpy(kL, nkL, 32);
    memcpy(cc, ncc, 32);
  }
}

void wc_ed25519_pubkey(const uint8_t kL[32], uint8_t pub[32]) {
  unsigned char priv_tmp[64];
  ed25519_create_keypair(pub, priv_tmp, kL);
}

void wc_base58_encode(const uint8_t* data, size_t len, char* out) {
  static const char* AL =
      "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  size_t zeros = 0;
  while (zeros < len && data[zeros] == 0) zeros++;

  uint8_t buf[40] = {0};
  memcpy(buf, data, len);
  char tmp[50];
  size_t tpos = 0;
  size_t start = 0;
  while (start < len) {
    uint32_t rem = 0;
    bool allzero = true;
    for (size_t i = start; i < len; ++i) {
      uint32_t acc = rem * 256 + buf[i];
      buf[i] = (uint8_t)(acc / 58);
      rem = acc % 58;
      if (buf[i]) allzero = false;
    }
    if (rem) allzero = false;
    if (!allzero) tmp[tpos++] = AL[rem];
    while (start < len && buf[start] == 0) start++;
  }
  size_t o = 0;
  for (size_t z = 0; z < zeros; ++z) out[o++] = '1';
  while (tpos) out[o++] = tmp[--tpos];
  out[o] = 0;
}

void wc_solana_address(const uint8_t seed[64], char addr[WC_ADDRESS_MAX_LEN]) {
  uint8_t kL[32], pub[32];
  wc_solana_private_seed(seed, kL);
  wc_ed25519_pubkey(kL, pub);
  wc_base58_encode(pub, 32, addr);
}
