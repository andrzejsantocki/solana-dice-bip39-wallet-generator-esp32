#include "wallet_core.h"
#include <stdlib.h>
#include <string.h>
#include "../bip39/wordlist.h"
#include "../utf8proc/utf8proc.h"
#include "../ed25519/ed25519.h"

// ---------------- secure wipe ----------------
void wc_secure_zero(void* p, size_t n) {
  volatile uint8_t* v = (volatile uint8_t*)p;
  while (n--) *v++ = 0;
}

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
    wc_secure_zero(h, sizeof(h));
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

  wc_secure_zero(k, sizeof(k));
  wc_secure_zero(ipad, sizeof(ipad));
  wc_secure_zero(opad, sizeof(opad));
  wc_secure_zero(inner, sizeof(inner));
  wc_secure_zero(h, sizeof(h));
}

// ---------------- Von Neumann extraction ----------------
size_t wc_vn_extract(const char* rolls, size_t roll_count, uint8_t out[32]) {
  memset(out, 0, 32);
  size_t bit = 0;
  for (size_t i = 1; i < roll_count && bit < 256; i += 2) {
    char a = rolls[i - 1], b = rolls[i];
    if (a < '1' || a > '6' || b < '1' || b > '6') continue;
    if (a == b) continue;
    if (a > b) out[bit / 8] |= (uint8_t)(1 << (7 - (bit % 8)));
    bit++;
  }
  return bit;
}

// ---------------- Raw dice extraction (bias kept) ----------------
size_t wc_raw_extract(const char* rolls, size_t roll_count, uint8_t out[32]) {
  // Exact uniform conversion (fair independent d6 only):
  // X = value of 100 base-6 digits; L = 5 * 2^256. 2^256 < 6^100 < 6*2^256,
  // so exactly five 256-bit ranges fit in the outcome space.
  //   X >= L: reject the whole batch (start 100 fresh rolls)
  //   X <  L: out = X mod 2^256  (exactly uniform: 5 preimages per output)
  const size_t RAW_ROLLS = 100;
  memset(out, 0, 32);
  uint8_t acc[33] = {0};  // little-endian, 6^100 < 2^259
  size_t accBytes = 1;
  size_t used = 0;
  for (size_t i = 0; i < roll_count && used < RAW_ROLLS; ++i) {
    char c = rolls[i];
    if (c < '1' || c > '6') continue;
    uint32_t carry = (uint32_t)(c - '1');
    for (size_t b = 0; b < accBytes; ++b) {
      uint32_t t = (uint32_t)acc[b] * 6 + carry;
      acc[b] = (uint8_t)t;
      carry = t >> 8;
    }
    if (carry) acc[accBytes++] = (uint8_t)carry;
    used++;
  }
  if (used < RAW_ROLLS) { wc_secure_zero(acc, sizeof(acc)); return 0; }
  // X = acc[32]*2^256 + low; X >= L (= 5*2^256) iff acc[32] >= 5
  // (accBytes == 33 means acc[32] >= 1; max 6^100 < 6*2^256 so acc[32] <= 5)
  if (accBytes >= 33 && acc[32] >= 5) {
    wc_secure_zero(acc, sizeof(acc));
    return WC_RAW_REJECTED;
  }
  // X mod 2^256, big-endian bytes (matches wc_vn_extract byte order)
  for (size_t i = 0; i < 32; ++i) out[i] = acc[31 - i];
  wc_secure_zero(acc, sizeof(acc));
  return 256;
}

// ---------------- quiz positions ----------------
void wc_quiz_positions(const uint8_t hash[32], uint8_t pos[4]) {
  uint8_t k = 0;
  for (uint8_t candidate = 0; candidate < 32 && k < 4; ++candidate) {
    uint8_t p = hash[candidate] % 24;
    bool dup = false;
    for (uint8_t j = 0; j < k; ++j) if (pos[j] == p) dup = true;
    if (!dup) pos[k++] = p;
  }
  // Deterministic fallback: first unused indices ascending (guarantees 4).
  for (uint8_t v = 0; v < 24 && k < 4; ++v) {
    bool used = false;
    for (uint8_t j = 0; j < k; ++j) if (pos[j] == v) used = true;
    if (!used) pos[k++] = v;
  }
}

// ---------------- keyboard edge parsing ----------------
void wc_key_edges(const uint8_t* word, size_t word_len, bool enter, bool del,
                  uint32_t mask[WC_ASCII_BUCKETS], bool* prevEnter,
                  bool* prevDel, WcKeyEdges* out) {
  out->addedCount = 0;
  out->chord = false;
  out->enter = false;
  out->del = false;
  uint32_t cur[WC_ASCII_BUCKETS] = {0, 0, 0, 0};
  char chars[8];
  uint8_t n = 0;
  for (size_t i = 0; i < word_len && n < 8; ++i) {
    uint8_t c = word[i];
    if (c >= 0x20 && c <= 0x7E) {
      chars[n++] = (char)c;
      cur[c >> 5] |= 1u << (c & 31);
    }
  }
  for (uint8_t i = 0; i < n; ++i) {
    uint8_t c = (uint8_t)chars[i];
    uint32_t bit = 1u << (c & 31);
    if (!(mask[c >> 5] & bit)) out->added[out->addedCount++] = chars[i];
  }
  out->chord = out->addedCount > 1;
  memcpy(mask, cur, sizeof(cur));
  out->enter = enter && !*prevEnter;
  *prevEnter = enter;
  out->del = del && !*prevDel;
  *prevDel = del;
}

// ---------------- constant-time equality ----------------
bool wc_ct_equal(const void* a, const void* b, size_t n) {
  const volatile uint8_t* pa = (const volatile uint8_t*)a;
  const volatile uint8_t* pb = (const volatile uint8_t*)b;
  uint8_t diff = 0;
  for (size_t i = 0; i < n; ++i) diff |= (uint8_t)(pa[i] ^ pb[i]);
  return diff == 0;
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
  wc_secure_zero(cs, sizeof(cs));
  wc_secure_zero(bits, sizeof(bits));
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
  wc_secure_zero(salt, sizeof(salt));
  wc_secure_zero(U, sizeof(U));
  wc_secure_zero(T, sizeof(T));
}

// ---------------- NFKD ----------------
bool wc_nfkd(const char* in, char* out, size_t out_cap) {
  if (out_cap == 0) return false;
  utf8proc_uint8_t* res = NULL;
  utf8proc_ssize_t n = utf8proc_map(
      (const utf8proc_uint8_t*)in, 0, &res,
      (utf8proc_option_t)(UTF8PROC_NULLTERM | UTF8PROC_STABLE |
                          UTF8PROC_DECOMPOSE | UTF8PROC_COMPAT));
  if (n < 0 || (size_t)n >= out_cap) {
    if (res) wc_secure_zero(res, (size_t)n > 0 ? (size_t)n : 0);
    if (res) free(res);
    return false;
  }
  memcpy(out, res, (size_t)n);
  out[(size_t)n] = 0;  // utf8proc_map returns payload length only — terminate explicitly
  wc_secure_zero(res, (size_t)n);
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
  wc_secure_zero(I, sizeof(I));
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
  wc_secure_zero(data, sizeof(data));
  wc_secure_zero(I, sizeof(I));
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
    wc_secure_zero(nkL, sizeof(nkL));
    wc_secure_zero(ncc, sizeof(ncc));
  }
  wc_secure_zero(cc, sizeof(cc));
}

void wc_ed25519_pubkey(const uint8_t kL[32], uint8_t pub[32]) {
  unsigned char priv_tmp[64];
  ed25519_create_keypair(pub, priv_tmp, kL);
  wc_secure_zero(priv_tmp, sizeof(priv_tmp));
}

bool wc_base58_encode(const uint8_t* data, size_t len, char* out,
                      size_t out_cap) {
  if (len == 0 || len > 40 || out_cap < 2) return false;
  static const char* AL =
      "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  size_t zeros = 0;
  while (zeros < len && data[zeros] == 0) zeros++;

  uint8_t buf[40];
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
  if (zeros + tpos + 1 > out_cap) return false;
  size_t o = 0;
  for (size_t z = 0; z < zeros; ++z) out[o++] = '1';
  while (tpos) out[o++] = tmp[--tpos];
  out[o] = 0;
  return true;
}

void wc_solana_address(const uint8_t seed[64], char addr[WC_ADDRESS_MAX_LEN]) {
  uint8_t kL[32], pub[32];
  wc_solana_private_seed(seed, kL);
  wc_ed25519_pubkey(kL, pub);
  wc_base58_encode(pub, 32, addr, WC_ADDRESS_MAX_LEN);
  wc_secure_zero(kL, sizeof(kL));
  wc_secure_zero(pub, sizeof(pub));
}
