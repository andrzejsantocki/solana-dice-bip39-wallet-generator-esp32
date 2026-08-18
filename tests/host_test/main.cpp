// Host test harness: wallet_core vs official reference vectors.
// Returns nonzero on any mismatch.
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "wallet_core.h"
#include "sha256.h"
#include "vectors.inc"

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { ++failures; printf("FAIL: %s\n", msg); } } while (0)

static void hex_to_bytes(const char* hex, uint8_t* out, size_t n) {
  for (size_t i = 0; i < n; ++i) {
    unsigned v;
    sscanf(hex + i * 2, "%2x", &v);
    out[i] = (uint8_t)v;
  }
}

int main() {
  // 0) sha256 self-check (host primitive) vs FIPS vector
  {
    uint8_t d[64] = "abc";
    uint8_t h[32];
    sha256_compute(d, 3, h);
    const char* expect = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    char got[65];
    for (int i = 0; i < 32; ++i) sprintf(got + i * 2, "%02x", h[i]);
    CHECK(strcmp(got, expect) == 0, "sha256('abc')");
  }

  // 1) BIP39: entropy -> mnemonic; mnemonic+passphrase -> seed
  for (int i = 0; i < BIP39_VECTOR_COUNT; ++i) {
    const Bip39Vector* v = &BIP39_VECTORS[i];
    uint8_t ent[32];
    hex_to_bytes(v->entropy, ent, 32);
    char mnemonic[WC_MNEMONIC_MAX_LEN];
    wc_mnemonic_from_entropy(ent, mnemonic);
    if (strcmp(mnemonic, v->mnemonic) != 0) {
      ++failures;
      printf("FAIL: bip39 mnemonic[%d]\n  got:      %s\n  expected: %s\n",
             i, mnemonic, v->mnemonic);
    }
    char pp_nfkd[WC_PASSPHRASE_MAX_LEN];
    if (!wc_nfkd(v->passphrase, pp_nfkd, sizeof(pp_nfkd))) {
      ++failures; printf("FAIL: nfkd[%d]\n", i); continue;
    }
    uint8_t seed[64];
    wc_seed_from_mnemonic(mnemonic, pp_nfkd, seed);
    char got[129];
    for (int j = 0; j < 64; ++j) sprintf(got + j * 2, "%02x", seed[j]);
    if (strcmp(got, v->seed) != 0) {
      ++failures;
      printf("FAIL: bip39 seed[%d]\n  got:      %s\n  expected: %s\n", i, got, v->seed);
    }
  }
  printf("BIP39: %d vectors checked\n", BIP39_VECTOR_COUNT);

  // 2) SLIP-0010: master + children from seed 000102...0f
  {
    uint8_t seed[64] = {0};
    for (int i = 0; i < 16; ++i) seed[i] = (uint8_t)i;
    uint8_t kL[32], cc[32];
    wc_slip10_master(seed, 16, kL, cc);
    const uint32_t child1 = 0, child2 = 1;
    int vidx = 0;
    for (int i = 0; i < SLIP10_VECTOR_COUNT; ++i) {
      const Slip10Vector* v = &SLIP10_VECTORS[i];
      char got[65];
      for (int j = 0; j < 32; ++j) sprintf(got + j * 2, "%02x", kL[j]);
      CHECK(strcmp(got, v->priv) == 0, "slip10 private");
      for (int j = 0; j < 32; ++j) sprintf(got + j * 2, "%02x", cc[j]);
      CHECK(strcmp(got, v->chaincode) == 0, "slip10 chaincode");
      uint8_t pub[32];
      wc_ed25519_pubkey(kL, pub);
      for (int j = 0; j < 32; ++j) sprintf(got + j * 2, "%02x", pub[j]);
      CHECK(strcmp(got, v->pub) == 0, "slip10 pubkey");
      // step to next node in vector chain
      if (vidx == 0) {
        uint8_t nkL[32], ncc[32];
        wc_slip10_child(kL, cc, child1, nkL, ncc);
        memcpy(kL, nkL, 32); memcpy(cc, ncc, 32);
      } else if (vidx == 1) {
        uint8_t nkL[32], ncc[32];
        wc_slip10_child(kL, cc, child2, nkL, ncc);
        memcpy(kL, nkL, 32); memcpy(cc, ncc, 32);
      }
      ++vidx;
    }
  }
  printf("SLIP-0010: %d vectors checked\n", SLIP10_VECTOR_COUNT);

  // 3) Solana m/44'/501'/0'/0': address + private + pubkey
  for (int i = 0; i < SOLANA_VECTOR_COUNT; ++i) {
    const SolanaVector* v = &SOLANA_VECTORS[i];
    char pp_nfkd[WC_PASSPHRASE_MAX_LEN];
    wc_nfkd(v->passphrase, pp_nfkd, sizeof(pp_nfkd));
    uint8_t seed[64];
    wc_seed_from_mnemonic(v->mnemonic, pp_nfkd, seed);
    char addr[WC_ADDRESS_MAX_LEN];
    wc_solana_address(seed, addr);
    CHECK(strcmp(addr, v->address) == 0, "solana address");
    uint8_t kL[32];
    wc_solana_private_seed(seed, kL);
    char got[65];
    for (int j = 0; j < 32; ++j) sprintf(got + j * 2, "%02x", kL[j]);
    CHECK(strcmp(got, v->priv) == 0, "solana private seed");
    uint8_t pub[32];
    wc_ed25519_pubkey(kL, pub);
    for (int j = 0; j < 32; ++j) sprintf(got + j * 2, "%02x", pub[j]);
    CHECK(strcmp(got, v->pub) == 0, "solana pubkey");
  }
  printf("Solana: %d vectors checked\n", SOLANA_VECTOR_COUNT);

  // 4) NFKD: NFD and NFC forms normalize to the same seed
  for (int i = 0; i < NFKD_VECTOR_COUNT; ++i) {
    const NfkdVector* v = &NFKD_VECTORS[i];
    char n1[WC_PASSPHRASE_MAX_LEN], n2[WC_PASSPHRASE_MAX_LEN];
    CHECK(wc_nfkd(v->nfd, n1, sizeof(n1)), "nfkd(nfd)");
    CHECK(wc_nfkd(v->nfc, n2, sizeof(n2)), "nfkd(nfc)");
    CHECK(strcmp(n1, n2) == 0, "nfkd(nfd)==nfkd(nfc)");
    uint8_t seed[64];
    wc_seed_from_mnemonic(BIP39_VECTORS[0].mnemonic, n1, seed);
    char got[129];
    for (int j = 0; j < 64; ++j) sprintf(got + j * 2, "%02x", seed[j]);
    CHECK(strcmp(got, v->seed) == 0, "nfkd seed");
  }
  printf("NFKD: %d vectors checked\n", NFKD_VECTOR_COUNT);

  if (failures) {
    printf("\n%d FAILURES\n", failures);
    return 1;
  }
  printf("\nALL HOST TESTS PASSED\n");
  return 0;
}
