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

  // 5) Von Neumann dice pipeline: transcript -> entropy -> fingerprint -> wallet
  {
    const VnVector* v = &VN_VECTOR;
    uint8_t ent[32];
    size_t bits = wc_vn_extract(v->transcript, strlen(v->transcript), ent);
    CHECK(bits == 256, "vn bits == 256");
    char got[129];
    for (int j = 0; j < 32; ++j) sprintf(got + j * 2, "%02x", ent[j]);
    CHECK(strcmp(got, v->entropy) == 0, "vn entropy");
    uint8_t raw[32];
    size_t rawbits = wc_raw_extract(v->transcript, strlen(v->transcript), raw);
    CHECK(rawbits == 256, "raw bits == 256 (100 rolls)");
    for (int j = 0; j < 32; ++j) sprintf(got + j * 2, "%02x", raw[j]);
    CHECK(strcmp(got, v->raw_entropy) == 0, "raw entropy");
    CHECK(wc_raw_extract(v->transcript, 99, raw) == 0, "raw <100 rolls rejected");
    // extreme legal transcripts
    char ones[100]; memset(ones, '1', sizeof(ones));
    uint8_t zo[32]; memset(zo, 0xAA, sizeof(zo));
    CHECK(wc_raw_extract(ones, 100, zo) == 256, "raw all-1s accepted");
    bool allzero = true;
    for (int j = 0; j < 32; ++j) if (zo[j] != 0) allzero = false;
    CHECK(allzero, "raw all-1s -> zero entropy (no OOB)");
    char sixes[100]; memset(sixes, '6', sizeof(sixes));
    CHECK(wc_raw_extract(sixes, 100, zo) == WC_RAW_REJECTED, "raw all-6s batch rejected");
    // acceptance rate sanity: 100 random transcripts, ~88.6% accepted
    {
      uint32_t lcg = 0x12345678;
      int okc = 0;
      char t[100];
      for (int r = 0; r < 100; ++r) {
        for (int i = 0; i < 100; ++i) { lcg = lcg * 1664525u + 1013904223u; t[i] = (char)('1' + (lcg >> 28) % 6); }
        if (wc_raw_extract(t, 100, zo) == 256) okc++;
      }
      CHECK(okc > 60 && okc < 100, "raw acceptance ~88.6%");
    }
    const char* dom = "DiceWallet audit v1";
    uint8_t dombuf[64];
    memcpy(dombuf, dom, strlen(dom));
    memcpy(dombuf + strlen(dom), ent, 32);
    uint8_t h[32];
    sha256_compute(dombuf, strlen(dom) + 32, h);
    for (int j = 0; j < 32; ++j) sprintf(got + j * 2, "%02x", h[j]);
    CHECK(strcmp(got, v->fingerprint) == 0, "vn fingerprint");
    char mnemonic[WC_MNEMONIC_MAX_LEN];
    wc_mnemonic_from_entropy(ent, mnemonic);
    CHECK(strcmp(mnemonic, v->mnemonic) == 0, "vn mnemonic");
    uint8_t seed[64];
    wc_seed_from_mnemonic(mnemonic, "", seed);
    char addr[WC_ADDRESS_MAX_LEN];
    wc_solana_address(seed, addr);
    CHECK(strcmp(addr, v->address) == 0, "vn address");
  }
  printf("VN pipeline: end-to-end vector checked\n");

  // 6) wc_nfkd contract: oversized output must fail, never truncate
  {
    char out[4];
    CHECK(!wc_nfkd("abcdefgh", out, sizeof(out)), "nfkd overflow returns false");
    CHECK(!wc_nfkd("x", out, 0), "nfkd out_cap==0 returns false");
  }
  printf("NFKD contract: overflow rejection checked\n");

  // 7) wc_base58_encode bounds
  {
    uint8_t big[41] = {0};
    char out[8];
    CHECK(!wc_base58_encode(big, 41, out, sizeof(out)), "base58 len>40 rejected");
    uint8_t key32[32] = {1};
    CHECK(!wc_base58_encode(key32, 32, out, sizeof(out)), "base58 out too small rejected");
  }
  printf("base58 bounds: rejection checked\n");

  // 8) wc_key_edges boundaries: ' ', '_', '`', 'a', 'z', '~', chords, enter/del
  {
    WcKeyEdges e;
    uint32_t mask[WC_ASCII_BUCKETS] = {0, 0, 0, 0};
    bool pe = false, pd = false;
    const uint8_t key_a[] = {'a'};
    wc_key_edges(key_a, 1, false, false, mask, &pe, &pd, &e);
    CHECK(e.addedCount == 1 && e.added[0] == 'a' && !e.chord, "key 'a' added");
    wc_key_edges(key_a, 1, false, false, mask, &pe, &pd, &e);
    CHECK(e.addedCount == 0, "held 'a': no repeat edge");
    const uint8_t key_z[] = {'z'};
    memset(mask, 0, sizeof(mask));
    wc_key_edges(key_z, 1, false, false, mask, &pe, &pd, &e);
    CHECK(e.addedCount == 1 && e.added[0] == 'z', "key 'z' added");
    const uint8_t key_tilde[] = {'~'};  // 0x7E: top printable bucket boundary
    memset(mask, 0, sizeof(mask));
    wc_key_edges(key_tilde, 1, false, false, mask, &pe, &pd, &e);
    CHECK(e.addedCount == 1 && e.added[0] == '~', "key '~' added");
    const uint8_t key_sp[] = {' '};  // 0x20: bottom printable
    memset(mask, 0, sizeof(mask));
    wc_key_edges(key_sp, 1, false, false, mask, &pe, &pd, &e);
    CHECK(e.addedCount == 1 && e.added[0] == ' ', "key ' ' added");
    const uint8_t key_us[] = {'_'};  // 0x5F: bucket 2 boundary
    memset(mask, 0, sizeof(mask));
    wc_key_edges(key_us, 1, false, false, mask, &pe, &pd, &e);
    CHECK(e.addedCount == 1 && e.added[0] == '_', "key '_' added");
    const uint8_t key_bt[] = {'`'};  // 0x60: bucket 3 start
    memset(mask, 0, sizeof(mask));
    wc_key_edges(key_bt, 1, false, false, mask, &pe, &pd, &e);
    CHECK(e.addedCount == 1 && e.added[0] == '`', "key '`' added");
    const uint8_t key_chord[] = {'a', 'b'};
    memset(mask, 0, sizeof(mask));
    wc_key_edges(key_chord, 2, false, false, mask, &pe, &pd, &e);
    CHECK(e.chord && e.addedCount == 2, "chord detected");
    memset(mask, 0, sizeof(mask));
    wc_key_edges(NULL, 0, true, true, mask, &pe, &pd, &e);
    CHECK(e.enter && e.del, "enter/del first press");
    wc_key_edges(NULL, 0, true, true, mask, &pe, &pd, &e);
    CHECK(!e.enter && !e.del, "enter/del held: no repeat");
    const uint8_t key_np[] = {0x01, 0x7F, 'a'};
    memset(mask, 0, sizeof(mask));
    wc_key_edges(key_np, 3, false, false, mask, &pe, &pd, &e);
    CHECK(e.addedCount == 1 && e.added[0] == 'a', "non-printable skipped");
  }
  printf("wc_key_edges: boundary tests checked\n");

  // 9) wc_ct_equal
  {
    const char a1[] = "passphrase-one", a2[] = "passphrase-one";
    const char b1[] = "passphrase-two";
    CHECK(wc_ct_equal(a1, a2, sizeof(a1)), "ct_equal: equal");
    CHECK(!wc_ct_equal(a1, b1, sizeof(a1)), "ct_equal: differs");
    uint8_t x[64] = {0}, y[64] = {0};
    y[63] = 1;
    CHECK(!wc_ct_equal(x, y, 64), "ct_equal: last-byte differs");
  }
  printf("wc_ct_equal: checked\n");

  // 10) wc_quiz_positions: distinct, in-range, terminates on adversarial hash
  {
    uint8_t pos[4];
    uint8_t h[32] = {0};
    for (int i = 0; i < 32; ++i) h[i] = (uint8_t)(i * 37);
    wc_quiz_positions(h, pos);
    bool distinct = true;
    for (int i = 0; i < 4; ++i) {
      if (pos[i] >= 24) distinct = false;
      for (int j = 0; j < i; ++j) if (pos[i] == pos[j]) distinct = false;
    }
    CHECK(distinct, "quiz positions distinct and <24");
    // adversarial: every byte % 24 == 7 — old code looped forever here
    memset(h, 7, sizeof(h));
    wc_quiz_positions(h, pos);
    distinct = true;
    for (int i = 0; i < 4; ++i) {
      if (pos[i] >= 24) distinct = false;
      for (int j = 0; j < i; ++j) if (pos[i] == pos[j]) distinct = false;
    }
    CHECK(distinct, "quiz positions survive all-duplicate hash");
    memset(h, 0x17, sizeof(h));  // all 23s
    wc_quiz_positions(h, pos);
    distinct = true;
    for (int i = 0; i < 4; ++i) {
      if (pos[i] >= 24) distinct = false;
      for (int j = 0; j < i; ++j) if (pos[i] == pos[j]) distinct = false;
    }
    CHECK(distinct, "quiz positions survive all-identical hash");
  }
  printf("wc_quiz_positions: checked\n");

  // 11) wc_hybrid_dice_digest: exact KATs + strict input contract
  {
    uint8_t d[32];
    char got[129];
    const struct { const char* name; const char* rolls; const char* expect; } kats[] = {
      {"ones",  "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
       "133c8135cc278518f788104fac03fe77fab95bdd66553b5530fd06df38d5a8fc"},
      {"sixes", "6666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666",
       "447d8804a067075c6b7394b386b1c947b347f4b85531323bdadc8bd61f4e129b"},
      {"seq",   "1234561234561234561234561234561234561234561234561234561234561234561234561234561234561234561234561234",
       "6b8a9b2fc2953c48ddfe4394136896c6f83a0afa6fd1958f22f62971993eecc3"},
      {"alt",   "1616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616",
       "7422dc0713a2cd6c4ec8d2e025af5d9a3a13d0bc0dcaf7f4f48346f916c51043"},
    };
    for (auto& k : kats) {
      CHECK(wc_hybrid_dice_digest(k.rolls, strlen(k.rolls), d), "hybrid digest ok");
      for (int j = 0; j < 32; ++j) sprintf(got + j * 2, "%02x", d[j]);
      CHECK(strcmp(got, k.expect) == 0, "hybrid dice digest KAT");
    }
    // strict contract: wrong length, invalid chars, null pointers
    char t101[101]; memset(t101, '1', 101);
    CHECK(!wc_hybrid_dice_digest(t101, 101, d), "hybrid 101 rejected");
    char t99[99]; memset(t99, '1', 99);
    CHECK(!wc_hybrid_dice_digest(t99, 99, d), "hybrid 99 rejected");
    CHECK(!wc_hybrid_dice_digest(kats[0].rolls, 0, d), "hybrid 0 rejected");
    char bad0[100]; memset(bad0, '1', 100); bad0[50] = '0';
    CHECK(!wc_hybrid_dice_digest(bad0, 100, d), "hybrid '0' rejected");
    char bad7[100]; memset(bad7, '1', 100); bad7[50] = '7';
    CHECK(!wc_hybrid_dice_digest(bad7, 100, d), "hybrid '7' rejected");
    char badNul[100]; memset(badNul, '1', 100); badNul[50] = 0;
    CHECK(!wc_hybrid_dice_digest(badNul, 100, d), "hybrid NUL rejected");
    char badX[100]; memset(badX, '1', 100); badX[50] = 'x';
    CHECK(!wc_hybrid_dice_digest(badX, 100, d), "hybrid 'x' rejected");
    uint8_t probe[32]; memset(probe, 0xCC, sizeof(probe));
    CHECK(!wc_hybrid_dice_digest(NULL, 100, probe), "hybrid NULL rolls rejected");
    bool zeroed = true;
    for (int j = 0; j < 32; ++j) if (probe[j] != 0) zeroed = false;
    CHECK(zeroed, "hybrid NULL input zeroes out");
    CHECK(!wc_hybrid_dice_digest(kats[0].rolls, 100, NULL), "hybrid NULL out rejected");
  }
  printf("wc_hybrid_dice_digest: KATs + strict contract checked\n");

  // 12) wc_hybrid_combine: trivial vectors
  {
    uint8_t z[32] = {0}, f[32], o[32];
    memset(f, 0xFF, sizeof(f));
    memset(o, 0, sizeof(o));
    wc_hybrid_combine(z, z, o);
    bool allz = true; for (int j = 0; j < 32; ++j) if (o[j]) allz = false;
    CHECK(allz, "combine 0^0 = 0");
    wc_hybrid_combine(f, z, o);
    bool allf = true; for (int j = 0; j < 32; ++j) if (o[j] != 0xFF) allf = false;
    CHECK(allf, "combine F^0 = F");
    wc_hybrid_combine(f, f, o);
    allz = true; for (int j = 0; j < 32; ++j) if (o[j]) allz = false;
    CHECK(allz, "combine F^F = 0");
    uint8_t a[32], b[32], c[32];
    for (int j = 0; j < 32; ++j) { a[j] = (uint8_t)j; b[j] = (uint8_t)(0x55 + j); }
    wc_hybrid_combine(a, b, c);
    bool ok = true; for (int j = 0; j < 32; ++j) if (c[j] != (uint8_t)(a[j] ^ b[j])) ok = false;
    CHECK(ok, "combine known vector");
  }
  printf("wc_hybrid_combine: checked\n");

  // 12b) wc_hwrng_stream_finish: health check + domain structure (shared core)
  {
    const uint8_t* chunks[16];
    uint8_t pool[16][32];
    uint8_t out[32];
    // catastrophic failure: all 16 blocks identical (stuck constant) -> fail closed
    for (int i = 0; i < 16; ++i) {
      for (int j = 0; j < 32; ++j) pool[i][j] = 0xA5;
      chunks[i] = pool[i];
    }
    memset(out, 0xCC, sizeof(out));
    CHECK(!wc_hwrng_stream_finish(chunks, out), "hwrng all-identical blocks rejected");
    bool zeroed = true;
    for (int j = 0; j < 32; ++j) if (out[j] != 0) zeroed = false;
    CHECK(zeroed, "hwrng failure zeroes output");
    // one distinct chunk -> accepted
    pool[15][0] ^= 0x01;
    CHECK(wc_hwrng_stream_finish(chunks, out), "hwrng one-distinct-block accepted");
    // rebuild the deterministic fake stream -> digest equals the platform fake
    for (int i = 0; i < 16; ++i)
      for (int j = 0; j < 32; ++j) pool[i][j] = (uint8_t)(i * 32 + j);
    CHECK(wc_hwrng_stream_finish(chunks, out), "hwrng fake stream accepted");
    uint8_t ref[32];
    CHECK(wc_platform_hwrng_digest(ref, NULL), "hwrng platform fake ok");
    CHECK(memcmp(out, ref, 32) == 0, "hwrng conditioner matches platform fake");
    // NULL contract
    uint8_t probe[32]; memset(probe, 0xCC, sizeof(probe));
    CHECK(!wc_hwrng_stream_finish(NULL, probe), "hwrng NULL chunks rejected");
    zeroed = true;
    for (int j = 0; j < 32; ++j) if (probe[j] != 0) zeroed = false;
    CHECK(zeroed, "hwrng NULL zeroes output");
    // inner NULL: every pointer must be validated before any data is read
    // (the comparison loop exits early, so this catches partial validation)
    {
      const uint8_t* inner[16];
      for (int i = 0; i < 16; ++i) inner[i] = chunks[i];
      inner[7] = nullptr;
      CHECK(!wc_hwrng_stream_finish(inner, probe), "inner NULL chunk rejected");
      zeroed = true;
      for (int j = 0; j < 32; ++j) if (probe[j] != 0) zeroed = false;
      CHECK(zeroed, "inner NULL zeroes output");
    }
  }
  printf("wc_hwrng_stream_finish: health check checked\n");

  // 13) full hybrid KAT: fake HWRNG + transcript -> entropy -> mnemonic -> address
  {
    const HybridVector* v = &HYBRID_VECTOR;
    char got[129];
    uint8_t dice[32], hw[32], ent[32];
    CHECK(wc_hybrid_dice_digest(v->transcript, strlen(v->transcript), dice), "hybrid dice digest");
    for (int j = 0; j < 32; ++j) sprintf(got + j * 2, "%02x", dice[j]);
    CHECK(strcmp(got, v->dice_digest) == 0, "hybrid dice digest vector");
    CHECK(wc_platform_hwrng_digest(hw, NULL), "hybrid hw digest ok");
    for (int j = 0; j < 32; ++j) sprintf(got + j * 2, "%02x", hw[j]);
    CHECK(strcmp(got, v->hw_digest) == 0, "hybrid hw digest vector");
    // 10-value display sample from the first block (fake stream -> deterministic)
    {
      char smp[24];
      uint8_t dummy[32];
      CHECK(wc_platform_hwrng_digest(dummy, smp), "hwrng sample ok");
      CHECK(strcmp(smp, v->hw_sample) == 0, "hybrid hw sample vector");
    }
    wc_hybrid_combine(hw, dice, ent);
    for (int j = 0; j < 32; ++j) sprintf(got + j * 2, "%02x", ent[j]);
    CHECK(strcmp(got, v->entropy) == 0, "hybrid entropy vector");
    // audit fingerprint over the hybrid entropy (same domain as firmware)
    {
      static const uint8_t dom[] = "DiceWallet audit v1";
      uint8_t fpbuf[sizeof(dom) - 1 + 32];
      memcpy(fpbuf, dom, sizeof(dom) - 1);
      memcpy(fpbuf + sizeof(dom) - 1, ent, 32);
      uint8_t fp[32];
      wc_sha256(fpbuf, sizeof(fpbuf), fp);
      for (int j = 0; j < 32; ++j) sprintf(got + j * 2, "%02x", fp[j]);
      CHECK(strcmp(got, v->fingerprint) == 0, "hybrid fingerprint vector");
    }
    char mn[WC_MNEMONIC_MAX_LEN];
    wc_mnemonic_from_entropy(ent, mn);
    CHECK(strcmp(mn, v->mnemonic) == 0, "hybrid mnemonic vector");
    uint8_t seed[64];
    wc_seed_from_mnemonic(mn, "", seed);
    char addr[45];
    wc_solana_address(seed, addr);
    CHECK(strcmp(addr, v->address) == 0, "hybrid address vector");
    // fault injection: one hw byte flips -> entropy changes
    uint8_t ent2[32];
    hw[0] ^= 1;
    wc_hybrid_combine(hw, dice, ent2);
    bool differs = false;
    for (int j = 0; j < 32; ++j) if (ent2[j] != ent[j]) differs = true;
    CHECK(differs, "fault D: one hwrng byte change -> entropy changes");
    // fault injection: one dice char changes -> dice digest changes
    char t2[100];
    memcpy(t2, v->transcript, 100);
    t2[47] = (t2[47] == '4') ? '3' : '4';
    uint8_t d2[32];
    CHECK(wc_hybrid_dice_digest(t2, 100, d2), "fault E: digest ok");
    differs = false;
    for (int j = 0; j < 32; ++j) if (d2[j] != dice[j]) differs = true;
    CHECK(differs, "fault E: roll[47] change -> dice digest changes");
    // fault B/C: degenerate dice transcripts still yield valid distinct entropy
    char ones[100]; memset(ones, '1', 100);
    char alts[100]; memset(alts, '1', 100);
    for (int j = 1; j < 100; j += 2) alts[j] = '6';
    uint8_t d1[32], da[32], e1[32], ea[32];
    uint8_t hw2[32];
    CHECK(wc_platform_hwrng_digest(hw2, NULL), "fault B hw");
    CHECK(wc_hybrid_dice_digest(ones, 100, d1), "fault B digest");
    wc_hybrid_combine(hw2, d1, e1);
    CHECK(wc_hybrid_dice_digest(alts, 100, da), "fault C digest");
    wc_hybrid_combine(hw2, da, ea);
    differs = false;
    for (int j = 0; j < 32; ++j) if (e1[j] != ea[j]) differs = true;
    CHECK(differs, "fault B vs C: 111... vs 1616... differ");
  }
  printf("hybrid KAT: fake HWRNG + transcript -> wallet checked\n");

  if (failures) {
    printf("\n%d FAILURES\n", failures);
    return 1;
  }
  printf("\nALL HOST TESTS PASSED\n");
  return 0;
}
