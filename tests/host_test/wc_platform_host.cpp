// Host platform layer for wallet_core: standalone sha256 + orlp sha512.
#include "wallet_core.h"
#include "sha256.h"
#include <cstring>
extern "C" {
#include "sha512.h"  // orlp ed25519's sha512 (no extern-C guards in header)
}

void wc_sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
  sha256_compute(data, len, out);
}

void wc_sha512(const uint8_t* data, size_t len, uint8_t out[64]) {
  sha512(data, len, out);
}

// Deterministic fake HWRNG for hybrid-mode tests: stream = 512 bytes
// 0x00 0x01 0x02 ... 0xFF 0x00 0x01 ... (byte k & 0xFF). All 16 chunks
// distinct, so the shared production health check passes. Runs through the
// SAME conditioner (wc_hwrng_stream_finish) as the ESP layer, so the
// health-check + domain-separation logic is exercised on CI.
bool wc_platform_hwrng_digest(uint8_t out[32]) {
  const uint8_t* chunks[16];
  uint8_t pool[16][32];
  for (int i = 0; i < 16; ++i) {
    for (int j = 0; j < 32; ++j) pool[i][j] = (uint8_t)(i * 32 + j);
    chunks[i] = pool[i];
  }
  return wc_hwrng_stream_finish(chunks, out);
}
