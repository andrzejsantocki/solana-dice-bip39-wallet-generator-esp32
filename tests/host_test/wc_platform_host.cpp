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
// distinct, so the production health check would pass. Domain-separated
// digest identical in structure to src/wc_platform_esp.cpp.
bool wc_platform_hwrng_digest(uint8_t out[32]) {
  static const uint8_t domain[] = "DiceWallet hybrid hwrng v1";  // 26 bytes
  uint8_t buf[sizeof(domain) - 1 + 512];
  memcpy(buf, domain, sizeof(domain) - 1);
  for (int i = 0; i < 512; ++i) buf[sizeof(domain) - 1 + i] = (uint8_t)i;
  sha256_compute(buf, sizeof(buf), out);
  return true;
}
