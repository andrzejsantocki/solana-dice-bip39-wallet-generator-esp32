// Host platform layer for wallet_core: standalone sha256 + orlp sha512.
#include "wallet_core.h"
#include "sha256.h"
extern "C" {
#include "sha512.h"  // orlp ed25519's sha512 (no extern-C guards in header)
}

void wc_sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
  sha256_compute(data, len, out);
}

void wc_sha512(const uint8_t* data, size_t len, uint8_t out[64]) {
  sha512(data, len, out);
}
