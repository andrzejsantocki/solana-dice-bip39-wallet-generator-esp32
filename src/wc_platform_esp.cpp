// ESP32 platform layer for wallet_core: mbedtls primitives.
#include "wallet_core.h"
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <esp_random.h>
#include <bootloader_random.h>
#include <cstring>

void wc_sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, data, len);
  mbedtls_sha256_finish(&ctx, out);
  mbedtls_sha256_free(&ctx);
}

void wc_sha512(const uint8_t* data, size_t len, uint8_t out[64]) {
  mbedtls_sha512_context ctx;
  mbedtls_sha512_init(&ctx);
  mbedtls_sha512_starts(&ctx, 0);
  mbedtls_sha512_update(&ctx, data, len);
  mbedtls_sha512_finish(&ctx, out);
  mbedtls_sha512_free(&ctx);
}

// Conditioned ESP32-S3 HWRNG digest for hybrid mode.
// 16 x 32-byte chunks streamed through SHA-256 (domain-separated), never
// holding all 512 bytes at once. Catastrophic-failure health check: if all
// 16 chunks are identical (e.g. stuck constant), fail closed — never fall
// back to dice silently. Single exit path: bootloader_random_disable()
// always runs, chunk buffer always wiped.
extern "C" bool wc_platform_hwrng_digest(uint8_t out[32]) {
  bool ok = false;
  uint8_t chunk[32];
  uint8_t first[32];
  bool firstSet = false;
  bool allIdentical = true;
  mbedtls_sha256_context ctx;

  wc_secure_zero(out, 32);
  mbedtls_sha256_init(&ctx);
  bootloader_random_enable();

  // no early return between enable and disable (single cleanup path)
  mbedtls_sha256_starts(&ctx, 0);
  {
    static const uint8_t domain[] = "DiceWallet hybrid hwrng v1";  // 26 bytes
    mbedtls_sha256_update(&ctx, domain, sizeof(domain) - 1);
    for (int i = 0; i < 16; ++i) {
      esp_fill_random(chunk, sizeof(chunk));
      if (!firstSet) { memcpy(first, chunk, sizeof(chunk)); firstSet = true; }
      else if (memcmp(first, chunk, sizeof(chunk)) != 0) allIdentical = false;
      mbedtls_sha256_update(&ctx, chunk, sizeof(chunk));
      wc_secure_zero(chunk, sizeof(chunk));
    }
    ok = !allIdentical;
    if (ok) mbedtls_sha256_finish(&ctx, out);
  }

  mbedtls_sha256_free(&ctx);
  bootloader_random_disable();  // unconditional: no early return above this
  wc_secure_zero(chunk, sizeof(chunk));
  wc_secure_zero(first, sizeof(first));
  if (!ok) wc_secure_zero(out, 32);
  return ok;
}
