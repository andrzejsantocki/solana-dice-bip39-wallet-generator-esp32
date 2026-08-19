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
// Collects 16 x 32-byte chunks from the SAR entropy source and hands them
// to the shared streaming conditioner (domain separation + all-identical
// health check, host-tested). This is the only ESP-hardware part of the
// hybrid path.
// Single cleanup path: no early return between enable and disable, chunk
// buffers always wiped, failed runs zero the output.
extern "C" bool wc_platform_hwrng_digest(uint8_t out[32]) {
  const uint8_t* chunks[16];
  uint8_t pool[16][32];
  bool ok = false;

  wc_secure_zero(out, 32);
  bootloader_random_enable();
  for (int i = 0; i < 16; ++i) {
    esp_fill_random(pool[i], 32);
    chunks[i] = pool[i];
  }
  ok = wc_hwrng_stream_finish(chunks, out);
  bootloader_random_disable();  // unconditional: no early return above this

  wc_secure_zero(pool, sizeof(pool));
  if (!ok) wc_secure_zero(out, 32);
  return ok;
}
