// ESP32 platform layer for wallet_core: mbedtls primitives.
#include "wallet_core.h"
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>

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
