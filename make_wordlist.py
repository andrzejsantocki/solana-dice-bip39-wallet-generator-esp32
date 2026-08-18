import hashlib

# Build PROGMEM wordlist header from english.txt
with open("lib/bip39/english.txt") as f:
    words = [w.strip() for w in f if w.strip()]

assert len(words) == 2048, len(words)
assert len(set(words)) == 2048, "dupes"

entries = ",\n  ".join(f'"{w}"' for w in words)
header = f"""// BIP39 English wordlist (2048 words), PROGMEM for ESP32 flash storage.
// Source: bitcoin/bips bip-0039 (MIT licensed).
// Generated from lib/bip39/english.txt - do not edit by hand.
#pragma once
#include <pgmspace.h>

#define BIP39_WORD_COUNT 2048

static const char* const BIP39_WORDS[BIP39_WORD_COUNT] PROGMEM = {{
  {entries}
}};

// Pointer accessor: PROGMEM on ESP32, plain RAM on host tests.
static inline const char* bip39_word_ptr(uint16_t i) {{
#if defined(ESP32)
  return (const char*)pgm_read_ptr(&BIP39_WORDS[i]);
#else
  return BIP39_WORDS[i];
#endif
}}
"""
with open("lib/bip39/wordlist.h", "w") as f:
    f.write(header)

# sanity checks
print("words:", len(words))
print("first:", words[:5])
print("last:", words[-5:])
print("header bytes:", len(header))
print("sha256:", hashlib.sha256(open("lib/bip39/english.txt","rb").read()).hexdigest()[:16])
