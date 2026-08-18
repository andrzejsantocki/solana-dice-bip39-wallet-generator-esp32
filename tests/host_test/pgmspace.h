// Host shim so wordlist.h compiles without Arduino.
#pragma once
#define PROGMEM
static inline const void* pgm_read_ptr(const void* p) {
  return *(void* const*)p;
}
