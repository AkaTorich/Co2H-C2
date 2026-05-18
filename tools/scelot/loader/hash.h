// Compile-time string hashing for API/DLL name resolution inside the loader stub.
// Using a simple djb2 variant — the runtime walks PEB/EAT and compares hashes
// instead of carrying readable strings in .rdata.
#ifndef SCELOT_HASH_H
#define SCELOT_HASH_H

#include <stdint.h>

#define HASH_INIT 5381u

static __forceinline uint32_t hash_step(uint32_t h, uint8_t c) {
    // make hashing case-insensitive for ASCII letters — DLL names compared
    // against PEB entries which can be in mixed case.
    if (c >= 'a' && c <= 'z') c = (uint8_t)(c - 32);
    return ((h << 5) + h) ^ c;
}

static __forceinline uint32_t hash_ansi(const char* s) {
    uint32_t h = HASH_INIT;
    while (*s) h = hash_step(h, (uint8_t)*s++);
    return h;
}

static __forceinline uint32_t hash_unicode(const wchar_t* s) {
    uint32_t h = HASH_INIT;
    while (*s) h = hash_step(h, (uint8_t)*s++);
    return h;
}

// Compile-time recursion macro — works under MSVC for short strings.
// For long names just use hash_ansi at runtime over a constant; the compiler
// will fold it via constant folding when called with a literal in /O2.
#define H(s) (hash_ansi(s))

#endif
