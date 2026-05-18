// RNG wrapper. Uses BCryptGenRandom with the system-preferred provider.
#include "rng.h"

#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

int rng_fill(uint8_t* buf, uint32_t len) {
    NTSTATUS st = BCryptGenRandom(NULL, buf, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return st == 0 ? 0 : -1;
}

uint32_t rng_u32(void) {
    uint32_t v = 0;
    rng_fill((uint8_t*)&v, sizeof(v));
    return v;
}
