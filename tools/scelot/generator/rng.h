// Cryptographic-quality random bytes via BCryptGenRandom.
#ifndef SCELOT_RNG_H
#define SCELOT_RNG_H

#include <stdint.h>

int rng_fill(uint8_t* buf, uint32_t len); // returns 0 on success
uint32_t rng_u32(void);

#endif
