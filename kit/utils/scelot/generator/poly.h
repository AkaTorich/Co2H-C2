// Polymorphic engine. Stage-3 stub — only patches placeholders inside the
// stub blob (size, AES key, AES IV). Real block shuffling / junk insertion
// arrives in stage 8.
#ifndef SCELOT_POLY_H
#define SCELOT_POLY_H

#include <stdint.h>

// Patches `stub` in place. `buf_len` is the size of the buffer pointed at
// by `stub` (the stub bytes that will be searched). `runtime_size` is the
// value written into the stub-size placeholder (= stub_len + pad_len).
int poly_patch_stub(uint8_t* stub, uint32_t buf_len, uint32_t runtime_size,
                    const uint8_t key[16], const uint8_t iv[16]);

#endif
