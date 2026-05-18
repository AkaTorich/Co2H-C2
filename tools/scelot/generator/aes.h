// Compact AES-128 in CTR mode, no CRT, no external dependencies.
// Same source file is consumed by the generator and by the loader stub.
#ifndef SCELOT_AES_H
#define SCELOT_AES_H

#include <stdint.h>

typedef struct _AES128_CTX {
    uint8_t round_keys[176]; // 11 round keys * 16 bytes
} AES128_CTX;

void aes128_key_expand(AES128_CTX* ctx, const uint8_t key[16]);

// Encrypts/decrypts buffer in-place using AES-128 in CTR mode.
// CTR is symmetric: same call performs encryption and decryption.
void aes128_ctr_xcrypt(AES128_CTX* ctx, const uint8_t iv[16], uint8_t* buf, uint32_t len);

#endif // SCELOT_AES_H
