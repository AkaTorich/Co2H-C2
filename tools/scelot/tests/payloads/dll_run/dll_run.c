// Test #3: DLL with Run(LPSTR) export. No CRT.
#include <windows.h>

BOOL WINAPI _DllMainCRTStartup(HINSTANCE h, DWORD r, LPVOID v) {
    (void)h; (void)r; (void)v;
    return TRUE;
}

__declspec(dllexport) void __stdcall Run(LPSTR args) {
    char buf[1024];
    wsprintfA(buf, "dll_run.Run called\nargs: \"%s\"",
              args ? args : "(null)");
    MessageBoxA(NULL, buf, "dll_run", MB_OK);
}
