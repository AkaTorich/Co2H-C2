// Test #1: MessageBoxA, no CRT. Entry is the WinMain-like function called
// directly — no CRT startup that could interfere with the IAT hooks the
// loader installs.
#include <windows.h>

void __stdcall scelot_entry(void) {
    MessageBoxA(NULL, "scelot OK", "hello_msg", MB_OK | MB_ICONINFORMATION);
    ExitProcess(0);
}
