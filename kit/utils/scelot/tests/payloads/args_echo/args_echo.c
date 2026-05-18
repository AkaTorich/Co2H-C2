// Test #2: prints what GetCommandLineA returns. No CRT — calling
// GetCommandLineA goes through the IAT directly, which the loader has
// hooked, so we observe the substituted command line.
#include <windows.h>

static int my_strlen(const char* s) { int n = 0; while (s[n]) ++n; return n; }

void __stdcall scelot_entry(void) {
    LPCSTR cmd = GetCommandLineA();
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    static const char prefix[] = "[args_echo] GetCommandLineA: \"";
    static const char suffix[] = "\"\r\n";
    DWORD wr;
    WriteFile(out, prefix, sizeof(prefix) - 1, &wr, NULL);
    WriteFile(out, cmd, my_strlen(cmd), &wr, NULL);
    WriteFile(out, suffix, sizeof(suffix) - 1, &wr, NULL);
    ExitProcess(0);
}
