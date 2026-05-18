// Manual PE mapping: relocations, imports, per-section permissions,
// optional GetCommandLine* IAT hooking, optional RtlAddFunctionTable.
#ifndef SCELOT_MAP_PE_H
#define SCELOT_MAP_PE_H

#include <stdint.h>
#include <windows.h>

typedef HMODULE (WINAPI *fn_LoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *fn_GetProcAddress)(HMODULE, LPCSTR);
typedef LPVOID  (WINAPI *fn_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *fn_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
#ifdef _M_X64
typedef BOOLEAN (WINAPI *fn_RtlAddFunctionTable)(PRUNTIME_FUNCTION, DWORD, DWORD64);
#else
typedef void* fn_RtlAddFunctionTable; // unused on x86
#endif

typedef struct _MAP_API {
    fn_LoadLibraryA        pLoadLibraryA;
    fn_GetProcAddress      pGetProcAddress;
    fn_VirtualAlloc        pVirtualAlloc;
    fn_VirtualProtect      pVirtualProtect;
    fn_RtlAddFunctionTable pRtlAddFunctionTable; // may be NULL on x86
} MAP_API;

void* map_pe_full(const MAP_API* api, const uint8_t* image, uint32_t image_size,
                  void** out_entry);

void* map_pe_find_export(void* base, const char* name);

// Walks IAT of a mapped image and replaces resolved entries that match
// kernel32!GetCommandLineA / GetCommandLineW with `replacement_a` /
// `replacement_w`. Returns number of patched entries.
int map_pe_hook_cmdline(const MAP_API* api, void* base,
                        void* replacement_a, void* replacement_w);

#endif
