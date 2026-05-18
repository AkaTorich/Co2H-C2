// Full manual mapper plus IAT hooking and SEH table registration.
#include "map_pe.h"

static void copy_bytes(uint8_t* dst, const uint8_t* src, uint32_t n) {
    for (uint32_t i = 0; i < n; ++i) dst[i] = src[i];
}

static int str_eq_ansi(const char* a, const char* b) {
    while (*a && *b) { if (*a != *b) return 0; ++a; ++b; }
    return *a == *b;
}

static int str_iequal_ansi(const char* a, const char* b) {
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'a' && ca <= 'z') ca = (char)(ca - 32);
        if (cb >= 'a' && cb <= 'z') cb = (char)(cb - 32);
        if (ca != cb) return 0;
        ++a; ++b;
    }
    return *a == *b;
}

static void apply_relocations(uint8_t* base, IMAGE_NT_HEADERS* nt, intptr_t delta) {
    IMAGE_DATA_DIRECTORY* dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!dir->Size || !dir->VirtualAddress || !delta) return;
    IMAGE_BASE_RELOCATION* rel =
        (IMAGE_BASE_RELOCATION*)(base + dir->VirtualAddress);
    uint8_t* end = (uint8_t*)rel + dir->Size;
    while ((uint8_t*)rel < end && rel->SizeOfBlock) {
        uint32_t count = (rel->SizeOfBlock - sizeof(*rel)) / 2;
        uint16_t* items = (uint16_t*)(rel + 1);
        uint8_t* page = base + rel->VirtualAddress;
        for (uint32_t i = 0; i < count; ++i) {
            uint16_t e = items[i];
            uint16_t type = e >> 12;
            uint16_t off  = e & 0x0FFF;
            if (type == IMAGE_REL_BASED_DIR64) {
                *(uint64_t*)(page + off) += (uint64_t)delta;
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                *(uint32_t*)(page + off) += (uint32_t)delta;
            }
        }
        rel = (IMAGE_BASE_RELOCATION*)((uint8_t*)rel + rel->SizeOfBlock);
    }
}

static int resolve_imports(const MAP_API* api, uint8_t* base, IMAGE_NT_HEADERS* nt) {
    IMAGE_DATA_DIRECTORY* dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir->Size || !dir->VirtualAddress) return 0;
    IMAGE_IMPORT_DESCRIPTOR* imp =
        (IMAGE_IMPORT_DESCRIPTOR*)(base + dir->VirtualAddress);
    while (imp->Name) {
        const char* dll_name = (const char*)(base + imp->Name);
        HMODULE dll = api->pLoadLibraryA(dll_name);
        if (!dll) return -1;
        uintptr_t* oft = (uintptr_t*)(base + (imp->OriginalFirstThunk
                                              ? imp->OriginalFirstThunk
                                              : imp->FirstThunk));
        uintptr_t* ft  = (uintptr_t*)(base + imp->FirstThunk);
        while (*oft) {
            FARPROC p;
            if (*oft & ((uintptr_t)1 << ((sizeof(uintptr_t) * 8) - 1))) {
                p = api->pGetProcAddress(dll, (LPCSTR)(*oft & 0xFFFF));
            } else {
                IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(base + *oft);
                p = api->pGetProcAddress(dll, ibn->Name);
            }
            if (!p) return -2;
            *ft = (uintptr_t)p;
            ++oft; ++ft;
        }
        ++imp;
    }
    return 0;
}

static DWORD section_protect(DWORD ch) {
    int x = (ch & IMAGE_SCN_MEM_EXECUTE) ? 1 : 0;
    int r = (ch & IMAGE_SCN_MEM_READ)    ? 1 : 0;
    int w = (ch & IMAGE_SCN_MEM_WRITE)   ? 1 : 0;
    if (x && r && w) return PAGE_EXECUTE_READWRITE;
    if (x && r)      return PAGE_EXECUTE_READ;
    if (x)           return PAGE_EXECUTE;
    if (r && w)      return PAGE_READWRITE;
    if (r)           return PAGE_READONLY;
    return PAGE_NOACCESS;
}

static void apply_section_perms(const MAP_API* api, uint8_t* base, IMAGE_NT_HEADERS* nt) {
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    DWORD old;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!sec->VirtualAddress || !sec->Misc.VirtualSize) continue;
        api->pVirtualProtect(base + sec->VirtualAddress,
                             sec->Misc.VirtualSize,
                             section_protect(sec->Characteristics), &old);
    }
}

#ifdef _M_X64
static void register_seh(const MAP_API* api, uint8_t* base, IMAGE_NT_HEADERS* nt) {
    if (!api->pRtlAddFunctionTable) return;
    IMAGE_DATA_DIRECTORY* d =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!d->Size || !d->VirtualAddress) return;
    PRUNTIME_FUNCTION rf = (PRUNTIME_FUNCTION)(base + d->VirtualAddress);
    DWORD count = d->Size / sizeof(RUNTIME_FUNCTION);
    api->pRtlAddFunctionTable(rf, count, (DWORD64)base);
}
#endif

void* map_pe_full(const MAP_API* api, const uint8_t* image, uint32_t image_size,
                  void** out_entry) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)image;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(image + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    SIZE_T sz = nt->OptionalHeader.SizeOfImage;
    uint8_t* base = (uint8_t*)api->pVirtualAlloc(
        (LPVOID)(uintptr_t)nt->OptionalHeader.ImageBase,
        sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!base) {
        base = (uint8_t*)api->pVirtualAlloc(NULL, sz,
                                            MEM_COMMIT | MEM_RESERVE,
                                            PAGE_READWRITE);
        if (!base) return 0;
    }

    copy_bytes(base, image, nt->OptionalHeader.SizeOfHeaders);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (sec->SizeOfRawData) {
            copy_bytes(base + sec->VirtualAddress,
                       image + sec->PointerToRawData,
                       sec->SizeOfRawData);
        }
    }

    intptr_t delta = (intptr_t)(base - (uint8_t*)(uintptr_t)nt->OptionalHeader.ImageBase);
    apply_relocations(base, nt, delta);

    IMAGE_NT_HEADERS* mapped_nt =
        (IMAGE_NT_HEADERS*)(base + ((IMAGE_DOS_HEADER*)base)->e_lfanew);
    mapped_nt->OptionalHeader.ImageBase = (uintptr_t)base;

    if (resolve_imports(api, base, mapped_nt) != 0) return 0;
    apply_section_perms(api, base, mapped_nt);

#ifdef _M_X64
    register_seh(api, base, mapped_nt);
#endif

    *out_entry = base + mapped_nt->OptionalHeader.AddressOfEntryPoint;
    return base;
}

void* map_pe_find_export(void* base_v, const char* name) {
    uint8_t* base = (uint8_t*)base_v;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY* dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir->VirtualAddress) return 0;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + dir->VirtualAddress);
    uint32_t* names = (uint32_t*)(base + exp->AddressOfNames);
    uint16_t* ords  = (uint16_t*)(base + exp->AddressOfNameOrdinals);
    uint32_t* funcs = (uint32_t*)(base + exp->AddressOfFunctions);
    for (uint32_t i = 0; i < exp->NumberOfNames; ++i) {
        const char* n = (const char*)(base + names[i]);
        if (str_eq_ansi(n, name)) return base + funcs[ords[i]];
    }
    return 0;
}

int map_pe_hook_cmdline(const MAP_API* api, void* base_v,
                        void* replacement_a, void* replacement_w) {
    uint8_t* base = (uint8_t*)base_v;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY* dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir->Size || !dir->VirtualAddress) return 0;

    int patched = 0;
    IMAGE_IMPORT_DESCRIPTOR* imp =
        (IMAGE_IMPORT_DESCRIPTOR*)(base + dir->VirtualAddress);
    while (imp->Name) {
        const char* dll_name = (const char*)(base + imp->Name);
        if (str_iequal_ansi(dll_name, "kernel32.dll") ||
            str_iequal_ansi(dll_name, "KERNELBASE.dll") ||
            str_iequal_ansi(dll_name, "api-ms-win-core-processenvironment-l1-1-0.dll")) {

            uintptr_t* oft = (uintptr_t*)(base + (imp->OriginalFirstThunk
                                                  ? imp->OriginalFirstThunk
                                                  : imp->FirstThunk));
            uintptr_t* ft  = (uintptr_t*)(base + imp->FirstThunk);
            while (*oft) {
                if (!(*oft & ((uintptr_t)1 << ((sizeof(uintptr_t) * 8) - 1)))) {
                    IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(base + *oft);
                    void* repl = 0;
                    if (str_eq_ansi(ibn->Name, "GetCommandLineA")) repl = replacement_a;
                    else if (str_eq_ansi(ibn->Name, "GetCommandLineW")) repl = replacement_w;
                    if (repl) {
                        DWORD old;
                        api->pVirtualProtect(ft, sizeof(uintptr_t), PAGE_READWRITE, &old);
                        *ft = (uintptr_t)repl;
                        api->pVirtualProtect(ft, sizeof(uintptr_t), old, &old);
                        ++patched;
                    }
                }
                ++oft; ++ft;
            }
        }
        ++imp;
    }
    return patched;
}
