// Walks PEB.Ldr.InMemoryOrderModuleList to locate a loaded DLL by name hash,
// then walks the export directory to resolve a function by name hash.
#include "peb.h"
#include "hash.h"

#include <windows.h>
#include <winternl.h>

typedef struct _LDR_DATA_TABLE_ENTRY_FULL {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_FULL;

static PEB* current_peb(void) {
#if defined(_M_X64)
    return (PEB*)__readgsqword(0x60);
#elif defined(_M_IX86)
    return (PEB*)__readfsdword(0x30);
#else
#error unsupported arch
#endif
}

void* peb_find_module(uint32_t name_hash) {
    PEB* peb = current_peb();
    PEB_LDR_DATA* ldr = peb->Ldr;
    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
    for (LIST_ENTRY* cur = head->Flink; cur != head; cur = cur->Flink) {
        LDR_DATA_TABLE_ENTRY_FULL* e =
            (LDR_DATA_TABLE_ENTRY_FULL*)((uint8_t*)cur - sizeof(LIST_ENTRY));
        if (!e->BaseDllName.Buffer) continue;
        uint32_t h = HASH_INIT;
        wchar_t* p = e->BaseDllName.Buffer;
        USHORT n = e->BaseDllName.Length / sizeof(wchar_t);
        for (USHORT i = 0; i < n; ++i) h = hash_step(h, (uint8_t)p[i]);
        if (h == name_hash) return e->DllBase;
    }
    return 0;
}

void* peb_find_proc(void* module, uint32_t proc_hash) {
    if (!module) return 0;
    uint8_t* base = (uint8_t*)module;
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
        const char* name = (const char*)(base + names[i]);
        uint32_t h = HASH_INIT;
        for (const char* p = name; *p; ++p) h = hash_step(h, (uint8_t)*p);
        if (h == proc_hash) {
            uint16_t ord = ords[i];
            return base + funcs[ord];
        }
    }
    return 0;
}
