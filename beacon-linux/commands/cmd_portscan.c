// cmd_portscan.c — TCP connect scan (Linux/macOS порт).
//
// Синтаксис: portscan <target> [ports]
//   target  — IP-адрес или hostname
//   ports   — "22,80,443"  или  "1-1024"  или  "22,100-200,443"
//             Если не указан — сканируются ~30 самых распространённых портов.
//
// Метод: неблокирующий connect() + select с таймаутом TIMEOUT_MS.
// Сканирует батчами по SCAN_BATCH сокетов одновременно.
// Выводит только открытые порты + итоговую строку.
// Payload KV: {target utf8, ports utf8 (опц.)} — совместимо с Windows-биконом.

#include "../core/beacon.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define TIMEOUT_MS   500    // таймаут ожидания connect на один батч
#define SCAN_BATCH    60    // сокетов за раз (оставляем запас до FD_SETSIZE)

// Таблица имён сервисов — только самые распространённые.
static const struct { uint16_t port; const char* name; } kSvc[] = {
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
static const uint16_t kDefaultPorts[] = {
    21,22,23,25,53,80,110,111,135,139,
    143,389,443,445,636,993,995,1433,1723,2049,
    3306,3389,5900,5985,5986,8080,8443,9090,27017,6379
};
#define kDefaultPortsCount (sizeof(kDefaultPorts)/sizeof(kDefaultPorts[0]))

// ---- Вспомогательные функции ------------------------------------------------

// Парсит беззнаковое число из строки и двигает указатель.
static uint32_t parse_u32(const char** p) {
    uint32_t n = 0;
    while (**p >= '0' && **p <= '9') {
        n = n * 10u + (uint32_t)(**p - '0');
        (*p)++;
    }
    return n;
}

// Возвращает имя сервиса для порта или пустую строку.
static const char* svc_name(uint16_t port) {
    for (int i = 0; kSvc[i].name; i++)
        if (kSvc[i].port == port) return kSvc[i].name;
    return "";
}

// Установить сокет в неблокирующий режим.
static void set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// out_write строкового литерала.
#define ow(s) out_write((s), sizeof(s) - 1)

// Печатает строку таблицы для открытого порта.
static void print_open(uint16_t port) {
    // Формат: "22/tcp    open      ssh\n"
    char line[64];
    int n = snprintf(line, sizeof(line), "%u/tcp", (unsigned)port);
    out_write(line, (size_t)n);
    // Выравнивание до 10 символов.
    int pad = 10 - n;
    if (pad > 0) { char sp[] = "          "; out_write(sp, (size_t)pad); }
    ow("open");
    out_write("      ", 6);
    const char* svc = svc_name(port);
    if (*svc) out_write(svc, strlen(svc));
    ow("\n");
}

// ---- Основная функция -------------------------------------------------------

void cmd_portscan(const BeaconTask* t) {
    char target[256]      = {0};
    char ports_spec[2048] = {0};

    kv_get_str(t->pay, t->pay_len, "target", target, sizeof(target));
    kv_get_str(t->pay, t->pay_len, "ports",  ports_spec, sizeof(ports_spec));

    if (!target[0]) {
        ow("[!] portscan: no target\n");
        return;
    }

    // Выделяем массив портов для сканирования (макс. 65535).
    uint16_t* ports = (uint16_t*)bmalloc(65535u * sizeof(uint16_t));
    if (!ports) { ow("[!] portscan: out of memory\n"); return; }
    uint32_t port_count = 0;

    if (!ports_spec[0]) {
        // Список по умолчанию.
        for (uint32_t i = 0; i < kDefaultPortsCount; i++)
            ports[port_count++] = kDefaultPorts[i];
    } else {
        // Парсим пользовательский список: "22,80,100-200,443"
        const char* p = ports_spec;
        while (*p && port_count < 65535u) {
            while (*p == ' ' || *p == ',') p++;
            if (!*p) break;
            uint32_t a = parse_u32(&p);
            if (*p == '-') {
                p++;
                uint32_t b = parse_u32(&p);
                if (b < a) { uint32_t tmp = a; a = b; b = tmp; }
                if (b > 65535) b = 65535;
                for (uint32_t pp = a; pp <= b && port_count < 65535u; pp++)
                    ports[port_count++] = (uint16_t)pp;
            } else {
                if (a && a <= 65535) ports[port_count++] = (uint16_t)a;
            }
        }
    }

    if (port_count == 0) {
        ow("[!] portscan: no valid ports\n");
        bfree(ports);
        return;
    }

    // Разрешаем hostname → адрес.
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(target, NULL, &hints, &res) != 0 || !res) {
        char err[300];
        int n = snprintf(err, sizeof(err), "[!] portscan: cannot resolve '%s'\n", target);
        out_write(err, (size_t)n);
        bfree(ports);
        return;
    }

    struct sockaddr_storage base_sa;
    socklen_t sa_len = res->ai_addrlen;
    memcpy(&base_sa, res->ai_addr, sa_len);
    freeaddrinfo(res);

    // Транспорт нужен для промежуточных flush'ей.
    const TransportVtbl* tv = get_transport();

    // Заголовок таблицы.
    ow("PORT      STATE     SERVICE\n");
    ow("--------- --------- -------\n");
    out_flush_chunk(tv, 0);

    struct timeval t0;
    gettimeofday(&t0, NULL);

    uint32_t open_count = 0;

    // Массивы для текущего батча.
    int      socks[SCAN_BATCH];
    uint16_t sport[SCAN_BATCH];

    for (uint32_t base = 0; base < port_count; base += SCAN_BATCH) {
        uint32_t batch = port_count - base;
        if (batch > SCAN_BATCH) batch = SCAN_BATCH;

        // Открываем неблокирующие сокеты и запускаем connect.
        uint32_t actual = 0;
        for (uint32_t i = 0; i < batch; i++) {
            int s = socket(base_sa.ss_family, SOCK_STREAM, IPPROTO_TCP);
            if (s < 0) continue;

            set_nonblock(s);
            sock_nosigpipe(s);

            // Устанавливаем порт в копии адреса.
            struct sockaddr_storage sa;
            memcpy(&sa, &base_sa, sa_len);
            if (sa.ss_family == AF_INET)
                ((struct sockaddr_in*)&sa)->sin_port = htons(ports[base + i]);
            else
                ((struct sockaddr_in6*)&sa)->sin6_port = htons(ports[base + i]);

            int ret = connect(s, (struct sockaddr*)&sa, sa_len);
            if (ret == 0) {
                // Мгновенное подключение (loopback/LAN).
                print_open(ports[base + i]);
                open_count++;
                close(s);
            } else if (errno == EINPROGRESS) {
                socks[actual] = s;
                sport[actual] = ports[base + i];
                actual++;
            } else {
                close(s);
            }
        }

        if (!actual) continue;

        // select: ждём TIMEOUT_MS мс до завершения соединений.
        fd_set wset;
        FD_ZERO(&wset);
        int maxfd = 0;
        for (uint32_t i = 0; i < actual; i++) {
            FD_SET(socks[i], &wset);
            if (socks[i] > maxfd) maxfd = socks[i];
        }
        struct timeval tval;
        tval.tv_sec  = TIMEOUT_MS / 1000;
        tval.tv_usec = (TIMEOUT_MS % 1000) * 1000;
        select(maxfd + 1, NULL, &wset, NULL, &tval);

        // Проверяем результаты.
        uint32_t batch_open = 0;
        for (uint32_t i = 0; i < actual; i++) {
            if (FD_ISSET(socks[i], &wset)) {
                int so_err = 0;
                socklen_t elen = sizeof(so_err);
                getsockopt(socks[i], SOL_SOCKET, SO_ERROR, &so_err, &elen);
                if (so_err == 0) {
                    print_open(sport[i]);
                    open_count++;
                    batch_open++;
                }
            }
            close(socks[i]);
        }

        // Флашим результаты батча — оператор видит порты по мере сканирования.
        if (batch_open > 0 || (base % (SCAN_BATCH * 8u)) == 0)
            out_flush_chunk(tv, 0);
    }

    bfree(ports);

    // Итоговая строка.
    struct timeval t1;
    gettimeofday(&t1, NULL);
    uint32_t elapsed_ms = (uint32_t)((t1.tv_sec - t0.tv_sec) * 1000
                                     + (t1.tv_usec - t0.tv_usec) / 1000);

    char footer[256];
    int n = snprintf(footer, sizeof(footer),
        "\nScan of %s: %u open port(s), %u scanned (%u.%03us)\n",
        target, (unsigned)open_count, (unsigned)port_count,
        (unsigned)(elapsed_ms / 1000u), (unsigned)(elapsed_ms % 1000u));
    out_write(footer, (size_t)n);

    // Финальный кадр.
    out_flush_chunk(tv, 1);
}
