// KV encoder/decoder + metadata builder for the Linux beacon.
// Wire format identical to Windows beacon (big-endian key/value lengths).

#include "beacon.h"
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/utsname.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// ---- KV encoder (thread-local-free, single global buffer) ------------------

typedef struct KvBuf {
    uint8_t* buf;
    size_t   cap;
    size_t   pos;
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
    memcpy(g_kv.buf + g_kv.pos, b, n);
    g_kv.pos += n;
}

void kv_reset(uint8_t* buf, size_t cap) {
    g_kv.buf = buf;
    g_kv.cap = cap;
    g_kv.pos = 2;      // reserve 2 bytes for count prefix
    g_kv.count = 0;
}

void kv_put_str(const char* key, const char* val) {
    uint16_t kl = (uint16_t)strlen(key);
    uint32_t vl = (uint32_t)strlen(val);
    w_u16(kl); w_bytes((const uint8_t*)key, kl);
    w_u32(vl); w_bytes((const uint8_t*)val, vl);
    g_kv.count++;
}

void kv_put_bytes(const char* key, const uint8_t* val, uint32_t len) {
    uint16_t kl = (uint16_t)strlen(key);
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

// ---- KV decoder ------------------------------------------------------------

int kv_find(const uint8_t* buf, size_t len, const char* key,
            const uint8_t** out_val, uint32_t* out_len) {
    if (len < 2) return 0;
    uint16_t n = ((uint16_t)buf[0] << 8) | buf[1];
    size_t off = 2;
    size_t klen = strlen(key);
    for (uint16_t i = 0; i < n; ++i) {
        if (off + 2 > len) return 0;
        uint16_t kl = ((uint16_t)buf[off] << 8) | buf[off+1]; off += 2;
        if (off + kl > len) return 0;
        int match = (kl == (uint16_t)klen && memcmp(buf + off, key, kl) == 0);
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
    memcpy(out, v, vl); out[vl] = 0;
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

// ---- UTF-16LE → UTF-8 conversion ------------------------------------------

size_t utf16le_to_utf8(const uint16_t* src, size_t max_chars,
                       char* dst, size_t dst_cap) {
    size_t out = 0;
    for (size_t i = 0; i < max_chars && src[i]; ++i) {
        uint16_t c = src[i];
        if (c < 0x80) {
            if (out + 1 >= dst_cap) break;
            dst[out++] = (char)c;
        } else if (c < 0x800) {
            if (out + 2 >= dst_cap) break;
            dst[out++] = (char)(0xC0 | (c >> 6));
            dst[out++] = (char)(0x80 | (c & 0x3F));
        } else {
            if (out + 3 >= dst_cap) break;
            dst[out++] = (char)(0xE0 | (c >> 12));
            dst[out++] = (char)(0x80 | ((c >> 6) & 0x3F));
            dst[out++] = (char)(0x80 | (c & 0x3F));
        }
    }
    if (out < dst_cap) dst[out] = 0;
    return out;
}

// ---- Metadata builder ------------------------------------------------------

size_t build_metadata(uint8_t* out, size_t cap,
                      const uint8_t* wrapped_key, uint32_t wrapped_key_len) {
    kv_reset(out, cap);

    // Hostname
    char hostname[256] = "";
    gethostname(hostname, sizeof(hostname));
    kv_put_str("host", hostname);

    // Username
    char user[128] = "";
    struct passwd* pw = getpwuid(getuid());
    if (pw && pw->pw_name) {
        size_t n = strlen(pw->pw_name);
        if (n >= sizeof(user)) n = sizeof(user) - 1;
        memcpy(user, pw->pw_name, n);
        user[n] = 0;
    }
    kv_put_str("user", user);

    // PID
    kv_put_u32("pid", (uint32_t)getpid());

    // Architecture
    kv_put_str("arch", "x64");

    // Internal IP: first non-loopback IPv4 address
    {
        char ip_buf[64] = "";
        struct ifaddrs* ifa_list = NULL;
        if (getifaddrs(&ifa_list) == 0) {
            for (struct ifaddrs* ifa = ifa_list; ifa; ifa = ifa->ifa_next) {
                if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
                    continue;
                struct sockaddr_in* sin = (struct sockaddr_in*)ifa->ifa_addr;
                uint32_t addr = ntohl(sin->sin_addr.s_addr);
                if ((addr >> 24) == 127) continue;  // skip loopback
                inet_ntop(AF_INET, &sin->sin_addr, ip_buf, sizeof(ip_buf));
                break;
            }
            freeifaddrs(ifa_list);
        }
        kv_put_str("ip", ip_buf);
    }

    // OS type — not in the Windows protocol but server ignores unknown keys
#ifdef __APPLE__
    kv_put_str("os", "macos");
#else
    kv_put_str("os", "linux");
#endif

    // Parent beacon id
    BeaconState* st = beacon_state();
    if (st && st->parent_id[0]) {
        kv_put_str("parent_id", st->parent_id);
    }

    // RSA-OAEP-wrapped per-session AES key
    if (wrapped_key && wrapped_key_len > 0) {
        kv_put_bytes("wrapped_key", wrapped_key, wrapped_key_len);
    }

    return kv_finish(NULL);
}
