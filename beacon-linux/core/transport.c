// Transport selector for Linux beacon.
//
// Active transport is determined by uri_checkin prefix (patched by artifact-gen):
//   "tcp://..."  -> g_transport_tcp   (raw TCP, persistent socket)
//   "dns://..."  -> g_transport_dns   (DNS over UDP, A/TXT queries)
//   otherwise    -> g_transport_https (HTTPS via OpenSSL BIO)

#include "beacon.h"
#include <stddef.h>

// Compare UTF-16LE uint16_t[] against ASCII prefix.
static int u16_startswith(const uint16_t* s, const char* prefix) {
    for (size_t i = 0; prefix[i]; ++i) {
        if (s[i] != (uint16_t)(unsigned char)prefix[i]) return 0;
    }
    return 1;
}

const TransportVtbl* select_transport(void) {
    BeaconState* st = beacon_state();
    const uint16_t* u = st->uri_checkin;

    if (u16_startswith(u, "tcp://")) {
        bdbg("[transport] selected: TCP\n");
        return &g_transport_tcp;
    }
    if (u16_startswith(u, "dns://")) {
        bdbg("[transport] selected: DNS\n");
        return &g_transport_dns;
    }
    bdbg("[transport] selected: HTTPS\n");
    return &g_transport_https;
}
