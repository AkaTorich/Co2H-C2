// bof_ldap_recon.c — LDAP-разведка домена (BloodHound-collector lite)
//
// Перечисляет из Active Directory:
//   - Базовая информация о домене + политика паролей + Machine Account Quota
//   - Привилегированные группы (Domain Admins, Enterprise Admins, Schema Admins,
//     Administrators, Account Operators, Backup Operators, Remote Desktop Users,
//     Group Policy Creator Owners)
//   - Kerberoastable-пользователи  (servicePrincipalName + включены)
//   - AS-REP Roastable-пользователи (DONT_REQUIRE_PREAUTH + включены)
//   - Компьютеры домена (ОС, дней с последнего логона)
//   - Доверительные отношения (Domain Trusts)
//
// Использование (клиент):
//   bof bof_ldap_recon             -- DC обнаруживается автоматически
//   bof bof_ldap_recon dc01.corp   -- указать конкретный DC
//
// Аргумент передаётся через BeaconDataExtract (length-prefixed string).
// Если аргументов нет — LDAP подключается к DC текущего домена.

#include "bof_api.h"

// ============================================================================
// Opaque LDAP types (winldap.h не включаем — конфликты макросов в BOF-среде)
// ============================================================================

typedef struct co2h_ldap_s     LDAP;
typedef struct co2h_ldapmsg_s  LDAPMessage;
typedef void                   BerElement;

// LDAP constants
#define LDAP_PORT                   389
#define LDAP_VERSION3               3
#define LDAP_OPT_PROTOCOL_VERSION   0x11
#define LDAP_AUTH_NEGOTIATE         0x0486  // SSPI Negotiate (Kerberos / NTLM)
#define LDAP_SCOPE_BASE             0x00
#define LDAP_SCOPE_SUBTREE          0x02
#define LDAP_SUCCESS                0
#define LDAP_SIZELIMIT_EXCEEDED     4

// ============================================================================
// LDAP imports
// ============================================================================

DECLSPEC_IMPORT LDAP*        __cdecl WLDAP32$ldap_initW       (PWCHAR, ULONG);
DECLSPEC_IMPORT ULONG        __cdecl WLDAP32$ldap_connect      (LDAP*, void*);
DECLSPEC_IMPORT ULONG        __cdecl WLDAP32$ldap_bind_sW      (LDAP*, PWCHAR, PWCHAR, ULONG);
DECLSPEC_IMPORT ULONG        __cdecl WLDAP32$ldap_set_optionW  (LDAP*, int, const void*);
DECLSPEC_IMPORT ULONG        __cdecl WLDAP32$ldap_search_sW    (LDAP*, PWCHAR, ULONG,
                                                                  PWCHAR, PWCHAR*, ULONG,
                                                                  LDAPMessage**);
DECLSPEC_IMPORT ULONG        __cdecl WLDAP32$ldap_count_entries (LDAP*, LDAPMessage*);
DECLSPEC_IMPORT LDAPMessage* __cdecl WLDAP32$ldap_first_entry   (LDAP*, LDAPMessage*);
DECLSPEC_IMPORT LDAPMessage* __cdecl WLDAP32$ldap_next_entry    (LDAP*, LDAPMessage*);
DECLSPEC_IMPORT PWCHAR*      __cdecl WLDAP32$ldap_get_valuesW   (LDAP*, LDAPMessage*, PWCHAR);
DECLSPEC_IMPORT ULONG        __cdecl WLDAP32$ldap_count_valuesW (PWCHAR*);
DECLSPEC_IMPORT ULONG        __cdecl WLDAP32$ldap_value_freeW   (PWCHAR*);
DECLSPEC_IMPORT ULONG        __cdecl WLDAP32$ldap_msgfree       (LDAPMessage*);
DECLSPEC_IMPORT ULONG        __cdecl WLDAP32$ldap_unbind        (LDAP*);
DECLSPEC_IMPORT ULONG        __cdecl WLDAP32$LdapGetLastError   (void);

// ============================================================================
// Kernel32 imports
// ============================================================================

DECLSPEC_IMPORT void WINAPI KERNEL32$GetSystemTimeAsFileTime(LPFILETIME);

// ============================================================================
// Строковые хелперы (без CRT)
// ============================================================================

// Копирование wide-строки
static void lr_wcpy(WCHAR* dst, const WCHAR* src, int maxlen) {
    int i = 0;
    if (!src || !dst) return;
    while (src[i] && i < maxlen - 1) { dst[i] = src[i]; ++i; }
    dst[i] = 0;
}

// Wide → narrow (ASCII-safe; non-ASCII → '?')
static void lr_w2a(char* dst, const WCHAR* src, int maxlen) {
    int i = 0;
    if (!src || !dst) return;
    while (src[i] && i < maxlen - 1) {
        dst[i] = (char)(src[i] <= 0x7F ? src[i] : '?');
        ++i;
    }
    dst[i] = '\0';
}

// Wide-строка в int (знаковый)
static int lr_wtoi(const WCHAR* s) {
    int v = 0, neg = 0;
    if (!s) return 0;
    if (*s == L'-') { neg = 1; ++s; }
    while (*s >= L'0' && *s <= L'9') { v = v * 10 + (*s - L'0'); ++s; }
    return neg ? -v : v;
}

// Wide-строка в unsigned 64-bit
static unsigned __int64 lr_wtoull(const WCHAR* s) {
    unsigned __int64 v = 0;
    if (!s) return 0;
    while (*s >= L'0' && *s <= L'9') {
        v = v * 10 + (unsigned __int64)(*s++ - L'0');
    }
    return v;
}

// AD-интервал (хранится как отрицательное число в 100нс-тиках) → дни.
// 0 = не задан / бесконечность.
static int lr_interval_days(const WCHAR* s) {
    if (!s || !*s) return 0;
    if (*s == L'-') ++s;                          // убрать знак
    unsigned __int64 v = lr_wtoull(s);
    if (!v || v >= 0x7FFFFFFFFFFFFFFFULL) return 0;
    return (int)(v / 864000000000ULL);            // 100нс → дни
}

// AD-интервал → минуты (для lockoutDuration)
static int lr_interval_min(const WCHAR* s) {
    if (!s || !*s) return 0;
    if (*s == L'-') ++s;
    unsigned __int64 v = lr_wtoull(s);
    if (!v || v >= 0x7FFFFFFFFFFFFFFFULL) return 0;
    return (int)(v / 600000000ULL);               // 100нс → минуты
}

// AD FILETIME-строка → сколько дней назад. -1 = никогда/нет данных.
static int lr_filetime_age(const WCHAR* s) {
    if (!s || !*s) return -1;
    unsigned __int64 ft = lr_wtoull(s);
    if (!ft || ft >= 0x7FFFFFFFFFFFFFFFULL) return -1;
    FILETIME now_raw;
    KERNEL32$GetSystemTimeAsFileTime(&now_raw);
    unsigned __int64 now = ((unsigned __int64)now_raw.dwHighDateTime << 32)
                           | now_raw.dwLowDateTime;
    if (now <= ft) return 0;
    return (int)((now - ft) / 864000000000ULL);
}

// Извлечь CN из DN: "CN=John Doe,OU=..." → "John Doe"
static void lr_dn_cn(char* dst, const WCHAR* dn, int maxlen) {
    if (!dn || !dst) return;
    if ((dn[0] == L'C' || dn[0] == L'c') &&
        (dn[1] == L'N' || dn[1] == L'n') &&
         dn[2] == L'=') dn += 3;
    int i = 0;
    while (dn[i] && dn[i] != L',' && i < maxlen - 1) {
        dst[i] = (char)(dn[i] <= 0x7F ? dn[i] : '?');
        ++i;
    }
    dst[i] = '\0';
}

// Построить строку вида "domain.local" из "DC=domain,DC=local"
static void lr_base_to_fqdn(char* dst, const WCHAR* base, int maxlen) {
    int oi = 0;
    BOOL first = TRUE;
    const WCHAR* p = base;
    while (*p && oi < maxlen - 1) {
        if ((p[0] == L'D' || p[0] == L'd') &&
            (p[1] == L'C' || p[1] == L'c') &&
             p[2] == L'=') {
            p += 3;
            if (!first && oi < maxlen - 1) dst[oi++] = '.';
            first = FALSE;
            while (*p && *p != L',' && oi < maxlen - 1)
                dst[oi++] = (char)(*p++ <= 0x7F ? p[-1] : '?');
        } else {
            ++p;
        }
    }
    dst[oi] = '\0';
}

// ============================================================================
// LDAP value-хелперы
// ============================================================================

// Первое значение атрибута → narrow-буфер. TRUE если нашли.
static BOOL lv_a(LDAP* ld, LDAPMessage* e, PWCHAR attr, char* buf, int bufsz) {
    PWCHAR* v = WLDAP32$ldap_get_valuesW(ld, e, attr);
    if (!v || !v[0]) { if (v) WLDAP32$ldap_value_freeW(v); if (buf) buf[0] = '\0'; return FALSE; }
    lr_w2a(buf, v[0], bufsz);
    WLDAP32$ldap_value_freeW(v);
    return TRUE;
}

// Первое значение атрибута → wide-буфер. TRUE если нашли.
static BOOL lv_w(LDAP* ld, LDAPMessage* e, PWCHAR attr, WCHAR* buf, int bufsz) {
    PWCHAR* v = WLDAP32$ldap_get_valuesW(ld, e, attr);
    if (!v || !v[0]) { if (v) WLDAP32$ldap_value_freeW(v); if (buf) buf[0] = 0; return FALSE; }
    lr_wcpy(buf, v[0], bufsz);
    WLDAP32$ldap_value_freeW(v);
    return TRUE;
}

// Первое значение атрибута → int.
static int lv_i(LDAP* ld, LDAPMessage* e, PWCHAR attr) {
    PWCHAR* v = WLDAP32$ldap_get_valuesW(ld, e, attr);
    if (!v || !v[0]) { if (v) WLDAP32$ldap_value_freeW(v); return 0; }
    int r = lr_wtoi(v[0]);
    WLDAP32$ldap_value_freeW(v);
    return r;
}

// Первое значение атрибута → дни (AD-интервал).
static int lv_idays(LDAP* ld, LDAPMessage* e, PWCHAR attr) {
    PWCHAR* v = WLDAP32$ldap_get_valuesW(ld, e, attr);
    if (!v || !v[0]) { if (v) WLDAP32$ldap_value_freeW(v); return 0; }
    int r = lr_interval_days(v[0]);
    WLDAP32$ldap_value_freeW(v);
    return r;
}

// Первое значение атрибута → минуты (AD-интервал).
static int lv_imin(LDAP* ld, LDAPMessage* e, PWCHAR attr) {
    PWCHAR* v = WLDAP32$ldap_get_valuesW(ld, e, attr);
    if (!v || !v[0]) { if (v) WLDAP32$ldap_value_freeW(v); return 0; }
    int r = lr_interval_min(v[0]);
    WLDAP32$ldap_value_freeW(v);
    return r;
}

// Первое значение атрибута → дней назад (FILETIME).
static int lv_age(LDAP* ld, LDAPMessage* e, PWCHAR attr) {
    PWCHAR* v = WLDAP32$ldap_get_valuesW(ld, e, attr);
    if (!v || !v[0]) { if (v) WLDAP32$ldap_value_freeW(v); return -1; }
    int r = lr_filetime_age(v[0]);
    WLDAP32$ldap_value_freeW(v);
    return r;
}

// ============================================================================
// Уровень функциональности домена → строка
// ============================================================================

static const char* lr_funclevel(int level) {
    switch (level) {
        case 0: return "2000";
        case 1: return "2003 Mixed";
        case 2: return "2003";
        case 3: return "2008";
        case 4: return "2008 R2";
        case 5: return "2012";
        case 6: return "2012 R2";
        case 7: return "2016/2019/2022";
        default: return "unknown";
    }
}

// ============================================================================
// Секции отчёта
// ============================================================================

// --- Политика паролей и Machine Account Quota ---
static void sec_domain(LDAP* ld, const WCHAR* base_dn) {
    PWCHAR attrs[] = {
        L"minPwdLength", L"pwdHistoryLength", L"maxPwdAge",
        L"lockoutThreshold", L"lockoutDuration",
        L"ms-DS-MachineAccountQuota", NULL
    };
    LDAPMessage* res = NULL;
    ULONG rc = WLDAP32$ldap_search_sW(ld, (PWCHAR)base_dn, LDAP_SCOPE_BASE,
                                       L"(objectClass=domain)", attrs, 0, &res);
    if (rc != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "    (domain query failed: %u)\n", (unsigned)rc);
        return;
    }
    LDAPMessage* e = WLDAP32$ldap_first_entry(ld, res);
    if (!e) { WLDAP32$ldap_msgfree(res); return; }

    int min_len    = lv_i   (ld, e, L"minPwdLength");
    int history    = lv_i   (ld, e, L"pwdHistoryLength");
    int max_days   = lv_idays(ld, e, L"maxPwdAge");
    int lk_thr     = lv_i   (ld, e, L"lockoutThreshold");
    int lk_min     = lv_imin(ld, e, L"lockoutDuration");
    int maq        = lv_i   (ld, e, L"ms-DS-MachineAccountQuota");

    BeaconPrintf(CALLBACK_OUTPUT, "    Min length      : %d\n", min_len);
    BeaconPrintf(CALLBACK_OUTPUT, "    History         : %d\n", history);

    if (max_days)
        BeaconPrintf(CALLBACK_OUTPUT, "    Max age         : %d days\n", max_days);
    else
        BeaconPrintf(CALLBACK_OUTPUT, "    Max age         : never\n");

    if (lk_thr == 0)
        BeaconPrintf(CALLBACK_OUTPUT, "    Lockout thr     : disabled\n");
    else
        BeaconPrintf(CALLBACK_OUTPUT, "    Lockout thr     : %d attempts\n", lk_thr);

    if (lk_min == 0)
        BeaconPrintf(CALLBACK_OUTPUT, "    Lockout duration: indefinite\n");
    else
        BeaconPrintf(CALLBACK_OUTPUT, "    Lockout duration: %d min\n", lk_min);

    BeaconPrintf(CALLBACK_OUTPUT, "    Machine quota   : %d\n", maq);

    WLDAP32$ldap_msgfree(res);
}

// --- Одна привилегированная группа ---
static void sec_group(LDAP* ld, const WCHAR* base_dn, const PWCHAR gname) {
    // Построить фильтр: (sAMAccountName=<gname>)
    WCHAR filter[256];
    int fi = 0;
    const WCHAR pfx[] = L"(sAMAccountName=";
    for (int i = 0; pfx[i]; ++i)   filter[fi++] = pfx[i];
    for (int i = 0; gname[i] && fi < 248; ++i) filter[fi++] = gname[i];
    filter[fi++] = L')'; filter[fi] = 0;

    PWCHAR attrs[] = { L"member", NULL };
    LDAPMessage* res = NULL;
    ULONG rc = WLDAP32$ldap_search_sW(ld, (PWCHAR)base_dn, LDAP_SCOPE_SUBTREE,
                                       filter, attrs, 0, &res);
    if (rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED) return; // группы нет

    LDAPMessage* e = WLDAP32$ldap_first_entry(ld, res);
    if (!e) { WLDAP32$ldap_msgfree(res); return; }

    PWCHAR* members = WLDAP32$ldap_get_valuesW(ld, e, L"member");
    ULONG   cnt     = members ? WLDAP32$ldap_count_valuesW(members) : 0;

    char gname_a[128];
    lr_w2a(gname_a, gname, sizeof(gname_a));
    BeaconPrintf(CALLBACK_OUTPUT, "    %-32s %u member(s)\n", gname_a, (unsigned)cnt);

    ULONG show = cnt < 15 ? cnt : 15;
    for (ULONG i = 0; i < show; ++i) {
        char cn[128];
        lr_dn_cn(cn, members[i], sizeof(cn));
        BeaconPrintf(CALLBACK_OUTPUT, "        - %s\n", cn);
    }
    if (cnt > 15)
        BeaconPrintf(CALLBACK_OUTPUT, "        ... (%u more)\n", (unsigned)(cnt - 15));

    if (members) WLDAP32$ldap_value_freeW(members);
    WLDAP32$ldap_msgfree(res);
}

// --- Kerberoastable-пользователи ---
static void sec_kerberoastable(LDAP* ld, const WCHAR* base_dn) {
    PWCHAR attrs[] = {
        L"sAMAccountName", L"servicePrincipalName",
        L"pwdLastSet", L"lastLogonTimestamp", NULL
    };
    PWCHAR filter =
        L"(&(objectClass=user)(servicePrincipalName=*)"
        L"(!(sAMAccountName=krbtgt))"
        L"(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";

    LDAPMessage* res = NULL;
    ULONG rc = WLDAP32$ldap_search_sW(ld, (PWCHAR)base_dn, LDAP_SCOPE_SUBTREE,
                                       filter, attrs, 0, &res);
    if (rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED) {
        BeaconPrintf(CALLBACK_ERROR, "    (query failed: %u)\n", (unsigned)rc);
        return;
    }

    ULONG total = WLDAP32$ldap_count_entries(ld, res);
    BeaconPrintf(CALLBACK_OUTPUT, "    Found: %u\n", (unsigned)total);

    LDAPMessage* e = WLDAP32$ldap_first_entry(ld, res);
    while (e) {
        char sam[128] = {0};
        lv_a(ld, e, L"sAMAccountName", sam, sizeof(sam));

        int pwd_age   = lv_age(ld, e, L"pwdLastSet");
        int logon_age = lv_age(ld, e, L"lastLogonTimestamp");

        BeaconPrintf(CALLBACK_OUTPUT, "    [+] %-30s", sam);
        if (pwd_age >= 0)
            BeaconPrintf(CALLBACK_OUTPUT, "  pwd: %dd ago", pwd_age);
        if (logon_age >= 0)
            BeaconPrintf(CALLBACK_OUTPUT, "  logon: %dd ago", logon_age);
        else
            BeaconPrintf(CALLBACK_OUTPUT, "  logon: never");
        BeaconPrintf(CALLBACK_OUTPUT, "\n");

        // SPNs (max 4)
        PWCHAR* spns = WLDAP32$ldap_get_valuesW(ld, e, L"servicePrincipalName");
        if (spns) {
            ULONG nspn = WLDAP32$ldap_count_valuesW(spns);
            ULONG show = nspn < 4 ? nspn : 4;
            for (ULONG i = 0; i < show; ++i) {
                char spn[256];
                lr_w2a(spn, spns[i], sizeof(spn));
                BeaconPrintf(CALLBACK_OUTPUT, "        SPN: %s\n", spn);
            }
            if (nspn > 4)
                BeaconPrintf(CALLBACK_OUTPUT, "        ... (%u more SPNs)\n", (unsigned)(nspn - 4));
            WLDAP32$ldap_value_freeW(spns);
        }

        e = WLDAP32$ldap_next_entry(ld, e);
    }
    WLDAP32$ldap_msgfree(res);
}

// --- AS-REP Roastable-пользователи (DONT_REQUIRE_PREAUTH = 0x400000) ---
static void sec_asrep(LDAP* ld, const WCHAR* base_dn) {
    PWCHAR attrs[] = { L"sAMAccountName", L"lastLogonTimestamp", NULL };
    PWCHAR filter  =
        L"(&(objectClass=user)"
        L"(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
        L"(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";

    LDAPMessage* res = NULL;
    ULONG rc = WLDAP32$ldap_search_sW(ld, (PWCHAR)base_dn, LDAP_SCOPE_SUBTREE,
                                       filter, attrs, 0, &res);
    if (rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED) {
        BeaconPrintf(CALLBACK_ERROR, "    (query failed: %u)\n", (unsigned)rc);
        return;
    }

    ULONG total = WLDAP32$ldap_count_entries(ld, res);
    BeaconPrintf(CALLBACK_OUTPUT, "    Found: %u\n", (unsigned)total);

    LDAPMessage* e = WLDAP32$ldap_first_entry(ld, res);
    while (e) {
        char sam[128] = {0};
        lv_a(ld, e, L"sAMAccountName", sam, sizeof(sam));
        int logon_age = lv_age(ld, e, L"lastLogonTimestamp");
        if (logon_age >= 0)
            BeaconPrintf(CALLBACK_OUTPUT, "    [+] %-30s  logon: %d days ago\n", sam, logon_age);
        else
            BeaconPrintf(CALLBACK_OUTPUT, "    [+] %-30s  logon: never\n", sam);
        e = WLDAP32$ldap_next_entry(ld, e);
    }
    WLDAP32$ldap_msgfree(res);
}

// --- Компьютеры домена ---
static void sec_computers(LDAP* ld, const WCHAR* base_dn) {
    PWCHAR attrs[] = {
        L"sAMAccountName", L"operatingSystem",
        L"lastLogonTimestamp", L"userAccountControl", NULL
    };
    LDAPMessage* res = NULL;
    ULONG rc = WLDAP32$ldap_search_sW(ld, (PWCHAR)base_dn, LDAP_SCOPE_SUBTREE,
                                       L"(objectClass=computer)", attrs, 0, &res);
    if (rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED) {
        BeaconPrintf(CALLBACK_ERROR, "    (query failed: %u)\n", (unsigned)rc);
        return;
    }

    ULONG total = WLDAP32$ldap_count_entries(ld, res);
    BeaconPrintf(CALLBACK_OUTPUT, "    Found: %u (showing first 50)\n", (unsigned)total);

    ULONG shown = 0;
    LDAPMessage* e = WLDAP32$ldap_first_entry(ld, res);
    while (e && shown < 50) {
        char sam[128] = {0}, os[128] = {0};
        lv_a(ld, e, L"sAMAccountName",  sam, sizeof(sam));
        lv_a(ld, e, L"operatingSystem", os,  sizeof(os));

        int uac       = lv_i  (ld, e, L"userAccountControl");
        int logon_age = lv_age(ld, e, L"lastLogonTimestamp");

        // Убрать завершающий $ из имени компьютера
        int slen = 0;
        while (sam[slen]) ++slen;
        if (slen > 0 && sam[slen - 1] == '$') sam[slen - 1] = '\0';

        const char* dis = (uac & 0x0002) ? " [DISABLED]" : "";

        if (logon_age >= 0)
            BeaconPrintf(CALLBACK_OUTPUT, "    %-20s %-38s %3d days ago%s\n",
                         sam, os[0] ? os : "?", logon_age, dis);
        else
            BeaconPrintf(CALLBACK_OUTPUT, "    %-20s %-38s never%s\n",
                         sam, os[0] ? os : "?", dis);

        e = WLDAP32$ldap_next_entry(ld, e);
        ++shown;
    }
    if (total > 50)
        BeaconPrintf(CALLBACK_OUTPUT, "    ... (%u more)\n", (unsigned)(total - 50));

    WLDAP32$ldap_msgfree(res);
}

// --- Доверительные отношения ---
static void sec_trusts(LDAP* ld, const WCHAR* base_dn) {
    // Объекты trustedDomain живут в CN=System,<base_dn>
    WCHAR sys_dn[512];
    int si = 0;
    const WCHAR pfx[] = L"CN=System,";
    for (int i = 0; pfx[i]; ++i)    sys_dn[si++] = pfx[i];
    for (int i = 0; base_dn[i] && si < 510; ++i) sys_dn[si++] = base_dn[i];
    sys_dn[si] = 0;

    PWCHAR attrs[] = {
        L"name", L"flatName", L"trustDirection",
        L"trustType", L"trustAttributes", NULL
    };
    LDAPMessage* res = NULL;
    ULONG rc = WLDAP32$ldap_search_sW(ld, sys_dn, LDAP_SCOPE_SUBTREE,
                                       L"(objectClass=trustedDomain)", attrs, 0, &res);
    if (rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED) {
        BeaconPrintf(CALLBACK_OUTPUT, "    (none found or access denied)\n");
        return;
    }

    ULONG total = WLDAP32$ldap_count_entries(ld, res);
    if (!total) {
        BeaconPrintf(CALLBACK_OUTPUT, "    (none)\n");
        WLDAP32$ldap_msgfree(res);
        return;
    }

    LDAPMessage* e = WLDAP32$ldap_first_entry(ld, res);
    while (e) {
        char name[256] = {0}, flat[64] = {0};
        lv_a(ld, e, L"name",     name, sizeof(name));
        lv_a(ld, e, L"flatName", flat, sizeof(flat));

        int dir  = lv_i(ld, e, L"trustDirection");
        int type = lv_i(ld, e, L"trustType");
        int attr = lv_i(ld, e, L"trustAttributes");

        const char* dir_str =
            dir == 0 ? "DISABLED" :
            dir == 1 ? "INBOUND (we trust them)" :
            dir == 2 ? "OUTBOUND (they trust us)" :
            dir == 3 ? "BIDIRECTIONAL" : "?";

        const char* type_str =
            type == 1 ? "NT4"  :
            type == 2 ? "AD"   :
            type == 3 ? "Kerberos" : "?";

        BeaconPrintf(CALLBACK_OUTPUT, "    %-40s  [%s]  type=%s", name, dir_str, type_str);
        if (attr & 0x08) BeaconPrintf(CALLBACK_OUTPUT, " [FOREST]");
        if (attr & 0x10) BeaconPrintf(CALLBACK_OUTPUT, " [CROSS-ORG]");
        if (attr & 0x04) BeaconPrintf(CALLBACK_OUTPUT, " [QUARANTINED]");
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
        if (flat[0])
            BeaconPrintf(CALLBACK_OUTPUT, "        NetBIOS: %s\n", flat);

        e = WLDAP32$ldap_next_entry(ld, e);
    }
    WLDAP32$ldap_msgfree(res);
}

// ============================================================================
// Точка входа BOF
// ============================================================================

void go(char* args, int alen) {
    // Разбор необязательного аргумента — имя DC
    WCHAR   dc_host[256] = {0};
    PWCHAR  dc_ptr       = NULL; // NULL → DC текущего домена (auto)

    if (args && alen > 4) {
        datap dp;
        BeaconDataParse(&dp, args, alen);
        int   slen = 0;
        char* dc_a = BeaconDataExtract(&dp, &slen);
        if (dc_a && slen > 0 && slen < 255) {
            for (int i = 0; i < slen; ++i)
                dc_host[i] = (WCHAR)(unsigned char)dc_a[i];
            dc_host[slen] = 0;
            dc_ptr = dc_host;
        }
    }

    // ---- Инициализация LDAP-соединения ----
    LDAP* ld = WLDAP32$ldap_initW(dc_ptr, LDAP_PORT);
    if (!ld) {
        BeaconPrintf(CALLBACK_ERROR,
            "[ldap_recon] ldap_initW failed (err=%u)\n",
            (unsigned)WLDAP32$LdapGetLastError());
        return;
    }

    int ver = LDAP_VERSION3;
    WLDAP32$ldap_set_optionW(ld, LDAP_OPT_PROTOCOL_VERSION, &ver);

    ULONG rc = WLDAP32$ldap_connect(ld, NULL);
    if (rc != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR,
            "[ldap_recon] ldap_connect failed (%u)\n", (unsigned)rc);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    // Аутентификация через SSPI (Kerberos / NTLM) по текущим учётным данным
    rc = WLDAP32$ldap_bind_sW(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (rc != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR,
            "[ldap_recon] ldap_bind_sW failed (%u)\n", (unsigned)rc);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    // ---- rootDSE: получить base DN, имя DC, уровень функциональности ----
    PWCHAR rdse_attrs[] = {
        L"defaultNamingContext", L"dnsHostName",
        L"domainFunctionality",  NULL
    };
    LDAPMessage* rdse_res = NULL;
    rc = WLDAP32$ldap_search_sW(ld, L"", LDAP_SCOPE_BASE,
                                 L"(objectClass=*)", rdse_attrs, 0, &rdse_res);
    if (rc != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR,
            "[ldap_recon] rootDSE query failed (%u)\n", (unsigned)rc);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    WCHAR base_dn[512] = {0};
    char  dc_name[256] = {0};
    int   func_lvl     = 0;

    LDAPMessage* rdse_e = WLDAP32$ldap_first_entry(ld, rdse_res);
    if (rdse_e) {
        lv_w(ld, rdse_e, L"defaultNamingContext", base_dn, 512);
        lv_a(ld, rdse_e, L"dnsHostName",          dc_name, sizeof(dc_name));
        func_lvl = lv_i(ld, rdse_e, L"domainFunctionality");
    }
    WLDAP32$ldap_msgfree(rdse_res);

    if (!base_dn[0]) {
        BeaconPrintf(CALLBACK_ERROR,
            "[ldap_recon] could not determine defaultNamingContext\n");
        WLDAP32$ldap_unbind(ld);
        return;
    }

    // Красивое имя домена из base DN
    char fqdn[256] = {0};
    char base_a[512] = {0};
    lr_base_to_fqdn(fqdn, base_dn, sizeof(fqdn));
    lr_w2a(base_a, base_dn, sizeof(base_a));

    BeaconPrintf(CALLBACK_OUTPUT,
        "\n================================================\n"
        " LDAP Recon: %s\n"
        "================================================\n"
        "[*] DC           : %s\n"
        "[*] Base DN      : %s\n"
        "[*] Func level   : %d (Windows Server %s)\n",
        fqdn,
        dc_name[0] ? dc_name : "(auto-discovered)",
        base_a,
        func_lvl, lr_funclevel(func_lvl));

    // ---- Политика паролей ----
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Password Policy\n");
    sec_domain(ld, base_dn);

    // ---- Привилегированные группы ----
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Privileged Groups\n");
    sec_group(ld, base_dn, L"Domain Admins");
    sec_group(ld, base_dn, L"Enterprise Admins");
    sec_group(ld, base_dn, L"Schema Admins");
    sec_group(ld, base_dn, L"Administrators");
    sec_group(ld, base_dn, L"Account Operators");
    sec_group(ld, base_dn, L"Backup Operators");
    sec_group(ld, base_dn, L"Remote Desktop Users");
    sec_group(ld, base_dn, L"Group Policy Creator Owners");

    // ---- Kerberoastable ----
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Kerberoastable Users\n");
    sec_kerberoastable(ld, base_dn);

    // ---- AS-REP Roastable ----
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] AS-REP Roastable Users (DONT_REQUIRE_PREAUTH)\n");
    sec_asrep(ld, base_dn);

    // ---- Компьютеры ----
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Computer Accounts\n");
    sec_computers(ld, base_dn);

    // ---- Доверительные отношения ----
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Domain Trusts\n");
    sec_trusts(ld, base_dn);

    BeaconPrintf(CALLBACK_OUTPUT,
        "\n================================================\n"
        " Done: %s\n"
        "================================================\n", fqdn);

    WLDAP32$ldap_unbind(ld);
}
