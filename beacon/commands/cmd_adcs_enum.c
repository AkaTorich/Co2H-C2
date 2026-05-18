// cmd_adcs_enum.c -- ADCS misconfiguration scanner (ESC1-16, исключая 12 и 14).
//
// ESC1:  Template allows enrollee to set arbitrary SAN + Client Auth EKU
//        + low-privilege principal can enroll
// ESC2:  Template has Any Purpose EKU (or no EKU at all)
//        + low-privilege principal can enroll
// ESC3:  Template has Certificate Request Agent EKU
//        + low-privilege principal can enroll
// ESC4:  Non-admin has write/GenericWrite/WriteDACL/WriteOwner on a template
// ESC5:  Non-admin has write on a PKI container object (NTAuth, Root CA, etc.)
// ESC6:  CA has EDITF_ATTRIBUTESUBJECTALTNAME2 set in its LDAP flags attribute
// ESC7:  Non-admin has write/GenericWrite on a CA enrollment-service LDAP object
// ESC8:  Web Enrollment endpoint (/certsrv/) is reachable; 401 = NTLM relay possible
// ESC9:  Template has CT_FLAG_NO_SECURITY_EXTENSION (no SID in cert) +
//        ENROLLEE_SUPPLIES_SUBJECT — bypass strong binding (KB5014754)
// ESC10: DC has weak certificate mapping enabled (StrongCertificateBindingEnforcement=0
//        or Schannel CertificateMappingMethods has UPN/S4U2Self bits)
// ESC11: CA has IF_ENFORCEENCRYPTICERTREQUEST not set — RPC enrollment not encrypted
// ESC13: Template's application policy OID is linked to AD group via
//        msDS-OIDToGroupLink — enrolling grants group membership
// ESC15: Schema v1 template with ENROLLEE_SUPPLIES_SUBJECT (EKUwu / CVE-2024-49019)
// ESC16: CA has SID extension OID in DisableExtensionList — globally no SID
//
// KV params:
//   domain  (utf8, optional) -- target domain; falls back to USERDNSDOMAIN
//
// Requirements: domain-joined machine, no special privileges.
// Links: Wldap32.lib  Netapi32.lib  Winhttp.lib  Advapi32.lib

#include "../core/beacon.h"
#include <winldap.h>
#include <dsgetdc.h>
#include <lmcons.h>
#include <lmapibuf.h>
#include <winhttp.h>
#include <sddl.h>

// ============================================================================
// Constants
// ============================================================================

// msPKI-Certificate-Name-Flag
#define CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT   0x00000001UL

// msPKI-Enrollment-Flag
#define CT_FLAG_NO_SECURITY_EXTENSION       0x00080000UL  // ESC9 — no SID in cert

// CA flags: EDITF_ATTRIBUTESUBJECTALTNAME2
#define EDITF_ATTRIBUTESUBJECTALTNAME2      0x00040000UL

// CA InterfaceFlags
#define IF_ENFORCEENCRYPTICERTREQUEST       0x00000200UL  // ESC11 — RPC encryption

// Schannel CertificateMappingMethods bits (weak mappings)
#define CMM_UPN                             0x00000004UL  // weak: UPN match
#define CMM_S4U2SELF                        0x00000010UL  // weak: implicit S4U2Self
#define CMM_WEAK_MASK                       (CMM_UPN | CMM_S4U2SELF)

// AD access masks (DS)
#define ADS_RIGHT_DS_CONTROL_ACCESS         0x00000100UL
#define ADS_RIGHT_DS_WRITE_PROP             0x00000020UL
#define ADS_RIGHT_DS_CREATE_CHILD           0x00000001UL

// Enroll extended right GUID: {0e10c1f0-78d8-11d0-92f2-00c04fb983e2}
static const GUID s_guidEnroll = {
    0x0e10c1f0, 0x78d8, 0x11d0,
    {0x92, 0xf2, 0x00, 0xc0, 0x4f, 0xb9, 0x83, 0xe2}
};
// AutoEnroll extended right GUID: {a05b8cc2-17bc-4802-a710-e7c15ab866a2}
static const GUID s_guidAutoEnroll = {
    0xa05b8cc2, 0x17bc, 0x4802,
    {0xa7, 0x10, 0xe7, 0xc1, 0x5a, 0xb8, 0x66, 0xa2}
};

// EKU OIDs
static const char OID_CLIENT_AUTH[]    = "1.3.6.1.5.5.7.3.2";
static const char OID_SMART_CARD[]     = "1.3.6.1.4.1.311.20.2.2";
static const char OID_PKINIT[]         = "1.3.6.1.5.2.3.4";
static const char OID_ANY_PURPOSE[]    = "2.5.29.37.0";
static const char OID_CERT_REQ_AGENT[] = "1.3.6.1.4.1.311.20.2.1";
// SID extension OID (szOID_NTDS_OBJECTSID) — ESC16 detection
static const char OID_NTDS_OBJECTSID[] = "1.3.6.1.4.1.311.25.2";

// SD_FLAGS LDAP control: request DACL only (BER INTEGER 4)
static BYTE        s_sdBer[]  = {0x30, 0x03, 0x02, 0x01, 0x04};
static LDAPControlW s_sdCtrl  = {
    (PWCHAR)L"1.2.840.113556.1.4.801",
    {5, (PCHAR)s_sdBer},
    FALSE
};
static PLDAPControlW s_sdCtrls[] = {&s_sdCtrl, NULL};

// ============================================================================
// Output helpers
// ============================================================================

static void ae_out(const char* s) { out_write(s, (DWORD)rt_strlen(s)); }
static void ae_flush(void)        { out_flush_chunk(get_transport(), 0); }

static int ae_wcs_to_u8(const wchar_t* w, char* b, int cap) {
    return WideCharToMultiByte(CP_UTF8, 0, w, -1, b, cap, NULL, NULL);
}
static int ae_u8_to_wcs(const char* s, wchar_t* b, int cap) {
    return MultiByteToWideChar(CP_UTF8, 0, s, -1, b, cap);
}

static DWORD ae_fmt_u32(char* buf, DWORD v) {
    if (!v) { buf[0]='0'; buf[1]=0; return 1; }
    char tmp[12]; DWORD n=0;
    while (v) { tmp[n++]=(char)('0'+v%10); v/=10; }
    DWORD i=0; while(n) buf[i++]=tmp[--n]; buf[i]=0; return i;
}

static void ae_wcat(wchar_t* dst, int cap, const wchar_t* src) {
    int i=0; while(dst[i]) ++i;
    for(int j=0; src[j] && i<cap-1; ++j) dst[i++]=src[j];
    dst[i]=0;
}

// "corp.local" -> "DC=corp,DC=local"
static void ae_build_base_dn(const wchar_t* dom, wchar_t* out, int cap) {
    int pos=0, di=0;
    while (dom[di] && pos<cap-10) {
        if (pos>0) out[pos++]=L',';
        out[pos++]=L'D'; out[pos++]=L'C'; out[pos++]=L'=';
        while (dom[di] && dom[di]!=L'.' && pos<cap-2) out[pos++]=dom[di++];
        if (dom[di]==L'.') ++di;
    }
    out[pos]=0;
}

// ============================================================================
// LDAP helpers
// ============================================================================

static DWORD ae_get_u32(LDAP* ld, LDAPMessage* e, const wchar_t* attr) {
    PWCHAR* v = ldap_get_valuesW(ld, e, (PWCHAR)attr);
    if (!v || !v[0]) { if(v) ldap_value_freeW(v); return 0; }
    DWORD r=0; int neg=0, i=0;
    if (v[0][0]==L'-') { neg=1; i=1; }
    while (v[0][i]>=L'0' && v[0][i]<=L'9') r=r*10+(DWORD)(v[0][i++]-L'0');
    ldap_value_freeW(v);
    return neg ? (DWORD)(-(LONG)r) : r;
}

static void ae_get_str(LDAP* ld, LDAPMessage* e, const wchar_t* attr,
                       char* buf, int cap) {
    PWCHAR* v = ldap_get_valuesW(ld, e, (PWCHAR)attr);
    if (!v || !v[0]) { if(v) ldap_value_freeW(v); buf[0]=0; return; }
    ae_wcs_to_u8(v[0], buf, cap);
    ldap_value_freeW(v);
}

static int ae_has_eku(LDAP* ld, LDAPMessage* e, const char* oid) {
    PWCHAR* v = ldap_get_valuesW(ld, e, (PWCHAR)L"pKIExtendedKeyUsage");
    if (!v) return 0;
    size_t ol = rt_strlen(oid);
    int found = 0;
    for (int i=0; v[i] && !found; ++i) {
        char buf[128]={0};
        ae_wcs_to_u8(v[i], buf, sizeof(buf));
        if (rt_strlen(buf)==ol && rt_memcmp(buf, oid, ol)==0) found=1;
    }
    ldap_value_freeW(v);
    return found;
}

static int ae_eku_count(LDAP* ld, LDAPMessage* e) {
    PWCHAR* v = ldap_get_valuesW(ld, e, (PWCHAR)L"pKIExtendedKeyUsage");
    if (!v) return 0;
    int c=0; while(v[c]) ++c;
    ldap_value_freeW(v);
    return c;
}

// Returns binary attribute as berval array. Free with ldap_value_free_len.
static struct berval** ae_get_bin(LDAP* ld, LDAPMessage* e, const char* attr) {
    return ldap_get_values_len(ld, e, (PCHAR)attr);
}

// ============================================================================
// SID helpers
// ============================================================================

// Returns 1 if SID is a low-privilege principal:
// Everyone, Authenticated Users, Domain Users, Domain Computers,
// Interactive, Network.
static int ae_is_low_priv(PSID sid, PSID domSid) {
    if (!sid || !IsValidSid(sid)) return 0;
    BYTE buf[SECURITY_MAX_SID_SIZE]; DWORD sz;

    static const WELL_KNOWN_SID_TYPE s_world[] = {
        WinWorldSid,              // S-1-1-0  Everyone
        WinAuthenticatedUserSid,  // S-1-5-11 Authenticated Users
        WinInteractiveSid,        // S-1-5-4  Interactive
        WinNetworkSid,            // S-1-5-2  Network
    };
    for (int i=0; i<4; ++i) {
        sz=sizeof(buf);
        if (CreateWellKnownSid(s_world[i], NULL, (PSID)buf, &sz)
            && EqualSid(sid, (PSID)buf)) return 1;
    }
    if (domSid) {
        sz=sizeof(buf);
        if (CreateWellKnownSid(WinAccountDomainUsersSid, domSid, (PSID)buf, &sz)
            && EqualSid(sid, (PSID)buf)) return 1;
        sz=sizeof(buf);
        if (CreateWellKnownSid(WinAccountComputersSid, domSid, (PSID)buf, &sz)
            && EqualSid(sid, (PSID)buf)) return 1;
    }
    return 0;
}

// Returns 1 for well-known admin SIDs (skip in ESC4/5 checks).
static int ae_is_admin(PSID sid, PSID domSid) {
    if (!sid || !IsValidSid(sid)) return 1;
    BYTE buf[SECURITY_MAX_SID_SIZE]; DWORD sz;

    static const WELL_KNOWN_SID_TYPE s_adm[] = {
        WinBuiltinAdministratorsSid, // S-1-5-32-544
        WinLocalSystemSid,           // S-1-5-18
        WinCreatorOwnerSid,          // S-1-3-0
    };
    for (int i=0; i<3; ++i) {
        sz=sizeof(buf);
        if (CreateWellKnownSid(s_adm[i], NULL, (PSID)buf, &sz)
            && EqualSid(sid, (PSID)buf)) return 1;
    }
    if (domSid) {
        sz=sizeof(buf);
        if (CreateWellKnownSid(WinAccountDomainAdminsSid, domSid, (PSID)buf, &sz)
            && EqualSid(sid, (PSID)buf)) return 1;
        sz=sizeof(buf);
        if (CreateWellKnownSid(WinAccountEnterpriseAdminsSid, domSid, (PSID)buf, &sz)
            && EqualSid(sid, (PSID)buf)) return 1;
    }
    return 0;
}

// SID -> "DOMAIN\account" or "S-1-5-..."
static void ae_sid_name(PSID sid, char* buf, int cap) {
    wchar_t name[256]={0}, dom[256]={0};
    DWORD nl=256, dl=256;
    SID_NAME_USE use;
    if (LookupAccountSidW(NULL, sid, name, &nl, dom, &dl, &use) && name[0]) {
        char nu[256]={0}, du[256]={0};
        ae_wcs_to_u8(name, nu, sizeof(nu));
        ae_wcs_to_u8(dom, du, sizeof(du));
        int i=0;
        for (int j=0; du[j] && i<cap-2; ++j) buf[i++]=du[j];
        if (i<cap-1) buf[i++]='\\';
        for (int j=0; nu[j] && i<cap-1; ++j) buf[i++]=nu[j];
        buf[i]=0;
        return;
    }
    wchar_t* ws=NULL;
    if (ConvertSidToStringSidW(sid, &ws) && ws) {
        ae_wcs_to_u8(ws, buf, cap);
        LocalFree(ws);
    } else {
        buf[0]='?'; buf[1]=0;
    }
}

// Get domain SID by resolving "domain\Domain Users" and stripping last RID.
// Returns bmalloc'd buffer; caller must bfree().
static PSID ae_get_domain_sid(const char* domain8) {
    wchar_t full[512]={0};
    ae_u8_to_wcs(domain8, full, 256);
    const wchar_t sfx[] = L"\\Domain Users";
    int i=0; while(full[i]) ++i;
    for (int j=0; sfx[j] && i<510; ++j) full[i++]=sfx[j];
    full[i]=0;

    BYTE sidBuf[SECURITY_MAX_SID_SIZE]; DWORD sidSz=sizeof(sidBuf);
    wchar_t refDom[256]={0}; DWORD rdSz=256;
    SID_NAME_USE use;
    if (!LookupAccountNameW(NULL, full, (PSID)sidBuf, &sidSz, refDom, &rdSz, &use))
        return NULL;

    // sidBuf = S-1-5-21-X-Y-Z-513; drop last sub-authority to get domain SID
    UCHAR cnt = *GetSidSubAuthorityCount((PSID)sidBuf);
    if (!cnt) return NULL;
    DWORD len = GetLengthSid((PSID)sidBuf);
    PSID dom = (PSID)bmalloc(len);
    if (!dom) return NULL;
    rt_memcpy(dom, sidBuf, len);
    *GetSidSubAuthorityCount(dom) = cnt - 1;
    return dom;
}

// ============================================================================
// DACL analysis
// ============================================================================

typedef struct {
    int  low_priv_enroll;  // ESC1-3: low-privilege principal can enroll
    int  non_admin_write;  // ESC4-5-7: non-admin has dangerous write
    char enroll_who[256];  // principal that can enroll
    char enroll_right[48]; // right granting enrollment
    char write_who[256];   // principal with dangerous write
    char write_right[48];  // dangerous write right name
} AclResult;

static AclResult ae_check_dacl(const BYTE* sdBlob, DWORD sdLen, PSID domSid) {
    AclResult r; rt_memset(&r, 0, sizeof(r));
    if (!sdBlob || sdLen < 8) return r;

    PSECURITY_DESCRIPTOR psd = (PSECURITY_DESCRIPTOR)(void*)sdBlob;
    if (!IsValidSecurityDescriptor(psd)) return r;

    BOOL hasDacl=FALSE, defaulted=FALSE;
    PACL dacl=NULL;
    if (!GetSecurityDescriptorDacl(psd, &hasDacl, &dacl, &defaulted)
        || !hasDacl || !dacl) return r;

    ACL_SIZE_INFORMATION info={0};
    if (!GetAclInformation(dacl, &info, sizeof(info), AclSizeInformation)) return r;

    for (DWORD i=0; i<info.AceCount; ++i) {
        LPVOID pAce=NULL;
        if (!GetAce(dacl, i, &pAce)) continue;

        BYTE aceType = ((ACE_HEADER*)pAce)->AceType;
        if (aceType != ACCESS_ALLOWED_ACE_TYPE
            && aceType != ACCESS_ALLOWED_OBJECT_ACE_TYPE) continue;

        // Parse mask and SID via raw offsets to handle variable OBJECT_ACE layout.
        // Layout: ACE_HEADER(4) | Mask(4) | [Flags(4) | [ObjGUID(16)] | [InhGUID(16)]] | SID
        ACCESS_MASK mask = *(ACCESS_MASK*)((BYTE*)pAce + 4);
        const GUID* objGuid = NULL;
        PSID sid;

        if (aceType == ACCESS_ALLOWED_ACE_TYPE) {
            sid = (PSID)((BYTE*)pAce + 8);
        } else {
            DWORD oflags = *(DWORD*)((BYTE*)pAce + 8);
            BYTE* p = (BYTE*)pAce + 12;
            if (oflags & ACE_OBJECT_TYPE_PRESENT)            { objGuid=(GUID*)p; p+=16; }
            if (oflags & ACE_INHERITED_OBJECT_TYPE_PRESENT)  { p+=16; }
            sid = (PSID)p;
        }

        if (!IsValidSid(sid)) continue;

        int isLow   = ae_is_low_priv(sid, domSid);
        int isAdmin = ae_is_admin(sid, domSid);

        // Check Enroll right for low-privilege principals
        if (isLow) {
            if (mask & GENERIC_ALL) {
                r.low_priv_enroll = 1;
                if (!r.enroll_who[0]) {
                    ae_sid_name(sid, r.enroll_who, sizeof(r.enroll_who));
                    rt_memcpy(r.enroll_right, "GenericAll", 11);
                }
            } else if (mask & ADS_RIGHT_DS_CONTROL_ACCESS) {
                if (!objGuid
                    || IsEqualGUID(objGuid, &s_guidEnroll)
                    || IsEqualGUID(objGuid, &s_guidAutoEnroll))
                {
                    r.low_priv_enroll = 1;
                    if (!r.enroll_who[0]) {
                        ae_sid_name(sid, r.enroll_who, sizeof(r.enroll_who));
                        rt_memcpy(r.enroll_right, "Enroll", 7);
                    }
                }
            }
        }

        // Check dangerous write rights for non-admins.
        // GENERIC_ALL/WRITE/WRITE_DAC/WRITE_OWNER are always dangerous.
        // WRITE_PROP and CREATE_CHILD are dangerous ONLY when objGuid==NULL
        // (no ObjectType GUID = applies to all properties/children).
        // A scoped OBJECT_ACE with WRITE_PROP + specific attribute GUID (e.g.
        // msPKI-*) is a normal Read/Enroll ACE on default templates — not ESC4.
        // NOTE: write_who/write_right are separate from enroll_who/enroll_right
        // so that a template with both Enroll and GenericWrite for the same
        // principal correctly shows the write right in ESC4 output.
        if (!isAdmin) {
            const char* wr = NULL;
            if      (mask & GENERIC_ALL)                               wr = "GenericAll";
            else if (mask & GENERIC_WRITE)                             wr = "GenericWrite";
            else if (mask & WRITE_DAC)                                 wr = "WriteDACL";
            else if (mask & WRITE_OWNER)                               wr = "WriteOwner";
            else if ((mask & ADS_RIGHT_DS_WRITE_PROP)   && !objGuid)  wr = "WriteProperty";
            else if ((mask & ADS_RIGHT_DS_CREATE_CHILD) && !objGuid)  wr = "CreateChild";

            if (wr) {
                r.non_admin_write = 1;
                if (!r.write_who[0]) {
                    ae_sid_name(sid, r.write_who, sizeof(r.write_who));
                    DWORD rl = (DWORD)rt_strlen(wr);
                    if (rl >= sizeof(r.write_right)) rl = sizeof(r.write_right) - 1;
                    rt_memcpy(r.write_right, wr, rl + 1);
                }
            }
        }
    }
    return r;
}

// ============================================================================
// Helper: read certificateTemplates from all pKIEnrollmentService objects.
// Builds a newline-delimited list "\nTmpl1\nTmpl2\n..." for whole-name lookup.
// ============================================================================

static void ae_get_published_templates(LDAP* ld, const wchar_t* confDn,
                                       char* out, int cap) {
    out[0] = '\n'; out[1] = 0;
    wchar_t dn[1024] = L"CN=Enrollment Services,CN=Public Key Services,CN=Services,";
    ae_wcat(dn, 1024, confDn);
    PWCHAR attrs[] = { (PWCHAR)L"certificateTemplates", NULL };
    LDAPMessage* res = NULL;
    if (ldap_search_sW(ld, dn, LDAP_SCOPE_ONELEVEL,
                       (PWCHAR)L"(objectClass=pKIEnrollmentService)",
                       attrs, 0, &res) != LDAP_SUCCESS || !res)
        return;
    for (LDAPMessage* e = ldap_first_entry(ld,res); e; e = ldap_next_entry(ld,e)) {
        PWCHAR* vals = ldap_get_valuesW(ld, e, (PWCHAR)L"certificateTemplates");
        if (!vals) continue;
        for (int i = 0; vals[i]; ++i) {
            char name[128] = {0};
            ae_wcs_to_u8(vals[i], name, sizeof(name));
            DWORD ol = (DWORD)rt_strlen(out);
            DWORD nl = (DWORD)rt_strlen(name);
            if (ol + nl + 2 < (DWORD)cap) {
                rt_memcpy(out+ol, name, nl);
                out[ol+nl] = '\n'; out[ol+nl+1] = 0;
            }
        }
        ldap_value_freeW(vals);
    }
    ldap_msgfree(res);
}

// ESC13 — OID-to-Group linkage tracking.
// Когда msDS-OIDToGroupLink установлен на msPKI-Enterprise-Oid объекте,
// сертификаты с этой application policy дают пользователю членство в группе.
typedef struct {
    char oid[128];     // msPKI-Cert-Template-OID
    char group[256];   // DN целевой группы (msDS-OIDToGroupLink)
} AeLinkedOid;

static AeLinkedOid s_linkedOids[64];
static int s_linkedOidCount = 0;

// ============================================================================
// Deferred output — накапливаем все находки, печатаем отсортированными по ESC.
// ============================================================================
#define AF_BUFSZ    1024
#define AF_MAXCNT   128

typedef struct { int esc; char text[AF_BUFSZ]; } AeFinding;
static AeFinding s_findings[AF_MAXCNT];
static int       s_findingCount = 0;
static int       s_curFinding   = -1;

static void af_begin(int esc) {
    if (s_findingCount >= AF_MAXCNT) return;
    s_curFinding = s_findingCount++;
    s_findings[s_curFinding].esc     = esc;
    s_findings[s_curFinding].text[0] = 0;
}
static void af_str(const char* s) {
    if (s_curFinding < 0) return;
    char* dst = s_findings[s_curFinding].text;
    DWORD used = (DWORD)rt_strlen(dst);
    DWORD sl   = (DWORD)rt_strlen(s);
    if (sl > AF_BUFSZ - used - 1) sl = AF_BUFSZ - used - 1;
    rt_memcpy(dst + used, s, sl);
    dst[used + sl] = 0;
}
static void af_print_all(void) {
    // Сортируем индексы по номеру ESC (insertion sort на массиве индексов)
    int idx[AF_MAXCNT];
    for (int i = 0; i < s_findingCount; ++i) idx[i] = i;
    for (int i = 1; i < s_findingCount; ++i) {
        int tmp = idx[i], j = i - 1;
        while (j >= 0 && s_findings[idx[j]].esc > s_findings[tmp].esc) {
            idx[j+1] = idx[j]; --j;
        }
        idx[j+1] = tmp;
    }
    for (int i = 0; i < s_findingCount; ++i) {
        ae_out(s_findings[idx[i]].text);
        ae_flush();
    }
    if (!s_findingCount) { ae_out("  (no vulnerabilities found)\n"); ae_flush(); }
}

static void ae_collect_linked_oids(LDAP* ld, const wchar_t* confDn) {
    s_linkedOidCount = 0;
    wchar_t dn[1024] = L"CN=OID,CN=Public Key Services,CN=Services,";
    ae_wcat(dn, 1024, confDn);
    PWCHAR attrs[] = {
        (PWCHAR)L"msPKI-Cert-Template-OID",
        (PWCHAR)L"msDS-OIDToGroupLink",
        NULL
    };
    LDAPMessage* res = NULL;
    if (ldap_search_sW(ld, dn, LDAP_SCOPE_ONELEVEL,
        (PWCHAR)L"(&(objectClass=msPKI-Enterprise-Oid)(msDS-OIDToGroupLink=*))",
        attrs, 0, &res) != LDAP_SUCCESS || !res) return;

    for (LDAPMessage* e = ldap_first_entry(ld, res);
         e && s_linkedOidCount < 64;
         e = ldap_next_entry(ld, e))
    {
        AeLinkedOid* lo = &s_linkedOids[s_linkedOidCount];
        ae_get_str(ld, e, L"msPKI-Cert-Template-OID", lo->oid,   sizeof(lo->oid));
        ae_get_str(ld, e, L"msDS-OIDToGroupLink",     lo->group, sizeof(lo->group));
        if (lo->oid[0] && lo->group[0]) s_linkedOidCount++;
    }
    ldap_msgfree(res);
}

// Returns index of matching linked OID in template's app-policy list, or -1.
static int ae_template_linked_oid(LDAP* ld, LDAPMessage* e) {
    if (s_linkedOidCount == 0) return -1;
    PWCHAR* vals = ldap_get_valuesW(ld, e,
        (PWCHAR)L"msPKI-Certificate-Application-Policy");
    if (!vals) return -1;
    int found = -1;
    for (int i = 0; vals[i] && found < 0; ++i) {
        char buf[128] = {0};
        ae_wcs_to_u8(vals[i], buf, sizeof(buf));
        DWORD bl = (DWORD)rt_strlen(buf);
        for (int j = 0; j < s_linkedOidCount; ++j) {
            DWORD ol = (DWORD)rt_strlen(s_linkedOids[j].oid);
            if (bl == ol && rt_memcmp(buf, s_linkedOids[j].oid, bl) == 0) {
                found = j;
                break;
            }
        }
    }
    ldap_value_freeW(vals);
    return found;
}

// Returns 1 if name appears as a complete entry in the newline-delimited list.
static int ae_name_in_list(const char* list, const char* name) {
    DWORD nl = (DWORD)rt_strlen(name);
    for (const char* p = list; *p; ++p) {
        if (*p != '\n') continue;
        const char* s = p + 1; DWORD i = 0;
        while (i < nl && s[i] && s[i] != '\n' && s[i] == name[i]) ++i;
        if (i == nl && (s[i] == '\n' || s[i] == 0)) return 1;
    }
    return 0;
}

// ============================================================================
// ESC1-4: Certificate Templates
// ============================================================================

static void ae_enum_templates(LDAP* ld, const wchar_t* confDn, PSID domSid,
                               const char* pubTemplates) {
    wchar_t dn[1024] = L"CN=Certificate Templates,CN=Public Key Services,CN=Services,";
    ae_wcat(dn, 1024, confDn);

    PWCHAR attrs[] = {
        (PWCHAR)L"name",
        (PWCHAR)L"displayName",
        (PWCHAR)L"msPKI-Certificate-Name-Flag",
        (PWCHAR)L"msPKI-Enrollment-Flag",
        (PWCHAR)L"msPKI-Template-Schema-Version",
        (PWCHAR)L"msPKI-Certificate-Application-Policy",
        (PWCHAR)L"pKIExtendedKeyUsage",
        (PWCHAR)L"nTSecurityDescriptor",
        NULL
    };

    LDAPMessage* res=NULL;
    ULONG lr = ldap_search_ext_sW(ld, dn, LDAP_SCOPE_ONELEVEL,
        (PWCHAR)L"(objectClass=pKICertificateTemplate)",
        attrs, 0, (PLDAPControlW*)s_sdCtrls, NULL, NULL, 0, &res);

    if (lr != LDAP_SUCCESS || !res) {
        char msg[128] = "[!] Template search failed, LDAP error ";
        DWORD ml = (DWORD)rt_strlen(msg);
        ml += ae_fmt_u32(msg+ml, lr);
        msg[ml++]='\n'; msg[ml]=0;
        ae_out(msg); ae_flush(); return;
    }

    int count=0;
    for (LDAPMessage* e=ldap_first_entry(ld,res); e; e=ldap_next_entry(ld,e)) {
        char name[256]={0};
        ae_get_str(ld, e, L"name", name, sizeof(name));
        if (!name[0]) continue;
        count++;

        DWORD nameFlag   = ae_get_u32(ld, e, L"msPKI-Certificate-Name-Flag");
        DWORD enrollFlag = ae_get_u32(ld, e, L"msPKI-Enrollment-Flag");
        DWORD schemaVer  = ae_get_u32(ld, e, L"msPKI-Template-Schema-Version");
        int   ekuCnt     = ae_eku_count(ld, e);
        int   hasCA      = ae_has_eku(ld, e, OID_CLIENT_AUTH);
        int   hasSC      = ae_has_eku(ld, e, OID_SMART_CARD);
        int   hasPK      = ae_has_eku(ld, e, OID_PKINIT);
        int   hasAny     = ae_has_eku(ld, e, OID_ANY_PURPOSE);
        int   hasCRA     = ae_has_eku(ld, e, OID_CERT_REQ_AGENT);

        struct berval** bv = ae_get_bin(ld, e, "nTSecurityDescriptor");
        AclResult acl; rt_memset(&acl, 0, sizeof(acl));
        if (bv && bv[0] && bv[0]->bv_len > 0)
            acl = ae_check_dacl((BYTE*)bv[0]->bv_val, (DWORD)bv[0]->bv_len, domSid);
        if (bv) ldap_value_free_len(bv);

        // Check if template is published to any CA (not published = CA will deny)
        int published = ae_name_in_list(pubTemplates, name);

        // ESC1: enrollee supplies SAN + auth EKU + low-priv can enroll
        if ((nameFlag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
            && (hasCA || hasSC || hasPK || ekuCnt == 0)
            && acl.low_priv_enroll)
        {
            af_begin(1);
            af_str("[ESC1] "); af_str(name); af_str(" (VULNERABLE)\n");
            af_str("       Flag:   CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (arbitrary SAN)\n");
            af_str("       EKU:    ");
            if (hasCA) af_str("Client Authentication ");
            if (hasSC) af_str("Smart Card Logon ");
            if (hasPK) af_str("PKINIT ");
            if (!ekuCnt) af_str("(none - sub-CA capable)");
            af_str("\n");
            af_str("       Enroll: "); af_str(acl.enroll_who);
            af_str(" ("); af_str(acl.enroll_right); af_str(")\n");
            if (!published)
                af_str("       *** NOT PUBLISHED to any CA — publish via certtmpl.msc ***\n");
        }

        // ESC2: Any Purpose or empty EKU + low-priv can enroll
        if ((hasAny || ekuCnt == 0) && acl.low_priv_enroll) {
            af_begin(2);
            af_str("[ESC2] "); af_str(name); af_str(" (VULNERABLE)\n");
            af_str("       EKU:    ");
            af_str(hasAny ? "Any Purpose (2.5.29.37.0)"
                          : "(no EKU - unrestricted usage)");
            af_str("\n");
            af_str("       Enroll: "); af_str(acl.enroll_who);
            af_str(" ("); af_str(acl.enroll_right); af_str(")\n");
            if (!published)
                af_str("       *** NOT PUBLISHED to any CA ***\n");
        }

        // ESC3: Certificate Request Agent EKU + low-priv can enroll
        if (hasCRA && acl.low_priv_enroll) {
            af_begin(3);
            af_str("[ESC3] "); af_str(name); af_str(" (VULNERABLE)\n");
            af_str("       EKU:    Certificate Request Agent (enrollment agent)\n");
            af_str("       Enroll: "); af_str(acl.enroll_who);
            af_str(" ("); af_str(acl.enroll_right); af_str(")\n");
            if (!published)
                af_str("       *** NOT PUBLISHED to any CA ***\n");
        }

        // ESC4: non-admin has write on template
        if (acl.non_admin_write) {
            af_begin(4);
            af_str("[ESC4] "); af_str(name); af_str(" (VULNERABLE)\n");
            af_str("       Write:  "); af_str(acl.write_who);
            af_str(" ("); af_str(acl.write_right); af_str(")\n");
            if (!published)
                af_str("       *** NOT PUBLISHED to any CA ***\n");
        }

        // ESC9: NO_SECURITY_EXTENSION — CA не вставит SID в сертификат, что
        // обходит StrongCertificateBindingEnforcement (KB5014754). Опасен в
        // комбинации с ENROLLEE_SUPPLIES_SUBJECT и auth-EKU + low-priv enroll.
        if ((enrollFlag & CT_FLAG_NO_SECURITY_EXTENSION)
            && (nameFlag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
            && (hasCA || hasSC || hasPK || ekuCnt == 0)
            && acl.low_priv_enroll)
        {
            af_begin(9);
            af_str("[ESC9] "); af_str(name); af_str(" (VULNERABLE)\n");
            af_str("       Flag:   CT_FLAG_NO_SECURITY_EXTENSION (no SID in cert)\n");
            af_str("       + ENROLLEE_SUPPLIES_SUBJECT — bypass strong binding (KB5014754)\n");
            af_str("       Enroll: "); af_str(acl.enroll_who);
            af_str(" ("); af_str(acl.enroll_right); af_str(")\n");
            if (!published)
                af_str("       *** NOT PUBLISHED to any CA ***\n");
        }

        // ESC13: template's application policy OID is linked to AD group via
        // msDS-OIDToGroupLink — enrolling gets group membership in the cert.
        int linkIdx = ae_template_linked_oid(ld, e);
        if (linkIdx >= 0 && acl.low_priv_enroll) {
            af_begin(13);
            af_str("[ESC13] "); af_str(name); af_str(" (VULNERABLE)\n");
            af_str("        OID:    "); af_str(s_linkedOids[linkIdx].oid); af_str("\n");
            af_str("        Group:  "); af_str(s_linkedOids[linkIdx].group); af_str("\n");
            af_str("        Enroll: "); af_str(acl.enroll_who);
            af_str(" ("); af_str(acl.enroll_right); af_str(")\n");
            if (!published)
                af_str("        *** NOT PUBLISHED to any CA ***\n");
        }

        // ESC15 (EKUwu): schema v1 шаблон с ENROLLEE_SUPPLIES_SUBJECT.
        // V1-шаблоны не валидируют application policies из CSR — клиент
        // может подсунуть произвольные EKU (Client Auth, Smart Card Logon)
        // даже если в самом шаблоне их нет.
        if (schemaVer == 1
            && (nameFlag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
            && acl.low_priv_enroll)
        {
            af_begin(15);
            af_str("[ESC15] "); af_str(name); af_str(" (VULNERABLE)\n");
            af_str("        Schema: V1 + ENROLLEE_SUPPLIES_SUBJECT (EKUwu / CVE-2024-49019)\n");
            af_str("        Client может выставить произвольные application policies в CSR\n");
            af_str("        Enroll: "); af_str(acl.enroll_who);
            af_str(" ("); af_str(acl.enroll_right); af_str(")\n");
            if (!published)
                af_str("        *** NOT PUBLISHED to any CA ***\n");
        }
    }

    if (!count) { ae_out("  (no certificate templates found)\n"); ae_flush(); }
    ldap_msgfree(res);
}

// ============================================================================
// ESC5: PKI container objects
// ============================================================================

static void ae_enum_pki_objects(LDAP* ld, const wchar_t* confDn, PSID domSid) {
    static const wchar_t* s_containers[] = {
        L"CN=Public Key Services,CN=Services,",
        L"CN=NTAuthCertificates,CN=Public Key Services,CN=Services,",
        L"CN=Certification Authorities,CN=Public Key Services,CN=Services,",
        L"CN=KRA,CN=Public Key Services,CN=Services,",
        L"CN=OID,CN=Public Key Services,CN=Services,",
        NULL
    };

    PWCHAR attrs[] = {(PWCHAR)L"distinguishedName",
                      (PWCHAR)L"nTSecurityDescriptor", NULL};

    for (int ci=0; s_containers[ci]; ++ci) {
        wchar_t dn[1024]={0};
        ae_wcat(dn, 1024, s_containers[ci]);
        ae_wcat(dn, 1024, confDn);

        LDAPMessage* res=NULL;
        if (ldap_search_ext_sW(ld, dn, LDAP_SCOPE_BASE,
                (PWCHAR)L"(objectClass=*)", attrs, 0,
                (PLDAPControlW*)s_sdCtrls, NULL, NULL, 0, &res) != LDAP_SUCCESS
            || !res) continue;

        LDAPMessage* e = ldap_first_entry(ld, res);
        if (e) {
            struct berval** bv = ae_get_bin(ld, e, "nTSecurityDescriptor");
            if (bv && bv[0] && bv[0]->bv_len > 0) {
                AclResult acl = ae_check_dacl(
                    (BYTE*)bv[0]->bv_val, (DWORD)bv[0]->bv_len, domSid);
                if (acl.non_admin_write) {
                    // Extract short name: "CN=NTAuthCertificates,..." -> "NTAuthCertificates"
                    char cname[128]={0};
                    const wchar_t* wc = s_containers[ci];
                    int pi=3, ci2=0; // skip "CN="
                    while (wc[pi] && wc[pi]!=L',' && ci2<126)
                        cname[ci2++]=(char)wc[pi++];
                    cname[ci2]=0;
                    af_begin(5);
                    af_str("[ESC5] "); af_str(cname); af_str(" (VULNERABLE)\n");
                    af_str("       Write: "); af_str(acl.write_who);
                    af_str(" ("); af_str(acl.write_right); af_str(")\n");
                }
            }
            if (bv) ldap_value_free_len(bv);
        }
        ldap_msgfree(res);
    }
}

// Returns 1 if "who" (e.g. "LAB\DC01$") is the machine account of the given
// FQDN host (e.g. "DC01.lab.local"). Used to suppress the false-positive ESC7
// hit that ADCS setup creates for the CA server's own computer account.
static int ae_is_host_machine_account(const char* who, const char* fqdn) {
    if (!who || !fqdn || !who[0] || !fqdn[0]) return 0;
    // Build "NETBIOS$" from FQDN
    char netbios[66]={0}; int ni=0;
    while (fqdn[ni] && fqdn[ni]!='.' && ni<63) { netbios[ni]=fqdn[ni]; ++ni; }
    netbios[ni]='$'; netbios[ni+1]=0;
    // Find account part (after '\')
    const char* acct = who;
    while (*acct && *acct!='\\') ++acct;
    if (*acct=='\\') ++acct;
    // Case-insensitive compare
    size_t nl = rt_strlen(netbios);
    if (rt_strlen(acct) != nl) return 0;
    for (size_t i=0; i<nl; ++i) {
        char a=netbios[i], b=acct[i];
        if (a>='A'&&a<='Z') a+=32;
        if (b>='A'&&b<='Z') b+=32;
        if (a!=b) return 0;
    }
    return 1;
}

// ============================================================================
// ESC6-7: Certificate Authorities
// caHostOut receives the first CA's dNSHostName for ESC8 probing.
// ============================================================================

static void ae_enum_cas(LDAP* ld, const wchar_t* confDn, PSID domSid,
                        char* caHostOut, int caHostCap) {
    wchar_t dn[1024] = L"CN=Enrollment Services,CN=Public Key Services,CN=Services,";
    ae_wcat(dn, 1024, confDn);

    PWCHAR attrs[] = {
        (PWCHAR)L"cn",
        (PWCHAR)L"dNSHostName",
        (PWCHAR)L"nTSecurityDescriptor",
        NULL
    };

    LDAPMessage* res=NULL;
    ULONG lr = ldap_search_ext_sW(ld, dn, LDAP_SCOPE_ONELEVEL,
        (PWCHAR)L"(objectClass=pKIEnrollmentService)",
        attrs, 0, (PLDAPControlW*)s_sdCtrls, NULL, NULL, 0, &res);

    if (lr != LDAP_SUCCESS || !res) {
        char msg[128] = "[!] CA search failed, LDAP error ";
        DWORD ml = (DWORD)rt_strlen(msg);
        ml += ae_fmt_u32(msg+ml, lr);
        msg[ml++]='\n'; msg[ml]=0;
        ae_out(msg); ae_flush(); return;
    }

    int count=0;
    for (LDAPMessage* e=ldap_first_entry(ld,res); e; e=ldap_next_entry(ld,e)) {
        char caName[256]={0}, caHost[256]={0};
        ae_get_str(ld, e, L"cn",          caName, sizeof(caName));
        ae_get_str(ld, e, L"dNSHostName", caHost, sizeof(caHost));
        if (!caName[0]) continue;
        count++;

        // Store CA hostname for ESC8
        if (caHost[0] && caHostOut && !caHostOut[0]) {
            int i=0;
            while (caHost[i] && i<caHostCap-1) { caHostOut[i]=caHost[i]; ++i; }
            caHostOut[i]=0;
        }

        // ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2
        // The flag lives in HKLM\...\CertSvc\Configuration\<CA>\EditFlags on the
        // CA server — NOT in the LDAP 'flags' attribute of pKIEnrollmentService.
        // Read it via remote registry (requires Remote Registry svc + read access).
        if (caHost[0]) {
            wchar_t caHostW[256]={0}; ae_u8_to_wcs(caHost, caHostW, 256);
            wchar_t caNameW[256]={0}; ae_u8_to_wcs(caName, caNameW, 256);
            wchar_t regPath[512] =
                L"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\";
            ae_wcat(regPath, 512, caNameW);
            HKEY hReg=NULL, hKey=NULL;
            if (RegConnectRegistryW(caHostW, HKEY_LOCAL_MACHINE, &hReg)
                    == ERROR_SUCCESS) {
                if (RegOpenKeyExW(hReg, regPath, 0, KEY_READ, &hKey)
                        == ERROR_SUCCESS) {
                    DWORD ef=0, sz=sizeof(ef);
                    if (RegQueryValueExW(hKey, L"EditFlags", NULL, NULL,
                                        (LPBYTE)&ef, &sz) == ERROR_SUCCESS
                        && (ef & EDITF_ATTRIBUTESUBJECTALTNAME2))
                    {
                        af_begin(6);
                        af_str("[ESC6] CA: "); af_str(caName); af_str(" (VULNERABLE)\n");
                        af_str("       EDITF_ATTRIBUTESUBJECTALTNAME2 is set\n");
                        af_str("       Any user can request a cert with arbitrary SAN\n");
                    }

                    // ESC11: IF_ENFORCEENCRYPTICERTREQUEST не выставлен → RPC
                    // enrollment без шифрования, можно перехватить/relay'ить.
                    DWORD iflags=0; sz=sizeof(iflags);
                    if (RegQueryValueExW(hKey, L"InterfaceFlags", NULL, NULL,
                                        (LPBYTE)&iflags, &sz) == ERROR_SUCCESS
                        && !(iflags & IF_ENFORCEENCRYPTICERTREQUEST))
                    {
                        af_begin(11);
                        af_str("[ESC11] CA: "); af_str(caName); af_str(" (VULNERABLE)\n");
                        af_str("        IF_ENFORCEENCRYPTICERTREQUEST not set\n");
                        af_str("        ICertPassage RPC accepts unencrypted requests — relay possible\n");
                    }

                    RegCloseKey(hKey);

                    // ESC16: DisableExtensionList лежит в подключе политики
                    // PolicyModules\CertificateAuthority_MicrosoftDefault.Policy
                    // (туда certutil -setreg policy\... пишет).
                    HKEY hPol = NULL;
                    wchar_t polPath[640];
                    {
                        // polPath = regPath + L"\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy"
                        DWORD i=0; while (regPath[i] && i<639) { polPath[i]=regPath[i]; i++; }
                        const wchar_t* tail = L"\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy";
                        DWORD j=0; while (tail[j] && i<639) { polPath[i++]=tail[j++]; }
                        polPath[i]=0;
                    }
                    if (RegOpenKeyExW(hReg, polPath, 0, KEY_READ, &hPol) == ERROR_SUCCESS) {
                        DWORD dlSize = 0;
                        if (RegQueryValueExW(hPol, L"DisableExtensionList",
                                            NULL, NULL, NULL, &dlSize) == ERROR_SUCCESS
                            && dlSize > 4)
                        {
                            WCHAR* dl = (WCHAR*)bmalloc(dlSize + 4);
                            if (dl) {
                                DWORD sz2 = dlSize;
                                if (RegQueryValueExW(hPol, L"DisableExtensionList",
                                    NULL, NULL, (LPBYTE)dl, &sz2) == ERROR_SUCCESS)
                                {
                                    DWORD wcCount = sz2 / sizeof(WCHAR);
                                    WCHAR* p = dl;
                                    int found = 0;
                                    while ((DWORD)(p - dl) < wcCount && *p && !found) {
                                        char buf[64]={0};
                                        ae_wcs_to_u8(p, buf, sizeof(buf));
                                        DWORD bl = (DWORD)rt_strlen(buf);
                                        DWORD ol = (DWORD)rt_strlen(OID_NTDS_OBJECTSID);
                                        if (bl == ol
                                            && rt_memcmp(buf, OID_NTDS_OBJECTSID, ol) == 0)
                                            found = 1;
                                        while ((DWORD)(p - dl) < wcCount && *p) ++p;
                                        ++p;
                                    }
                                    if (found) {
                                        af_begin(16);
                                        af_str("[ESC16] CA: "); af_str(caName); af_str(" (VULNERABLE)\n");
                                        af_str("        SID extension (1.3.6.1.4.1.311.25.2) globally disabled\n");
                                        af_str("        Все сертификаты выпускаются без SID — bypass strong binding\n");
                                    }
                                }
                                bfree(dl);
                            }
                        }
                        RegCloseKey(hPol);
                    }
                }
                RegCloseKey(hReg);
            }
        }

        // ESC7: non-admin write on CA LDAP object
        struct berval** bv = ae_get_bin(ld, e, "nTSecurityDescriptor");
        if (bv && bv[0] && bv[0]->bv_len > 0) {
            AclResult acl = ae_check_dacl(
                (BYTE*)bv[0]->bv_val, (DWORD)bv[0]->bv_len, domSid);
            if (acl.non_admin_write) {
                // Suppress false positive: computer accounts (name ends with '$')
                // on CA objects are expected — ADCS grants the CA server account
                // write on its own enrollment-service AD object during installation.
                DWORD wl = (DWORD)rt_strlen(acl.write_who);
                int isComputer = (wl > 0 && acl.write_who[wl - 1] == '$');
                if (!isComputer) {
                    af_begin(7);
                    af_str("[ESC7] CA: "); af_str(caName); af_str(" (VULNERABLE)\n");
                    af_str("       Write: "); af_str(acl.write_who);
                    af_str(" ("); af_str(acl.write_right); af_str(")\n");
                    af_str("       Note: internal CA rights (ManageCA/ManageCertificates)\n");
                    af_str("       require ICertAdmin; above shows the AD object ACL.\n");
                }
            }
        }
        if (bv) ldap_value_free_len(bv);
    }

    if (!count) { ae_out("  (no enrollment services found)\n"); ae_flush(); }
    ldap_msgfree(res);
}

// ============================================================================
// ESC10: Weak certificate mapping on Domain Controller.
// Checks DC's registry remotely:
//   1. StrongCertificateBindingEnforcement (Kdc) — 0/absent allows weak Kerberos PKINIT mapping
//   2. CertificateMappingMethods (Schannel)      — bits 0x4 (UPN) / 0x10 (S4U2Self) = weak
// ============================================================================

static void ae_check_esc10(const wchar_t* dcHostW, const char* dcHost8) {
    // Если DC = локальная машина, используем HKEY_LOCAL_MACHINE напрямую.
    // RegConnectRegistry к себе по FQDN иногда возвращает handle с урезанной
    // видимостью некоторых subkey-ов (виден CertSvc, но не Kdc/SCHANNEL).
    HKEY hReg = NULL;
    int isLocal = 0;
    {
        wchar_t localFQDN[256] = {0};
        DWORD fqdnSz = 256;
        if (GetComputerNameExW(ComputerNameDnsFullyQualified, localFQDN, &fqdnSz)) {
            // case-insensitive compare
            DWORD i = 0;
            int eq = 1;
            while (localFQDN[i] || dcHostW[i]) {
                wchar_t a = localFQDN[i], b = dcHostW[i];
                if (a >= L'A' && a <= L'Z') a += 32;
                if (b >= L'A' && b <= L'Z') b += 32;
                if (a != b) { eq = 0; break; }
                ++i;
            }
            isLocal = eq;
        }
    }
    if (isLocal) {
        hReg = HKEY_LOCAL_MACHINE;
    } else if (RegConnectRegistryW((LPWSTR)dcHostW, HKEY_LOCAL_MACHINE, &hReg)
            != ERROR_SUCCESS) {
        ae_out("  (ESC10 check skipped — RemoteRegistry unavailable on DC)\n");
        ae_flush();
        return;
    }

    // (1) KDC StrongCertificateBindingEnforcement
    HKEY hKdc = NULL;
    if (RegOpenKeyExW(hReg,
            L"SYSTEM\\CurrentControlSet\\Services\\Kdc",
            0, KEY_READ, &hKdc) == ERROR_SUCCESS)
    {
        DWORD strong = 0xFFFFFFFF; DWORD sz = sizeof(strong);
        LONG st = RegQueryValueExW(hKdc, L"StrongCertificateBindingEnforcement",
                                   NULL, NULL, (LPBYTE)&strong, &sz);
        if (st != ERROR_SUCCESS || strong == 0) {
            af_begin(10);
            af_str("[ESC10] DC: "); af_str(dcHost8); af_str(" (VULNERABLE)\n");
            af_str("        Kdc\\StrongCertificateBindingEnforcement = ");
            if (st != ERROR_SUCCESS) {
                af_str("(absent — defaults to disabled on legacy systems)\n");
            } else {
                char nb[12]; ae_fmt_u32(nb, strong); af_str(nb); af_str("\n");
            }
            af_str("        KDC accepts weak (UPN-based) certificate-to-user mapping\n");
        }
        RegCloseKey(hKdc);
    }

    // (2) Schannel CertificateMappingMethods
    HKEY hSch = NULL;
    if (RegOpenKeyExW(hReg,
            L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL",
            0, KEY_READ, &hSch) == ERROR_SUCCESS)
    {
        DWORD methods = 0; DWORD sz = sizeof(methods);
        if (RegQueryValueExW(hSch, L"CertificateMappingMethods",
                NULL, NULL, (LPBYTE)&methods, &sz) == ERROR_SUCCESS
            && (methods & CMM_WEAK_MASK))
        {
            af_begin(10);
            af_str("[ESC10] DC: "); af_str(dcHost8); af_str(" (VULNERABLE)\n");
            af_str("        Schannel\\CertificateMappingMethods = 0x");
            // hex output
            char hb[12]; DWORD hi=0; DWORD m = methods;
            if (!m) hb[hi++]='0';
            else {
                char tt[12]; DWORD tn=0;
                while (m) { tt[tn++]="0123456789ABCDEF"[m & 0xF]; m >>= 4; }
                while (tn) hb[hi++]=tt[--tn];
            }
            hb[hi]=0; af_str(hb); af_str("\n");
            if (methods & CMM_UPN)
                af_str("        Bit 0x04 set — UPN mapping enabled (weak)\n");
            if (methods & CMM_S4U2SELF)
                af_str("        Bit 0x10 set — S4U2Self mapping enabled (weak)\n");
        }
        RegCloseKey(hSch);
    }

    if (!isLocal) RegCloseKey(hReg);
}

// ============================================================================
// ESC8: Web Enrollment HTTP probe
// ============================================================================

static void ae_probe_esc8(const char* caHost8) {
    if (!caHost8 || !caHost8[0]) return;

    wchar_t caHostW[256]={0};
    ae_u8_to_wcs(caHost8, caHostW, 256);

    HINTERNET hSess = WinHttpOpen(
        L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSess) return;

    // Probe both HTTP (80) and HTTPS (443)
    static const struct { int port; int https; } s_probes[] = {{80,0},{443,1}};
    for (int pi=0; pi<2; ++pi) {
        DWORD redir = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        HINTERNET hConn = WinHttpConnect(
            hSess, caHostW, (INTERNET_PORT)s_probes[pi].port, 0);
        if (!hConn) continue;

        DWORD flags = s_probes[pi].https ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", L"/certsrv/", NULL,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
        if (!hReq) { WinHttpCloseHandle(hConn); continue; }

        if (s_probes[pi].https) {
            DWORD sslOpts = SECURITY_FLAG_IGNORE_UNKNOWN_CA
                          | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                          | SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
            WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS,
                             &sslOpts, sizeof(sslOpts));
        }
        WinHttpSetOption(hReq, WINHTTP_OPTION_REDIRECT_POLICY,
                         &redir, sizeof(redir));

        if (WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                               NULL, 0, 0, 0)
            && WinHttpReceiveResponse(hReq, NULL))
        {
            DWORD status=0; DWORD sz=sizeof(status);
            WinHttpQueryHeaders(hReq,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                NULL, &status, &sz, NULL);

            if (status == 200 || status == 401 || status == 403) {
                af_begin(8);
                af_str("[ESC8] Web Enrollment: ");
                af_str(s_probes[pi].https ? "https://" : "http://");
                af_str(caHost8); af_str("/certsrv/ -- HTTP ");
                char ss[8]; ae_fmt_u32(ss, status); af_str(ss);
                if      (status == 401) af_str(" (NTLM relay possible!) (VULNERABLE)");
                else if (status == 200) af_str(" (VULNERABLE)");
                else if (status == 403) af_str(" (SSL required — relay via HTTP blocked)");
                af_str("\n");
            }
        }
        WinHttpCloseHandle(hReq);
        WinHttpCloseHandle(hConn);
    }
    WinHttpCloseHandle(hSess);
}

// ============================================================================
// Entry point
// ============================================================================

void cmd_adcs_enum(const BeaconTask* t) {
    char domain8[256]={0};
    kv_get_str(t->pay, t->pay_len, "domain", domain8, sizeof(domain8));

    wchar_t wDomain[256]={0};
    if (!domain8[0]) {
        if (!GetEnvironmentVariableW(L"USERDNSDOMAIN", wDomain, 256) || !wDomain[0]) {
            ae_out("[!] Domain not set and USERDNSDOMAIN is empty\n"); return;
        }
        ae_wcs_to_u8(wDomain, domain8, sizeof(domain8));
    } else {
        ae_u8_to_wcs(domain8, wDomain, 256);
    }

    PDOMAIN_CONTROLLER_INFOW dcInfo=NULL;
    DWORD dcErr = DsGetDcNameW(NULL, wDomain, NULL, NULL,
        DS_DIRECTORY_SERVICE_REQUIRED | DS_RETURN_DNS_NAME, &dcInfo);
    if (dcErr || !dcInfo) {
        char msg[64] = "[!] DsGetDcName failed: ";
        DWORD ml = (DWORD)rt_strlen(msg);
        ml += ae_fmt_u32(msg+ml, dcErr ? dcErr : GetLastError());
        msg[ml++]='\n'; msg[ml]=0;
        ae_out(msg); return;
    }
    const wchar_t* dcHost = dcInfo->DomainControllerName;
    while (*dcHost==L'\\') ++dcHost;

    char dcHost8[256]={0}; ae_wcs_to_u8(dcHost, dcHost8, sizeof(dcHost8));

    ae_out("=== ADCS Enumeration ===\n");
    ae_out("Domain: "); ae_out(domain8);  ae_out("\n");
    ae_out("DC:     "); ae_out(dcHost8); ae_out("\n\n");
    ae_flush();

    LDAP* ld = ldap_initW((PWCHAR)dcHost, LDAP_PORT);
    if (!ld) {
        ae_out("[!] ldap_init failed\n"); NetApiBufferFree(dcInfo); return;
    }
    ULONG ver=LDAP_VERSION3;
    ldap_set_optionW(ld, LDAP_OPT_PROTOCOL_VERSION, &ver);
    if (ldap_bind_sW(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE) != LDAP_SUCCESS) {
        ae_out("[!] ldap_bind failed\n");
        ldap_unbind(ld); NetApiBufferFree(dcInfo); return;
    }

    wchar_t baseDn[512]={0};
    ae_build_base_dn(wDomain, baseDn, 512);
    wchar_t confDn[512] = L"CN=Configuration,";
    ae_wcat(confDn, 512, baseDn);

    PSID domSid = ae_get_domain_sid(domain8);

    // Собираем все находки (вывода нет)
    char pubTemplates[4096] = {0};
    ae_get_published_templates(ld, confDn, pubTemplates, sizeof(pubTemplates));
    ae_collect_linked_oids(ld, confDn);
    ae_enum_templates(ld, confDn, domSid, pubTemplates);
    ae_enum_pki_objects(ld, confDn, domSid);
    char caHost[256]={0};
    ae_enum_cas(ld, confDn, domSid, caHost, sizeof(caHost));
    ae_check_esc10(dcHost, dcHost8);
    if (caHost[0]) ae_probe_esc8(caHost);

    // Выводим все находки в порядке ESC1 -> ESC16
    ae_out("\n--- Findings ---\n"); ae_flush();
    af_print_all();

    ae_out("\n=== Done ===\n"); ae_flush();

    if (domSid) bfree(domSid);
    ldap_unbind(ld);
    NetApiBufferFree(dcInfo);
}
