// AES-256-GCM via BCryptXxx — single shared algorithm handle.
// Frame layout consumed/produced here matches server BeaconCrypto:
//   [1 byte ver=0x01][12 nonce][ciphertext+tag(16)].

#include "beacon.h"
#include <bcrypt.h>

#define STATUS_SUCCESS ((NTSTATUS)0)
#define BEACON_FRAME_VER 0x01
#define GCM_NONCE_LEN 12
#define GCM_TAG_LEN   16

static BCRYPT_ALG_HANDLE g_aes_alg = NULL;
static BCRYPT_ALG_HANDLE g_rng_alg = NULL;

static NTSTATUS ensure_aes_alg(void) {
    if (g_aes_alg) return STATUS_SUCCESS;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&g_aes_alg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (st != STATUS_SUCCESS) return st;
    return BCryptSetProperty(g_aes_alg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
}

static NTSTATUS ensure_rng(void) {
    if (g_rng_alg) return STATUS_SUCCESS;
    return BCryptOpenAlgorithmProvider(&g_rng_alg, BCRYPT_RNG_ALGORITHM, NULL, 0);
}

void bc_random(uint8_t* out, size_t n) {
    if (ensure_rng() != STATUS_SUCCESS) return;
    BCryptGenRandom(g_rng_alg, out, (ULONG)n, 0);
}

size_t aes_gcm_seal(const uint8_t* key32, const uint8_t* nonce12,
                    const uint8_t* pt, size_t pt_len, uint8_t* out) {
    if (ensure_aes_alg() != STATUS_SUCCESS) return 0;

    BCRYPT_KEY_HANDLE h = NULL;
    if (BCryptGenerateSymmetricKey(g_aes_alg, &h, NULL, 0,
            (PUCHAR)key32, 32, 0) != STATUS_SUCCESS) return 0;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce    = (PUCHAR)nonce12;
    info.cbNonce    = GCM_NONCE_LEN;
    info.pbTag      = out + pt_len;
    info.cbTag      = GCM_TAG_LEN;

    ULONG written = 0;
    NTSTATUS st = BCryptEncrypt(h,
        (PUCHAR)pt, (ULONG)pt_len,
        &info, NULL, 0,
        out, (ULONG)pt_len, &written, 0);
    BCryptDestroyKey(h);
    if (st != STATUS_SUCCESS) return 0;
    return (size_t)written + GCM_TAG_LEN;
}

size_t aes_gcm_open(const uint8_t* key32, const uint8_t* nonce12,
                    const uint8_t* ct_tag, size_t ct_tag_len, uint8_t* out_pt) {
    if (ct_tag_len < GCM_TAG_LEN) return 0;
    if (ensure_aes_alg() != STATUS_SUCCESS) return 0;

    BCRYPT_KEY_HANDLE h = NULL;
    if (BCryptGenerateSymmetricKey(g_aes_alg, &h, NULL, 0,
            (PUCHAR)key32, 32, 0) != STATUS_SUCCESS) return 0;

    ULONG ct_len = (ULONG)(ct_tag_len - GCM_TAG_LEN);
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)nonce12;
    info.cbNonce = GCM_NONCE_LEN;
    info.pbTag   = (PUCHAR)(ct_tag + ct_len);
    info.cbTag   = GCM_TAG_LEN;

    ULONG written = 0;
    NTSTATUS st = BCryptDecrypt(h,
        (PUCHAR)ct_tag, ct_len,
        &info, NULL, 0,
        out_pt, ct_len, &written, 0);
    BCryptDestroyKey(h);
    if (st != STATUS_SUCCESS) return 0;
    return (size_t)written;
}

size_t seal_frame(const uint8_t* key32, const uint8_t* pt, size_t pt_len,
                  uint8_t* out) {
    out[0] = BEACON_FRAME_VER;
    bc_random(out + 1, GCM_NONCE_LEN);
    size_t ct = aes_gcm_seal(key32, out + 1, pt, pt_len, out + 1 + GCM_NONCE_LEN);
    if (!ct) return 0;
    return 1 + GCM_NONCE_LEN + ct;
}

size_t open_frame(const uint8_t* key32, const uint8_t* blob, size_t blob_len,
                  uint8_t* out) {
    if (blob_len < 1 + GCM_NONCE_LEN + GCM_TAG_LEN) return 0;
    if (blob[0] != BEACON_FRAME_VER) return 0;
    return aes_gcm_open(key32, blob + 1,
                        blob + 1 + GCM_NONCE_LEN,
                        blob_len - 1 - GCM_NONCE_LEN, out);
}

// ---- RSA-OAEP-SHA256 encrypt (server-pubkey wrap of session key) -------
// Imports BCRYPT_RSAPUBLIC_BLOB from rsa_pub_blob and encrypts pt with
// OAEP-SHA256 padding (no label). Returns ciphertext length on success
// (256 bytes for RSA-2048), or 0 on failure.
size_t rsa_oaep_encrypt(const uint8_t* pub_blob, uint32_t pub_blob_len,
                        const uint8_t* pt, uint32_t pt_len,
                        uint8_t* out, uint32_t out_cap) {
    if (!pub_blob || pub_blob_len == 0) return 0;

    BCRYPT_ALG_HANDLE alg = NULL;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM, NULL, 0)
            != STATUS_SUCCESS)
        return 0;

    BCRYPT_KEY_HANDLE key = NULL;
    NTSTATUS st = BCryptImportKeyPair(alg, NULL, BCRYPT_RSAPUBLIC_BLOB,
                                      &key,
                                      (PUCHAR)pub_blob, pub_blob_len, 0);
    if (st != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return 0;
    }

    BCRYPT_OAEP_PADDING_INFO oaep;
    rt_memset(&oaep, 0, sizeof(oaep));
    oaep.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    oaep.pbLabel  = NULL;
    oaep.cbLabel  = 0;

    ULONG written = 0;
    st = BCryptEncrypt(key,
                       (PUCHAR)pt, pt_len,
                       &oaep, NULL, 0,
                       out, out_cap, &written,
                       BCRYPT_PAD_OAEP);
    BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (st != STATUS_SUCCESS) return 0;
    return (size_t)written;
}
