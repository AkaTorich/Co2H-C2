// AES-256-GCM + RSA-OAEP-SHA256 crypto for the Linux beacon via OpenSSL EVP API.
// Parses Windows BCRYPT_RSAPUBLIC_BLOB format for RSA key import.

#include "beacon.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>

// ---- Random ----------------------------------------------------------------

void bc_random(uint8_t* out, size_t n) {
    RAND_bytes(out, (int)n);
}

// ---- AES-256-GCM -----------------------------------------------------------

size_t aes_gcm_seal(const uint8_t* key32, const uint8_t* nonce12,
                    const uint8_t* pt, size_t pt_len,
                    uint8_t* out) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    int ok = 1;
    int outl = 0;
    size_t total = 0;

    ok = ok && EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_LEN, NULL);
    ok = ok && EVP_EncryptInit_ex(ctx, NULL, NULL, key32, nonce12);
    ok = ok && EVP_EncryptUpdate(ctx, out, &outl, pt, (int)pt_len);
    total += (size_t)outl;
    ok = ok && EVP_EncryptFinal_ex(ctx, out + total, &outl);
    total += (size_t)outl;
    // Append GCM tag
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, out + total);
    if (ok) total += GCM_TAG_LEN;

    EVP_CIPHER_CTX_free(ctx);
    return ok ? total : 0;
}

size_t aes_gcm_open(const uint8_t* key32, const uint8_t* nonce12,
                    const uint8_t* ct_tag, size_t ct_tag_len,
                    uint8_t* out_pt) {
    if (ct_tag_len < GCM_TAG_LEN) return 0;
    size_t ct_len = ct_tag_len - GCM_TAG_LEN;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    int ok = 1;
    int outl = 0;
    size_t total = 0;

    ok = ok && EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_LEN, NULL);
    ok = ok && EVP_DecryptInit_ex(ctx, NULL, NULL, key32, nonce12);
    ok = ok && EVP_DecryptUpdate(ctx, out_pt, &outl, ct_tag, (int)ct_len);
    total += (size_t)outl;
    // Set expected tag
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN,
                                    (void*)(ct_tag + ct_len));
    ok = ok && EVP_DecryptFinal_ex(ctx, out_pt + total, &outl);
    total += (size_t)outl;

    EVP_CIPHER_CTX_free(ctx);
    return ok ? total : 0;
}

// ---- Frame sealing ---------------------------------------------------------
// Format: [1 ver][12 nonce][ciphertext + 16 tag]

size_t seal_frame(const uint8_t* key32, const uint8_t* pt, size_t pt_len,
                  uint8_t* out) {
    out[0] = BEACON_FRAME_VER;
    bc_random(out + 1, GCM_NONCE_LEN);
    size_t sealed = aes_gcm_seal(key32, out + 1, pt, pt_len,
                                 out + 1 + GCM_NONCE_LEN);
    if (!sealed) return 0;
    return 1 + GCM_NONCE_LEN + sealed;
}

size_t open_frame(const uint8_t* key32, const uint8_t* blob, size_t blob_len,
                  uint8_t* out) {
    if (blob_len < 1 + GCM_NONCE_LEN + GCM_TAG_LEN) return 0;
    if (blob[0] != BEACON_FRAME_VER) return 0;
    const uint8_t* nonce = blob + 1;
    const uint8_t* ct_tag = blob + 1 + GCM_NONCE_LEN;
    size_t ct_tag_len = blob_len - 1 - GCM_NONCE_LEN;
    return aes_gcm_open(key32, nonce, ct_tag, ct_tag_len, out);
}

// ---- RSA-OAEP-SHA256 -------------------------------------------------------
// Parse Windows BCRYPT_RSAPUBLIC_BLOB:
//   struct BCRYPT_RSAKEY_BLOB {
//     uint32_t Magic;        // 0x31415352 = "RSA1" for public
//     uint32_t BitLength;
//     uint32_t cbPublicExp;
//     uint32_t cbModulus;
//     uint32_t cbPrime1;     // 0 for public
//     uint32_t cbPrime2;     // 0 for public
//   };
//   followed by: PublicExponent[cbPublicExp] || Modulus[cbModulus]

size_t rsa_oaep_encrypt(const uint8_t* pub_blob, uint32_t pub_blob_len,
                        const uint8_t* pt, uint32_t pt_len,
                        uint8_t* out, uint32_t out_cap) {
    if (pub_blob_len < 24) return 0;

    // Parse BCRYPT_RSAKEY_BLOB header
    uint32_t magic = pub_blob[0] | ((uint32_t)pub_blob[1] << 8)
                   | ((uint32_t)pub_blob[2] << 16) | ((uint32_t)pub_blob[3] << 24);
    if (magic != 0x31415352) {  // "RSA1"
        bdbg("[beacon] rsa: invalid blob magic\n");
        return 0;
    }

    uint32_t cb_exp = pub_blob[8] | ((uint32_t)pub_blob[9] << 8)
                    | ((uint32_t)pub_blob[10] << 16) | ((uint32_t)pub_blob[11] << 24);
    uint32_t cb_mod = pub_blob[12] | ((uint32_t)pub_blob[13] << 8)
                    | ((uint32_t)pub_blob[14] << 16) | ((uint32_t)pub_blob[15] << 24);

    if (24 + cb_exp + cb_mod > pub_blob_len) {
        bdbg("[beacon] rsa: blob too short for exp+mod\n");
        return 0;
    }

    const uint8_t* exp_bytes = pub_blob + 24;
    const uint8_t* mod_bytes = pub_blob + 24 + cb_exp;

    // Build OpenSSL RSA key from raw exponent + modulus
    BIGNUM* e = BN_bin2bn(exp_bytes, (int)cb_exp, NULL);
    BIGNUM* n = BN_bin2bn(mod_bytes, (int)cb_mod, NULL);
    if (!e || !n) {
        BN_free(e); BN_free(n);
        return 0;
    }

    EVP_PKEY* pkey = EVP_PKEY_new();
    RSA* rsa = RSA_new();
    if (!pkey || !rsa) {
        RSA_free(rsa); EVP_PKEY_free(pkey);
        BN_free(e); BN_free(n);
        return 0;
    }
    RSA_set0_key(rsa, n, e, NULL);  // n, e ownership transferred to rsa
    EVP_PKEY_assign_RSA(pkey, rsa); // rsa ownership transferred to pkey

    // Encrypt with RSA-OAEP-SHA256
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pctx) { EVP_PKEY_free(pkey); return 0; }

    size_t enc_len = 0;
    int ok = 1;
    ok = ok && (EVP_PKEY_encrypt_init(pctx) > 0);
    ok = ok && (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING) > 0);
    ok = ok && (EVP_PKEY_CTX_set_rsa_oaep_md(pctx, EVP_sha256()) > 0);
    ok = ok && (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) > 0);

    if (ok) {
        // Query output length first
        ok = (EVP_PKEY_encrypt(pctx, NULL, &enc_len, pt, pt_len) > 0);
        if (ok && enc_len <= out_cap) {
            ok = (EVP_PKEY_encrypt(pctx, out, &enc_len, pt, pt_len) > 0);
        } else {
            ok = 0;
        }
    }

    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    return ok ? enc_len : 0;
}
