#include "RsaOaep.hpp"

#ifdef _WIN32
// ---- Windows: BCrypt (CNG) ------------------------------------------------

#include <windows.h>
#include <bcrypt.h>
#include <ntstatus.h>

#pragma comment(lib, "bcrypt.lib")

namespace co2h::server::https {

namespace {

class AlgHandle {
public:
    AlgHandle() {
        BCryptOpenAlgorithmProvider(&h_, BCRYPT_RSA_ALGORITHM, nullptr, 0);
    }
    ~AlgHandle() { if (h_) BCryptCloseAlgorithmProvider(h_, 0); }
    BCRYPT_ALG_HANDLE get() const { return h_; }
private:
    BCRYPT_ALG_HANDLE h_ = nullptr;
};

class KeyHandle {
public:
    ~KeyHandle() { if (h_) BCryptDestroyKey(h_); }
    BCRYPT_KEY_HANDLE* slot()       { return &h_; }
    BCRYPT_KEY_HANDLE  get()  const { return h_; }
private:
    BCRYPT_KEY_HANDLE h_ = nullptr;
};

}

bool rsa_generate_2048(Bytes& pub_blob, Bytes& priv_blob) {
    AlgHandle alg;
    if (!alg.get()) return false;

    KeyHandle key;
    if (BCryptGenerateKeyPair(alg.get(), key.slot(), 2048, 0) != STATUS_SUCCESS)
        return false;
    if (BCryptFinalizeKeyPair(key.get(), 0) != STATUS_SUCCESS)
        return false;

    ULONG need = 0;
    if (BCryptExportKey(key.get(), nullptr, BCRYPT_RSAPUBLIC_BLOB,
                        nullptr, 0, &need, 0) != STATUS_SUCCESS) return false;
    pub_blob.resize(need);
    ULONG got = 0;
    if (BCryptExportKey(key.get(), nullptr, BCRYPT_RSAPUBLIC_BLOB,
                        pub_blob.data(), need, &got, 0) != STATUS_SUCCESS)
        return false;
    pub_blob.resize(got);

    if (BCryptExportKey(key.get(), nullptr, BCRYPT_RSAFULLPRIVATE_BLOB,
                        nullptr, 0, &need, 0) != STATUS_SUCCESS) return false;
    priv_blob.resize(need);
    if (BCryptExportKey(key.get(), nullptr, BCRYPT_RSAFULLPRIVATE_BLOB,
                        priv_blob.data(), need, &got, 0) != STATUS_SUCCESS)
        return false;
    priv_blob.resize(got);
    return true;
}

std::optional<Bytes> rsa_oaep_decrypt(BytesView priv_blob, BytesView ct) {
    AlgHandle alg;
    if (!alg.get()) return std::nullopt;

    KeyHandle key;
    if (BCryptImportKeyPair(alg.get(), nullptr,
                            BCRYPT_RSAFULLPRIVATE_BLOB,
                            key.slot(),
                            const_cast<PUCHAR>(priv_blob.data()),
                            static_cast<ULONG>(priv_blob.size()),
                            0) != STATUS_SUCCESS)
        return std::nullopt;

    BCRYPT_OAEP_PADDING_INFO oaep{};
    oaep.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    oaep.pbLabel  = nullptr;
    oaep.cbLabel  = 0;

    ULONG need = 0;
    if (BCryptDecrypt(key.get(),
                      const_cast<PUCHAR>(ct.data()),
                      static_cast<ULONG>(ct.size()),
                      &oaep, nullptr, 0,
                      nullptr, 0, &need,
                      BCRYPT_PAD_OAEP) != STATUS_SUCCESS)
        return std::nullopt;
    Bytes out(need);
    ULONG got = 0;
    if (BCryptDecrypt(key.get(),
                      const_cast<PUCHAR>(ct.data()),
                      static_cast<ULONG>(ct.size()),
                      &oaep, nullptr, 0,
                      out.data(), need, &got,
                      BCRYPT_PAD_OAEP) != STATUS_SUCCESS)
        return std::nullopt;
    out.resize(got);
    return out;
}

}

#else
// ---- Linux/macOS: OpenSSL EVP ---------------------------------------------

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/param_build.h>

#include <cstring>

namespace co2h::server::https {

// ---------------------------------------------------------------------------
// Внутренний формат blob'ов: BCrypt RSAPUBLIC_BLOB / RSAFULLPRIVATE_BLOB.
// Бикон (Windows) генерирует и разбирает именно этот формат, поэтому
// серверу на Linux нужно уметь читать и записывать его.
//
// BCRYPT_RSAKEY_BLOB layout:
//   ULONG Magic, ULONG BitLength, ULONG cbPublicExp, ULONG cbModulus,
//   ULONG cbPrime1, ULONG cbPrime2
//   [publicExponent][Modulus]                         — RSAPUBLIC_BLOB
//   + [Prime1][Prime2][Exp1][Exp2][Coeff][PrivateExp] — RSAFULLPRIVATE_BLOB
//
// Magics: RSAPUBLIC  = 0x31415352 ("RSA1")
//         RSAFULLPRIV= 0x33415352 ("RSA3")
// ---------------------------------------------------------------------------

static constexpr uint32_t BCRYPT_RSAPUBLIC_MAGIC      = 0x31415352;
static constexpr uint32_t BCRYPT_RSAFULLPRIVATE_MAGIC  = 0x33415352;

#pragma pack(push, 1)
struct BcryptRsaKeyBlob {
    uint32_t Magic;
    uint32_t BitLength;
    uint32_t cbPublicExp;
    uint32_t cbModulus;
    uint32_t cbPrime1;
    uint32_t cbPrime2;
};
#pragma pack(pop)

// Утилита: записать BIGNUM в буфер с дополнением нулями слева до нужного размера.
static void bn_to_fixed(const BIGNUM* bn, uint8_t* out, size_t len) {
    std::memset(out, 0, len);
    int bnlen = BN_num_bytes(bn);
    if (bnlen > 0 && static_cast<size_t>(bnlen) <= len)
        BN_bn2bin(bn, out + (len - static_cast<size_t>(bnlen)));
}

// Утилита: создать BIGNUM из буфера фиксированной длины.
static BIGNUM* bn_from_fixed(const uint8_t* data, size_t len) {
    return BN_bin2bn(data, static_cast<int>(len), nullptr);
}

bool rsa_generate_2048(Bytes& pub_blob, Bytes& priv_blob) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) return false;
    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    EVP_PKEY_CTX_free(ctx);

    // Извлекаем компоненты RSA-ключа.
    BIGNUM *n = nullptr, *e = nullptr, *d = nullptr;
    BIGNUM *p = nullptr, *q = nullptr;
    BIGNUM *dp = nullptr, *dq = nullptr, *qinv = nullptr;
    EVP_PKEY_get_bn_param(pkey, "n",     &n);
    EVP_PKEY_get_bn_param(pkey, "e",     &e);
    EVP_PKEY_get_bn_param(pkey, "d",     &d);
    EVP_PKEY_get_bn_param(pkey, "rsa-factor1", &p);
    EVP_PKEY_get_bn_param(pkey, "rsa-factor2", &q);
    EVP_PKEY_get_bn_param(pkey, "rsa-exponent1", &dp);
    EVP_PKEY_get_bn_param(pkey, "rsa-exponent2", &dq);
    EVP_PKEY_get_bn_param(pkey, "rsa-coefficient1", &qinv);
    EVP_PKEY_free(pkey);

    if (!n || !e || !d || !p || !q || !dp || !dq || !qinv) {
        BN_free(n); BN_free(e); BN_free(d);
        BN_free(p); BN_free(q); BN_free(dp); BN_free(dq); BN_free(qinv);
        return false;
    }

    uint32_t cbExp    = static_cast<uint32_t>(BN_num_bytes(e));
    uint32_t cbMod    = static_cast<uint32_t>(BN_num_bytes(n));
    uint32_t cbPrime1 = static_cast<uint32_t>(BN_num_bytes(p));
    uint32_t cbPrime2 = static_cast<uint32_t>(BN_num_bytes(q));

    // --- Public blob ---
    {
        size_t total = sizeof(BcryptRsaKeyBlob) + cbExp + cbMod;
        pub_blob.resize(total);
        auto* hdr = reinterpret_cast<BcryptRsaKeyBlob*>(pub_blob.data());
        hdr->Magic      = BCRYPT_RSAPUBLIC_MAGIC;
        hdr->BitLength   = 2048;
        hdr->cbPublicExp = cbExp;
        hdr->cbModulus   = cbMod;
        hdr->cbPrime1    = 0;
        hdr->cbPrime2    = 0;
        uint8_t* ptr = pub_blob.data() + sizeof(BcryptRsaKeyBlob);
        bn_to_fixed(e, ptr, cbExp); ptr += cbExp;
        bn_to_fixed(n, ptr, cbMod);
    }

    // --- Full private blob ---
    {
        uint32_t cbDp   = cbPrime1;
        uint32_t cbDq   = cbPrime2;
        uint32_t cbCoef = cbPrime1;
        uint32_t cbPriv = cbMod;
        size_t total = sizeof(BcryptRsaKeyBlob) + cbExp + cbMod
                     + cbPrime1 + cbPrime2 + cbDp + cbDq + cbCoef + cbPriv;
        priv_blob.resize(total);
        auto* hdr = reinterpret_cast<BcryptRsaKeyBlob*>(priv_blob.data());
        hdr->Magic      = BCRYPT_RSAFULLPRIVATE_MAGIC;
        hdr->BitLength   = 2048;
        hdr->cbPublicExp = cbExp;
        hdr->cbModulus   = cbMod;
        hdr->cbPrime1    = cbPrime1;
        hdr->cbPrime2    = cbPrime2;
        uint8_t* ptr = priv_blob.data() + sizeof(BcryptRsaKeyBlob);
        bn_to_fixed(e,    ptr, cbExp);    ptr += cbExp;
        bn_to_fixed(n,    ptr, cbMod);    ptr += cbMod;
        bn_to_fixed(p,    ptr, cbPrime1); ptr += cbPrime1;
        bn_to_fixed(q,    ptr, cbPrime2); ptr += cbPrime2;
        bn_to_fixed(dp,   ptr, cbDp);     ptr += cbDp;
        bn_to_fixed(dq,   ptr, cbDq);     ptr += cbDq;
        bn_to_fixed(qinv, ptr, cbCoef);   ptr += cbCoef;
        bn_to_fixed(d,    ptr, cbPriv);
    }

    BN_free(n); BN_free(e); BN_free(d);
    BN_free(p); BN_free(q); BN_free(dp); BN_free(dq); BN_free(qinv);
    return true;
}

std::optional<Bytes> rsa_oaep_decrypt(BytesView priv_blob, BytesView ct) {
    // Разбираем BCrypt full-private blob.
    if (priv_blob.size() < sizeof(BcryptRsaKeyBlob))
        return std::nullopt;
    auto* hdr = reinterpret_cast<const BcryptRsaKeyBlob*>(priv_blob.data());
    if (hdr->Magic != BCRYPT_RSAFULLPRIVATE_MAGIC)
        return std::nullopt;

    const uint8_t* ptr = priv_blob.data() + sizeof(BcryptRsaKeyBlob);
    size_t remaining = priv_blob.size() - sizeof(BcryptRsaKeyBlob);

    auto read_bn = [&](uint32_t len) -> BIGNUM* {
        if (len > remaining) return nullptr;
        BIGNUM* bn = BN_bin2bn(ptr, static_cast<int>(len), nullptr);
        ptr += len; remaining -= len;
        return bn;
    };

    BIGNUM* e    = read_bn(hdr->cbPublicExp);
    BIGNUM* n    = read_bn(hdr->cbModulus);
    BIGNUM* p    = read_bn(hdr->cbPrime1);
    BIGNUM* q    = read_bn(hdr->cbPrime2);
    BIGNUM* dp   = read_bn(hdr->cbPrime1);  // Exp1 = cbPrime1 байт
    BIGNUM* dq   = read_bn(hdr->cbPrime2);  // Exp2 = cbPrime2 байт
    BIGNUM* qinv = read_bn(hdr->cbPrime1);  // Coeff = cbPrime1 байт
    BIGNUM* d    = read_bn(hdr->cbModulus);  // PrivateExp = cbModulus байт

    if (!e || !n || !d || !p || !q || !dp || !dq || !qinv) {
        BN_free(e); BN_free(n); BN_free(d); BN_free(p);
        BN_free(q); BN_free(dp); BN_free(dq); BN_free(qinv);
        return std::nullopt;
    }

    // Собираем EVP_PKEY из компонентов.
    EVP_PKEY_CTX* build_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!build_ctx || !pkey) {
        BN_free(e); BN_free(n); BN_free(d); BN_free(p);
        BN_free(q); BN_free(dp); BN_free(dq); BN_free(qinv);
        EVP_PKEY_CTX_free(build_ctx); EVP_PKEY_free(pkey);
        return std::nullopt;
    }

    // OpenSSL 3.x: через EVP_PKEY_fromdata.
    OSSL_PARAM params[10];
    int idx = 0;
    params[idx++] = OSSL_PARAM_construct_BN("n", const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(ptr)), 0);
    // Проще использовать EVP_PKEY_fromdata с OSSL_PARAM... но компоненты уже в BIGNUM.
    // Вместо этого используем устаревший, но рабочий RSA_new + RSA_set0_key.
    EVP_PKEY_CTX_free(build_ctx);
    EVP_PKEY_free(pkey);

    // Используем низкоуровневое API через EVP_PKEY_fromdata и OSSL_PARAM_BLD.
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (!bld) {
        BN_free(e); BN_free(n); BN_free(d); BN_free(p);
        BN_free(q); BN_free(dp); BN_free(dq); BN_free(qinv);
        return std::nullopt;
    }

    OSSL_PARAM_BLD_push_BN(bld, "n", n);
    OSSL_PARAM_BLD_push_BN(bld, "e", e);
    OSSL_PARAM_BLD_push_BN(bld, "d", d);
    OSSL_PARAM_BLD_push_BN(bld, "rsa-factor1", p);
    OSSL_PARAM_BLD_push_BN(bld, "rsa-factor2", q);
    OSSL_PARAM_BLD_push_BN(bld, "rsa-exponent1", dp);
    OSSL_PARAM_BLD_push_BN(bld, "rsa-exponent2", dq);
    OSSL_PARAM_BLD_push_BN(bld, "rsa-coefficient1", qinv);

    OSSL_PARAM* ossl_params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);

    EVP_PKEY_CTX* from_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    pkey = nullptr;
    int rc = EVP_PKEY_fromdata_init(from_ctx);
    if (rc <= 0) {
        OSSL_PARAM_free(ossl_params);
        EVP_PKEY_CTX_free(from_ctx);
        BN_free(e); BN_free(n); BN_free(d); BN_free(p);
        BN_free(q); BN_free(dp); BN_free(dq); BN_free(qinv);
        return std::nullopt;
    }
    rc = EVP_PKEY_fromdata(from_ctx, &pkey, EVP_PKEY_KEYPAIR, ossl_params);
    OSSL_PARAM_free(ossl_params);
    EVP_PKEY_CTX_free(from_ctx);
    BN_free(e); BN_free(n); BN_free(d); BN_free(p);
    BN_free(q); BN_free(dp); BN_free(dq); BN_free(qinv);

    if (rc <= 0 || !pkey)
        return std::nullopt;

    // Ра��шифровка OAEP-SHA256.
    EVP_PKEY_CTX* dec_ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    EVP_PKEY_free(pkey);
    if (!dec_ctx) return std::nullopt;

    if (EVP_PKEY_decrypt_init(dec_ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(dec_ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(dec_ctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(dec_ctx);
        return std::nullopt;
    }

    size_t out_len = 0;
    if (EVP_PKEY_decrypt(dec_ctx, nullptr, &out_len, ct.data(), ct.size()) <= 0) {
        EVP_PKEY_CTX_free(dec_ctx);
        return std::nullopt;
    }

    Bytes out(out_len);
    if (EVP_PKEY_decrypt(dec_ctx, out.data(), &out_len, ct.data(), ct.size()) <= 0) {
        EVP_PKEY_CTX_free(dec_ctx);
        return std::nullopt;
    }
    EVP_PKEY_CTX_free(dec_ctx);

    out.resize(out_len);
    return out;
}

}

#endif
