#include "crypto.hpp"

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <charconv>
#include <cstring>
#include <memory>

namespace co2h::crypto {

namespace {

using EvpPKeyPtr       = std::unique_ptr<EVP_PKEY,       decltype(&EVP_PKEY_free)>;
using EvpCtxPtr        = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
using EvpPKeyCtxPtr    = std::unique_ptr<EVP_PKEY_CTX,   decltype(&EVP_PKEY_CTX_free)>;
using EvpMdCtxPtr      = std::unique_ptr<EVP_MD_CTX,     decltype(&EVP_MD_CTX_free)>;
using BioPtr           = std::unique_ptr<BIO,            decltype(&BIO_free_all)>;

std::string b64_encode(BytesView b) {
    BioPtr mem{BIO_new(BIO_s_mem()), BIO_free_all};
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* chain = BIO_push(b64, mem.get());
    BIO_write(chain, b.data(), static_cast<int>(b.size()));
    BIO_flush(chain);
    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(chain, &bptr);
    std::string out(bptr->data, bptr->length);
    BIO_free(b64); // chain keeps mem alive via unique_ptr
    return out;
}

Bytes b64_decode(std::string_view s) {
    Bytes out(s.size());
    BIO* mem = BIO_new_mem_buf(s.data(), static_cast<int>(s.size()));
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* chain = BIO_push(b64, mem);
    int n = BIO_read(chain, out.data(), static_cast<int>(out.size()));
    BIO_free_all(chain);
    if (n < 0) return {};
    out.resize(n);
    return out;
}

} // namespace

bool random_bytes(std::uint8_t* out, std::size_t n) {
    return RAND_bytes(out, static_cast<int>(n)) == 1;
}

AesKey random_aes_key() {
    AesKey k{};
    random_bytes(k.data(), k.size());
    return k;
}

AesNonce random_aes_nonce() {
    AesNonce n{};
    random_bytes(n.data(), n.size());
    return n;
}

Bytes aes_gcm_encrypt(const AesKey& key, const AesNonce& nonce,
                      BytesView pt, BytesView aad) {
    EvpCtxPtr ctx{EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free};
    Bytes out(pt.size() + kAesTagLen);
    int outl = 0, total = 0;

    EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                        static_cast<int>(nonce.size()), nullptr);
    EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data());

    if (!aad.empty()) {
        EVP_EncryptUpdate(ctx.get(), nullptr, &outl, aad.data(),
                          static_cast<int>(aad.size()));
    }
    EVP_EncryptUpdate(ctx.get(), out.data(), &outl, pt.data(),
                      static_cast<int>(pt.size()));
    total = outl;
    EVP_EncryptFinal_ex(ctx.get(), out.data() + total, &outl);
    total += outl;

    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                        kAesTagLen, out.data() + total);
    out.resize(total + kAesTagLen);
    return out;
}

std::optional<Bytes> aes_gcm_decrypt(const AesKey& key, const AesNonce& nonce,
                                     BytesView ct_tag, BytesView aad) {
    if (ct_tag.size() < kAesTagLen) return std::nullopt;
    const std::size_t ct_len = ct_tag.size() - kAesTagLen;

    EvpCtxPtr ctx{EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free};
    Bytes out(ct_len);
    int outl = 0, total = 0;

    EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                        static_cast<int>(nonce.size()), nullptr);
    EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data());

    if (!aad.empty()) {
        EVP_DecryptUpdate(ctx.get(), nullptr, &outl, aad.data(),
                          static_cast<int>(aad.size()));
    }
    if (ct_len > 0) {
        EVP_DecryptUpdate(ctx.get(), out.data(), &outl, ct_tag.data(),
                          static_cast<int>(ct_len));
        total = outl;
    }

    std::uint8_t tag[kAesTagLen];
    std::memcpy(tag, ct_tag.data() + ct_len, kAesTagLen);
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, kAesTagLen, tag);

    if (EVP_DecryptFinal_ex(ctx.get(), out.data() + total, &outl) <= 0) {
        return std::nullopt;
    }
    total += outl;
    out.resize(total);
    return out;
}

std::optional<Bytes> rsa_oaep_encrypt(const RsaPublicKey& pk, BytesView pt) {
    BioPtr bio{BIO_new_mem_buf(pk.pem.data(), static_cast<int>(pk.pem.size())),
               BIO_free_all};
    EvpPKeyPtr key{PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr),
                   EVP_PKEY_free};
    if (!key) return std::nullopt;

    EvpPKeyCtxPtr ctx{EVP_PKEY_CTX_new(key.get(), nullptr), EVP_PKEY_CTX_free};
    if (!ctx || EVP_PKEY_encrypt_init(ctx.get()) <= 0) return std::nullopt;
    EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha256());

    std::size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx.get(), nullptr, &outlen, pt.data(), pt.size()) <= 0)
        return std::nullopt;
    Bytes out(outlen);
    if (EVP_PKEY_encrypt(ctx.get(), out.data(), &outlen, pt.data(), pt.size()) <= 0)
        return std::nullopt;
    out.resize(outlen);
    return out;
}

std::optional<Bytes> rsa_oaep_decrypt(const RsaPrivateKey& sk, BytesView ct) {
    BioPtr bio{BIO_new_mem_buf(sk.pem.data(), static_cast<int>(sk.pem.size())),
               BIO_free_all};
    EvpPKeyPtr key{PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr),
                   EVP_PKEY_free};
    if (!key) return std::nullopt;

    EvpPKeyCtxPtr ctx{EVP_PKEY_CTX_new(key.get(), nullptr), EVP_PKEY_CTX_free};
    if (!ctx || EVP_PKEY_decrypt_init(ctx.get()) <= 0) return std::nullopt;
    EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha256());

    std::size_t outlen = 0;
    if (EVP_PKEY_decrypt(ctx.get(), nullptr, &outlen, ct.data(), ct.size()) <= 0)
        return std::nullopt;
    Bytes out(outlen);
    if (EVP_PKEY_decrypt(ctx.get(), out.data(), &outlen, ct.data(), ct.size()) <= 0)
        return std::nullopt;
    out.resize(outlen);
    return out;
}

bool ed25519_sign(const Ed25519Private& sk, BytesView msg, Ed25519Sig& out) {
    EvpPKeyPtr key{EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
                                                sk.data(), sk.size()),
                   EVP_PKEY_free};
    if (!key) return false;
    EvpMdCtxPtr md{EVP_MD_CTX_new(), EVP_MD_CTX_free};
    if (!md) return false;
    if (EVP_DigestSignInit(md.get(), nullptr, nullptr, nullptr, key.get()) <= 0)
        return false;
    std::size_t siglen = out.size();
    if (EVP_DigestSign(md.get(), out.data(), &siglen, msg.data(), msg.size()) <= 0)
        return false;
    return siglen == out.size();
}

bool ed25519_verify(const Ed25519Public& pk, BytesView msg, const Ed25519Sig& sig) {
    EvpPKeyPtr key{EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                               pk.data(), pk.size()),
                   EVP_PKEY_free};
    if (!key) return false;
    EvpMdCtxPtr md{EVP_MD_CTX_new(), EVP_MD_CTX_free};
    if (!md) return false;
    if (EVP_DigestVerifyInit(md.get(), nullptr, nullptr, nullptr, key.get()) <= 0)
        return false;
    return EVP_DigestVerify(md.get(), sig.data(), sig.size(),
                            msg.data(), msg.size()) == 1;
}

std::string password_hash(std::string_view password, std::uint32_t iterations) {
    std::uint8_t salt[16];
    random_bytes(salt, sizeof(salt));
    std::uint8_t out[32];
    if (PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
                          salt, sizeof(salt), static_cast<int>(iterations),
                          EVP_sha256(), sizeof(out), out) != 1) {
        return {};
    }
    std::string enc = "pbkdf2$";
    enc += std::to_string(iterations);
    enc += '$';
    enc += b64_encode({salt, sizeof(salt)});
    enc += '$';
    enc += b64_encode({out, sizeof(out)});
    return enc;
}

bool password_verify(std::string_view password, std::string_view encoded) {
    if (encoded.substr(0, 7) != "pbkdf2$") return false;
    std::string_view rest = encoded.substr(7);
    auto p1 = rest.find('$'); if (p1 == std::string_view::npos) return false;
    auto iter_str = rest.substr(0, p1);
    rest.remove_prefix(p1 + 1);
    auto p2 = rest.find('$'); if (p2 == std::string_view::npos) return false;
    auto salt_b64 = rest.substr(0, p2);
    auto hash_b64 = rest.substr(p2 + 1);

    std::uint32_t iterations = 0;
    auto [ptr, ec] = std::from_chars(iter_str.data(),
                                     iter_str.data() + iter_str.size(),
                                     iterations);
    if (ec != std::errc{} || iterations == 0) return false;

    Bytes salt = b64_decode(salt_b64);
    Bytes want = b64_decode(hash_b64);
    if (salt.empty() || want.size() != 32) return false;

    std::uint8_t out[32];
    if (PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
                          salt.data(), static_cast<int>(salt.size()),
                          static_cast<int>(iterations),
                          EVP_sha256(), sizeof(out), out) != 1) {
        return false;
    }
    std::uint8_t diff = 0;
    for (std::size_t i = 0; i < sizeof(out); ++i)
        diff |= static_cast<std::uint8_t>(out[i] ^ want[i]);
    return diff == 0;
}

std::array<std::uint8_t, 32> sha256(BytesView data) {
    std::array<std::uint8_t, 32> out{};
    SHA256(data.data(), data.size(), out.data());
    return out;
}

}
