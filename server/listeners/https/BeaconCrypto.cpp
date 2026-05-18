#include "BeaconCrypto.hpp"

#include <algorithm>   // std::copy_n

namespace co2h::server::https {

namespace {

const char* kB64UrlChars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int b64url_index(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

constexpr std::uint8_t kFrameVer = 0x01;

}

std::string b64url_encode(BytesView b) {
    std::string out;
    out.reserve(((b.size() + 2) / 3) * 4);
    std::size_t i = 0;
    while (i + 3 <= b.size()) {
        std::uint32_t v = (b[i] << 16) | (b[i+1] << 8) | b[i+2];
        out.push_back(kB64UrlChars[(v >> 18) & 0x3F]);
        out.push_back(kB64UrlChars[(v >> 12) & 0x3F]);
        out.push_back(kB64UrlChars[(v >>  6) & 0x3F]);
        out.push_back(kB64UrlChars[ v        & 0x3F]);
        i += 3;
    }
    if (i + 1 == b.size()) {
        std::uint32_t v = b[i] << 16;
        out.push_back(kB64UrlChars[(v >> 18) & 0x3F]);
        out.push_back(kB64UrlChars[(v >> 12) & 0x3F]);
    } else if (i + 2 == b.size()) {
        std::uint32_t v = (b[i] << 16) | (b[i+1] << 8);
        out.push_back(kB64UrlChars[(v >> 18) & 0x3F]);
        out.push_back(kB64UrlChars[(v >> 12) & 0x3F]);
        out.push_back(kB64UrlChars[(v >>  6) & 0x3F]);
    }
    return out;
}

Bytes b64url_decode(std::string_view s) {
    Bytes out;
    out.reserve((s.size() * 3) / 4);
    std::uint32_t v = 0;
    int bits = 0;
    for (char c : s) {
        int idx = b64url_index(c);
        if (idx < 0) {
            if (c == '=' ) continue;
            return {};
        }
        v = (v << 6) | static_cast<std::uint32_t>(idx);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<std::uint8_t>((v >> bits) & 0xFF));
        }
    }
    return out;
}

Bytes seal_frame(const crypto::AesKey& key, BytesView plaintext) {
    auto nonce = crypto::random_aes_nonce();
    auto ct    = crypto::aes_gcm_encrypt(key, nonce, plaintext, {});
    Bytes out;
    out.reserve(1 + nonce.size() + ct.size());
    out.push_back(kFrameVer);
    out.insert(out.end(), nonce.begin(), nonce.end());
    out.insert(out.end(), ct.begin(), ct.end());
    return out;
}

std::optional<Bytes> open_frame(const crypto::AesKey& key, BytesView blob) {
    if (blob.size() < 1 + crypto::kAesNonceLen + crypto::kAesTagLen)
        return std::nullopt;
    if (blob[0] != kFrameVer) return std::nullopt;
    crypto::AesNonce nonce{};
    std::copy_n(blob.begin() + 1, nonce.size(), nonce.begin());
    BytesView ct{blob.data() + 1 + nonce.size(),
                 blob.size() - 1 - nonce.size()};
    return crypto::aes_gcm_decrypt(key, nonce, ct, {});
}

Bytes seal_checkin(const crypto::AesKey& key, BytesView plaintext) {
    return seal_frame(key, plaintext);
}

std::optional<Bytes> open_checkin(const crypto::AesKey& key, BytesView blob) {
    return open_frame(key, blob);
}

}
