#pragma once

#include "bytes.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace co2h::crypto {

constexpr std::size_t kAesKeyLen   = 32; // AES-256
constexpr std::size_t kAesNonceLen = 12; // GCM
constexpr std::size_t kAesTagLen   = 16;

using AesKey   = std::array<std::uint8_t, kAesKeyLen>;
using AesNonce = std::array<std::uint8_t, kAesNonceLen>;

bool random_bytes(std::uint8_t* out, std::size_t n);
AesKey   random_aes_key();
AesNonce random_aes_nonce();

// AES-256-GCM. Tag is appended to ciphertext. aad can be empty.
Bytes aes_gcm_encrypt(const AesKey& key, const AesNonce& nonce,
                      BytesView plaintext, BytesView aad);
std::optional<Bytes> aes_gcm_decrypt(const AesKey& key, const AesNonce& nonce,
                                     BytesView ciphertext_with_tag,
                                     BytesView aad);

// RSA-OAEP SHA-256. PEM keys.
struct RsaPublicKey  { std::string pem; };
struct RsaPrivateKey { std::string pem; };

std::optional<Bytes> rsa_oaep_encrypt(const RsaPublicKey& pk, BytesView pt);
std::optional<Bytes> rsa_oaep_decrypt(const RsaPrivateKey& sk, BytesView ct);

// Ed25519 sign / verify on raw 32-byte seed private key and 32-byte public key.
using Ed25519Public  = std::array<std::uint8_t, 32>;
using Ed25519Private = std::array<std::uint8_t, 32>;
using Ed25519Sig     = std::array<std::uint8_t, 64>;

bool ed25519_sign(const Ed25519Private& sk, BytesView msg, Ed25519Sig& out);
bool ed25519_verify(const Ed25519Public& pk, BytesView msg, const Ed25519Sig& sig);

// PBKDF2-HMAC-SHA256 password hashing. Output string format:
//   "pbkdf2$<iter>$<salt_b64>$<hash_b64>"
std::string password_hash(std::string_view password, std::uint32_t iterations = 200000);
bool        password_verify(std::string_view password, std::string_view encoded);

// SHA-256 of buffer.
std::array<std::uint8_t, 32> sha256(BytesView data);

}
