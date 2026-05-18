#pragma once

#include <co2h/bytes.hpp>

#include <optional>

namespace co2h::server::https {

// RSA-2048 OAEP-SHA256 helpers via Windows BCrypt. Blobs use BCrypt formats
// (BCRYPT_RSAPUBLIC_BLOB / BCRYPT_RSAFULLPRIVATE_BLOB) — same encoding as the
// beacon side, no DER/PEM conversion needed.

// Generates a fresh 2048-bit RSA keypair. On success fills both blobs and
// returns true.
bool rsa_generate_2048(Bytes& pub_blob, Bytes& priv_blob);

// Decrypts an OAEP-SHA256 ciphertext using the given full-private blob.
// Returns the plaintext, or nullopt on any failure (parse, size, padding).
std::optional<Bytes> rsa_oaep_decrypt(BytesView priv_blob, BytesView ct);

}
