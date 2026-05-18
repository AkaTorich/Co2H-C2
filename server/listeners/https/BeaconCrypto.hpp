#pragma once

#include <co2h/bytes.hpp>
#include <co2h/crypto.hpp>

#include <optional>
#include <string>

namespace co2h::server::https {

// base64url without padding (used for beacon metadata cookie / URI params).
std::string b64url_encode(BytesView b);
Bytes       b64url_decode(std::string_view s);

// Checkin ciphertext layout:
//   [1 byte ver=0x01][12 bytes nonce][ciphertext+tag]
// Plaintext is a small KV record produced by the beacon describing the host.
Bytes seal_checkin(const crypto::AesKey& key, BytesView plaintext);
std::optional<Bytes> open_checkin(const crypto::AesKey& key, BytesView blob);

// Task frame wire format (server -> beacon and beacon -> server):
//   [1 byte ver][12 nonce][ciphertext+tag]
// Plaintext body is caller-defined (kv-encoded task list / output).
Bytes seal_frame(const crypto::AesKey& key, BytesView plaintext);
std::optional<Bytes> open_frame(const crypto::AesKey& key, BytesView blob);

}
