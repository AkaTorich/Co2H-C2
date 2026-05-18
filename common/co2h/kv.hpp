#pragma once

#include <co2h/bytes.hpp>
#include <co2h/proto.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace co2h::kv {

// Minimal key-value payload encoding used inside frames:
//   [u16 n_fields]{[u16 keylen][key][u32 vlen][value]}
// Values can be strings, bytes, or integers (serialized as strings by caller).
// This is a pragmatic stand-in for msgpack for the MVP.

class Writer {
public:
    void put_str(std::string_view key, std::string_view value);
    void put_bytes(std::string_view key, BytesView value);
    void put_u32(std::string_view key, std::uint32_t value);
    void put_u64(std::string_view key, std::uint64_t value);
    Bytes finish();
private:
    Bytes   buf_;
    std::uint16_t count_ = 0;
};

class Reader {
public:
    explicit Reader(BytesView data);
    std::optional<std::string_view> get_str(std::string_view key) const;
    std::optional<BytesView>        get_bytes(std::string_view key) const;
    std::optional<std::uint32_t>    get_u32(std::string_view key) const;
    std::optional<std::uint64_t>    get_u64(std::string_view key) const;
    bool ok() const { return ok_; }
private:
    struct Field { std::string_view key; BytesView value; };
    std::vector<Field> fields_;
    bool ok_ = false;
};

}
