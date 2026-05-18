#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace co2h {

using Bytes = std::vector<std::uint8_t>;
using BytesView = std::span<const std::uint8_t>;

inline BytesView as_bytes(std::string_view s) noexcept {
    return BytesView{reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}

inline std::string_view as_string(BytesView b) noexcept {
    return std::string_view{reinterpret_cast<const char*>(b.data()), b.size()};
}

inline void append(Bytes& dst, BytesView src) {
    dst.insert(dst.end(), src.begin(), src.end());
}

inline void append_u16_be(Bytes& dst, std::uint16_t v) {
    dst.push_back(static_cast<std::uint8_t>(v >> 8));
    dst.push_back(static_cast<std::uint8_t>(v));
}

inline void append_u32_be(Bytes& dst, std::uint32_t v) {
    dst.push_back(static_cast<std::uint8_t>(v >> 24));
    dst.push_back(static_cast<std::uint8_t>(v >> 16));
    dst.push_back(static_cast<std::uint8_t>(v >> 8));
    dst.push_back(static_cast<std::uint8_t>(v));
}

inline std::uint16_t read_u16_be(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

inline std::uint32_t read_u32_be(const std::uint8_t* p) noexcept {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8)  |
           (static_cast<std::uint32_t>(p[3]));
}

std::string hex_encode(BytesView b);
Bytes       hex_decode(std::string_view hex);

}
