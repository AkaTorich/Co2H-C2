#include "proto.hpp"
#include "bytes.hpp"

namespace co2h {

namespace {
constexpr char hex_chars[] = "0123456789abcdef";
}

std::string hex_encode(BytesView b) {
    std::string out;
    out.resize(b.size() * 2);
    for (std::size_t i = 0; i < b.size(); ++i) {
        out[i * 2]     = hex_chars[(b[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex_chars[b[i] & 0xF];
    }
    return out;
}

Bytes hex_decode(std::string_view hex) {
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + c - 'a';
        if (c >= 'A' && c <= 'F') return 10 + c - 'A';
        return -1;
    };
    Bytes out;
    if (hex.size() % 2 != 0) return out;
    out.resize(hex.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) {
        int hi = nibble(hex[i * 2]);
        int lo = nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return {};
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return out;
}

}
