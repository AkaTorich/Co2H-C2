#include "kv.hpp"

#include <charconv>
#include <cstring>

namespace co2h::kv {

namespace {
void write_u16(Bytes& b, std::uint16_t v) {
    b.push_back(static_cast<std::uint8_t>(v >> 8));
    b.push_back(static_cast<std::uint8_t>(v));
}
void write_u32(Bytes& b, std::uint32_t v) {
    b.push_back(static_cast<std::uint8_t>(v >> 24));
    b.push_back(static_cast<std::uint8_t>(v >> 16));
    b.push_back(static_cast<std::uint8_t>(v >> 8));
    b.push_back(static_cast<std::uint8_t>(v));
}
std::uint16_t read_u16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}
std::uint32_t read_u32(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24)
         | (static_cast<std::uint32_t>(p[1]) << 16)
         | (static_cast<std::uint32_t>(p[2]) << 8)
         |  static_cast<std::uint32_t>(p[3]);
}
}

void Writer::put_str(std::string_view key, std::string_view value) {
    write_u16(buf_, static_cast<std::uint16_t>(key.size()));
    buf_.insert(buf_.end(), key.begin(), key.end());
    write_u32(buf_, static_cast<std::uint32_t>(value.size()));
    buf_.insert(buf_.end(), value.begin(), value.end());
    ++count_;
}

void Writer::put_bytes(std::string_view key, BytesView value) {
    write_u16(buf_, static_cast<std::uint16_t>(key.size()));
    buf_.insert(buf_.end(), key.begin(), key.end());
    write_u32(buf_, static_cast<std::uint32_t>(value.size()));
    buf_.insert(buf_.end(), value.begin(), value.end());
    ++count_;
}

void Writer::put_u32(std::string_view key, std::uint32_t value) {
    char tmp[16];
    auto [p, ec] = std::to_chars(tmp, tmp + sizeof(tmp), value);
    put_str(key, std::string_view{tmp, static_cast<std::size_t>(p - tmp)});
}

void Writer::put_u64(std::string_view key, std::uint64_t value) {
    char tmp[32];
    auto [p, ec] = std::to_chars(tmp, tmp + sizeof(tmp), value);
    put_str(key, std::string_view{tmp, static_cast<std::size_t>(p - tmp)});
}

Bytes Writer::finish() {
    Bytes out;
    out.reserve(buf_.size() + 2);
    write_u16(out, count_);
    out.insert(out.end(), buf_.begin(), buf_.end());
    return out;
}

Reader::Reader(BytesView data) {
    if (data.size() < 2) return;
    std::uint16_t n = read_u16(data.data());
    std::size_t off = 2;
    for (std::uint16_t i = 0; i < n; ++i) {
        if (off + 2 > data.size()) return;
        std::uint16_t kl = read_u16(data.data() + off);
        off += 2;
        if (off + kl > data.size()) return;
        std::string_view key{reinterpret_cast<const char*>(data.data() + off), kl};
        off += kl;
        if (off + 4 > data.size()) return;
        std::uint32_t vl = read_u32(data.data() + off);
        off += 4;
        if (off + vl > data.size()) return;
        BytesView val{data.data() + off, vl};
        off += vl;
        fields_.push_back({key, val});
    }
    ok_ = (off == data.size());
}

std::optional<std::string_view> Reader::get_str(std::string_view key) const {
    for (auto& f : fields_) if (f.key == key) {
        return std::string_view{reinterpret_cast<const char*>(f.value.data()),
                                f.value.size()};
    }
    return std::nullopt;
}

std::optional<BytesView> Reader::get_bytes(std::string_view key) const {
    for (auto& f : fields_) if (f.key == key) return f.value;
    return std::nullopt;
}

std::optional<std::uint32_t> Reader::get_u32(std::string_view key) const {
    auto s = get_str(key);
    if (!s) return std::nullopt;
    std::uint32_t v = 0;
    auto [p, ec] = std::from_chars(s->data(), s->data() + s->size(), v);
    if (ec != std::errc{}) return std::nullopt;
    return v;
}

std::optional<std::uint64_t> Reader::get_u64(std::string_view key) const {
    auto s = get_str(key);
    if (!s) return std::nullopt;
    std::uint64_t v = 0;
    auto [p, ec] = std::from_chars(s->data(), s->data() + s->size(), v);
    if (ec != std::errc{}) return std::nullopt;
    return v;
}

}
