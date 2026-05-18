#include "Wrappers.hpp"
#include <fstream>
#include <iterator>

namespace co2h::artgen {

std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(f), {});
}

bool write_file(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream f(path, std::ios::binary);
    if (!f) return false;
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
    return f.good();
}

std::string hex(const uint8_t* p, size_t n, size_t max_bytes) {
    const char* h = "0123456789abcdef";
    std::string out;
    size_t lim = n < max_bytes ? n : max_bytes;
    out.reserve(lim * 2 + 3);
    for (size_t i = 0; i < lim; ++i) {
        out += h[p[i] >> 4];
        out += h[p[i] & 0xF];
    }
    if (n > max_bytes) out += "...";
    return out;
}

} // namespace co2h::artgen
