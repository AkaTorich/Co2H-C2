#pragma once
#include <cstdint>
#include <vector>
#include <string>

namespace co2h::artgen {

std::vector<uint8_t> read_file(const std::string& path);
bool write_file(const std::string& path, const std::vector<uint8_t>& data);
std::string hex(const uint8_t* p, size_t n, size_t max_bytes = 32);

} // namespace co2h::artgen
