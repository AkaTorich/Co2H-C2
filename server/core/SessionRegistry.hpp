#pragma once

#include <co2h/bytes.hpp>
#include <co2h/crypto.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace co2h::server {

struct BeaconSession {
    std::string  id;             // opaque beacon-id (hex)
    std::string  parent_id;      // parent beacon hex-id (empty = root beacon)
    std::string  listener;       // listener name this beacon belongs to
    std::string  hostname;
    std::string  username;
    std::uint32_t pid = 0;
    std::string  arch;           // "x64"
    std::string  os;             // "windows" / "linux"
    std::string  internal_ip;
    std::string  external_ip;
    std::chrono::system_clock::time_point first_seen;
    std::chrono::system_clock::time_point last_seen;

    crypto::AesKey session_key{};   // shared AES key for this beacon
};

class SessionRegistry {
public:
    std::shared_ptr<BeaconSession> create_or_update(const BeaconSession& s);
    std::shared_ptr<BeaconSession> get(const std::string& id);
    std::vector<std::shared_ptr<BeaconSession>> snapshot();

private:
    std::mutex mu_;
    std::unordered_map<std::string, std::shared_ptr<BeaconSession>> map_;
};

}
