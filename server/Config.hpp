#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace co2h::server {

struct TlsConfig {
    std::filesystem::path cert_file;   // server cert for operator channel
    std::filesystem::path key_file;    // server private key
    std::filesystem::path ca_file;     // CA to verify operator client certs
};

struct ListenerSeed {
    std::string   kind;     // "https" | "socks5"
    std::string   name;
    std::string   bind_host;
    std::uint16_t bind_port{};
    std::filesystem::path tls_cert;
    std::filesystem::path tls_key;
    std::filesystem::path profile;     // path to malleable profile (optional)
    std::string   beacon_id;           // socks5: which beacon to proxy through
    std::string   c2_domain;           // dns: authoritative domain suffix
    std::string   listener_key;        // hex AES-256 (64 hex chars); пустая = авто из БД
};

struct Config {
    std::string           operator_bind = "0.0.0.0";
    std::uint16_t         operator_port = 50050;
    TlsConfig             tls;
    std::filesystem::path database = "co2h.db";
    std::filesystem::path log_dir  = "logs";
    int                   io_threads = 0;   // 0 => auto

    std::vector<ListenerSeed> listeners;
};

std::optional<Config> load_config(const std::filesystem::path& file,
                                  std::string& err);

}
