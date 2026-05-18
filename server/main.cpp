#include "Config.hpp"
#include "Core.hpp"
#include "net/OperatorAcceptor.hpp"
#include "listeners/https/HttpsListener.hpp"
#include "listeners/https/RsaOaep.hpp"
#include "listeners/dns/DnsListener.hpp"
#include <co2h/bytes.hpp>
#include <co2h/crypto.hpp>
#include <co2h/version.hpp>

#include <asio.hpp>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <thread>

namespace {

void print_usage() {
    // Справка отключена: teamserver запускается клиентом автоматически,
    // вручную пользователь его не вызывает.
    // std::cerr <<
    //     "Usage: teamserver --config <file.toml>\n"
    //     "       teamserver --init-config <out.toml>\n";
}

int cmd_init_config(const std::filesystem::path& out) {
    const char* tpl =
        "[operators]\n"
        "bind = \"0.0.0.0\"\n"
        "port = 50050\n"
        "\n"
        "[tls]\n"
        "cert = \"server.crt\"\n"
        "key  = \"server.key\"\n"
        "ca   = \"operators-ca.crt\"   # comment out to disable mTLS (dev only)\n"
        "\n"
        "[database]\n"
        "path = \"co2h.db\"\n"
        "\n"
        "[log]\n"
        "dir = \"logs\"\n"
        "\n"
        "[io]\n"
        "threads = 0  # 0 = auto (hardware concurrency)\n"
        "\n"
        "[[listeners]]\n"
        "kind     = \"https\"\n"
        "name     = \"https-default\"\n"
        "bind     = \"0.0.0.0\"\n"
        "port     = 443\n"
        "tls_cert = \"certs/listener.crt\"\n"
        "tls_key  = \"certs/listener.key\"\n"
        "profile  = \"\"  # leave empty for built-in default profile\n"
        "# listener_key = \"\"  # 64 hex chars (AES-256); omit = auto-generate\n";
    std::ofstream o{out};
    if (!o) { std::cerr << "cannot write " << out << "\n"; return 1; }
    o << tpl;
    std::cout << "wrote " << out << "\n";
    return 0;
}

void setup_logging(const std::filesystem::path& dir) {
    try {
        std::filesystem::create_directories(dir);
        auto file = spdlog::rotating_logger_mt(
            "teamserver",
            (dir / "teamserver.log").string(),
            10 * 1024 * 1024, 5);
        auto con  = spdlog::stdout_color_mt("console");
        spdlog::set_default_logger(con);
        spdlog::set_level(spdlog::level::info);
        spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");
    } catch (const std::exception& e) {
        std::cerr << "log setup failed: " << e.what() << "\n";
    }
}

volatile std::sig_atomic_t g_stop = 0;
void on_signal(int) { g_stop = 1; }

}

int main(int argc, char** argv) {
    std::filesystem::path config_file;
    bool init_cfg = false;
    std::filesystem::path init_cfg_out;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--config" && i + 1 < argc) {
            config_file = argv[++i];
        } else if (a == "--init-config" && i + 1 < argc) {
            init_cfg = true;
            init_cfg_out = argv[++i];
        } else if (a == "--version") {
            std::cout << co2h::kProductName << " " << co2h::kProductVersion << "\n";
            return 0;
        } else {
            print_usage();
            return a == "--help" ? 0 : 1;
        }
    }

    if (init_cfg) return cmd_init_config(init_cfg_out);
    if (config_file.empty()) { print_usage(); return 1; }

    // Change working directory to the config file's directory so all relative
    // paths in the config (certs/, profiles/, database, logs/) resolve correctly
    // regardless of where the binary is invoked from.
    config_file = std::filesystem::absolute(config_file);
    std::error_code ec;
    std::filesystem::current_path(config_file.parent_path(), ec);
    if (ec) {
        std::cerr << "cannot chdir to config directory: " << ec.message() << "\n";
        return 1;
    }

    std::string err;
    auto cfg_opt = co2h::server::load_config(config_file, err);
    if (!cfg_opt) {
        std::cerr << "config error: " << err << "\n";
        return 1;
    }
    auto cfg = *cfg_opt;
    setup_logging(cfg.log_dir);

    spdlog::info("{} {} starting", co2h::kProductName, co2h::kProductVersion);

    std::shared_ptr<co2h::server::Core> core;
    try {
        core = co2h::server::Core::create(cfg);
    } catch (const std::exception& e) {
        spdlog::critical("startup failed: {}", e.what());
        return 1;
    }

    auto op_acc = std::make_shared<co2h::server::OperatorAcceptor>(core);
    try {
        op_acc->start();
    } catch (const std::exception& e) {
        spdlog::critical("operator acceptor failed: {}", e.what());
        return 1;
    }

    for (auto& seed : cfg.listeners) {
        if (seed.kind == "dns") {
            co2h::server::dns_c2::DnsConfig d;
            d.name      = seed.name;
            d.bind_host = seed.bind_host;
            d.bind_port = seed.bind_port;
            d.c2_domain = seed.c2_domain;
            // AES listener key: конфиг → БД → рандом.
            if (seed.listener_key.size() == 64) {
                // Явно задан в конфиге — использовать и сохранить в БД.
                auto raw = co2h::hex_decode(seed.listener_key);
                if (raw.size() == 32) {
                    std::copy(raw.begin(), raw.end(), d.listener_key.begin());
                    core->db()->set_listener_key_hex(seed.name, seed.listener_key);
                    spdlog::info("dns listener '{}' using key from config", seed.name);
                } else {
                    spdlog::error("dns listener '{}' invalid listener_key (need 64 hex chars)", seed.name);
                    continue;
                }
            } else {
                auto stored_hex = core->db()->get_listener_key_hex(seed.name);
                if (stored_hex && stored_hex->size() == 64) {
                    auto raw = co2h::hex_decode(*stored_hex);
                    if (raw.size() == 32)
                        std::copy(raw.begin(), raw.end(), d.listener_key.begin());
                    else
                        stored_hex.reset();
                }
                if (!stored_hex || stored_hex->size() != 64) {
                    d.listener_key = co2h::crypto::random_aes_key();
                    core->db()->set_listener_key_hex(seed.name,
                        co2h::hex_encode({d.listener_key.data(), d.listener_key.size()}));
                }
            }
            // RSA-2048 keypair for per-session key wrapping.
            if (!core->db()->get_listener_rsa(seed.name, d.rsa_pub_blob, d.rsa_priv_blob)) {
                if (!co2h::server::https::rsa_generate_2048(d.rsa_pub_blob, d.rsa_priv_blob)) {
                    spdlog::error("dns listener '{}' RSA keypair generation failed", seed.name);
                    continue;
                }
                core->db()->set_listener_rsa(seed.name,
                    {d.rsa_pub_blob.data(),  d.rsa_pub_blob.size()},
                    {d.rsa_priv_blob.data(), d.rsa_priv_blob.size()});
            }
            auto name = seed.name;
            auto core_captured = core;
            core->listeners().add(name,
                [core_captured, d]() -> std::shared_ptr<co2h::server::Listener> {
                    return std::make_shared<co2h::server::dns_c2::DnsListener>(
                        core_captured, d);
                });
            continue;
        }
        if (seed.kind != "https") {
            spdlog::warn("skipping listener '{}' (unsupported kind '{}')",
                         seed.name, seed.kind);
            continue;
        }
        co2h::server::https::HttpsConfig h;
        h.name      = seed.name;
        h.bind_host = seed.bind_host;
        h.bind_port = seed.bind_port;
        h.cert_file = seed.tls_cert;
        h.key_file  = seed.tls_key;
        std::string perr;
        auto prof = co2h::server::https::load_profile(seed.profile, perr);
        if (!prof) {
            spdlog::warn("profile '{}' for listener '{}' failed: {}",
                         seed.profile.string(), seed.name, perr);
            continue;
        }
        h.profile = *prof;
        // AES listener key: конфиг → БД → рандом.
        if (seed.listener_key.size() == 64) {
            auto raw = co2h::hex_decode(seed.listener_key);
            if (raw.size() == 32) {
                std::copy(raw.begin(), raw.end(), h.listener_key.begin());
                core->db()->set_listener_key_hex(seed.name, seed.listener_key);
                spdlog::info("listener '{}' using key from config", seed.name);
            } else {
                spdlog::error("listener '{}' invalid listener_key (need 64 hex chars)", seed.name);
                continue;
            }
        } else {
            auto stored_hex = core->db()->get_listener_key_hex(seed.name);
            if (stored_hex && stored_hex->size() == 64) {
                auto raw = co2h::hex_decode(*stored_hex);
                if (raw.size() == 32)
                    std::copy(raw.begin(), raw.end(), h.listener_key.begin());
                else
                    stored_hex.reset();
            }
            if (!stored_hex || stored_hex->size() != 64) {
                h.listener_key = co2h::crypto::random_aes_key();
                core->db()->set_listener_key_hex(seed.name,
                    co2h::hex_encode({h.listener_key.data(), h.listener_key.size()}));
            }
        }
        // RSA-2048 keypair for per-session key wrapping; persisted alongside.
        if (!core->db()->get_listener_rsa(seed.name, h.rsa_pub_blob, h.rsa_priv_blob)) {
            if (!co2h::server::https::rsa_generate_2048(h.rsa_pub_blob, h.rsa_priv_blob)) {
                spdlog::error("listener '{}' RSA keypair generation failed", seed.name);
                continue;
            }
            core->db()->set_listener_rsa(seed.name,
                {h.rsa_pub_blob.data(),  h.rsa_pub_blob.size()},
                {h.rsa_priv_blob.data(), h.rsa_priv_blob.size()});
        }
        auto name = seed.name;
        auto core_captured = core;
        core->listeners().add(name,
            [core_captured, h]() -> std::shared_ptr<co2h::server::Listener> {
                return std::make_shared<co2h::server::https::HttpsListener>(
                    core_captured, h);
            });
    }

    std::signal(SIGINT,  on_signal);
    std::signal(SIGTERM, on_signal);

    std::thread watchdog([&]{
        while (!g_stop) std::this_thread::sleep_for(std::chrono::milliseconds(250));
        spdlog::info("shutdown signal received");
        op_acc->stop();
        core->stop();
    });

    core->run(cfg.io_threads);
    watchdog.join();
    spdlog::info("teamserver stopped");
    return 0;
}
