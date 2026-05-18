#pragma once

#include "../../core/ListenerManager.hpp"
#include <co2h/bytes.hpp>
#include <co2h/crypto.hpp>

#include <asio.hpp>

#include <memory>
#include <string>

namespace co2h::server { class Core; }

namespace co2h::server::tcp_raw {

struct TcpConfig {
    std::string    name;
    std::string    bind_host = "0.0.0.0";
    std::uint16_t  bind_port = 4444;
    crypto::AesKey listener_key;
    Bytes          rsa_pub_blob;   // BCRYPT_RSAPUBLIC_BLOB — baked into beacon
    Bytes          rsa_priv_blob;  // BCRYPT_RSAFULLPRIVATE_BLOB — server only
};

class TcpListener
    : public Listener,
      public std::enable_shared_from_this<TcpListener> {
public:
    TcpListener(std::shared_ptr<Core> core, TcpConfig cfg);

    void start() override;
    void stop() override;
    std::string name()      const override { return cfg_.name; }
    std::string kind()      const override { return "tcp"; }
    std::string bind_addr() const override {
        return cfg_.bind_host + ":" + std::to_string(cfg_.bind_port);
    }
    std::string key_hex() const override {
        return co2h::hex_encode({cfg_.listener_key.data(), cfg_.listener_key.size()});
    }
    std::string pubkey_hex() const override {
        return co2h::hex_encode({cfg_.rsa_pub_blob.data(), cfg_.rsa_pub_blob.size()});
    }

    const crypto::AesKey&  listener_key() const { return cfg_.listener_key; }
    const crypto::AesKey& listener_key_data() const override { return cfg_.listener_key; }
    BytesView              rsa_priv_blob() const {
        return {cfg_.rsa_priv_blob.data(), cfg_.rsa_priv_blob.size()};
    }
    BytesView rsa_priv_data() const override {
        return {cfg_.rsa_priv_blob.data(), cfg_.rsa_priv_blob.size()};
    }
    std::shared_ptr<Core>  core() { return core_; }

private:
    void do_accept();

    std::shared_ptr<Core>   core_;
    TcpConfig               cfg_;
    asio::ip::tcp::acceptor acc_;
};

}
