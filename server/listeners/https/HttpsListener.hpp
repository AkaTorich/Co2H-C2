#pragma once

#include "../../core/ListenerManager.hpp"
#include "MalleableProfile.hpp"

#include <co2h/bytes.hpp>
#include <co2h/crypto.hpp>

#include <asio.hpp>
#include <asio/ssl.hpp>

#include <filesystem>
#include <memory>
#include <string>

namespace co2h::server {
class Core;
}

namespace co2h::server::https {

struct HttpsConfig {
    std::string   name;
    std::string   bind_host = "0.0.0.0";
    std::uint16_t bind_port = 443;
    std::filesystem::path cert_file;
    std::filesystem::path key_file;
    MalleableProfile profile;
    crypto::AesKey   listener_key;   // shared AES-256 key baked into beacons
    Bytes            rsa_pub_blob;   // BCRYPT_RSAPUBLIC_BLOB — baked into beacon
    Bytes            rsa_priv_blob;  // BCRYPT_RSAFULLPRIVATE_BLOB — server only
};

class HttpsListener
    : public Listener,
      public std::enable_shared_from_this<HttpsListener> {
public:
    HttpsListener(std::shared_ptr<Core> core, HttpsConfig cfg);

    void        start() override;
    void        stop() override;
    std::string name()      const override { return cfg_.name; }
    std::string kind()      const override { return "https"; }
    std::string bind_addr() const override {
        return cfg_.bind_host + ":" + std::to_string(cfg_.bind_port);
    }
    std::string key_hex() const override {
        return co2h::hex_encode({cfg_.listener_key.data(), cfg_.listener_key.size()});
    }
    std::string pubkey_hex() const override {
        return co2h::hex_encode({cfg_.rsa_pub_blob.data(), cfg_.rsa_pub_blob.size()});
    }

    const MalleableProfile& profile() const { return cfg_.profile; }

    std::string uri_checkin()     const override { return cfg_.profile.get.uri_checkin; }
    std::string uri_task()        const override { return cfg_.profile.get.uri_task; }
    std::string uri_post()        const override { return cfg_.profile.post.uri; }
    std::string metadata_cookie() const override { return cfg_.profile.get.metadata_cookie; }
    std::string user_agent()      const override {
        auto it = cfg_.profile.get.client_headers.find("User-Agent");
        return it != cfg_.profile.get.client_headers.end() ? it->second : std::string{};
    }
    const crypto::AesKey&  listener_key() const { return cfg_.listener_key; }
    const crypto::AesKey& listener_key_data() const override { return cfg_.listener_key; }
    BytesView rsa_priv_data() const override {
        return {cfg_.rsa_priv_blob.data(), cfg_.rsa_priv_blob.size()};
    }
    BytesView              rsa_priv_blob() const {
        return {cfg_.rsa_priv_blob.data(), cfg_.rsa_priv_blob.size()};
    }
    BytesView              rsa_pub_blob() const {
        return {cfg_.rsa_pub_blob.data(), cfg_.rsa_pub_blob.size()};
    }
    std::shared_ptr<Core>  core() { return core_; }

private:
    void init_tls();
    void do_accept();

    std::shared_ptr<Core>  core_;
    HttpsConfig            cfg_;
    asio::ssl::context     tls_{asio::ssl::context::tls_server};
    asio::ip::tcp::acceptor acc_;
};

}
