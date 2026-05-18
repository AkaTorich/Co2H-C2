#pragma once

#include "../../core/ListenerManager.hpp"
#include <co2h/bytes.hpp>
#include <co2h/crypto.hpp>

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace co2h::server { class Core; }

namespace co2h::server::smb {

struct SmbConfig {
    std::string    name;
    std::string    pipe_name = "co2h";   // → \\.\pipe\<pipe_name>
    crypto::AesKey listener_key;
    Bytes          rsa_pub_blob;   // BCRYPT_RSAPUBLIC_BLOB — baked into beacon
    Bytes          rsa_priv_blob;  // BCRYPT_RSAFULLPRIVATE_BLOB — server only
};

// SMB listener: hosts a named pipe и принимает beacon-ы.
// Реализован на чистом Win32 (CreateNamedPipeW + ConnectNamedPipe) в фоновом
// потоке. На не-Windows платформах start() — no-op.
class SmbListener
    : public Listener,
      public std::enable_shared_from_this<SmbListener> {
public:
    SmbListener(std::shared_ptr<Core> core, SmbConfig cfg);
    ~SmbListener();

    void start() override;
    void stop() override;
    std::string name()      const override { return cfg_.name; }
    std::string kind()      const override { return "smb"; }
    std::string bind_addr() const override {
        return std::string{"\\\\.\\pipe\\"} + cfg_.pipe_name;
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
    void accept_loop();

    std::shared_ptr<Core> core_;
    SmbConfig             cfg_;
    std::atomic<bool>     stop_{false};
    std::thread           accept_thread_;
};

}
