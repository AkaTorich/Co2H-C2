#pragma once

#include <co2h/bytes.hpp>
#include <co2h/crypto.hpp>

#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace co2h::server {

class Listener {
public:
    virtual ~Listener()                  = default;
    virtual void        start()          = 0;
    virtual void        stop()           = 0;
    virtual std::string name() const     = 0;
    virtual std::string kind() const     = 0;
    virtual std::string bind_addr() const= 0;
    virtual std::string key_hex() const  { return {}; }
    // RSA-2048 BCRYPT_RSAPUBLIC_BLOB hex (only HTTPS). Empty for transports
    // that do not negotiate per-session keys.
    virtual std::string pubkey_hex() const { return {}; }
    // C2 domain suffix (DNS only). Empty for all other transports.
    virtual std::string domain() const { return {}; }

    // Malleable profile fields (HTTPS only). Empty for all other transports.
    // Used by kListListeners to propagate URI/cookie to the client so
    // artifact-gen receives the correct values at build time.
    virtual std::string uri_checkin()     const { return {}; }
    virtual std::string uri_task()        const { return {}; }
    virtual std::string uri_post()        const { return {}; }
    virtual std::string metadata_cookie() const { return {}; }
    virtual std::string user_agent()      const { return {}; }

    // Raw AES listener key (32 bytes). Used by relay processing to decrypt
    // child beacon CHECKIN frames that arrive through a relay parent.
    virtual const crypto::AesKey& listener_key_data() const {
        static const crypto::AesKey empty{};
        return empty;
    }
    // BCRYPT_RSAFULLPRIVATE_BLOB. Used by relay to unwrap per-session key
    // from child beacon CHECKIN.
    virtual BytesView rsa_priv_data() const { return {}; }
};

class ListenerManager {
public:
    using Factory = std::function<std::shared_ptr<Listener>()>;

    bool add(const std::string& name, Factory factory);
    bool remove(const std::string& name);

    std::shared_ptr<Listener> get(const std::string& name);
    std::vector<std::shared_ptr<Listener>> list();

    void stop_all();

private:
    std::mutex mu_;
    std::unordered_map<std::string, std::shared_ptr<Listener>> by_name_;
};

}
