#include "OperatorAuth.hpp"

#include <co2h/crypto.hpp>
#include <spdlog/spdlog.h>

namespace co2h::server {

std::optional<AuthResult> OperatorAuth::authenticate(const std::string& username,
                                                     const std::string& password) {
    auto row = db_->find_operator(username);
    if (!row) return std::nullopt;
    if (!crypto::password_verify(password, row->password_hash)) return std::nullopt;
    return AuthResult{row->id, row->username, row->role};
}

bool OperatorAuth::ensure_default_admin(const std::string& default_password) {
    if (db_->find_operator("admin")) return false;
    auto hash = crypto::password_hash(default_password);
    if (hash.empty()) return false;
    auto id = db_->add_operator("admin", hash, "admin");
    if (id > 0) {
        spdlog::warn("created default 'admin' operator — change the password!");
        db_->log_audit("system", "create_operator", "admin");
        return true;
    }
    return false;
}

}
