#pragma once

#include "../db/Database.hpp"

#include <memory>
#include <optional>
#include <string>

namespace co2h::server {

struct AuthResult {
    std::int64_t operator_id{};
    std::string  username;
    std::string  role;
};

class OperatorAuth {
public:
    explicit OperatorAuth(std::shared_ptr<Database> db) : db_(std::move(db)) {}

    std::optional<AuthResult> authenticate(const std::string& username,
                                           const std::string& password);

    bool ensure_default_admin(const std::string& default_password);

private:
    std::shared_ptr<Database> db_;
};

}
