#pragma once

#include <co2h/bytes.hpp>

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

struct sqlite3;
struct sqlite3_stmt;

namespace co2h::server {

struct OperatorRow {
    std::int64_t id{};
    std::string  username;
    std::string  password_hash;
    std::string  role;          // "admin", "operator"
    std::int64_t created_at{};
};

struct CredentialRow {
    std::int64_t id{};
    std::string  user;
    std::string  domain;
    std::string  kind;          // password | hash | ticket | identity
    std::string  secret;
    std::string  host;
    std::string  source;
    std::string  note;
    std::string  added_by;      // operator username
    std::int64_t added_at{};
};

// Thin synchronous wrapper around SQLite. Access is serialized via mutex;
// the server runs a small number of writes relative to network I/O.
class Database {
public:
    explicit Database(const std::filesystem::path& path);
    ~Database();
    Database(const Database&)            = delete;
    Database& operator=(const Database&) = delete;

    bool migrate();

    std::optional<OperatorRow> find_operator(const std::string& username);
    std::int64_t               add_operator(const std::string& username,
                                            const std::string& password_hash,
                                            const std::string& role);
    std::vector<OperatorRow>   list_operators();
    bool                       delete_operator(std::int64_t id);
    bool                       set_operator_password(std::int64_t id,
                                                     const std::string& password_hash);

    void log_audit(const std::string& op_username,
                   const std::string& action,
                   const std::string& detail);

    // Persistent listener key storage (survives server restarts).
    std::optional<std::string> get_listener_key_hex(const std::string& name);
    void set_listener_key_hex(const std::string& name, const std::string& hex);

    // Persistent RSA-OAEP keypair per HTTPS listener. Blobs are BCrypt-format
    // (BCRYPT_RSAPUBLIC_BLOB / BCRYPT_RSAFULLPRIVATE_BLOB).
    bool get_listener_rsa(const std::string& name,
                          Bytes& pub_blob, Bytes& priv_blob);
    void set_listener_rsa(const std::string& name,
                          BytesView pub_blob, BytesView priv_blob);

    // Credentials store (shared across operators).
    std::vector<CredentialRow> creds_list();
    std::int64_t               creds_add(const CredentialRow& r);
    bool                       creds_del(std::int64_t id);

private:
    bool exec(const char* sql);

    sqlite3*   db_ = nullptr;
    std::mutex mu_;
};

}
