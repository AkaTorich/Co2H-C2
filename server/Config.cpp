#include "Config.hpp"

#include <toml++/toml.hpp>

namespace co2h::server {

namespace {

template <typename View>
std::string str_or(View v, const std::string& fallback = {}) {
    if (auto s = v.template value<std::string>(); s) return *s;
    return fallback;
}

}

std::optional<Config> load_config(const std::filesystem::path& file,
                                  std::string& err) {
    toml::table tbl;
    try {
        tbl = toml::parse_file(file.string());
    } catch (const toml::parse_error& e) {
        err = e.description();
        return std::nullopt;
    }

    Config c;
    if (auto ops = tbl["operators"].as_table()) {
        c.operator_bind = str_or((*ops)["bind"], c.operator_bind);
        c.operator_port = static_cast<std::uint16_t>(
            (*ops)["port"].value_or<std::int64_t>(c.operator_port));
    }
    if (auto tls = tbl["tls"].as_table()) {
        c.tls.cert_file = str_or((*tls)["cert"]);
        c.tls.key_file  = str_or((*tls)["key"]);
        c.tls.ca_file   = str_or((*tls)["ca"]);
    }
    if (auto db = tbl["database"].as_table()) {
        c.database = str_or((*db)["path"], c.database.string());
    }
    if (auto io = tbl["io"].as_table()) {
        c.io_threads = static_cast<int>(
            (*io)["threads"].value_or<std::int64_t>(0));
    }
    if (auto log = tbl["log"].as_table()) {
        c.log_dir = str_or((*log)["dir"], c.log_dir.string());
    }

    if (auto arr = tbl["listeners"].as_array()) {
        for (auto& node : *arr) {
            if (auto* t = node.as_table()) {
                ListenerSeed ls;
                ls.kind = str_or((*t)["kind"], std::string{"https"});
                ls.name = str_or((*t)["name"]);
                ls.bind_host = str_or((*t)["bind"], std::string{"0.0.0.0"});
                ls.bind_port = static_cast<std::uint16_t>(
                    (*t)["port"].value_or<std::int64_t>(443));
                ls.tls_cert  = str_or((*t)["tls_cert"]);
                ls.tls_key   = str_or((*t)["tls_key"]);
                ls.profile   = str_or((*t)["profile"]);
                ls.beacon_id    = str_or((*t)["beacon_id"]);
                ls.c2_domain    = str_or((*t)["c2_domain"]);
                ls.listener_key = str_or((*t)["listener_key"]);
                c.listeners.push_back(std::move(ls));
            }
        }
    }

    if (c.tls.cert_file.empty() || c.tls.key_file.empty()) {
        err = "tls.cert and tls.key are required";
        return std::nullopt;
    }

    return c;
}

}
