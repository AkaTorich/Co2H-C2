#include "MalleableProfile.hpp"

#include <toml++/toml.hpp>

namespace co2h::server::https {

namespace {

void load_headers(toml::node* n,
                  std::unordered_map<std::string, std::string>& dst) {
    if (!n) return;
    if (auto* t = n->as_table()) {
        for (auto&& [k, v] : *t) {
            if (auto s = v.value<std::string>(); s) dst.emplace(k.str(), *s);
        }
    }
}

}

MalleableProfile default_profile() {
    MalleableProfile p;
    p.get.client_headers["User-Agent"] =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
    p.get.client_headers["Accept"] = "text/html,application/xhtml+xml,"
                                     "application/xml;q=0.9,*/*;q=0.8";
    p.post.client_headers["Content-Type"] = "application/octet-stream";
    p.server.headers["Server"] = "nginx";
    return p;
}

std::optional<MalleableProfile> load_profile(
    const std::filesystem::path& path, std::string& err) {
    if (path.empty()) return default_profile();
    toml::table tbl;
    try {
        tbl = toml::parse_file(path.string());
    } catch (const toml::parse_error& e) {
        err = std::string(e.description());
        return std::nullopt;
    } catch (const std::exception& e) {
        err = e.what();
        return std::nullopt;
    }
    MalleableProfile p = default_profile();

    if (auto g = tbl["http-get"].as_table()) {
        p.get.uri_checkin = (*g)["uri_checkin"].value_or(p.get.uri_checkin);
        p.get.uri_task    = (*g)["uri_task"].value_or(p.get.uri_task);
        p.get.verb        = (*g)["verb"].value_or(p.get.verb);
        p.get.metadata_cookie =
            (*g)["metadata_cookie"].value_or(p.get.metadata_cookie);
        load_headers((*g)["client_headers"].node(), p.get.client_headers);
    }
    if (auto po = tbl["http-post"].as_table()) {
        p.post.uri  = (*po)["uri"].value_or(p.post.uri);
        p.post.verb = (*po)["verb"].value_or(p.post.verb);
        load_headers((*po)["client_headers"].node(), p.post.client_headers);
    }
    if (auto s = tbl["server"].as_table()) {
        p.server.status       = static_cast<int>(
            (*s)["status"].value_or<std::int64_t>(p.server.status));
        p.server.content_type = (*s)["content_type"].value_or(p.server.content_type);
        p.server.wrap_prefix  = (*s)["wrap_prefix"].value_or(p.server.wrap_prefix);
        p.server.wrap_suffix  = (*s)["wrap_suffix"].value_or(p.server.wrap_suffix);
        load_headers((*s)["headers"].node(), p.server.headers);
    }
    return p;
}

}
