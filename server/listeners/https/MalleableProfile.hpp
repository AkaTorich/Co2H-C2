#pragma once

#include <co2h/bytes.hpp>

#include <filesystem>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace co2h::server::https {

// Minimal malleable profile for MVP. Full DSL lives in future releases; for
// now we consume a simple TOML document that covers the HTTP(S) transport:
//
//   [http-get]
//     uri_checkin = "/search"
//     uri_task    = "/api/feed"
//     verb        = "GET"
//     [http-get.client_headers]
//       "User-Agent" = "Mozilla/5.0 ..."
//       "Accept"     = "text/html,*/*;q=0.9"
//     metadata_cookie = "sid"          # where beacon metadata rides
//
//   [http-post]
//     uri         = "/submit"
//     verb        = "POST"
//     [http-post.client_headers]
//       "Content-Type" = "application/octet-stream"
//
//   [server]
//     status         = 200
//     content_type   = "text/html; charset=utf-8"
//     wrap_prefix    = "<html><body>"
//     wrap_suffix    = "</body></html>"
//
// Payloads are AES-GCM encrypted (session key), then base64url-encoded for
// GET, or sent raw in the body for POST.

struct HttpGetProfile {
    std::string uri_checkin = "/search";
    std::string uri_task    = "/api/feed";
    std::string verb        = "GET";
    std::unordered_map<std::string, std::string> client_headers;
    std::string metadata_cookie = "sid";
};

struct HttpPostProfile {
    std::string uri  = "/submit";
    std::string verb = "POST";
    std::unordered_map<std::string, std::string> client_headers;
};

struct ServerProfile {
    int         status = 200;
    std::string content_type = "text/html; charset=utf-8";
    std::string wrap_prefix;
    std::string wrap_suffix;
    std::unordered_map<std::string, std::string> headers;
};

struct MalleableProfile {
    HttpGetProfile  get;
    HttpPostProfile post;
    ServerProfile   server;
};

std::optional<MalleableProfile> load_profile(
    const std::filesystem::path& path, std::string& err);

MalleableProfile default_profile();

}
