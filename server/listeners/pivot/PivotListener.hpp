#pragma once

#include "../../Core.hpp"
#include "../../core/ListenerManager.hpp"

#include <asio.hpp>
#include <co2h/bytes.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace co2h::server::pivot {

// PivotConfig describes one pivot+socks listener pair:
//   pivot_port  — raw TCP port beacon connects to (carries frame protocol)
//   socks_port  — SOCKS5 port operators point their browser/proxychains at
struct PivotConfig {
    std::string   name;
    std::string   bind_host  = "0.0.0.0";
    std::uint16_t pivot_port = 4446;
    std::uint16_t socks_port = 1080;
};

class PivotConn;
class SocksSession;

// PivotListener manages:
//   1. A pivot acceptor  (pivot_port) — waits for one beacon raw TCP conn
//   2. A SOCKS5 acceptor (socks_port) — serves operator browsers
//
// When beacon connects, all pending and future SOCKS sessions use it.
class PivotListener
    : public Listener
    , public std::enable_shared_from_this<PivotListener> {
public:
    PivotListener(std::shared_ptr<Core> core, PivotConfig cfg);

    void        start()     override;
    void        stop()      override;
    std::string name()      const override { return cfg_.name; }
    std::string kind()      const override { return "pivot"; }
    std::string bind_addr() const override;

    // Called by PivotConn when it receives a DATA frame from beacon.
    void deliver_data(std::uint64_t conn_id, Bytes data);
    // Called by PivotConn when it receives a CLOSE frame from beacon.
    void deliver_close(std::uint64_t conn_id);
    // Called by PivotConn when beacon TCP connection drops.
    void on_beacon_disconnect();
    // Called by PivotConn once the raw TCP socket is ready.
    void on_beacon_connect(std::shared_ptr<PivotConn> pc);

    // Called by SocksSession to send frames to beacon.
    void send_connect(std::uint64_t conn_id,
                      const std::string& host, std::uint16_t port);
    void send_data  (std::uint64_t conn_id, BytesView data);
    void send_close (std::uint64_t conn_id);

    void register_session  (std::uint64_t id, std::shared_ptr<SocksSession> s);
    void unregister_session(std::uint64_t id);

    asio::io_context& io() const;

private:
    void accept_pivot();
    void accept_socks();

    std::shared_ptr<Core>  core_;
    PivotConfig            cfg_;
    asio::ip::tcp::acceptor pivot_acc_;
    asio::ip::tcp::acceptor socks_acc_;

    std::mutex                 mu_;
    std::shared_ptr<PivotConn> beacon_conn_; // current beacon TCP conn

    std::unordered_map<std::uint64_t,
                       std::shared_ptr<SocksSession>> sessions_;
};

} // namespace co2h::server::pivot
