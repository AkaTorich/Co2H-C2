#pragma once

#include "../../core/ListenerManager.hpp"

#include <co2h/bytes.hpp>

#include <asio.hpp>

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace co2h::server { class Core; }

namespace co2h::server::socks5 {

// SOCKS5 listener on teamserver.
// Принимает подключения от proxychains/etc, проксирует трафик через C2-канал
// указанного бикона с помощью OP_SOCKS_OPEN/DATA/CLOSE задач.
//
// Когда бикон отвечает на задачи (SOCKS_TASK_MAGIC output), ядро вызывает
// on_beacon_output() для маршрутизации данных к нужному клиентскому сокету.
class Socks5Listener
    : public Listener,
      public std::enable_shared_from_this<Socks5Listener> {
public:
    Socks5Listener(std::shared_ptr<Core> core,
                   std::string name,
                   std::string bind_host,
                   std::uint16_t bind_port,
                   std::string beacon_id);

    void        start()          override;
    void        stop()           override;
    std::string name()      const override { return name_; }
    std::string kind()      const override { return "socks5"; }
    std::string bind_addr() const override {
        return bind_host_ + ":" + std::to_string(bind_port_);
    }

    // Вызывается ядром, когда получены данные от бикона (SOCKS_TASK_MAGIC).
    // Формат data: [u64 conn_id BE][u8 type][payload...]
    void on_beacon_output(BytesView data);

    const std::string& beacon_id() const { return beacon_id_; }

private:
    struct SocksConn;
    void do_accept();

    std::shared_ptr<Core>  core_;
    std::string            name_;
    std::string            bind_host_;
    std::uint16_t          bind_port_;
    std::string            beacon_id_;
    asio::ip::tcp::acceptor acc_;

    std::mutex mu_;
    std::unordered_map<std::uint64_t, std::shared_ptr<SocksConn>> conns_;
    std::atomic<std::uint64_t> next_conn_id_{1};
};

}
