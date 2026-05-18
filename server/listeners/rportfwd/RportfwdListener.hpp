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

namespace co2h::server::rportfwd {

// Обратный проброс порта (Reverse Port Forward).
// Teamserver открывает TCP-листенер на bind_port; когда клиент подключается,
// сервер задаёт биконy OP_RPORTFWD_OPEN {conn_id, rhost, rport}.
// Бикон подключается к rhost:rport и сигнализирует через RPORTFWD_TASK_MAGIC.
// Данные маршрутизируются:
//   server → beacon: OP_RPORTFWD_DATA задачи
//   beacon → server: RPORTFWD_TASK_MAGIC out-of-band кадры (→ on_beacon_output)
class RportfwdListener
    : public Listener,
      public std::enable_shared_from_this<RportfwdListener> {
public:
    RportfwdListener(std::shared_ptr<Core> core,
                     std::string name,
                     std::string bind_host,
                     std::uint16_t bind_port,
                     std::string beacon_id,
                     std::string rhost,
                     std::uint16_t rport);

    void        start()          override;
    void        stop()           override;
    std::string name()      const override { return name_; }
    std::string kind()      const override { return "rportfwd"; }
    std::string bind_addr() const override {
        return bind_host_ + ":" + std::to_string(bind_port_);
    }

    // Вызывается ядром при поступлении RPORTFWD_TASK_MAGIC данных от бикона.
    // Формат data: [u64 conn_id BE][u8 type][optional payload]
    void on_beacon_output(BytesView data);

    const std::string& beacon_id() const { return beacon_id_; }

private:
    struct RpfConn;
    void do_accept();
    void task_beacon_open(std::uint64_t conn_id);
    void route_data_to_client(std::uint64_t conn_id, BytesView data);
    void close_conn(std::uint64_t conn_id);

    std::shared_ptr<Core>    core_;
    std::string              name_;
    std::string              bind_host_;
    std::uint16_t            bind_port_;
    std::string              beacon_id_;
    std::string              rhost_;
    std::uint16_t            rport_;
    asio::ip::tcp::acceptor  acc_;

    std::mutex mu_;
    std::unordered_map<std::uint64_t, std::shared_ptr<RpfConn>> conns_;
    std::atomic<std::uint64_t> next_conn_id_{1};
};

}
