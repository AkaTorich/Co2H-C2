// RportfwdListener.cpp — серверная часть Reverse Port Forward.
//
// Принимает TCP-соединения на bind_port, задаёт биконy OP_RPORTFWD_OPEN,
// маршрутизирует трафик между клиентом и биконом через C2-канал.

#include "RportfwdListener.hpp"
#include "../../Core.hpp"
#include "../../core/TaskQueue.hpp"

#include <co2h/kv.hpp>
#include <co2h/proto.hpp>
#include <spdlog/spdlog.h>

#include <array>
#include <cstring>

namespace co2h::server::rportfwd {

using namespace ::co2h::kv;

// ---- Состояние одного соединения -----------------------------------------

struct RportfwdListener::RpfConn
    : public std::enable_shared_from_this<RpfConn> {

    RpfConn(std::shared_ptr<RportfwdListener> l,
            asio::ip::tcp::socket s,
            std::uint64_t cid)
        : listener(std::move(l)), sock(std::move(s)), conn_id(cid)
    {}

    std::shared_ptr<RportfwdListener> listener;
    asio::ip::tcp::socket             sock;
    std::uint64_t                     conn_id;
    bool                              beacon_connected = false;

    void do_read() {
        auto self = shared_from_this();
        auto buf  = std::make_shared<std::array<std::uint8_t, 4096>>();
        sock.async_read_some(asio::buffer(*buf),
            [this, self, buf](const std::error_code& ec, std::size_t n) {
                if (ec) {
                    // Клиент отключился — закрыть соединение на бикона.
                    listener->close_conn(conn_id);
                    return;
                }
                if (!beacon_connected) {
                    // Данные пришли до того как бикон подключился — пока игнорируем.
                    // В production можно буферизовать.
                    do_read();
                    return;
                }
                // Переслать данные биконy через OP_RPORTFWD_DATA задачу.
                Writer w;
                w.put_u64("conn_id", conn_id);
                w.put_bytes("data", {buf->data(), n});
                auto pl = w.finish();
                listener->core_->tasks().enqueue(
                    listener->beacon_id_,
                    proto::TaskOp::RportfwdData,
                    Bytes{pl.begin(), pl.end()}, 0);
                do_read();
            });
    }

    void close() {
        std::error_code ec;
        sock.close(ec);
    }
};

// ---- RportfwdListener -------------------------------------------------------

RportfwdListener::RportfwdListener(std::shared_ptr<Core> core,
                                   std::string name,
                                   std::string bind_host,
                                   std::uint16_t bind_port,
                                   std::string beacon_id,
                                   std::string rhost,
                                   std::uint16_t rport)
    : core_(std::move(core))
    , name_(std::move(name))
    , bind_host_(std::move(bind_host))
    , bind_port_(bind_port)
    , beacon_id_(std::move(beacon_id))
    , rhost_(std::move(rhost))
    , rport_(rport)
    , acc_(core_->io())
{}

void RportfwdListener::start() {
    asio::ip::tcp::endpoint ep{
        asio::ip::make_address(bind_host_), bind_port_};
    acc_.open(ep.protocol());
    acc_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
    acc_.bind(ep);
    acc_.listen();
    spdlog::info("rportfwd listener '{}' on {} beacon={} -> {}:{}",
                 name_, bind_addr(), beacon_id_, rhost_, rport_);
    do_accept();
}

void RportfwdListener::stop() {
    std::error_code ec;
    acc_.close(ec);
    std::lock_guard lk{mu_};
    for (auto& [id, conn] : conns_) conn->close();
    conns_.clear();
}

void RportfwdListener::do_accept() {
    auto self = shared_from_this();
    auto sock = std::make_shared<asio::ip::tcp::socket>(core_->io());
    acc_.async_accept(*sock, [this, self, sock](const std::error_code& ec) {
        if (ec) {
            if (ec != asio::error::operation_aborted)
                spdlog::warn("rportfwd '{}' accept: {}", name_, ec.message());
            return;
        }
        auto cid  = next_conn_id_.fetch_add(1);
        auto conn = std::make_shared<RpfConn>(self, std::move(*sock), cid);
        {
            std::lock_guard lk{mu_};
            conns_[cid] = conn;
        }
        // Задаём биконy задачу: подключиться к rhost:rport с данным conn_id.
        task_beacon_open(cid);
        // Начинаем читать от клиента (данные буферизуются до beacon_connected=true).
        conn->do_read();
        do_accept();
    });
}

void RportfwdListener::task_beacon_open(std::uint64_t conn_id) {
    Writer w;
    w.put_u64("conn_id", conn_id);
    w.put_str("rhost",   rhost_);
    w.put_u32("rport",   rport_);
    auto pl = w.finish();
    core_->tasks().enqueue(beacon_id_,
        proto::TaskOp::RportfwdOpen,
        Bytes{pl.begin(), pl.end()}, 0);
    spdlog::debug("rportfwd '{}' open conn={} -> {}:{}", name_, conn_id, rhost_, rport_);
}

void RportfwdListener::route_data_to_client(std::uint64_t conn_id, BytesView data) {
    std::shared_ptr<RpfConn> conn;
    {
        std::lock_guard lk{mu_};
        auto it = conns_.find(conn_id);
        if (it == conns_.end()) return;
        conn = it->second;
    }
    // Асинхронная отправка данных клиенту.
    auto buf = std::make_shared<Bytes>(data.begin(), data.end());
    auto self = shared_from_this();
    asio::async_write(conn->sock, asio::buffer(*buf),
        [this, self, conn_id, buf](const std::error_code& ec, std::size_t) {
            if (ec) {
                spdlog::debug("rportfwd '{}' write to client failed: {}", name_, ec.message());
                close_conn(conn_id);
            }
        });
}

void RportfwdListener::close_conn(std::uint64_t conn_id) {
    std::shared_ptr<RpfConn> conn;
    {
        std::lock_guard lk{mu_};
        auto it = conns_.find(conn_id);
        if (it == conns_.end()) return;
        conn = it->second;
        conns_.erase(it);
    }
    conn->close();
    // Сказать биконy закрыть соединение.
    Writer w;
    w.put_u64("conn_id", conn_id);
    auto pl = w.finish();
    core_->tasks().enqueue(beacon_id_,
        proto::TaskOp::RportfwdClose,
        Bytes{pl.begin(), pl.end()}, 0);
}

// Вызывается Core::route_rportfwd_output() при получении RPORTFWD_TASK_MAGIC.
// Формат data: [u64 conn_id BE][u8 type][optional payload]
void RportfwdListener::on_beacon_output(BytesView data) {
    if (data.size() < 9) return;

    std::uint64_t cid = 0;
    for (int i = 0; i < 8; ++i) cid = (cid << 8) | data[i];
    std::uint8_t type = data[8];
    BytesView payload{data.data() + 9, data.size() - 9};

    std::shared_ptr<RpfConn> conn;
    {
        std::lock_guard lk{mu_};
        auto it = conns_.find(cid);
        if (it == conns_.end()) return;
        conn = it->second;
    }

    switch (type) {
        case 0x01: // CONNECT_OK — бикон подключился к rhost:rport
            spdlog::debug("rportfwd '{}' conn={} CONNECT_OK", name_, cid);
            conn->beacon_connected = true;
            break;

        case 0x02: // CONNECT_FAIL
            spdlog::debug("rportfwd '{}' conn={} CONNECT_FAIL", name_, cid);
            close_conn(cid);
            break;

        case 0x03: // DATA: [u32 len BE][bytes]
            if (payload.size() >= 4) {
                std::uint32_t dlen =
                    (std::uint32_t(payload[0]) << 24) |
                    (std::uint32_t(payload[1]) << 16) |
                    (std::uint32_t(payload[2]) <<  8) |
                     std::uint32_t(payload[3]);
                if (dlen > 0 && payload.size() >= 4u + dlen)
                    route_data_to_client(cid, {payload.data() + 4, dlen});
            }
            break;

        case 0x04: // CLOSE
            close_conn(cid);
            break;
    }
}

}
