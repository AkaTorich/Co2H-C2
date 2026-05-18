#pragma once

#include <co2h/framing.hpp>
#include <co2h/kv.hpp>
#include <co2h/proto.hpp>

#include <asio.hpp>
#include <asio/ssl.hpp>

#include <array>
#include <deque>
#include <memory>
#include <mutex>
#include <string>

namespace co2h::server {

class Core;

class OperatorSession : public std::enable_shared_from_this<OperatorSession> {
public:
    using SslStream = asio::ssl::stream<asio::ip::tcp::socket>;

    OperatorSession(std::shared_ptr<Core> core, SslStream&& stream);
    ~OperatorSession();

    void start();
    void close();

    void send_event(proto::EventCategory cat, BytesView payload);
    void send_response(std::uint64_t rpc_id, int status, BytesView payload);

    const std::string& username() const { return username_; }
    const std::string& role() const { return role_; }
    std::int64_t operator_id() const { return operator_id_; }

private:
    void do_read();
    void on_read(std::size_t n);
    void process_frame(const proto::Frame& f);
    void handle_hello(BytesView payload);
    void handle_auth(BytesView payload);
    void handle_subscribe(BytesView payload);
    void handle_command(BytesView payload);

    void enqueue_send(proto::MsgType type, BytesView payload);
    void do_write();

    std::shared_ptr<Core> core_;
    SslStream             stream_;
    FrameDecoder          decoder_;
    std::array<std::uint8_t, 8192> rbuf_{};

    std::mutex          wmu_;
    std::deque<Bytes>   wq_;
    bool                writing_ = false;

    std::string   username_;
    std::int64_t  operator_id_ = 0;
    std::string   role_;
    bool          authed_   = false;
    std::uint32_t subscriptions_ = 0;
    bool          closed_   = false;
};

}
