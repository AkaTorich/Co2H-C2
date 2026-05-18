#pragma once

#include <asio.hpp>
#include <memory>

namespace co2h::server {

class Core;

class OperatorAcceptor : public std::enable_shared_from_this<OperatorAcceptor> {
public:
    explicit OperatorAcceptor(std::shared_ptr<Core> core);
    void start();
    void stop();

private:
    void do_accept();

    std::shared_ptr<Core>        core_;
    asio::ip::tcp::acceptor      acc_;
};

}
