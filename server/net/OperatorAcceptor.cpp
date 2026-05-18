#include "OperatorAcceptor.hpp"
#include "OperatorSession.hpp"
#include "../Core.hpp"

#include <spdlog/spdlog.h>

namespace co2h::server {

OperatorAcceptor::OperatorAcceptor(std::shared_ptr<Core> core)
    : core_(std::move(core)),
      acc_(core_->io()) {}

void OperatorAcceptor::start() {
    asio::ip::tcp::endpoint ep{
        asio::ip::make_address(core_->config().operator_bind),
        core_->config().operator_port};
    acc_.open(ep.protocol());
    acc_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
    acc_.bind(ep);
    acc_.listen();
    spdlog::info("operator acceptor listening on {}:{}",
                 core_->config().operator_bind,
                 core_->config().operator_port);
    do_accept();
}

void OperatorAcceptor::stop() {
    std::error_code ec;
    acc_.close(ec);
}

void OperatorAcceptor::do_accept() {
    auto self = shared_from_this();
    auto sock = std::make_shared<asio::ip::tcp::socket>(core_->io());
    acc_.async_accept(*sock, [this, self, sock](const std::error_code& ec) {
        if (ec) {
            if (ec != asio::error::operation_aborted)
                spdlog::warn("operator accept: {}", ec.message());
            return;
        }
        auto stream = OperatorSession::SslStream{std::move(*sock),
                                                 core_->operator_tls()};
        auto sess = std::make_shared<OperatorSession>(core_, std::move(stream));
        sess->start();
        do_accept();
    });
}

}
