#pragma once

#include <QString>
#include <QWidget>

class QTableView;

namespace co2h::client {
class SessionsModel;
class ServerClient;
}

namespace co2h::client::ui {

class SessionsView : public QWidget {
    Q_OBJECT
public:
    explicit SessionsView(SessionsModel* model, ServerClient* client,
                          QWidget* parent = nullptr);

signals:
    void interactRequested(const QString& beacon_id);
    void relayChildRequested(const QString& beacon_id,
                             const QString& internal_ip,
                             const QString& listener_name);

private:
    SessionsModel* model_;
    ServerClient*  client_;
    QTableView*    view_;
};

}
