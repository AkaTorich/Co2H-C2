#pragma once

#include <QDialog>
#include <QString>

class QLineEdit;
class QPushButton;
class QLabel;

namespace co2h::client::ui {

struct LoginInfo {
    QString host;
    quint16 port = 50050;
    QString username;
    QString password;
    QString ca_file;
    QString client_cert;
    QString client_key;
};

class LoginDialog : public QDialog {
    Q_OBJECT
public:
    explicit LoginDialog(QWidget* parent = nullptr);
    LoginInfo info() const;
    void prefill(const LoginInfo& info);
    void setStatus(const QString& msg, bool error = false);

private:
    QLineEdit* host_ = nullptr;
    QLineEdit* port_ = nullptr;
    QLineEdit* user_ = nullptr;
    QLineEdit* pass_ = nullptr;
    QLineEdit* ca_   = nullptr;
    QLineEdit* cert_ = nullptr;
    QLineEdit* key_  = nullptr;
    QLabel*    status_ = nullptr;
    QPushButton* connect_ = nullptr;
};

}
