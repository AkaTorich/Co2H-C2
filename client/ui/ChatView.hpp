#pragma once

#include <QWidget>

class QLineEdit;
class QPlainTextEdit;

namespace co2h::client::ui {

class ChatView : public QWidget {
    Q_OBJECT
public:
    explicit ChatView(QWidget* parent = nullptr);

    // Чтобы выделять собственные сообщения и не задавать from себе.
    void setSelfUsername(const QString& name);

public slots:
    // Вызывается из MainWindow по сигналу ServerClient::chatReceived.
    void appendMessage(const QString& from, const QString& text, quint64 ts);
    // Локальная вставка системного сообщения (статус подключения и т. п.).
    void appendSystem(const QString& text);

signals:
    void sendRequested(const QString& text);

private slots:
    void onSubmit();

private:
    QString          self_;
    QPlainTextEdit*  output_ = nullptr;
    QLineEdit*       input_  = nullptr;
};

}
