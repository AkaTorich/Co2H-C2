#pragma once

#include "../models/CredentialsModel.hpp"

#include <QWidget>

class QTableView;

namespace co2h::client {
class CredentialsModel;
}

namespace co2h::client::ui {

class CredentialsView : public QWidget {
    Q_OBJECT
public:
    explicit CredentialsView(CredentialsModel* model, QWidget* parent = nullptr);

signals:
    // Оператор хочет применить пару user/pass на активном beacon'е через
    // make_token. MainWindow обрабатывает это, формируя задачу.
    void applyMakeToken(const QString& domainBackslashUser,
                        const QString& password);
    // Запросы к серверному хранилищу.
    void requestRefresh();
    void requestAdd(const co2h::client::CredentialRow& r);
    void requestDelete(quint64 id);

private slots:
    void onAdd();
    void onRemove();
    void onUse();
    void onCopySecret();
    void onRefresh();
    void onContextMenu(const QPoint&);

private:
    CredentialsModel* model_;
    QTableView*       view_;
};

}
