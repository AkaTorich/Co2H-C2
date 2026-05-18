#pragma once

#include <QAbstractTableModel>
#include <QDateTime>
#include <QString>
#include <QVector>

namespace co2h::client {

struct CredentialRow {
    quint64    id = 0;      // 0 = ещё не присвоен сервером (локальная очередь add)
    QString    user;
    QString    domain;
    QString    kind;        // password | hash | ticket | identity
    QString    secret;
    QString    host;
    QString    source;      // manual | getuid | beacon_id
    QString    note;
    QString    added_by;    // оператор-источник (для UI)
    QDateTime  added_at;
};

class CredentialsModel : public QAbstractTableModel {
    Q_OBJECT
public:
    enum Column {
        ColUser = 0, ColDomain, ColKind, ColSecret, ColHost, ColSource, ColAddedBy, ColAdded, ColCount
    };

    explicit CredentialsModel(QObject* parent = nullptr);

    int rowCount(const QModelIndex&) const override { return rows_.size(); }
    int columnCount(const QModelIndex&) const override { return ColCount; }
    QVariant data(const QModelIndex&, int) const override;
    QVariant headerData(int, Qt::Orientation, int) const override;

    // Возвращает true если такая запись (user/domain/secret/kind) уже есть.
    bool exists(const CredentialRow& r) const;
    // Полная замена набора (сервер вернул creds.list).
    void setRows(QVector<CredentialRow> rows);
    // Локально добавляет запись (используется при serverless fallback / для UI-эха).
    void add(const CredentialRow& r);
    void removeAt(int row);
    void clear();

    const CredentialRow* at(int r) const {
        return (r >= 0 && r < rows_.size()) ? &rows_[r] : nullptr;
    }

private:
    QVector<CredentialRow> rows_;
};

}
