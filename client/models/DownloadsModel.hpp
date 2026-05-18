#pragma once

#include <QAbstractTableModel>
#include <QDateTime>
#include <QString>
#include <QVector>

namespace co2h::client {

struct DownloadRow {
    quint64    task_id   = 0;          // 0 = pending (task_id ещё не пришёл)
    quint64    rpc_id    = 0;
    QString    beacon_id;
    QString    remote;
    QString    local;
    qint64     size      = -1;          // -1 = unknown / pending
    QDateTime  requested;
    QDateTime  completed;               // invalid пока не завершено
    QString    status;                  // pending | ok | error
    QString    error;
};

class DownloadsModel : public QAbstractTableModel {
    Q_OBJECT
public:
    enum Column {
        ColTime = 0, ColBeacon, ColRemote, ColLocal, ColSize, ColStatus, ColCount
    };

    explicit DownloadsModel(QObject* parent = nullptr);

    int rowCount(const QModelIndex&) const override { return rows_.size(); }
    int columnCount(const QModelIndex&) const override { return ColCount; }
    QVariant data(const QModelIndex&, int) const override;
    QVariant headerData(int, Qt::Orientation, int) const override;

    // Возвращает индекс созданной строки. Сразу же сериализуем.
    int addPending(quint64 rpc_id, const QString& beacon_id,
                   const QString& remote, const QString& local);

    // Сервер выдал task_id для ранее зарегистрированного rpc_id.
    void bindTaskId(quint64 rpc_id, quint64 task_id);

    // Завершение задачи. Если error непуст → status=error.
    void markCompleted(quint64 task_id, qint64 size, const QString& error);

    void removeAt(int row);
    void clear();

    const DownloadRow* at(int r) const {
        return (r >= 0 && r < rows_.size()) ? &rows_[r] : nullptr;
    }

    // Полная сериализация в QSettings (JSON-список).
    void load();
    void save() const;

private:
    QVector<DownloadRow> rows_;
};

}
