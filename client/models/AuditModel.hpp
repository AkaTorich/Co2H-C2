#pragma once

#include <QAbstractTableModel>
#include <QDateTime>
#include <QString>
#include <QVector>

namespace co2h::client {

// Одна запись журнала аудита: кто, когда, на каком beacon'е, какую команду выполнил.
struct AuditEntry {
    QDateTime timestamp;
    QString   op;          // имя оператора
    QString   beacon_id;   // идентификатор beacon'а
    QString   beacon_name; // алиас / hostname (для удобства чтения)
    QString   command;     // полная строка команды
};

class AuditModel : public QAbstractTableModel {
    Q_OBJECT
public:
    enum Column {
        ColTime = 0, ColOperator, ColBeaconId, ColBeaconName, ColCommand, ColCount
    };

    explicit AuditModel(QObject* parent = nullptr);

    int rowCount(const QModelIndex&) const override { return rows_.size(); }
    int columnCount(const QModelIndex&) const override { return ColCount; }
    QVariant data(const QModelIndex&, int) const override;
    QVariant headerData(int, Qt::Orientation, int) const override;

    // Добавить запись в начало таблицы (новые сверху).
    void append(const AuditEntry& entry);

    // Очистить журнал.
    void clear();

    const AuditEntry* at(int row) const {
        return (row >= 0 && row < rows_.size()) ? &rows_[row] : nullptr;
    }

private:
    QVector<AuditEntry> rows_;
};

}
