#pragma once

#include "../net/ServerClient.hpp"

#include <QAbstractTableModel>
#include <QVector>

namespace co2h::client {

class SessionsModel : public QAbstractTableModel {
    Q_OBJECT
public:
    enum Column {
        ColId = 0, ColHost, ColIp, ColUser, ColPid, ColArch, ColOs, ColListener, ColFirstSeen, ColLastSeen, ColCount
    };

    explicit SessionsModel(QObject* parent = nullptr);

    int rowCount(const QModelIndex&) const override { return rows_.size(); }
    int columnCount(const QModelIndex&) const override { return ColCount; }
    QVariant data(const QModelIndex& index, int role) const override;
    QVariant headerData(int section, Qt::Orientation, int role) const override;

    const BeaconRow* row(int r) const {
        return (r >= 0 && r < rows_.size()) ? &rows_[r] : nullptr;
    }

    // Доступ ко всему вектору (для скриптового движка и сравнений).
    const QVector<BeaconRow>& rows() const { return rows_; }

    // Поиск бикона по ID.
    const BeaconRow* findById(const QString& id) const {
        for (const auto& r : rows_)
            if (r.id == id) return &r;
        return nullptr;
    }

public slots:
    void setRows(QVector<BeaconRow> rows);

private:
    QVector<BeaconRow> rows_;
};

}
