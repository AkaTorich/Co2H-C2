#pragma once

#include "../net/ServerClient.hpp"

#include <QAbstractTableModel>
#include <QVector>

namespace co2h::client {

class ListenersModel : public QAbstractTableModel {
    Q_OBJECT
public:
    enum Column { ColName = 0, ColKind, ColBind, ColKey, ColCount };

    explicit ListenersModel(QObject* parent = nullptr);

    int rowCount(const QModelIndex&) const override { return rows_.size(); }
    int columnCount(const QModelIndex&) const override { return ColCount; }
    QVariant data(const QModelIndex& index, int role) const override;
    QVariant headerData(int section, Qt::Orientation, int role) const override;

    const ListenerRow* row(int r) const {
        return (r >= 0 && r < rows_.size()) ? &rows_[r] : nullptr;
    }

public slots:
    void setRows(QVector<ListenerRow> rows);

private:
    QVector<ListenerRow> rows_;
};

}
