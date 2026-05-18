#include "ListenersModel.hpp"

namespace co2h::client {

ListenersModel::ListenersModel(QObject* parent) : QAbstractTableModel(parent) {}

void ListenersModel::setRows(QVector<ListenerRow> rows) {
    beginResetModel();
    rows_ = std::move(rows);
    endResetModel();
}

QVariant ListenersModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || index.row() >= rows_.size()) return {};
    const auto& r = rows_[index.row()];
    if (role == Qt::UserRole) {
        switch (index.column()) {
            case ColKey:  return r.key_hex;
            case ColKind: return r.kind;
            case ColBind: return r.domain;
            default:      break;
        }
    }
    if (role != Qt::DisplayRole) return {};
    switch (index.column()) {
        case ColName: return r.name;
        case ColKind: return r.kind;
        case ColBind: return r.bind;
        case ColKey:  return r.key_hex.left(16) + "…";
    }
    return {};
}

QVariant ListenersModel::headerData(int section, Qt::Orientation o, int role) const {
    if (o != Qt::Horizontal || role != Qt::DisplayRole) return {};
    switch (section) {
        case ColName: return "Name";
        case ColKind: return "Kind";
        case ColBind: return "Bind";
        case ColKey:  return "Key (partial)";
    }
    return {};
}

}
