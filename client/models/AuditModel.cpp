#include "AuditModel.hpp"

#include <QColor>

namespace co2h::client {

AuditModel::AuditModel(QObject* parent) : QAbstractTableModel(parent) {}

QVariant AuditModel::headerData(int s, Qt::Orientation o, int role) const {
    if (role != Qt::DisplayRole || o != Qt::Horizontal) return {};
    switch (s) {
        case ColTime:       return "Time";
        case ColOperator:   return "Operator";
        case ColBeaconId:   return "Beacon ID";
        case ColBeaconName: return "Beacon";
        case ColCommand:    return "Command";
    }
    return {};
}

QVariant AuditModel::data(const QModelIndex& idx, int role) const {
    if (!idx.isValid() || idx.row() >= rows_.size()) return {};
    const auto& r = rows_[idx.row()];

    if (role == Qt::DisplayRole) {
        switch (idx.column()) {
            case ColTime:       return r.timestamp.toString("yyyy-MM-dd HH:mm:ss");
            case ColOperator:   return r.op;
            case ColBeaconId:   return r.beacon_id;
            case ColBeaconName: return r.beacon_name;
            case ColCommand:    return r.command;
        }
    }
    // Подсветка опасных команд красным цветом.
    if (role == Qt::ForegroundRole && idx.column() == ColCommand) {
        const auto& c = r.command;
        if (c.startsWith("exit") || c.startsWith("hashdump") ||
            c.startsWith("inject") || c.startsWith("migrate") ||
            c.startsWith("privesc"))
            return QColor("#ef4444");
    }
    // Полная команда как tooltip (если обрезана в колонке).
    if (role == Qt::ToolTipRole && idx.column() == ColCommand)
        return r.command;

    return {};
}

void AuditModel::append(const AuditEntry& entry) {
    beginInsertRows({}, 0, 0);
    rows_.prepend(entry);
    endInsertRows();
}

void AuditModel::clear() {
    beginResetModel();
    rows_.clear();
    endResetModel();
}

}
