#include "CredentialsModel.hpp"

#include <QColor>

namespace co2h::client {

CredentialsModel::CredentialsModel(QObject* parent) : QAbstractTableModel(parent) {}

QVariant CredentialsModel::headerData(int s, Qt::Orientation o, int role) const {
    if (role != Qt::DisplayRole || o != Qt::Horizontal) return {};
    switch (s) {
        case ColUser:   return "User";
        case ColDomain: return "Domain";
        case ColKind:   return "Kind";
        case ColSecret: return "Secret";
        case ColHost:   return "Host";
        case ColSource:  return "Source";
        case ColAddedBy: return "By";
        case ColAdded:   return "Added";
    }
    return {};
}

QVariant CredentialsModel::data(const QModelIndex& idx, int role) const {
    if (!idx.isValid() || idx.row() >= rows_.size()) return {};
    const auto& r = rows_[idx.row()];

    if (role == Qt::DisplayRole) {
        switch (idx.column()) {
            case ColUser:   return r.user;
            case ColDomain: return r.domain;
            case ColKind:   return r.kind;
            case ColSecret: {
                // Маскируем secret, чтобы не светить пароли в большой таблице.
                if (r.secret.isEmpty()) return QString();
                if (r.secret.size() <= 4) return QString(r.secret.size(), '*');
                return r.secret.left(2) + QString(r.secret.size() - 4, '*')
                       + r.secret.right(2);
            }
            case ColHost:    return r.host;
            case ColSource:  return r.source;
            case ColAddedBy: return r.added_by;
            case ColAdded:   return r.added_at.toString("yyyy-MM-dd HH:mm");
        }
    }
    if (role == Qt::ToolTipRole && idx.column() == ColSecret)
        return r.secret;
    if (role == Qt::ToolTipRole && idx.column() == ColUser && !r.note.isEmpty())
        return r.note;
    if (role == Qt::ForegroundRole && idx.column() == ColKind) {
        if (r.kind == "password") return QColor("#ef4444");
        if (r.kind == "hash")     return QColor("#f59e0b");
        if (r.kind == "ticket")   return QColor("#8b5cf6");
        if (r.kind == "identity") return QColor("#3b82f6");
    }
    return {};
}

bool CredentialsModel::exists(const CredentialRow& r) const {
    for (const auto& x : rows_) {
        if (x.user == r.user && x.domain == r.domain &&
            x.kind == r.kind && x.secret == r.secret) return true;
    }
    return false;
}

void CredentialsModel::setRows(QVector<CredentialRow> rows) {
    beginResetModel();
    rows_ = std::move(rows);
    endResetModel();
}

void CredentialsModel::add(const CredentialRow& r) {
    if (exists(r)) return;
    beginInsertRows({}, 0, 0);
    rows_.prepend(r);
    endInsertRows();
}

void CredentialsModel::removeAt(int row) {
    if (row < 0 || row >= rows_.size()) return;
    beginRemoveRows({}, row, row);
    rows_.removeAt(row);
    endRemoveRows();
}

void CredentialsModel::clear() {
    beginResetModel();
    rows_.clear();
    endResetModel();
}

}
