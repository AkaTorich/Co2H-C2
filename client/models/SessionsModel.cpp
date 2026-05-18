#include "SessionsModel.hpp"
#include "../ui/SvgIcon.hpp"

#include <QDateTime>
#include <algorithm>

namespace co2h::client {

static const QIcon& sessionIcon() {
    static QIcon icon = ui::glassyIcon(":/icons/session.svg", QColor("#10b981"), {16, 16});
    return icon;
}

SessionsModel::SessionsModel(QObject* parent) : QAbstractTableModel(parent) {}

void SessionsModel::setRows(QVector<BeaconRow> rows) {
    // Сортировка по времени первого появления — новые биконы внизу списка.
    std::stable_sort(rows.begin(), rows.end(),
                     [](const BeaconRow& a, const BeaconRow& b) {
                         return a.first_seen < b.first_seen;
                     });

    // Check if just the data changed (same IDs, same order) — update in-place
    // so the view doesn't lose its current selection.
    if (rows.size() == rows_.size()) {
        bool same_structure = true;
        for (int i = 0; i < rows.size() && same_structure; ++i)
            same_structure = (rows[i].id == rows_[i].id);
        if (same_structure) {
            rows_ = std::move(rows);
            if (!rows_.isEmpty())
                emit dataChanged(index(0, 0), index(rows_.size() - 1, ColCount - 1));
            return;
        }
    }
    beginResetModel();
    rows_ = std::move(rows);
    endResetModel();
}

QVariant SessionsModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || index.row() >= rows_.size()) return {};
    const auto& r = rows_[index.row()];

    if (role == Qt::DecorationRole && index.column() == ColId)
        return sessionIcon();

    if (role != Qt::DisplayRole && role != Qt::ToolTipRole) return {};
    switch (index.column()) {
        case ColId:       return r.id;
        case ColHost:     return r.host;
        case ColIp:       return r.internal_ip;
        case ColUser:     return r.user;
        case ColPid:      return r.pid;
        case ColArch:     return r.arch;
        case ColOs: {
            QString os = r.os.toLower();
            if (os == "linux") return QString("Linux");
            if (os == "macos" || os == "darwin") return QString("macOS");
            return QString("Windows");
        }
        case ColListener: return r.listener;
        case ColFirstSeen: {
            if (r.first_seen == 0) return QString("unknown");
            return QDateTime::fromSecsSinceEpoch(r.first_seen).toString("yyyy-MM-dd HH:mm:ss");
        }
        case ColLastSeen: {
            if (r.last_seen == 0) return QString("unknown");
            qint64 ago = QDateTime::currentSecsSinceEpoch() - r.last_seen;
            if (ago < 5)  return QString("just now");
            if (ago < 60) return QString("%1s ago").arg(ago);
            return QString("%1m %2s ago").arg(ago / 60).arg(ago % 60, 2, 10, QChar('0'));
        }
    }
    return {};
}

QVariant SessionsModel::headerData(int section, Qt::Orientation o, int role) const {
    if (o != Qt::Horizontal || role != Qt::DisplayRole) return {};
    switch (section) {
        case ColId:       return "Beacon ID";
        case ColHost:     return "Host";
        case ColIp:       return "IP";
        case ColUser:     return "User";
        case ColPid:      return "PID";
        case ColArch:      return "Arch";
        case ColOs:        return "OS";
        case ColListener:  return "Listener";
        case ColFirstSeen: return "First seen";
        case ColLastSeen:  return "Last seen";
    }
    return {};
}

}
