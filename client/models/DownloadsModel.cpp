#include "DownloadsModel.hpp"

#include <QColor>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocale>
#include <QSettings>

namespace co2h::client {

namespace {

QString fmtSize(qint64 n) {
    if (n < 0)             return "—";
    if (n < 1024)          return QString::number(n) + " B";
    if (n < 1024 * 1024)   return QString::number(n / 1024.0, 'f', 1) + " KB";
    if (n < 1024LL * 1024 * 1024)
                           return QString::number(n / (1024.0 * 1024), 'f', 1) + " MB";
    return QString::number(n / (1024.0 * 1024 * 1024), 'f', 2) + " GB";
}

} // namespace

DownloadsModel::DownloadsModel(QObject* parent) : QAbstractTableModel(parent) {
    load();
}

QVariant DownloadsModel::headerData(int section, Qt::Orientation o, int role) const {
    if (role != Qt::DisplayRole || o != Qt::Horizontal) return {};
    switch (section) {
        case ColTime:   return "Time";
        case ColBeacon: return "Beacon";
        case ColRemote: return "Remote path";
        case ColLocal:  return "Local path";
        case ColSize:   return "Size";
        case ColStatus: return "Status";
    }
    return {};
}

QVariant DownloadsModel::data(const QModelIndex& idx, int role) const {
    if (!idx.isValid() || idx.row() >= rows_.size()) return {};
    const auto& r = rows_[idx.row()];
    if (role == Qt::DisplayRole) {
        switch (idx.column()) {
            case ColTime:   return r.requested.toString("yyyy-MM-dd HH:mm:ss");
            case ColBeacon: return r.beacon_id;
            case ColRemote: return r.remote;
            case ColLocal:  return r.local;
            case ColSize:   return fmtSize(r.size);
            case ColStatus: return r.status;
        }
    }
    if (role == Qt::ToolTipRole && idx.column() == ColStatus && !r.error.isEmpty()) {
        return r.error;
    }
    if (role == Qt::ForegroundRole && idx.column() == ColStatus) {
        if (r.status == "ok")      return QColor("#10b981");
        if (r.status == "error")   return QColor("#ef4444");
        if (r.status == "pending") return QColor("#f59e0b");
    }
    return {};
}

int DownloadsModel::addPending(quint64 rpc_id, const QString& beacon_id,
                               const QString& remote, const QString& local) {
    DownloadRow r;
    r.rpc_id   = rpc_id;
    r.beacon_id = beacon_id;
    r.remote   = remote;
    r.local    = local;
    r.requested = QDateTime::currentDateTime();
    r.status   = "pending";
    beginInsertRows({}, 0, 0);
    rows_.prepend(r);
    endInsertRows();
    save();
    return 0;
}

void DownloadsModel::bindTaskId(quint64 rpc_id, quint64 task_id) {
    for (int i = 0; i < rows_.size(); ++i) {
        if (rows_[i].rpc_id == rpc_id && rows_[i].task_id == 0) {
            rows_[i].task_id = task_id;
            save();
            return;
        }
    }
}

void DownloadsModel::markCompleted(quint64 task_id, qint64 size,
                                   const QString& error) {
    for (int i = 0; i < rows_.size(); ++i) {
        if (rows_[i].task_id == task_id && rows_[i].status == "pending") {
            rows_[i].completed = QDateTime::currentDateTime();
            rows_[i].size  = size;
            rows_[i].status = error.isEmpty() ? "ok" : "error";
            rows_[i].error = error;
            emit dataChanged(index(i, 0), index(i, ColCount - 1));
            save();
            return;
        }
    }
}

void DownloadsModel::removeAt(int row) {
    if (row < 0 || row >= rows_.size()) return;
    beginRemoveRows({}, row, row);
    rows_.removeAt(row);
    endRemoveRows();
    save();
}

void DownloadsModel::clear() {
    beginResetModel();
    rows_.clear();
    endResetModel();
    save();
}

// ---- persistence ----------------------------------------------------------

void DownloadsModel::save() const {
    QJsonArray arr;
    for (const auto& r : rows_) {
        QJsonObject o;
        o["task_id"]   = QString::number(r.task_id);
        o["beacon_id"] = r.beacon_id;
        o["remote"]    = r.remote;
        o["local"]     = r.local;
        o["size"]      = static_cast<double>(r.size);
        o["requested"] = r.requested.toString(Qt::ISODate);
        o["completed"] = r.completed.isValid()
                             ? r.completed.toString(Qt::ISODate) : QString{};
        o["status"]    = r.status;
        o["error"]     = r.error;
        arr.append(o);
    }
    QSettings s("Co2H", "Client");
    s.setValue("downloads",
               QString::fromUtf8(QJsonDocument(arr).toJson(QJsonDocument::Compact)));
}

void DownloadsModel::load() {
    QSettings s("Co2H", "Client");
    const auto raw = s.value("downloads").toString().toUtf8();
    if (raw.isEmpty()) return;
    auto doc = QJsonDocument::fromJson(raw);
    if (!doc.isArray()) return;
    beginResetModel();
    rows_.clear();
    for (const auto& v : doc.array()) {
        const auto o = v.toObject();
        DownloadRow r;
        r.task_id   = o.value("task_id").toString().toULongLong();
        r.beacon_id = o.value("beacon_id").toString();
        r.remote    = o.value("remote").toString();
        r.local     = o.value("local").toString();
        r.size      = static_cast<qint64>(o.value("size").toDouble(-1));
        r.requested = QDateTime::fromString(o.value("requested").toString(),
                                            Qt::ISODate);
        const auto cs = o.value("completed").toString();
        if (!cs.isEmpty())
            r.completed = QDateTime::fromString(cs, Qt::ISODate);
        r.status    = o.value("status").toString();
        r.error     = o.value("error").toString();
        // Если приложение упало во время pending — отметить как error.
        if (r.status == "pending") {
            r.status = "error";
            r.error  = "interrupted (client restarted)";
        }
        rows_.append(r);
    }
    endResetModel();
}

}
