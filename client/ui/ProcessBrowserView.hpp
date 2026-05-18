#pragma once

#include <QWidget>
#include <QString>
#include <QHash>

class QTreeWidget;
class QTreeWidgetItem;
class QPushButton;
class QLabel;
class QLineEdit;
class QComboBox;

namespace co2h::client {
class ServerClient;
class SessionsModel;
}

namespace co2h::client::ui {

class ProcessBrowserView : public QWidget {
    Q_OBJECT
public:
    explicit ProcessBrowserView(ServerClient* client,
                                SessionsModel* sessions,
                                QWidget* parent = nullptr);

    QString beaconId() const { return beacon_id_; }

    // Parse ps output from beacon and build the tree.
    void onPsOutput(const QByteArray& output);
    void setPsError(const QString& err);

    quint64 pendingPsRpc() const { return pending_ps_rpc_; }
    void    setPendingPsRpc(quint64 id) { pending_ps_rpc_ = id; }

    // Update beacon combo when sessions list changes.
    void refreshBeaconList();

signals:
    void psRequested(const QString& beacon_id);
    void killRequested(const QString& beacon_id, quint32 pid);

private slots:
    void onRefresh();
    void onKillProcess();
    void onFilterChanged(const QString& text);
    void onBeaconChanged(int index);

private:
    void buildTree(const QByteArray& raw);
    void applyFilter(const QString& text);
    void setItemVisibleRecursive(QTreeWidgetItem* item, bool visible);
    bool matchesFilter(QTreeWidgetItem* item, const QString& filter);

    ServerClient*  client_;
    SessionsModel* sessions_model_;
    QString        beacon_id_;
    quint64        pending_ps_rpc_ = 0;

    QComboBox*    beacon_combo_;
    QPushButton*  btn_refresh_;
    QPushButton*  btn_kill_;
    QLineEdit*    filter_edit_;
    QLabel*       status_;
    QTreeWidget*  tree_;
};

}
