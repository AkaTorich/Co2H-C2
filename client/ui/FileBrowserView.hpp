#pragma once

#include <QHash>
#include <QStringList>
#include <QString>
#include <QWidget>

class QLabel;
class QLineEdit;
class QTableWidget;
class QPushButton;

namespace co2h::client {
class ServerClient;
}

namespace co2h::client::ui {

class FileBrowserView : public QWidget {
    Q_OBJECT
public:
    explicit FileBrowserView(ServerClient* client, QWidget* parent = nullptr);

    // Переключить активный бикон (вызывается из MainWindow при interactRequested).
    void setBeacon(const QString& beacon_id);

    // Разобрать вывод ls-задачи. Вызывается из MainWindow::onTaskOutput.
    void onLsOutput(const QByteArray& output);
    void setLsError(const QString& err);
    QString beaconId() const { return beacon_id_; }

    // Маршрутизация: хранит rpc_id последнего ls-запроса, чтобы MainWindow
    // мог отличить его от других задач и скинуть сюда.
    quint64 pendingLsRpc() const { return pending_ls_rpc_; }
    void    setPendingLsRpc(quint64 id) { pending_ls_rpc_ = id; }

signals:
    void lsRequested(const QString& beacon_id, const QString& path);
    void downloadRequested(const QString& beacon_id, const QString& remote,
                           const QString& local);
    void uploadRequested(const QString& beacon_id,
                         const QString& local, const QString& remote);
    void deleteRequested(const QString& beacon_id, const QString& path);

private slots:
    void onRefresh();
    void onGoBack();
    void onGoFwd();
    void onGoUp();
    void onPathEntered();
    void onItemDoubleClicked(int row, int col);
    void onDownload();
    void onUpload();
    void onDelete();

private:
    // push_history = true  — обычная навигация: сохранить current в back_stack_.
    // push_history = false — навигация кнопками назад/вперёд: стеки не трогать.
    void navigate(const QString& path, bool push_history = true);
    void updateNavButtons();
    QString selectedName() const;
    bool    selectedIsDir() const;

    ServerClient* client_;
    QString       beacon_id_;
    QString       current_path_;
    quint64       pending_ls_rpc_ = 0;

    // Стеки истории навигации (хранят пути, не индексы).
    QStringList back_stack_;
    QStringList fwd_stack_;

    QPushButton*  btn_back_;
    QPushButton*  btn_fwd_;
    QPushButton*  btn_up_;
    QPushButton*  btn_refresh_;
    QPushButton*  btn_download_;
    QPushButton*  btn_upload_;
    QPushButton*  btn_delete_;
    QLineEdit*    path_edit_;
    QLabel*       status_;
    QTableWidget* table_;
};

}
