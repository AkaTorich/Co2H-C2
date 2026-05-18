#pragma once

#include "LoginDialog.hpp"
#include <QHash>
#include <QMainWindow>
#include <QProcess>

class QTabWidget;
class QSplitter;
class QPlainTextEdit;
class QTimer;
class QAction;
class QToolBar;
class QToolButton;
class QStackedWidget;

namespace co2h::client {
class ServerClient;
class SessionsModel;
class ListenersModel;
class DownloadsModel;
class CredentialsModel;
class AuditModel;
class PluginContext;
class PluginManager;
struct BeaconRow;
struct ListenerRow;
}

namespace co2h::client::script {
class ScriptEngine;
}

namespace co2h::client::ui {

class SessionsView;
class ListenersView;
class DownloadsView;
class CredentialsView;
class AuditView;
class ChatView;
class GraphView;
class ConsoleWidget;
class FileBrowserView;
class ProcessBrowserView;
class ScriptsView;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(ServerClient* client, const LoginInfo& info, QWidget* parent = nullptr);

public slots:
    void refreshData();

private slots:
    void onConnected();
    void onDisconnected(const QString& reason);
    void onAuthOk(quint64 opId, const QString& role);
    void onAuthFailed(const QString& reason);
    void onSessions(QVector<BeaconRow> rows);
    void onListeners(QVector<ListenerRow> rows);
    void onTaskOutput(const QString& beaconId, quint64 taskId,
                      const QByteArray& output, const QString& error);
    void onTaskCreated(quint64 rpcId, quint64 taskId);
    void onCommandEntered(const QString& beaconId, const QString& cmd);
    void onIShellInput(const QString& beaconId, const QString& line);
    void onIShellStop(const QString& beaconId);
    void onInteract(const QString& beaconId);
    void onToggleTheme();
    void onStartServer();
    void onStopServer();
    void onServerStdout();
    void onServerStderr();
    void onServerFinished(int exitCode, QProcess::ExitStatus);
    void onGenerateArtifact();
    void onGenerateRelayChild(const QString& beaconId,
                              const QString& internalIp,
                              const QString& listenerName);
    void onNewListener();
    void onManageOperators();
    void onGenerateCerts();
    void onGenerateShellcode();
    void reconnect();

protected:
    void closeEvent(QCloseEvent* e) override;

private:
    void buildUi();
    void buildMenus();
    void buildToolbar();
    void buildStatusBar();
    void updateIcons();

    ServerClient*    client_;
    SessionsModel*   sessions_model_;
    ListenersModel*  listeners_model_;
    DownloadsModel*  downloads_model_ = nullptr;
    CredentialsModel* credentials_model_ = nullptr;
    AuditModel*      audit_model_     = nullptr;

    QTabWidget*      tabs_            = nullptr;
    SessionsView*    sessions_view_   = nullptr;
    ListenersView*   listeners_view_  = nullptr;
    DownloadsView*   downloads_view_  = nullptr;
    CredentialsView* credentials_view_ = nullptr;
    AuditView*       audit_view_      = nullptr;
    ChatView*        chat_view_       = nullptr;
    GraphView*       graph_view_      = nullptr;
    ConsoleWidget*   console_         = nullptr;  // Активная консоль (текущая вкладка).
    QTabWidget*      console_tabs_    = nullptr;  // Вкладки консолей.
    FileBrowserView*    file_browser_     = nullptr;
    ProcessBrowserView* process_browser_  = nullptr;
    QPlainTextEdit*     logs_             = nullptr;
    QSplitter*       vsplit_          = nullptr;
    QTimer*          poll_            = nullptr;

    QAction*         start_srv_act_   = nullptr;
    QAction*         stop_srv_act_    = nullptr;
    QAction*         operators_act_   = nullptr;
    QString          current_role_;
    QProcess*        server_proc_     = nullptr;
    LoginInfo        login_info_;

    // Сопоставление download-задач локальным путям сохранения.
    // Сначала запоминаем по rpc_id (известен сразу при отправке),
    // после ответа сервера переносим в карту по task_id.
    QHash<quint64, QString> dl_by_rpc_;
    QHash<quint64, QString> dl_by_task_;

    // Маршрутизация ls-задач файлового браузера: task_id → beacon_id.
    // При получении taskOutput проверяем наличие здесь и скидываем в FileBrowserView.
    QHash<quint64, QString> fb_ls_by_task_;  // task_id → beacon_id
    QHash<quint64, QString> fb_ls_by_rpc_;   // rpc_id  → beacon_id

    // Process browser routing.
    QHash<quint64, QString> pb_ps_by_task_;
    QHash<quint64, QString> pb_ps_by_rpc_;

    // Маршрутизация вывода задач в конкретную консоль.
    // rpc_id → ConsoleWidget*, при taskCreated переносим в task_id → ConsoleWidget*.
    QHash<quint64, ConsoleWidget*> con_by_rpc_;
    QHash<quint64, ConsoleWidget*> con_by_task_;

    // Plugin system.
    PluginContext*      plugin_ctx_     = nullptr;
    PluginManager*      plugin_mgr_    = nullptr;
    QToolBar*           plugin_bar_    = nullptr;
    QStackedWidget*     plugin_stack_  = nullptr;

    // Lua scripting engine.
    script::ScriptEngine* script_engine_ = nullptr;
    ScriptsView*          scripts_view_  = nullptr;
};

}
