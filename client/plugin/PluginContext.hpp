#pragma once

#include <QHash>
#include <QObject>
#include <QString>
#include <QVector>
#include <functional>

// Макрос экспорта: клиент экспортирует PluginContext,
// плагины импортируют его через import-библиотеку.
#ifdef _WIN32
  #ifdef CO2H_CLIENT_BUILD
    #define CO2H_PLUGIN_API __declspec(dllexport)
  #else
    #define CO2H_PLUGIN_API __declspec(dllimport)
  #endif
#else
  #define CO2H_PLUGIN_API __attribute__((visibility("default")))
#endif

class QAction;
class QIcon;
class QWidget;
class QTabWidget;
class QToolBar;
class QStackedWidget;
class QPlainTextEdit;
class QSplitter;

namespace co2h::client {
class ServerClient;
class SessionsModel;
class ListenersModel;
class DownloadsModel;
class CredentialsModel;
}

namespace co2h::client::ui {
class ConsoleWidget;
}

namespace co2h::client {

// Context object given to every plugin.
// Provides access to tabs, console, models and task routing.
class CO2H_PLUGIN_API PluginContext : public QObject {
    Q_OBJECT
public:
    PluginContext(QTabWidget*       tabs,
                 QToolBar*          pluginBar,
                 QStackedWidget*    pluginStack,
                 QSplitter*         vsplit,
                 ui::ConsoleWidget* console,
                 QPlainTextEdit*    logs,
                 ServerClient*      client,
                 SessionsModel*     sessions,
                 ListenersModel*    listeners,
                 DownloadsModel*    downloads,
                 CredentialsModel*  credentials,
                 QObject*           parent = nullptr);

    // ---- Plugin panel management ----

    // Add plugin widget as icon-button on the plugin toolbar.
    // Clicking the icon toggles the plugin view.  Returns widget index.
    int  addPluginButton(QWidget* widget, const QIcon& icon, const QString& label);
    // Remove a previously added plugin widget.
    void removePluginButton(QWidget* widget);

    // ---- Task execution ----

    using OutputCallback = std::function<void(const QByteArray& output,
                                              const QString& error)>;

    // High-level task helpers (no opcode knowledge needed).
    quint64 shell(const QString& beaconId, const QString& cmd,
                  OutputCallback cb = nullptr);
    quint64 run(const QString& beaconId, const QString& cmdline,
                OutputCallback cb = nullptr);
    quint64 ps(const QString& beaconId, OutputCallback cb = nullptr);
    quint64 ls(const QString& beaconId, const QString& path = {},
               OutputCallback cb = nullptr);
    quint64 pwd(const QString& beaconId, OutputCallback cb = nullptr);
    quint64 getuid(const QString& beaconId, OutputCallback cb = nullptr);
    quint64 screenshot(const QString& beaconId, OutputCallback cb = nullptr);
    quint64 upload(const QString& beaconId, const QByteArray& payload,
                   OutputCallback cb = nullptr);
    quint64 download(const QString& beaconId, const QString& remotePath,
                     OutputCallback cb = nullptr);

    // Generic: for custom BOF / opcode extensions (advanced use).
    quint64 sendTask(const QString& beaconId, quint16 op,
                     const QByteArray& payload,
                     OutputCallback callback = nullptr);

    // Execute a built-in client command by name and get the output.
    // Example: execCommand(bid, "hashdump", cb);
    //          execCommand(bid, "shell whoami", cb);
    // The callback receives the task output exactly like a direct task call.
    quint64 execCommand(const QString& beaconId, const QString& command,
                        OutputCallback cb = nullptr);

    // ---- Console commands ----

    // Register a custom command for the console.
    // handler receives (beaconId, raw arguments after the command name).
    using CommandHandler = std::function<void(const QString& beaconId,
                                              const QString& args)>;
    void registerCommand(const QString& name, const QString& argsHelp,
                         const QString& description, CommandHandler handler);

    // ---- Active beacon ----

    // Returns the beacon ID currently selected in the console.
    QString activeBeaconId() const;

    // ---- Console output ----

    // Append text to the console output area.
    void consoleWrite(const QString& text);
    void consoleError(const QString& text);

    // Append text to the Logs tab.
    void log(const QString& text);

    // ---- Model access (read-only recommended) ----

    ServerClient*     serverClient()     const { return client_; }
    SessionsModel*    sessionsModel()    const { return sessions_; }
    ListenersModel*   listenersModel()   const { return listeners_; }
    DownloadsModel*   downloadsModel()   const { return downloads_; }
    CredentialsModel* credentialsModel() const { return credentials_; }

    // ---- Internal: called by MainWindow for task routing ----

    // Transfer rpc_id → task_id mapping when server responds.
    void bindTaskId(quint64 rpcId, quint64 taskId);
    // Route task output to plugin callback. Returns true if handled.
    bool routeTaskOutput(quint64 taskId, const QByteArray& output,
                         const QString& error);

    // ---- Internal: command lookup by MainWindow ----

    struct PluginCommand {
        QString        name;
        QString        argsHelp;
        QString        description;
        CommandHandler handler;
    };
    const QVector<PluginCommand>& pluginCommands() const { return commands_; }

signals:
    // Emitted by execCommand() — MainWindow connects and dispatches.
    void commandRequested(const QString& beaconId, const QString& command);

private:
    QTabWidget*        tabs_;
    QToolBar*          plugin_bar_;
    QStackedWidget*    plugin_stack_;
    QSplitter*         vsplit_;
    ui::ConsoleWidget* console_;
    QPlainTextEdit*    logs_;
    ServerClient*      client_;
    SessionsModel*     sessions_;
    ListenersModel*    listeners_;
    DownloadsModel*    downloads_;
    CredentialsModel*  credentials_;

    QHash<QWidget*, QAction*>      plugin_actions_;
    QHash<quint64, OutputCallback> cb_by_rpc_;
    QHash<quint64, OutputCallback> cb_by_task_;
    QVector<PluginCommand>         commands_;
};

} // namespace co2h::client
