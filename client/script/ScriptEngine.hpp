#pragma once

#include <QObject>
#include <QHash>
#include <QString>
#include <QStringList>
#include <QVector>

#include <functional>
#include <memory>

// Forward-declare Lua state (avoid sol2 header in .hpp).
struct lua_State;

namespace co2h::client {
class ServerClient;
class SessionsModel;
struct BeaconRow;
}

namespace co2h::client::ui {
class ConsoleWidget;
}

namespace co2h::client::script {

// Описание пользовательской команды, зарегистрированной из Lua.
struct ScriptCommand {
    QString name;
    QString help;
    // callback index в Lua registry (вызывается с beacon_id, args).
};

// Lua-скриптовый движок для автоматизации оператора.
// Загружает .lua файлы из папки scripts/, предоставляет API для взаимодействия
// с teamserver'ом через существующие механизмы клиента.
class ScriptEngine : public QObject {
    Q_OBJECT
public:
    explicit ScriptEngine(QObject* parent = nullptr);
    ~ScriptEngine() override;

    // Инициализация: передать зависимости.
    void init(ServerClient* client, SessionsModel* sessions);

    // Загрузить все .lua из указанной директории.
    void loadDirectory(const QString& dir);

    // Загрузить один скрипт.
    bool loadFile(const QString& path);

    // Вызвать обработчики событий из Lua.
    void fireBeaconNew(const QString& beaconId);
    void fireBeaconLost(const QString& beaconId);
    void fireTaskOutput(const QString& beaconId, quint64 taskId,
                        const QString& output);
    void fireChat(const QString& from, const QString& text);

    // Проверяет, зарегистрирована ли скриптовая команда с таким именем.
    bool hasCommand(const QString& name) const;

    // Выполнить скриптовую команду (вызывается из MainWindow при диспатче).
    void execCommand(const QString& name, const QString& beaconId,
                     const QString& args);

    // Список зарегистрированных скриптовых команд (для автодополнения).
    QVector<QPair<QString, QString>> registeredCommands() const;

signals:
    // Скрипт хочет отправить команду бикону (через MainWindow::onCommandEntered).
    void taskRequested(const QString& beaconId, const QString& cmdText);
    // Скрипт хочет вывести текст в лог.
    void logRequested(const QString& text);
    // Скрипт хочет показать уведомление оператору.
    void alertRequested(const QString& title, const QString& text);
    // Скрипт успешно загружен (полный путь к файлу).
    void scriptLoaded(const QString& path);

private:
    void registerApi();

    lua_State* L_ = nullptr;
    ServerClient*  client_   = nullptr;
    SessionsModel* sessions_ = nullptr;

    // Lua registry refs для callback'ов on("event", fn).
    QHash<QString, QVector<int>> event_handlers_; // event_name -> [registry_ref...]
    // Пользовательские команды command("name", "help", fn).
    struct CmdEntry {
        QString help;
        int     ref = 0; // Lua registry ref
    };
    QHash<QString, CmdEntry> commands_;
};

}
