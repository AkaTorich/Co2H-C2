#pragma once

// Co2H Plugin SDK — контекст для взаимодействия плагина с клиентом.
// Плагин получает указатель на PluginContext в initialize().
// Все методы потокобезопасны для вызова из UI-потока.

#include <QHash>
#include <QObject>
#include <QString>
#include <QVector>
#include <functional>

// При сборке плагина CO2H_CLIENT_BUILD не определён → dllimport.
#ifdef _WIN32
  #ifdef CO2H_CLIENT_BUILD
    #define CO2H_PLUGIN_API __declspec(dllexport)
  #else
    #define CO2H_PLUGIN_API __declspec(dllimport)
  #endif
#else
  #define CO2H_PLUGIN_API __attribute__((visibility("default")))
#endif

class QIcon;
class QWidget;
class QTabWidget;
class QPlainTextEdit;

namespace co2h::client {

class ServerClient;
class SessionsModel;
class ListenersModel;
class DownloadsModel;
class CredentialsModel;

namespace ui { class ConsoleWidget; }

// Контекст, передаваемый каждому плагину.
// Предоставляет управление вкладками, консолью, моделями и отправку задач.
class CO2H_PLUGIN_API PluginContext : public QObject {
    Q_OBJECT
public:
    // ---- Управление виджетами плагина ----

    // Добавить виджет плагина. На панели плагинов появится иконка-кнопка.
    // Клик по иконке показывает/скрывает виджет. Возвращает индекс.
    int  addPluginButton(QWidget* widget, const QIcon& icon, const QString& label);
    // Убрать ранее добавленный виджет.
    void removePluginButton(QWidget* widget);

    // ---- Выполнение задач на beacon'е ----

    using OutputCallback = std::function<void(const QByteArray& output,
                                              const QString& error)>;

    // Высокоуровневые обёртки (не нужно знать числовые коды протокола).
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

    // Низкоуровневый: для пользовательских BOF / расширений.
    quint64 sendTask(const QString& beaconId, quint16 op,
                     const QByteArray& payload,
                     OutputCallback callback = nullptr);

    // Выполнить встроенную команду клиента по имени и получить вывод.
    // Полная строка как в консоли: "bof enum.o go -- z domain.local"
    // Callback получит результат задачи.
    quint64 execCommand(const QString& beaconId, const QString& command,
                        OutputCallback cb = nullptr);

    // ---- Консольные команды ----

    using CommandHandler = std::function<void(const QString& beaconId,
                                              const QString& args)>;
    // Зарегистрировать команду. Появится в автодополнении с пометкой [plugin].
    void registerCommand(const QString& name, const QString& argsHelp,
                         const QString& description, CommandHandler handler);

    // ---- Активный beacon ----

    // Возвращает ID beacon'а, выбранного в консоли.
    QString activeBeaconId() const;

    // ---- Вывод ----

    void consoleWrite(const QString& text);  // текст в консоль (обычный)
    void consoleError(const QString& text);  // ошибка (красный)
    void log(const QString& text);           // запись во вкладку Logs

    // ---- Доступ к моделям данных (только чтение) ----

    ServerClient*     serverClient()     const;
    SessionsModel*    sessionsModel()    const;
    ListenersModel*   listenersModel()   const;
    DownloadsModel*   downloadsModel()   const;
    CredentialsModel* credentialsModel() const;
};

} // namespace co2h::client
