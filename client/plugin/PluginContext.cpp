#include "PluginContext.hpp"
#include "../ui/ConsoleWidget.hpp"
#include "../net/ServerClient.hpp"

#include <QAction>
#include <QIcon>
#include <QPlainTextEdit>
#include <QSplitter>
#include <QStackedWidget>
#include <QTabWidget>
#include <QToolBar>
#include <QWidget>

namespace co2h::client {

PluginContext::PluginContext(QTabWidget*        tabs,
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
                             QObject*           parent)
    : QObject(parent)
    , tabs_(tabs), plugin_bar_(pluginBar), plugin_stack_(pluginStack)
    , vsplit_(vsplit), console_(console), logs_(logs)
    , client_(client)
    , sessions_(sessions), listeners_(listeners)
    , downloads_(downloads), credentials_(credentials)
{}

// ---- Plugin panel management ----

int PluginContext::addPluginButton(QWidget* widget, const QIcon& icon,
                          const QString& label)
{
    // Добавляем виджет в стек.
    int idx = plugin_stack_->addWidget(widget);

    // Создаём иконку-кнопку на панели плагинов.
    QAction* act = plugin_bar_->addAction(icon, label);
    act->setToolTip(label);
    act->setCheckable(true);
    plugin_actions_.insert(widget, act);

    // Показать панель (если первый плагин).
    plugin_bar_->setVisible(true);

    // Клик по иконке — переключить видимость виджета плагина.
    QObject::connect(act, &QAction::triggered, [this, widget, idx, act](bool checked) {
        if (checked) {
            // Снять выделение с остальных кнопок.
            for (auto it = plugin_actions_.begin(); it != plugin_actions_.end(); ++it) {
                if (it.value() != act)
                    it.value()->setChecked(false);
            }
            // Показать стек плагинов и выбрать нужный виджет.
            plugin_stack_->setCurrentIndex(idx);
            plugin_stack_->setVisible(true);
            // Скрыть основные вкладки.
            tabs_->setVisible(false);
        } else {
            // Повторный клик — вернуться к обычным вкладкам.
            plugin_stack_->setVisible(false);
            tabs_->setVisible(true);
        }
    });

    return idx;
}

void PluginContext::removePluginButton(QWidget* widget)
{
    auto it = plugin_actions_.find(widget);
    if (it != plugin_actions_.end()) {
        plugin_bar_->removeAction(it.value());
        delete it.value();
        plugin_actions_.erase(it);
    }
    int idx = plugin_stack_->indexOf(widget);
    if (idx >= 0) plugin_stack_->removeWidget(widget);

    // Если плагинов не осталось — скрыть панель.
    if (plugin_actions_.isEmpty())
        plugin_bar_->setVisible(false);

    // Вернуть вкладки.
    plugin_stack_->setVisible(false);
    tabs_->setVisible(true);
}

// ---- High-level task helpers ----

quint64 PluginContext::shell(const QString& bid, const QString& cmd,
                              OutputCallback cb) {
    return sendTask(bid, static_cast<quint16>(proto::TaskOp::Shell),
                    cmd.toUtf8(), std::move(cb));
}

quint64 PluginContext::run(const QString& bid, const QString& cmdline,
                            OutputCallback cb) {
    return sendTask(bid, static_cast<quint16>(proto::TaskOp::Run),
                    cmdline.toUtf8(), std::move(cb));
}

quint64 PluginContext::ps(const QString& bid, OutputCallback cb) {
    return sendTask(bid, static_cast<quint16>(proto::TaskOp::Ps),
                    {}, std::move(cb));
}

quint64 PluginContext::ls(const QString& bid, const QString& path,
                           OutputCallback cb) {
    return sendTask(bid, static_cast<quint16>(proto::TaskOp::Ls),
                    path.toUtf8(), std::move(cb));
}

quint64 PluginContext::pwd(const QString& bid, OutputCallback cb) {
    return sendTask(bid, static_cast<quint16>(proto::TaskOp::Pwd),
                    {}, std::move(cb));
}

quint64 PluginContext::getuid(const QString& bid, OutputCallback cb) {
    return sendTask(bid, static_cast<quint16>(proto::TaskOp::TokenGetuid),
                    {}, std::move(cb));
}

quint64 PluginContext::screenshot(const QString& bid, OutputCallback cb) {
    return sendTask(bid, static_cast<quint16>(proto::TaskOp::Screenshot),
                    {}, std::move(cb));
}

quint64 PluginContext::upload(const QString& bid, const QByteArray& payload,
                               OutputCallback cb) {
    return sendTask(bid, static_cast<quint16>(proto::TaskOp::Upload),
                    payload, std::move(cb));
}

quint64 PluginContext::download(const QString& bid, const QString& remotePath,
                                 OutputCallback cb) {
    return sendTask(bid, static_cast<quint16>(proto::TaskOp::Download),
                    remotePath.toUtf8(), std::move(cb));
}

// ---- Generic task (advanced) ----

quint64 PluginContext::sendTask(const QString& beaconId, quint16 op,
                                const QByteArray& payload,
                                OutputCallback callback)
{
    auto rpc = client_->taskBeacon(beaconId,
                                   static_cast<proto::TaskOp>(op),
                                   payload);
    if (rpc && callback)
        cb_by_rpc_.insert(rpc, std::move(callback));
    return rpc;
}

// ---- Execute built-in command ----

quint64 PluginContext::execCommand(const QString& beaconId,
                                   const QString& command,
                                   OutputCallback cb)
{
    // Запоминаем счётчик rpc ДО диспатча.
    const quint64 rpcBefore = client_->currentRpcCounter();

    // Сигнал commandRequested подключён к MainWindow::onCommandEntered
    // через Qt::DirectConnection (тот же поток) — выполнится синхронно.
    emit commandRequested(beaconId, command);

    // Если команда породила задачу — счётчик сдвинулся.
    const quint64 rpcAfter = client_->currentRpcCounter();
    if (rpcAfter > rpcBefore && cb) {
        // Привязываем callback к первому порождённому rpc_id.
        cb_by_rpc_.insert(rpcBefore, std::move(cb));
    }
    return rpcAfter > rpcBefore ? rpcBefore : 0;
}

// ---- Active beacon ----

QString PluginContext::activeBeaconId() const
{
    return console_ ? console_->beaconId() : QString{};
}

// ---- Console ----

void PluginContext::registerCommand(const QString& name,
                                     const QString& argsHelp,
                                     const QString& description,
                                     CommandHandler handler)
{
    commands_.append({name, argsHelp, description, std::move(handler)});
}

void PluginContext::consoleWrite(const QString& text)
{
    console_->appendOutput(text);
}

void PluginContext::consoleError(const QString& text)
{
    console_->appendError(text);
}

void PluginContext::log(const QString& text)
{
    if (logs_) logs_->appendPlainText(text);
}

// ---- Task routing ----

void PluginContext::bindTaskId(quint64 rpcId, quint64 taskId)
{
    auto it = cb_by_rpc_.find(rpcId);
    if (it != cb_by_rpc_.end()) {
        cb_by_task_.insert(taskId, it.value());
        cb_by_rpc_.erase(it);
    }
}

bool PluginContext::routeTaskOutput(quint64 taskId,
                                     const QByteArray& output,
                                     const QString& error)
{
    auto it = cb_by_task_.find(taskId);
    if (it == cb_by_task_.end()) return false;

    auto cb = it.value();
    cb_by_task_.erase(it);
    cb(output, error);
    return true;
}

} // namespace co2h::client
