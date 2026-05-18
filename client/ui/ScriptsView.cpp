#include "ScriptsView.hpp"
#include "../script/ScriptEngine.hpp"

#include <QCoreApplication>
#include <QDateTime>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFont>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QPlainTextEdit>
#include <QSplitter>
#include <QToolBar>
#include <QUrl>
#include <QVBoxLayout>

namespace co2h::client::ui {

ScriptsView::ScriptsView(script::ScriptEngine* engine, QWidget* parent)
    : QWidget(parent), engine_(engine)
{
    // -----------------------------------------------------------------------
    // Levaya panel: toolbar + vertikal'nyj splitter (spisok + log)
    // -----------------------------------------------------------------------
    auto* leftWidget = new QWidget(this);

    auto* leftTb    = new QToolBar(leftWidget);
    leftTb->setIconSize(QSize(16, 16));
    auto* loadBtn   = leftTb->addAction("Load script...");
    auto* reloadBtn = leftTb->addAction("Reload all");
    leftTb->addSeparator();
    auto* folderBtn = leftTb->addAction("Open scripts folder");

    connect(loadBtn,   &QAction::triggered, this, &ScriptsView::onLoad);
    connect(reloadBtn, &QAction::triggered, this, &ScriptsView::onReload);
    connect(folderBtn, &QAction::triggered, this, &ScriptsView::onOpenFolder);

    list_ = new QListWidget(leftWidget);
    list_->setAlternatingRowColors(true);
    connect(list_, &QListWidget::itemClicked,
            this,  &ScriptsView::onListItemClicked);

    log_ = new QPlainTextEdit(leftWidget);
    log_->setReadOnly(true);
    log_->setMaximumBlockCount(2000);
    {
        QFont f("Consolas", 9);
        f.setStyleHint(QFont::Monospace);
        log_->setFont(f);
    }

    auto* leftSplit = new QSplitter(Qt::Vertical, leftWidget);
    leftSplit->addWidget(list_);
    leftSplit->addWidget(log_);
    leftSplit->setStretchFactor(0, 1);
    leftSplit->setStretchFactor(1, 2);

    auto* leftLayout = new QVBoxLayout(leftWidget);
    leftLayout->setContentsMargins(0, 0, 0, 0);
    leftLayout->setSpacing(0);
    leftLayout->addWidget(leftTb);
    leftLayout->addWidget(leftSplit, 1);

    // -----------------------------------------------------------------------
    // Pravaya panel: toolbar (New / Save / Save & Reload + metka) + redaktor
    // -----------------------------------------------------------------------
    auto* rightWidget = new QWidget(this);

    auto* rightTb       = new QToolBar(rightWidget);
    rightTb->setIconSize(QSize(16, 16));
    auto* newBtn        = rightTb->addAction("New");
    auto* saveBtn       = rightTb->addAction("Save");
    auto* saveReloadBtn = rightTb->addAction("Save && Reload");
    rightTb->addSeparator();
    editor_label_ = new QLabel("  no file open  ", rightWidget);
    rightTb->addWidget(editor_label_);

    connect(newBtn,        &QAction::triggered, this, &ScriptsView::onNew);
    connect(saveBtn,       &QAction::triggered, this, &ScriptsView::onSave);
    connect(saveReloadBtn, &QAction::triggered, this, &ScriptsView::onSaveReload);

    editor_ = new QPlainTextEdit(rightWidget);
    editor_->setPlaceholderText(
        "Select a script from the list or create a new one...");
    {
        QFont f("Consolas", 10);
        f.setStyleHint(QFont::Monospace);
        editor_->setFont(f);
    }

    auto* rightLayout = new QVBoxLayout(rightWidget);
    rightLayout->setContentsMargins(0, 0, 0, 0);
    rightLayout->setSpacing(0);
    rightLayout->addWidget(rightTb);
    rightLayout->addWidget(editor_, 1);

    // -----------------------------------------------------------------------
    // Gorizontal'nyj splitter: levaya : pravaya = 1:2
    // -----------------------------------------------------------------------
    auto* hSplit = new QSplitter(Qt::Horizontal, this);
    hSplit->addWidget(leftWidget);
    hSplit->addWidget(rightWidget);
    hSplit->setStretchFactor(0, 1);
    hSplit->setStretchFactor(1, 2);

    auto* outer = new QHBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);
    outer->addWidget(hSplit);

    // -----------------------------------------------------------------------
    // Signal dvizka: skript zagruzhen -> dobavit v spisok i v mappirovanie
    // -----------------------------------------------------------------------
    connect(engine_, &script::ScriptEngine::scriptLoaded, this,
            [this](const QString& path) {
                const QString name = QFileInfo(path).fileName();
                if (!name_to_path_.contains(name)) {
                    name_to_path_[name] = path;
                    list_->addItem(name);
                }
            });
}

// ---------------------------------------------------------------------------
// Log
// ---------------------------------------------------------------------------

void ScriptsView::appendLog(const QString& text) {
    const QString ts = QDateTime::currentDateTime().toString("HH:mm:ss");
    log_->appendPlainText(QString("[%1] %2").arg(ts, text));
}

// ---------------------------------------------------------------------------
// Redaktor
// ---------------------------------------------------------------------------

void ScriptsView::openInEditor(const QString& path) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        appendLog(QString("cannot open: %1").arg(path));
        return;
    }
    editor_->setPlainText(QString::fromUtf8(f.readAll()));
    f.close();
    current_edit_path_ = path;
    editor_label_->setText(QString("  %1").arg(QFileInfo(path).fileName()));
}

void ScriptsView::onListItemClicked(QListWidgetItem* item) {
    if (!item) return;
    const QString name = item->text();
    if (name_to_path_.contains(name))
        openInEditor(name_to_path_[name]);
}

void ScriptsView::onNew() {
    const QString defaultDir = QCoreApplication::applicationDirPath()
                               + QStringLiteral("/scripts");
    QDir().mkpath(defaultDir);
    const QString path = QFileDialog::getSaveFileName(
        this, "New Lua script",
        defaultDir + QStringLiteral("/new_script.lua"),
        "Lua scripts (*.lua)");
    if (path.isEmpty()) return;

    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        appendLog(QString("cannot create: %1").arg(path));
        return;
    }
    f.write("-- new script\n\n");
    f.close();
    openInEditor(path);
}

void ScriptsView::onSave() {
    if (current_edit_path_.isEmpty()) return;
    QFile f(current_edit_path_);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        appendLog(QString("save failed: %1").arg(current_edit_path_));
        return;
    }
    f.write(editor_->toPlainText().toUtf8());
    f.close();
    appendLog(QString("saved: %1").arg(QFileInfo(current_edit_path_).fileName()));
}

void ScriptsView::onSaveReload() {
    onSave();
    if (!current_edit_path_.isEmpty())
        engine_->loadFile(current_edit_path_);
}

// ---------------------------------------------------------------------------
// Levaya panel — knopki
// ---------------------------------------------------------------------------

void ScriptsView::onLoad() {
    const QStringList files = QFileDialog::getOpenFileNames(
        this, "Load Lua script", {}, "Lua scripts (*.lua)");
    for (const auto& path : files)
        engine_->loadFile(path); // spisok i log — cherez signal scriptLoaded
}

void ScriptsView::onReload() {
    const QString scriptsDir = QCoreApplication::applicationDirPath()
                               + QStringLiteral("/scripts");

    // Sohranit puti vne standartnoj papki pered ochistkoj.
    QStringList extra;
    for (auto it = name_to_path_.constBegin(); it != name_to_path_.constEnd(); ++it)
        if (!it.value().startsWith(scriptsDir))
            extra.append(it.value());

    list_->clear();
    name_to_path_.clear();

    // Standartnyj katalog.
    QDir d(scriptsDir);
    if (d.exists()) {
        const auto files = d.entryList({"*.lua"}, QDir::Files, QDir::Name);
        for (const auto& f : files)
            engine_->loadFile(d.absoluteFilePath(f));
    }

    // Vruchtyu zagruzhennye.
    for (const auto& p : extra)
        engine_->loadFile(p);

    appendLog("reload complete");
}

void ScriptsView::onOpenFolder() {
    const QString dir = QCoreApplication::applicationDirPath()
                        + QStringLiteral("/scripts");
    QDir().mkpath(dir);
    QDesktopServices::openUrl(QUrl::fromLocalFile(dir));
}

}
