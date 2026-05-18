#include "AuditView.hpp"
#include "../models/AuditModel.hpp"

#include <QApplication>
#include <QClipboard>
#include <QFileDialog>
#include <QHeaderView>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QSortFilterProxyModel>
#include <QTableView>
#include <QTextStream>
#include <QToolBar>
#include <QVBoxLayout>

namespace co2h::client::ui {

AuditView::AuditView(AuditModel* model, QWidget* parent)
    : QWidget(parent), model_(model) {

    // Тулбар с кнопками и строкой фильтра.
    auto* tb = new QToolBar(this);
    tb->setIconSize(QSize(16, 16));
    auto* copyBtn   = tb->addAction("Copy");
    auto* exportBtn = tb->addAction("Export CSV");
    tb->addSeparator();
    auto* clearBtn  = tb->addAction("Clear");

    connect(copyBtn,   &QAction::triggered, this, &AuditView::onCopyRow);
    connect(exportBtn, &QAction::triggered, this, &AuditView::onExport);
    connect(clearBtn,  &QAction::triggered, this, &AuditView::onClear);

    // Строка фильтра (поиск по всем колонкам).
    filter_ = new QLineEdit(this);
    filter_->setPlaceholderText("Filter: operator, beacon, command...");
    filter_->setClearButtonEnabled(true);
    connect(filter_, &QLineEdit::textChanged,
            this, &AuditView::onFilterChanged);

    // Proxy-модель для фильтрации по тексту.
    proxy_ = new QSortFilterProxyModel(this);
    proxy_->setSourceModel(model_);
    proxy_->setFilterCaseSensitivity(Qt::CaseInsensitive);
    proxy_->setFilterKeyColumn(-1); // искать по всем колонкам

    // Таблица.
    view_ = new QTableView(this);
    view_->setModel(proxy_);
    view_->setSelectionBehavior(QAbstractItemView::SelectRows);
    view_->setSelectionMode(QAbstractItemView::SingleSelection);
    view_->setAlternatingRowColors(true);
    view_->verticalHeader()->setVisible(false);
    view_->horizontalHeader()->setStretchLastSection(true);
    view_->setSortingEnabled(true);
    view_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(view_, &QTableView::customContextMenuRequested,
            this, &AuditView::onContextMenu);

    auto* v = new QVBoxLayout(this);
    v->setContentsMargins(0, 0, 0, 0);
    v->addWidget(tb);
    v->addWidget(filter_);
    v->addWidget(view_, 1);
}

void AuditView::onFilterChanged(const QString& text) {
    proxy_->setFilterFixedString(text);
}

void AuditView::onCopyRow() {
    auto sel = view_->selectionModel()->selectedRows();
    if (sel.isEmpty()) return;
    const auto src = proxy_->mapToSource(sel.first());
    const auto* r = model_->at(src.row());
    if (!r) return;
    QString line = QString("[%1] %2 @ %3 (%4): %5")
        .arg(r->timestamp.toString("yyyy-MM-dd HH:mm:ss"),
             r->op, r->beacon_id, r->beacon_name, r->command);
    QApplication::clipboard()->setText(line);
}

void AuditView::onExport() {
    const QString path = QFileDialog::getSaveFileName(
        this, "Export Audit Log", "audit_log.csv", "CSV (*.csv)");
    if (path.isEmpty()) return;

    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, "Export", "Cannot write: " + path);
        return;
    }
    QTextStream out(&f);
    out << "Time,Operator,BeaconID,Beacon,Command\n";
    for (int i = 0; i < model_->rowCount({}); ++i) {
        const auto* r = model_->at(i);
        if (!r) continue;
        // CSV: экранируем кавычки в команде.
        QString cmd = r->command;
        cmd.replace('"', "\"\"");
        out << r->timestamp.toString("yyyy-MM-dd HH:mm:ss") << ','
            << r->op << ','
            << r->beacon_id << ','
            << r->beacon_name << ','
            << '"' << cmd << '"' << '\n';
    }
    f.close();
    QMessageBox::information(this, "Export", "Saved: " + path);
}

void AuditView::onClear() {
    if (QMessageBox::question(this, "Clear Audit Log",
            "Clear all audit entries?") == QMessageBox::Yes)
        model_->clear();
}

void AuditView::onContextMenu(const QPoint& pos) {
    if (!view_->indexAt(pos).isValid()) return;
    QMenu m(this);
    m.addAction("Copy row", this, &AuditView::onCopyRow);
    m.addAction("Export CSV", this, &AuditView::onExport);
    m.exec(view_->viewport()->mapToGlobal(pos));
}

}
