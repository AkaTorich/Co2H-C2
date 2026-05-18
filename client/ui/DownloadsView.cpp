#include "DownloadsView.hpp"
#include "../models/DownloadsModel.hpp"

#include <QApplication>
#include <QClipboard>
#include <QDesktopServices>
#include <QFileInfo>
#include <QHeaderView>
#include <QMenu>
#include <QMessageBox>
#include <QPushButton>
#include <QTableView>
#include <QToolBar>
#include <QUrl>
#include <QVBoxLayout>

namespace co2h::client::ui {

DownloadsView::DownloadsView(DownloadsModel* model, QWidget* parent)
    : QWidget(parent), model_(model) {

    auto* tb = new QToolBar(this);
    tb->setIconSize(QSize(16, 16));
    auto* openBtn   = tb->addAction("Open");
    auto* folderBtn = tb->addAction("Open folder");
    auto* copyBtn   = tb->addAction("Copy local path");
    tb->addSeparator();
    auto* rmBtn     = tb->addAction("Remove from list");
    auto* clearBtn  = tb->addAction("Clear all");

    connect(openBtn,   &QAction::triggered, this, &DownloadsView::openSelected);
    connect(folderBtn, &QAction::triggered, this, &DownloadsView::openFolderSelected);
    connect(copyBtn,   &QAction::triggered, this, &DownloadsView::copyPathSelected);
    connect(rmBtn,     &QAction::triggered, this, &DownloadsView::removeSelected);
    connect(clearBtn,  &QAction::triggered, this, [this]{
        if (QMessageBox::question(this, "Clear downloads",
                "Clear all download history? Local files are not affected.")
            == QMessageBox::Yes)
            model_->clear();
    });

    view_ = new QTableView(this);
    view_->setModel(model_);
    view_->setSelectionBehavior(QAbstractItemView::SelectRows);
    view_->setSelectionMode(QAbstractItemView::SingleSelection);
    view_->setAlternatingRowColors(true);
    view_->verticalHeader()->setVisible(false);
    view_->horizontalHeader()->setStretchLastSection(false);
    view_->horizontalHeader()->setSectionResizeMode(
        DownloadsModel::ColRemote, QHeaderView::Stretch);
    view_->horizontalHeader()->setSectionResizeMode(
        DownloadsModel::ColLocal,  QHeaderView::Stretch);
    view_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(view_, &QTableView::customContextMenuRequested,
            this, &DownloadsView::onContextMenu);
    connect(view_, &QTableView::doubleClicked,
            this, [this](const QModelIndex&){ openSelected(); });

    auto* v = new QVBoxLayout(this);
    v->setContentsMargins(0, 0, 0, 0);
    v->addWidget(tb);
    v->addWidget(view_, 1);
}

void DownloadsView::onContextMenu(const QPoint& pos) {
    if (!view_->indexAt(pos).isValid()) return;
    QMenu m(this);
    m.addAction("Open file",        this, &DownloadsView::openSelected);
    m.addAction("Open folder",      this, &DownloadsView::openFolderSelected);
    m.addAction("Copy local path",  this, &DownloadsView::copyPathSelected);
    m.addSeparator();
    m.addAction("Remove from list", this, &DownloadsView::removeSelected);
    m.exec(view_->viewport()->mapToGlobal(pos));
}

void DownloadsView::openSelected() {
    auto sel = view_->selectionModel()->selectedRows();
    if (sel.isEmpty()) return;
    const auto* row = model_->at(sel.first().row());
    if (!row) return;
    if (!QFileInfo::exists(row->local)) {
        QMessageBox::warning(this, "Open file",
            "File not found on disk:\n" + row->local);
        return;
    }
    QDesktopServices::openUrl(QUrl::fromLocalFile(row->local));
}

void DownloadsView::openFolderSelected() {
    auto sel = view_->selectionModel()->selectedRows();
    if (sel.isEmpty()) return;
    const auto* row = model_->at(sel.first().row());
    if (!row) return;
    const QString dir = QFileInfo(row->local).absolutePath();
    QDesktopServices::openUrl(QUrl::fromLocalFile(dir));
}

void DownloadsView::copyPathSelected() {
    auto sel = view_->selectionModel()->selectedRows();
    if (sel.isEmpty()) return;
    const auto* row = model_->at(sel.first().row());
    if (!row) return;
    QApplication::clipboard()->setText(row->local);
}

void DownloadsView::removeSelected() {
    auto sel = view_->selectionModel()->selectedRows();
    if (sel.isEmpty()) return;
    model_->removeAt(sel.first().row());
}

}
