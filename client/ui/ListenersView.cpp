#include "ListenersView.hpp"
#include "../models/ListenersModel.hpp"
#include "SvgIcon.hpp"

#include <QApplication>
#include <QClipboard>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QMenu>
#include <QPushButton>
#include <QTableView>
#include <QVBoxLayout>

namespace co2h::client::ui {

ListenersView::ListenersView(ListenersModel* model, QWidget* parent)
    : QWidget(parent), model_(model) {
    auto* v = new QVBoxLayout(this);
    auto* toolbar = new QHBoxLayout;
    auto* title = new QLabel;
    title->setText("   Listeners");
    title->setStyleSheet("font-weight: 600;");
    auto* add     = new QPushButton("Add");
    add->setIcon(glassyIcon(":/icons/add.svg",     QColor("#22c55e"), {18, 18}));
    auto* remove  = new QPushButton("Remove");
    remove->setIcon(glassyIcon(":/icons/remove.svg", QColor("#ef4444"), {18, 18}));
    auto* refresh = new QPushButton("Refresh");
    refresh->setIcon(glassyIcon(":/icons/refresh.svg", QColor("#60a5fa"), {18, 18}));
    toolbar->addWidget(title);
    toolbar->addStretch();
    toolbar->addWidget(add);
    toolbar->addWidget(remove);
    toolbar->addWidget(refresh);

    view_ = new QTableView(this);
    view_->setModel(model_);
    view_->setSelectionBehavior(QAbstractItemView::SelectRows);
    view_->setAlternatingRowColors(true);
    view_->verticalHeader()->setVisible(false);
    view_->horizontalHeader()->setStretchLastSection(true);
    view_->setContextMenuPolicy(Qt::CustomContextMenu);

    connect(view_, &QTableView::customContextMenuRequested,
            this,  &ListenersView::showContextMenu);

    connect(add,     &QPushButton::clicked, this, &ListenersView::addRequested);
    connect(refresh, &QPushButton::clicked, this, &ListenersView::refreshRequested);
    connect(remove,  &QPushButton::clicked, this, [this] {
        auto idx = view_->currentIndex();
        if (!idx.isValid()) return;
        auto name = model_->data(model_->index(idx.row(), ListenersModel::ColName),
                                 Qt::DisplayRole).toString();
        if (!name.isEmpty()) emit removeRequested(name);
    });

    v->addLayout(toolbar);
    v->addWidget(view_);
}

void ListenersView::showContextMenu(const QPoint& pos) {
    auto idx = view_->indexAt(pos);
    if (!idx.isValid()) return;
    int row = idx.row();
    auto key    = model_->data(model_->index(row, ListenersModel::ColKey),
                               Qt::UserRole).toString();
    auto kind   = model_->data(model_->index(row, ListenersModel::ColKind),
                               Qt::UserRole).toString();
    auto domain = model_->data(model_->index(row, ListenersModel::ColBind),
                               Qt::UserRole).toString();
    auto name   = model_->data(model_->index(row, ListenersModel::ColName),
                               Qt::DisplayRole).toString();
    auto bind   = model_->data(model_->index(row, ListenersModel::ColBind),
                               Qt::DisplayRole).toString();
    // Извлекаем host:port из строки bind (для не-DNS транспортов).
    QString host = bind.section(':', 0, 0);
    if (host == "0.0.0.0" || host.isEmpty()) host = "127.0.0.1";
    QString port = bind.section(':', 1, 1);

    if (key.isEmpty()) return;

    QMenu menu(this);

    menu.addAction("Stop listener", [this, name] {
        emit removeRequested(name);
    });
    menu.addSeparator();

    menu.addAction("Copy listener key", [key] {
        QApplication::clipboard()->setText(key);
    });

    // Путь к artifact-gen и beacon-файлам: на Windows — обратные слеши и .exe,
    // на Linux — прямые слеши, без .exe.
#ifdef _WIN32
    const QString agBin = ".\\bin\\artifact-gen.exe";
    const QString b64exe = "bin\\beacon64.exe";
    const QString b64dll = "bin\\beacon64.dll";
#else
    const QString agBin = "./bin/artifact-gen";
    const QString b64exe = "bin/beacon64.exe";
    const QString b64dll = "bin/beacon64.dll";
#endif

    if (kind == "dns") {
        // DNS: URI-checkin = dns://<domain>, --host = IP teamserver'а.
        menu.addAction("Copy artifact-gen command (DNS EXE)", [key, host, port, domain, agBin, b64exe] {
            QString cmd = QString(
                "%1 --input %2 "
                "--key %3 --host %4 --port %5 --uri-checkin dns://%6 --out payload.exe")
                .arg(agBin).arg(b64exe)
                .arg(key).arg(host).arg(port.isEmpty() ? "53" : port).arg(domain);
            QApplication::clipboard()->setText(cmd);
        });
        menu.addAction("Copy artifact-gen command (DNS DLL)", [key, host, port, domain, agBin, b64dll] {
            QString cmd = QString(
                "%1 --input %2 "
                "--key %3 --host %4 --port %5 --uri-checkin dns://%6 --out payload.dll")
                .arg(agBin).arg(b64dll)
                .arg(key).arg(host).arg(port.isEmpty() ? "53" : port).arg(domain);
            QApplication::clipboard()->setText(cmd);
        });
    } else {
        menu.addAction("Copy artifact-gen command (EXE)", [key, host, port, agBin, b64exe] {
            QString cmd = QString(
                "%1 --input %2 "
                "--key %3 --host %4 --port %5 --out payload.exe")
                .arg(agBin).arg(b64exe)
                .arg(key).arg(host).arg(port);
            QApplication::clipboard()->setText(cmd);
        });
        menu.addAction("Copy artifact-gen command (DLL)", [key, host, port, agBin, b64dll] {
            QString cmd = QString(
                "%1 --input %2 "
                "--key %3 --host %4 --port %5 --out payload.dll")
                .arg(agBin).arg(b64dll)
                .arg(key).arg(host).arg(port);
            QApplication::clipboard()->setText(cmd);
        });
    }
    menu.exec(view_->viewport()->mapToGlobal(pos));
}

}
