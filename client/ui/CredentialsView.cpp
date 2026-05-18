#include "CredentialsView.hpp"
#include "../models/CredentialsModel.hpp"

#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHeaderView>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QTableView>
#include <QToolBar>
#include <QVBoxLayout>

namespace co2h::client::ui {

CredentialsView::CredentialsView(CredentialsModel* model, QWidget* parent)
    : QWidget(parent), model_(model) {

    auto* tb = new QToolBar(this);
    tb->setIconSize(QSize(16, 16));
    auto* addBtn     = tb->addAction("Add");
    auto* useBtn     = tb->addAction("Use (make_token)");
    auto* copyBtn    = tb->addAction("Copy secret");
    tb->addSeparator();
    auto* rmBtn      = tb->addAction("Remove");
    auto* refreshBtn = tb->addAction("Refresh");

    connect(addBtn,     &QAction::triggered, this, &CredentialsView::onAdd);
    connect(useBtn,     &QAction::triggered, this, &CredentialsView::onUse);
    connect(copyBtn,    &QAction::triggered, this, &CredentialsView::onCopySecret);
    connect(rmBtn,      &QAction::triggered, this, &CredentialsView::onRemove);
    connect(refreshBtn, &QAction::triggered, this, &CredentialsView::onRefresh);

    view_ = new QTableView(this);
    view_->setModel(model_);
    view_->setSelectionBehavior(QAbstractItemView::SelectRows);
    view_->setSelectionMode(QAbstractItemView::SingleSelection);
    view_->setAlternatingRowColors(true);
    view_->verticalHeader()->setVisible(false);
    view_->horizontalHeader()->setStretchLastSection(true);
    view_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(view_, &QTableView::customContextMenuRequested,
            this, &CredentialsView::onContextMenu);

    auto* v = new QVBoxLayout(this);
    v->setContentsMargins(0, 0, 0, 0);
    v->addWidget(tb);
    v->addWidget(view_, 1);
}

void CredentialsView::onAdd() {
    QDialog dlg(this);
    dlg.setWindowTitle("Add credential");
    dlg.setMinimumWidth(360);

    auto* user   = new QLineEdit(&dlg);
    auto* domain = new QLineEdit(&dlg);
    auto* kind   = new QComboBox(&dlg);
    kind->addItems({"password", "hash", "ticket", "identity"});
    auto* secret = new QLineEdit(&dlg);
    secret->setEchoMode(QLineEdit::PasswordEchoOnEdit);
    auto* host   = new QLineEdit(&dlg);
    auto* note   = new QLineEdit(&dlg);

    auto* form = new QFormLayout;
    form->addRow("User:",   user);
    form->addRow("Domain:", domain);
    form->addRow("Kind:",   kind);
    form->addRow("Secret:", secret);
    form->addRow("Host:",   host);
    form->addRow("Note:",   note);

    auto* bb = new QDialogButtonBox(QDialogButtonBox::Ok|QDialogButtonBox::Cancel, &dlg);
    connect(bb, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(bb, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

    auto* lay = new QVBoxLayout(&dlg);
    lay->addLayout(form);
    lay->addWidget(bb);

    if (dlg.exec() != QDialog::Accepted) return;
    if (user->text().trimmed().isEmpty()) {
        QMessageBox::warning(this, "Add credential", "User is required.");
        return;
    }

    CredentialRow r;
    r.user     = user->text().trimmed();
    r.domain   = domain->text().trimmed();
    r.kind     = kind->currentText();
    r.secret   = secret->text();
    r.host     = host->text().trimmed();
    r.source   = "manual";
    r.note     = note->text().trimmed();
    r.added_at = QDateTime::currentDateTime();
    emit requestAdd(r);
}

void CredentialsView::onRemove() {
    auto sel = view_->selectionModel()->selectedRows();
    if (sel.isEmpty()) return;
    const auto* r = model_->at(sel.first().row());
    if (!r || r->id == 0) {
        QMessageBox::information(this, "Remove",
            "Entry not yet confirmed by server (id=0). Wait for Refresh.");
        return;
    }
    if (QMessageBox::question(this, "Remove credential",
            QString("Delete entry %1\\%2 (%3)?")
                .arg(r->domain, r->user, r->kind)) == QMessageBox::Yes)
        emit requestDelete(r->id);
}

void CredentialsView::onRefresh() {
    emit requestRefresh();
}

void CredentialsView::onUse() {
    auto sel = view_->selectionModel()->selectedRows();
    if (sel.isEmpty()) {
        QMessageBox::information(this, "Use", "Select an entry.");
        return;
    }
    const auto* r = model_->at(sel.first().row());
    if (!r) return;
    if (r->kind != "password") {
        QMessageBox::warning(this, "Use",
            "make_token only accepts user/password pairs.\n"
            "Hash/ticket require separate commands (planned for v1).");
        return;
    }
    if (r->user.isEmpty() || r->secret.isEmpty()) {
        QMessageBox::warning(this, "Use", "User and Secret are required.");
        return;
    }
    const QString upn = r->domain.isEmpty()
        ? r->user
        : QString("%1\\%2").arg(r->domain, r->user);
    emit applyMakeToken(upn, r->secret);
}

void CredentialsView::onCopySecret() {
    auto sel = view_->selectionModel()->selectedRows();
    if (sel.isEmpty()) return;
    const auto* r = model_->at(sel.first().row());
    if (!r) return;
    QApplication::clipboard()->setText(r->secret);
}

void CredentialsView::onContextMenu(const QPoint& pos) {
    if (!view_->indexAt(pos).isValid()) return;
    QMenu m(this);
    m.addAction("Use (make_token)", this, &CredentialsView::onUse);
    m.addAction("Copy secret",      this, &CredentialsView::onCopySecret);
    m.addSeparator();
    m.addAction("Remove",           this, &CredentialsView::onRemove);
    m.exec(view_->viewport()->mapToGlobal(pos));
}

}
