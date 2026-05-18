#include "LoginDialog.hpp"
#include "SvgIcon.hpp"

#include <QCoreApplication>
#include <QDialogButtonBox>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>

namespace co2h::client::ui {

namespace {
QWidget* makeFileField(QLineEdit** outEdit, const QString& filter,
                       QWidget* parent) {
    auto* w = new QWidget(parent);
    auto* h = new QHBoxLayout(w);
    h->setContentsMargins(0, 0, 0, 0);
    *outEdit = new QLineEdit(w);
    auto* btn = new QPushButton("…", w);
    btn->setFixedWidth(28);
    h->addWidget(*outEdit);
    h->addWidget(btn);
    QObject::connect(btn, &QPushButton::clicked, [edit = *outEdit, filter, parent]{
        auto path = QFileDialog::getOpenFileName(parent, "Select file", {}, filter);
        if (!path.isEmpty()) edit->setText(path);
    });
    return w;
}
}

LoginDialog::LoginDialog(QWidget* parent) : QDialog(parent) {
    setWindowTitle("Co2H — Connect");
    setWindowIcon(svgIcon(":/icons/logo.svg"));
    setModal(true);
    setMinimumWidth(440);

    host_ = new QLineEdit(this);
    host_->setPlaceholderText("teamserver host");
    host_->setText("127.0.0.1");

    port_ = new QLineEdit(this);
    port_->setText("50050");
    port_->setMaximumWidth(90);

    user_ = new QLineEdit(this);
    user_->setText("admin");

    pass_ = new QLineEdit(this);
    pass_->setEchoMode(QLineEdit::Password);

    auto* caWidget   = makeFileField(&ca_,   "Certificates (*.pem *.crt);;All (*)", this);
    auto* certWidget = makeFileField(&cert_, "Certificates (*.pem *.crt);;All (*)", this);
    auto* keyWidget  = makeFileField(&key_,  "Keys (*.pem *.key);;All (*)",          this);

    // Auto-fill cert paths from certs\ folder next to the exe
    {
        QString certsDir = QCoreApplication::applicationDirPath() + "/certs";
        auto tryFill = [&](QLineEdit* edit, const QString& name) {
            QString p = certsDir + "/" + name;
            if (QFileInfo::exists(p)) edit->setText(QDir::toNativeSeparators(p));
        };
        tryFill(ca_,   "ca.crt");
        tryFill(cert_, "operator.crt");
        tryFill(key_,  "operator.key");
    }

    status_ = new QLabel(this);
    status_->setWordWrap(true);

    auto* form = new QFormLayout;
    auto* hp = new QWidget(this);
    auto* hpL = new QHBoxLayout(hp);
    hpL->setContentsMargins(0, 0, 0, 0);
    hpL->addWidget(host_);
    hpL->addWidget(new QLabel(":"));
    hpL->addWidget(port_);
    form->addRow("Server:",           hp);
    form->addRow("Username:",         user_);
    form->addRow("Password:",         pass_);
    form->addRow("CA Certificate:",      caWidget);
    form->addRow("Operator Certificate:", certWidget);
    form->addRow("Operator Private Key:", keyWidget);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    connect_ = buttons->button(QDialogButtonBox::Ok);
    connect_->setText("Connect");
    connect_->setDefault(true);
    connect_->setIcon(glassyIcon(":/icons/connection.svg", QColor("#3b82f6"), {18, 18}));
    buttons->button(QDialogButtonBox::Cancel)->setIcon(
        glassyIcon(":/icons/close.svg", QColor("#ef4444"), {18, 18}));

    auto* v = new QVBoxLayout(this);
    auto* title = new QLabel("<h2>Co2H Operator Console</h2>");
    v->addWidget(title);
    v->addLayout(form);
    v->addWidget(status_);
    v->addWidget(buttons);

    QObject::connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    QObject::connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
}

LoginInfo LoginDialog::info() const {
    LoginInfo i;
    i.host        = host_->text();
    i.port        = static_cast<quint16>(port_->text().toInt());
    i.username    = user_->text();
    i.password    = pass_->text();
    i.ca_file     = ca_->text();
    i.client_cert = cert_->text();
    i.client_key  = key_->text();
    return i;
}

void LoginDialog::prefill(const LoginInfo& info) {
    host_->setText(info.host);
    port_->setText(QString::number(info.port));
    user_->setText(info.username);
    pass_->setText(info.password);
    if (!info.ca_file.isEmpty())     ca_->setText(info.ca_file);
    if (!info.client_cert.isEmpty()) cert_->setText(info.client_cert);
    if (!info.client_key.isEmpty())  key_->setText(info.client_key);
}

void LoginDialog::setStatus(const QString& msg, bool error) {
    status_->setText(msg);
    status_->setStyleSheet(error ? "color: #ef4444;" : "color: #10b981;");
}

}
