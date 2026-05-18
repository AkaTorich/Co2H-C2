#include "ChatView.hpp"

#include <QDateTime>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTextCharFormat>
#include <QTextCursor>
#include <QHBoxLayout>
#include <QVBoxLayout>

namespace co2h::client::ui {

ChatView::ChatView(QWidget* parent) : QWidget(parent) {
    output_ = new QPlainTextEdit(this);
    output_->setReadOnly(true);
    output_->setMaximumBlockCount(5000);

    input_ = new QLineEdit(this);
    input_->setPlaceholderText("Message to all operators... (Enter)");

    auto* sendBtn = new QPushButton("Send", this);

    auto* row = new QHBoxLayout;
    row->setContentsMargins(0, 0, 0, 0);
    row->addWidget(input_, 1);
    row->addWidget(sendBtn);

    auto* v = new QVBoxLayout(this);
    v->setContentsMargins(0, 0, 0, 0);
    v->addWidget(output_, 1);
    v->addLayout(row);

    connect(input_,  &QLineEdit::returnPressed, this, &ChatView::onSubmit);
    connect(sendBtn, &QPushButton::clicked,     this, &ChatView::onSubmit);
}

void ChatView::setSelfUsername(const QString& name) {
    self_ = name;
}

static void appendColored(QPlainTextEdit* out, const QString& s, const QColor& c) {
    QTextCharFormat f;
    f.setForeground(c);
    auto cur = out->textCursor();
    cur.movePosition(QTextCursor::End);
    cur.insertText(s, f);
    out->setTextCursor(cur);
    out->ensureCursorVisible();
}

void ChatView::appendMessage(const QString& from, const QString& text, quint64 ts) {
    const auto time = (ts > 0)
        ? QDateTime::fromSecsSinceEpoch(static_cast<qint64>(ts))
        : QDateTime::currentDateTime();
    const QString stamp = time.toString("HH:mm:ss");

    const bool self = (!self_.isEmpty() && from == self_);
    const QColor cFrom = self ? QColor("#10b981") : QColor("#3b82f6");

    appendColored(output_, "[" + stamp + "] ", QColor("#94a3b8"));
    appendColored(output_, from + ": ",        cFrom);
    appendColored(output_, text + "\n",        QColor("#e2e8f0"));
}

void ChatView::appendSystem(const QString& text) {
    const QString stamp = QDateTime::currentDateTime().toString("HH:mm:ss");
    appendColored(output_, "[" + stamp + "] -- " + text + "\n", QColor("#f59e0b"));
}

void ChatView::onSubmit() {
    const auto t = input_->text().trimmed();
    if (t.isEmpty()) return;
    input_->clear();
    emit sendRequested(t);
}

}
