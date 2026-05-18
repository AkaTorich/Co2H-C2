#include "Theme.hpp"

#include <QApplication>
#include <QFile>
#include <QPalette>

namespace co2h::client::ui {

namespace {
Theme g_theme = Theme::Dark;

void applyPalette(Theme t) {
    QPalette pal;
    if (t == Theme::Dark) {
        pal.setColor(QPalette::Window,          QColor("#0f141b"));
        pal.setColor(QPalette::WindowText,      QColor("#d7e3f4"));
        pal.setColor(QPalette::Base,            QColor("#0f141b"));
        pal.setColor(QPalette::AlternateBase,   QColor("#141b24"));
        pal.setColor(QPalette::Text,            QColor("#d7e3f4"));
        pal.setColor(QPalette::Button,          QColor("#1a2330"));
        pal.setColor(QPalette::ButtonText,      QColor("#d7e3f4"));
        pal.setColor(QPalette::Highlight,       QColor("#2563eb"));
        pal.setColor(QPalette::HighlightedText, QColor("#ffffff"));
        pal.setColor(QPalette::ToolTipBase,     QColor("#141b24"));
        pal.setColor(QPalette::ToolTipText,     QColor("#d7e3f4"));
    } else {
        pal.setColor(QPalette::Window,          QColor("#f5f6f8"));
        pal.setColor(QPalette::WindowText,      QColor("#1e232b"));
        pal.setColor(QPalette::Base,            QColor("#ffffff"));
        pal.setColor(QPalette::AlternateBase,   QColor("#f6f8fb"));
        pal.setColor(QPalette::Text,            QColor("#1e232b"));
        pal.setColor(QPalette::Button,          QColor("#ffffff"));
        pal.setColor(QPalette::ButtonText,      QColor("#1e232b"));
        pal.setColor(QPalette::Highlight,       QColor("#2563eb"));
        pal.setColor(QPalette::HighlightedText, QColor("#ffffff"));
    }
    qApp->setPalette(pal);
}

QString loadStylesheet(Theme t) {
    QFile f(t == Theme::Dark ? ":/themes/dark.qss" : ":/themes/light.qss");
    if (!f.open(QIODevice::ReadOnly)) return {};
    return QString::fromUtf8(f.readAll());
}

}

void applyTheme(Theme t) {
    g_theme = t;
    applyPalette(t);
    qApp->setStyleSheet(loadStylesheet(t));
}

Theme currentTheme() { return g_theme; }

}
