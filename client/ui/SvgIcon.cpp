#include "SvgIcon.hpp"

#include <QApplication>
#include <QByteArray>
#include <QFile>
#include <QIconEngine>
#include <QPainter>
#include <QPalette>
#include <QPixmap>
#include <QRadialGradient>
#include <QLinearGradient>
#include <QSvgRenderer>

namespace co2h::client::ui {

namespace {

QByteArray loadSvg(const QString& path) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return {};
    return f.readAll();
}

QByteArray tintSvg(const QByteArray& src, const QColor& color) {
    if (!color.isValid()) return src;
    QByteArray out = src;
    const QByteArray token = "currentColor";
    const QByteArray hex   = color.name(QColor::HexRgb).toUtf8();
    int from = 0;
    while ((from = out.indexOf(token, from)) != -1) {
        out.replace(from, token.size(), hex);
        from += hex.size();
    }
    return out;
}

QPixmap renderPixmap(const QByteArray& svg, const QSize& size, qreal dpr) {
    QSvgRenderer r(svg);
    QPixmap pm(size * dpr);
    pm.setDevicePixelRatio(dpr);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing);
    p.setRenderHint(QPainter::SmoothPixmapTransform);
    r.render(&p, QRectF(QPointF(0, 0), size));
    return pm;
}

}

QIcon svgIcon(const QString& resourcePath, const QColor& color, const QSize& base) {
    QByteArray raw = loadSvg(resourcePath);
    if (raw.isEmpty()) return QIcon();
    QByteArray tinted = tintSvg(raw, color);

    QIcon icon;
    const QList<qreal> dprs{1.0, 1.25, 1.5, 2.0, 3.0};
    for (qreal dpr : dprs) {
        icon.addPixmap(renderPixmap(tinted, base, dpr));
    }
    return icon;
}

QIcon themedIcon(const QString& resourcePath, const QSize& base) {
    QColor c = qApp ? qApp->palette().color(QPalette::WindowText) : QColor("#1e232b");
    return svgIcon(resourcePath, c, base);
}

QIcon glassyIcon(const QString& resourcePath, const QColor& accent, const QSize& base) {
    QByteArray raw = loadSvg(resourcePath);
    if (raw.isEmpty()) return QIcon();
    (void)accent; // accent kept for API compat; colour is baked into the SVG

    QIcon icon;
    const QList<qreal> dprs{1.0, 1.25, 1.5, 2.0, 3.0};
    for (qreal dpr : dprs)
        icon.addPixmap(renderPixmap(raw, base, dpr));
    return icon;
}

}
