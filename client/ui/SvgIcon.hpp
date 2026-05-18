#pragma once

#include <QColor>
#include <QIcon>
#include <QPixmap>
#include <QSize>
#include <QString>

namespace co2h::client::ui {

// Load an SVG resource path (e.g. ":/icons/beacon.svg") and recolor it by
// substituting currentColor before rendering.  Returns a multi-DPI QIcon that
// renders crisply at all common HiDPI scales (1x, 1.25x, 1.5x, 2x, 3x).
QIcon svgIcon(const QString& resourcePath,
              const QColor&  color = QColor(),
              const QSize&   base  = QSize(24, 24));

// Convenience: create an SVG icon tinted to match the application palette's
// WindowText role (theme-aware).
QIcon themedIcon(const QString& resourcePath,
                 const QSize&   base = QSize(24, 24));

// Colored glassy icon: accent tint + radial shine overlay.
QIcon glassyIcon(const QString& resourcePath,
                 const QColor&  accent,
                 const QSize&   base = QSize(24, 24));

}
