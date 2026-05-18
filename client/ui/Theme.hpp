#pragma once

#include <QApplication>

namespace co2h::client::ui {

enum class Theme { Light, Dark };

void applyTheme(Theme t);
Theme currentTheme();

}
