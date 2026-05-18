#include "App.hpp"
#include "ui/LoginDialog.hpp"
#include "ui/MainWindow.hpp"
#include "ui/Theme.hpp"

#include <QApplication>

namespace co2h::client {

App::App()
    : client_(std::make_unique<ServerClient>()) {
    ui::applyTheme(ui::Theme::Dark);
}

App::~App() = default;

int App::exec() {
    ui::LoginInfo defaults;
    defaults.host     = "127.0.0.1";
    defaults.port     = 50050;
    defaults.username = "admin";

    window_ = std::make_unique<ui::MainWindow>(client_.get(), defaults);
    window_->show();

    return QApplication::exec();
}

}
