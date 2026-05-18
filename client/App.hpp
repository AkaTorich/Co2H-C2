#pragma once

#include "net/ServerClient.hpp"

#include <QObject>
#include <memory>

namespace co2h::client::ui { class MainWindow; }

namespace co2h::client {

class App : public QObject {
    Q_OBJECT
public:
    App();
    ~App() override;

    ServerClient&    server()     { return *client_; }
    ui::MainWindow*  mainWindow() { return window_.get(); }

    int exec();

private:
    std::unique_ptr<ServerClient>   client_;
    std::unique_ptr<ui::MainWindow> window_;
};

}
