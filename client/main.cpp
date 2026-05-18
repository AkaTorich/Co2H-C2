#include "App.hpp"

#include <QApplication>
#include <QIcon>

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    QApplication::setApplicationName("Co2H");
    QApplication::setOrganizationName("Co2H");
    QApplication::setApplicationVersion("0.1.0");
    QApplication::setWindowIcon(QIcon(":/client-icon.ico"));

    co2h::client::App a;
    return a.exec();
}
