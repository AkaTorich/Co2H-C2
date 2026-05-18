// Example plugin: adds a "Recon" tab and a "recon" console command.
// Build as a shared library (.dll/.so), place in plugins/ next to co2h-client.

#include "../../client/plugin/IClientPlugin.hpp"
#include "../../client/plugin/PluginContext.hpp"

#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QPixmap>
#include <QPushButton>
#include <QSvgRenderer>
#include <QPainter>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QWidget>

using namespace co2h::client;
using namespace co2h::client::plugin;

// Иконка плагина (встроена в код — не зависит от ресурсов клиента).
static const char kReconSvg[] = R"SVG(
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
  <defs><radialGradient id="gr" cx="35%" cy="28%" r="65%">
    <stop offset="0%" stop-color="#60DDFF"/><stop offset="100%" stop-color="#0868C8"/>
  </radialGradient></defs>
  <circle fill="url(#gr)" cx="10.5" cy="10.5" r="7.5"/>
  <circle fill="#0A1628" cx="10.5" cy="10.5" r="5"/>
  <circle fill="white" opacity=".25" cx="8.5" cy="8" r="2.2"/>
  <rect fill="url(#gr)" x="16" y="16" width="6.5" height="3.2" rx="1.5" transform="rotate(-45 16 16)"/>
  <line stroke="#40CCFF" stroke-width="1" x1="7.5" y1="9" x2="13.5" y2="9" opacity=".7"/>
  <line stroke="#40CCFF" stroke-width="1" x1="7.5" y1="11" x2="13.5" y2="11" opacity=".5"/>
  <line stroke="#40CCFF" stroke-width="1" x1="8.5" y1="13" x2="12.5" y2="13" opacity=".3"/>
</svg>
)SVG";

static QIcon iconFromSvg(const char* data) {
    QByteArray svg(data);
    QSvgRenderer r(svg);
    QPixmap pix(24, 24);
    pix.fill(Qt::transparent);
    QPainter p(&pix);
    r.render(&p);
    return QIcon(pix);
}

class ExamplePlugin : public IClientPlugin {
public:
    PluginInfo info() const override {
        return {"example_recon", "1.0.0", "co2h",
                "Example plugin: adds Recon tab and recon command"};
    }

    void initialize(PluginContext* ctx) override {
        ctx_ = ctx;

        // Создаём виджет вкладки.
        tab_ = new QWidget;
        auto* layout = new QVBoxLayout(tab_);

        // Верхняя панель: кнопки.
        auto* toolbar = new QHBoxLayout;

        auto* runBtn = new QPushButton("Run Recon", tab_);
        toolbar->addWidget(runBtn);

        auto* clearBtn = new QPushButton("Clear", tab_);
        toolbar->addWidget(clearBtn);

        beacon_label_ = new QLabel("No beacon selected", tab_);
        toolbar->addWidget(beacon_label_);
        toolbar->addStretch();

        layout->addLayout(toolbar);

        // Текстовый вывод.
        output_ = new QTextEdit(tab_);
        output_->setReadOnly(true);
        layout->addWidget(output_);
        tab_->setLayout(layout);

        ctx_->addPluginButton(tab_, iconFromSvg(kReconSvg), "Recon");

        // Кнопка Run Recon — использует активный beacon из консоли.
        QObject::connect(runBtn, &QPushButton::clicked, [this]() {
            QString bid = ctx_->activeBeaconId();
            if (bid.isEmpty()) {
                output_->append("<b>Error:</b> interact with a beacon first (use console)");
                return;
            }
            beacon_label_->setText("Beacon: " + bid.left(8) + "...");
            runRecon(bid);
        });

        // Кнопка Clear.
        QObject::connect(clearBtn, &QPushButton::clicked, [this]() {
            output_->clear();
        });

        // Регистрируем консольную команду "recon".
        ctx_->registerCommand("recon", "",
            "run basic recon (whoami, ipconfig, net user) on the active beacon",
            [this](const QString& beaconId, const QString& args) {
                runRecon(beaconId);
            });
    }

    void shutdown() override {
        if (ctx_ && tab_) ctx_->removePluginButton(tab_);
        delete tab_;
        tab_ = nullptr;
    }

private:
    void runRecon(const QString& beaconId) {
        output_->append("<b>[recon]</b> starting on " + beaconId.left(8) + "...");
        ctx_->consoleWrite("[recon] starting basic recon...");

        ctx_->shell(beaconId, "whoami /all",
            [this](const QByteArray& out, const QString& err) {
                if (!err.isEmpty())
                    output_->append("<font color='red'>ERROR: " + err + "</font>");
                else
                    output_->append("<b>=== whoami /all ===</b><pre>"
                                    +
#ifdef _WIN32
                                    QString::fromUtf8(out)
#else
                                    QString::fromLocal8Bit(out)
#endif
                                    + "</pre>");
            });

        ctx_->shell(beaconId, "ipconfig /all",
            [this](const QByteArray& out, const QString& err) {
                if (!err.isEmpty())
                    output_->append("<font color='red'>ERROR: " + err + "</font>");
                else
                    output_->append("<b>=== ipconfig /all ===</b><pre>"
                                    +
#ifdef _WIN32
                                    QString::fromUtf8(out)
#else
                                    QString::fromLocal8Bit(out)
#endif
                                    + "</pre>");
            });

        ctx_->shell(beaconId, "net user /domain",
            [this](const QByteArray& out, const QString& err) {
                if (!err.isEmpty())
                    output_->append("<font color='red'>ERROR: " + err + "</font>");
                else
                    output_->append("<b>=== net user /domain ===</b><pre>"
                                    +
#ifdef _WIN32
                                    QString::fromUtf8(out)
#else
                                    QString::fromLocal8Bit(out)
#endif
                                    + "</pre>");
            });
    }

    PluginContext* ctx_          = nullptr;
    QWidget*       tab_          = nullptr;
    QTextEdit*     output_       = nullptr;
    QLabel*        beacon_label_ = nullptr;
};

// ---- Export symbols ----

CO2H_PLUGIN_EXPORT IClientPlugin* co2h_plugin_create() {
    return new ExamplePlugin;
}

CO2H_PLUGIN_EXPORT void co2h_plugin_destroy(IClientPlugin* p) {
    delete p;
}
