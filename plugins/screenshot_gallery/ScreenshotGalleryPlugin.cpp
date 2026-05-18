// Screenshot Gallery plugin: автоматический сбор скриншотов с галереей.
// Таймер, сетка миниатюр, экспорт в папку, открытие в системном просмотрщике.

#include "../../client/plugin/IClientPlugin.hpp"
#include "../../client/plugin/PluginContext.hpp"

#include <QDateTime>
#include <QDir>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QListWidget>
#include <QPainter>
#include <QPixmap>
#include <QPushButton>
#include <QSpinBox>
#include <QStandardPaths>
#include <QSvgRenderer>
#include <QTemporaryDir>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>
#include <QProcess>

using namespace co2h::client;
using namespace co2h::client::plugin;

// Иконка плагина (встроена в код — не зависит от ресурсов клиента).
static const char kScreenshotsSvg[] = R"SVG(
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
  <defs><linearGradient id="cg" x1="0%" y1="0%" x2="100%" y2="100%">
    <stop offset="0%" stop-color="#A855F7"/><stop offset="100%" stop-color="#6366F1"/>
  </linearGradient></defs>
  <rect fill="url(#cg)" x="2" y="5" width="20" height="14" rx="2.5"/>
  <path fill="#1E1B4B" d="M9.5 3.5h5l1.5 2h-8z"/>
  <circle fill="none" stroke="#E9D5FF" stroke-width="1.5" cx="12" cy="12.5" r="4.5"/>
  <circle fill="#FBBF24" cx="12" cy="12.5" r="2.5"/>
  <circle fill="white" opacity=".35" cx="10.5" cy="11" r="1.2"/>
  <rect fill="#C084FC" x="16.5" y="7" width="3" height="2" rx="1"/>
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

// ---- Хранение одного скриншота ----
struct ScreenshotEntry {
    QDateTime timestamp;
    QPixmap   pixmap;
    QString   beaconId;
};

// ---- Основной класс плагина ----
class ScreenshotGalleryPlugin : public IClientPlugin {
public:
    PluginInfo info() const override {
        return {"screenshot_gallery", "1.0.0", "co2h",
                "Auto-screenshot gallery with timer, export and system viewer"};
    }

    void initialize(PluginContext* ctx) override {
        ctx_ = ctx;
        temp_dir_ = new QTemporaryDir;

        // ---- UI ----
        tab_ = new QWidget;
        auto* main_layout = new QVBoxLayout(tab_);

        // == Панель управления ==
        auto* toolbar = new QHBoxLayout;

        toolbar->addWidget(new QLabel("Interval (sec):", tab_));

        interval_spin_ = new QSpinBox(tab_);
        interval_spin_->setRange(5, 3600);
        interval_spin_->setValue(30);
        interval_spin_->setFixedWidth(80);
        toolbar->addWidget(interval_spin_);

        start_btn_ = new QPushButton("Start", tab_);
        start_btn_->setStyleSheet(
            "QPushButton { background: #2a7a2a; color: white; padding: 4px 16px; }"
            "QPushButton:hover { background: #35953a; }");
        toolbar->addWidget(start_btn_);

        stop_btn_ = new QPushButton("Stop", tab_);
        stop_btn_->setEnabled(false);
        stop_btn_->setStyleSheet(
            "QPushButton { background: #7a2a2a; color: white; padding: 4px 16px; }"
            "QPushButton:hover { background: #953535; }");
        toolbar->addWidget(stop_btn_);

        auto* single_btn = new QPushButton("Take One", tab_);
        single_btn->setStyleSheet("padding: 4px 12px;");
        toolbar->addWidget(single_btn);

        toolbar->addSpacing(20);

        auto* export_btn = new QPushButton("Export All...", tab_);
        export_btn->setStyleSheet("padding: 4px 12px;");
        toolbar->addWidget(export_btn);

        auto* clear_btn = new QPushButton("Clear", tab_);
        clear_btn->setStyleSheet("padding: 4px 12px;");
        toolbar->addWidget(clear_btn);

        status_label_ = new QLabel("Stopped | 0 screenshots", tab_);
        status_label_->setStyleSheet("color: #aaa; margin-left: 10px;");
        toolbar->addWidget(status_label_);

        toolbar->addStretch();
        main_layout->addLayout(toolbar);

        // == Сетка миниатюр (QListWidget в режиме иконок) ==
        gallery_ = new QListWidget(tab_);
        gallery_->setViewMode(QListView::IconMode);
        gallery_->setIconSize(QSize(240, 160));
        gallery_->setGridSize(QSize(260, 200));
        gallery_->setResizeMode(QListView::Adjust);
        gallery_->setMovement(QListView::Static);
        gallery_->setWrapping(true);
        gallery_->setSpacing(8);
        gallery_->setSelectionMode(QAbstractItemView::SingleSelection);
        gallery_->setStyleSheet(
            "QListWidget { background: #1a1a1a; border: none; }"
            "QListWidget::item { background: #222; border: 1px solid #444; "
            "  border-radius: 4px; padding: 4px; color: #ccc; }"
            "QListWidget::item:selected { border: 2px solid #4a90d9; background: #2a2a3a; }"
            "QListWidget::item:hover { border: 1px solid #888; }");
        main_layout->addWidget(gallery_, 1);

        tab_->setLayout(main_layout);
        ctx_->addPluginButton(tab_, iconFromSvg(kScreenshotsSvg), "Screenshots");

        // ---- Таймер ----
        timer_ = new QTimer(tab_);

        // ---- Соединения ----
        QObject::connect(start_btn_, &QPushButton::clicked, [this]() {
            startCapture();
        });
        QObject::connect(stop_btn_, &QPushButton::clicked, [this]() {
            stopCapture();
        });
        QObject::connect(single_btn, &QPushButton::clicked, [this]() {
            takeScreenshot();
        });
        QObject::connect(export_btn, &QPushButton::clicked, [this]() {
            exportAll();
        });
        QObject::connect(clear_btn, &QPushButton::clicked, [this]() {
            clearGallery();
        });
        QObject::connect(timer_, &QTimer::timeout, [this]() {
            takeScreenshot();
        });

        // Двойной клик по миниатюре — открыть в системном просмотрщике.
        QObject::connect(gallery_, &QListWidget::itemDoubleClicked,
            [this](QListWidgetItem* item) {
                int idx = item->data(Qt::UserRole).toInt();
                openInSystemViewer(idx);
            });

        // ---- Консольные команды ----
        ctx_->registerCommand("screenshots_start", "<seconds>",
            "start auto-screenshot timer (default 30s)",
            [this](const QString&, const QString& args) {
                bool ok = false;
                int sec = args.trimmed().toInt(&ok);
                if (ok && sec >= 5) interval_spin_->setValue(sec);
                startCapture();
            });

        ctx_->registerCommand("screenshots_stop", "",
            "stop auto-screenshot timer",
            [this](const QString&, const QString&) {
                stopCapture();
            });

        ctx_->registerCommand("screenshots_take", "",
            "take a single screenshot from active beacon",
            [this](const QString&, const QString&) {
                takeScreenshot();
            });

        ctx_->registerCommand("screenshots_export", "<path>",
            "export all screenshots to a folder",
            [this](const QString&, const QString& args) {
                QString path = args.trimmed();
                if (path.isEmpty()) {
                    ctx_->consoleError("[screenshots] specify export path");
                    return;
                }
                exportToPath(path);
            });
    }

    void shutdown() override {
        if (timer_) timer_->stop();
        if (ctx_ && tab_) ctx_->removePluginButton(tab_);
        delete tab_;
        tab_ = nullptr;
        delete temp_dir_;
        temp_dir_ = nullptr;
    }

private:
    // ---- Запуск автосбора ----
    void startCapture() {
        QString bid = ctx_->activeBeaconId();
        if (bid.isEmpty()) {
            ctx_->consoleError("[screenshots] no active beacon - interact first");
            return;
        }

        int interval_ms = interval_spin_->value() * 1000;
        timer_->start(interval_ms);
        running_ = true;

        start_btn_->setEnabled(false);
        stop_btn_->setEnabled(true);
        interval_spin_->setEnabled(false);

        updateStatus();
        ctx_->consoleWrite("[screenshots] auto-capture started, interval "
                           + QString::number(interval_spin_->value()) + "s");
        takeScreenshot();
    }

    // ---- Остановка ----
    void stopCapture() {
        timer_->stop();
        running_ = false;

        start_btn_->setEnabled(true);
        stop_btn_->setEnabled(false);
        interval_spin_->setEnabled(true);

        updateStatus();
        ctx_->consoleWrite("[screenshots] auto-capture stopped");
    }

    // ---- Один скриншот ----
    void takeScreenshot() {
        QString bid = ctx_->activeBeaconId();
        if (bid.isEmpty()) {
            ctx_->consoleError("[screenshots] no active beacon");
            if (running_) stopCapture();
            return;
        }

        ctx_->screenshot(bid,
            [this, bid](const QByteArray& data, const QString& err) {
                if (!err.isEmpty()) {
                    ctx_->consoleError("[screenshots] error: " + err);
                    return;
                }

                QPixmap pix;
                if (!pix.loadFromData(data)) {
                    ctx_->consoleError("[screenshots] failed to decode image data");
                    return;
                }

                // Сохраняем запись.
                ScreenshotEntry entry;
                entry.timestamp = QDateTime::currentDateTime();
                entry.pixmap    = pix;
                entry.beaconId  = bid;
                int idx = entries_.size();
                entries_.append(entry);

                // Сохраняем PNG во временную папку.
                QString fpath;
                if (temp_dir_ && temp_dir_->isValid()) {
                    QString fname = entry.timestamp.toString("yyyyMMdd_HHmmss")
                                    + "_" + bid.left(8) + ".png";
                    fpath = temp_dir_->path() + "/" + fname;
                    pix.save(fpath, "PNG");
                }
                temp_files_.append(fpath);

                // Добавляем в сетку.
                addToGallery(idx);
                updateStatus();
            });
    }

    // ---- Добавление миниатюры в сетку ----
    void addToGallery(int index) {
        const auto& entry = entries_[index];

        // Миниатюра для иконки.
        QPixmap thumb = entry.pixmap.scaled(240, 160, Qt::KeepAspectRatio,
                                             Qt::SmoothTransformation);

        // Подпись: время + ID бикона.
        QString label = entry.timestamp.toString("HH:mm:ss") + " | "
                        + entry.beaconId.left(8);

        auto* item = new QListWidgetItem(QIcon(thumb), label);
        item->setData(Qt::UserRole, index);
        item->setSizeHint(QSize(260, 200));
        gallery_->addItem(item);

        // Прокрутка к последнему элементу.
        gallery_->scrollToItem(item);
    }

    // ---- Открыть в системном просмотрщике ----
    void openInSystemViewer(int index) {
        if (index < 0 || index >= entries_.size()) return;

        QString fpath;
        if (index < temp_files_.size() && !temp_files_[index].isEmpty()
            && QFile::exists(temp_files_[index])) {
            fpath = temp_files_[index];
        } else {
            // Сохраняем во временный файл.
            if (!temp_dir_ || !temp_dir_->isValid()) return;
            const auto& entry = entries_[index];
            fpath = temp_dir_->path() + "/"
                    + entry.timestamp.toString("yyyyMMdd_HHmmss")
                    + "_" + entry.beaconId.left(8) + ".png";
            entry.pixmap.save(fpath, "PNG");
            while (temp_files_.size() <= index)
                temp_files_.append(QString());
            temp_files_[index] = fpath;
        }

        QString native = QDir::toNativeSeparators(fpath);
#ifdef _WIN32
        QProcess::startDetached("explorer.exe", {native});
#else
        QProcess::startDetached("xdg-open", {native});
#endif
    }

    // ---- Экспорт (GUI) ----
    void exportAll() {
        if (entries_.isEmpty()) {
            ctx_->consoleError("[screenshots] no screenshots to export");
            return;
        }

        QString dir = QFileDialog::getExistingDirectory(
            tab_, "Export screenshots to...",
            QStandardPaths::writableLocation(QStandardPaths::DesktopLocation));
        if (dir.isEmpty()) return;

        exportToPath(dir);
    }

    // ---- Экспорт в путь ----
    void exportToPath(const QString& dir_path) {
        QDir dir(dir_path);
        if (!dir.exists()) dir.mkpath(".");

        int count = 0;
        for (int i = 0; i < entries_.size(); ++i) {
            const auto& entry = entries_[i];
            QString fname = entry.timestamp.toString("yyyyMMdd_HHmmss")
                            + "_" + entry.beaconId.left(8) + ".png";
            if (entry.pixmap.save(dir.filePath(fname), "PNG"))
                ++count;
        }

        ctx_->consoleWrite("[screenshots] exported " + QString::number(count)
                           + " screenshots to " + dir_path);
        ctx_->log("[screenshots] exported " + QString::number(count)
                  + " screenshots to " + dir_path);
    }

    // ---- Очистка ----
    void clearGallery() {
        gallery_->clear();
        entries_.clear();
        temp_files_.clear();
        updateStatus();
    }

    // ---- Статус ----
    void updateStatus() {
        QString state = running_ ? "Running" : "Stopped";
        status_label_->setText(state + " | "
                               + QString::number(entries_.size()) + " screenshots");
    }

    // ---- Поля ----
    PluginContext*  ctx_           = nullptr;
    QWidget*        tab_           = nullptr;
    QTimer*         timer_         = nullptr;
    QSpinBox*       interval_spin_ = nullptr;
    QPushButton*    start_btn_     = nullptr;
    QPushButton*    stop_btn_      = nullptr;
    QLabel*         status_label_  = nullptr;
    QListWidget*    gallery_       = nullptr;
    QTemporaryDir*  temp_dir_      = nullptr;

    QVector<ScreenshotEntry> entries_;
    QStringList              temp_files_;
    bool                     running_ = false;
};

// ---- Экспорт ----

CO2H_PLUGIN_EXPORT IClientPlugin* co2h_plugin_create() {
    return new ScreenshotGalleryPlugin;
}

CO2H_PLUGIN_EXPORT void co2h_plugin_destroy(IClientPlugin* p) {
    delete p;
}
