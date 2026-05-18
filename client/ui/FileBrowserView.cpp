#include "FileBrowserView.hpp"
#include "SvgIcon.hpp"
#include "../net/ServerClient.hpp"

#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

namespace co2h::client::ui {

// Элемент колонки Name: папки всегда выше файлов, внутри группы — по имени
// без учёта регистра.
class FileSortItem : public QTableWidgetItem {
public:
    using QTableWidgetItem::QTableWidgetItem;
    bool operator<(const QTableWidgetItem& other) const override {
        bool this_dir  = data(Qt::UserRole).toBool();
        bool other_dir = other.data(Qt::UserRole).toBool();
        if (this_dir != other_dir)
            return this_dir;   // папка "меньше" файла → всегда наверху
        return text().compare(other.text(), Qt::CaseInsensitive) < 0;
    }
};

static QPushButton* navBtn(const QIcon& icon, const QString& tip, QWidget* parent) {
    auto* b = new QPushButton(icon, "", parent);
    b->setToolTip(tip);
    b->setFixedSize(28, 28);
    b->setFlat(true);
    b->setIconSize({16, 16});
    b->setStyleSheet("QPushButton { border: none; border-radius: 4px; }"
                     "QPushButton:hover  { background: rgba(255,255,255,0.08); }"
                     "QPushButton:pressed{ background: rgba(255,255,255,0.14); }");
    return b;
}

FileBrowserView::FileBrowserView(ServerClient* client, QWidget* parent)
    : QWidget(parent), client_(client) {

    const QSize ico{16, 16};

    // Кнопки навигации.
    const QColor navClr("#94a3b8");
    const QColor refClr("#10b981");
    btn_back_    = navBtn(glassyIcon(":/icons/nav_back.svg", navClr, ico), "Back",    this);
    btn_fwd_     = navBtn(glassyIcon(":/icons/nav_fwd.svg",  navClr, ico), "Forward", this);
    btn_up_      = navBtn(glassyIcon(":/icons/nav_up.svg",   navClr, ico), "Up",      this);
    btn_refresh_ = navBtn(glassyIcon(":/icons/refresh.svg",  refClr, ico), "Refresh", this);
    btn_back_->setEnabled(false);
    btn_fwd_->setEnabled(false);
    btn_up_->setEnabled(false);

    path_edit_ = new QLineEdit(this);
    path_edit_->setPlaceholderText("Path on target (e.g. C:\\Users)");

    auto* nav_row = new QHBoxLayout;
    nav_row->setContentsMargins(0, 0, 0, 0);
    nav_row->setSpacing(2);
    nav_row->addWidget(btn_back_);
    nav_row->addWidget(btn_fwd_);
    nav_row->addWidget(btn_up_);
    nav_row->addWidget(btn_refresh_);
    nav_row->addWidget(path_edit_, 1);

    // Панель действий.
    btn_download_ = new QPushButton(glassyIcon(":/icons/download.svg", QColor("#3b82f6"), ico),
                                    " Download", this);
    btn_upload_   = new QPushButton(glassyIcon(":/icons/upload.svg",   QColor("#f59e0b"), ico),
                                    " Upload",   this);
    btn_delete_   = new QPushButton(glassyIcon(":/icons/trash.svg",    QColor("#ef4444"), ico),
                                    " Delete",   this);
    btn_download_->setEnabled(false);
    btn_upload_->setEnabled(false);
    btn_delete_->setEnabled(false);

    auto* act_row = new QHBoxLayout;
    act_row->setContentsMargins(0, 0, 0, 0);
    act_row->addWidget(btn_download_);
    act_row->addWidget(btn_upload_);
    act_row->addWidget(btn_delete_);
    act_row->addStretch();

    // Таблица файлов.
    table_ = new QTableWidget(0, 4, this);
    table_->setHorizontalHeaderLabels({"Name", "Size", "Modified", "Type"});
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setAlternatingRowColors(true);
    table_->verticalHeader()->setVisible(false);
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    table_->setSortingEnabled(true);
    table_->horizontalHeader()->setSortIndicator(0, Qt::AscendingOrder);

    status_ = new QLabel("No beacon selected", this);
    status_->setStyleSheet("color:#94a3b8; padding:2px 4px;");

    auto* v = new QVBoxLayout(this);
    v->setContentsMargins(4, 4, 4, 4);
    v->setSpacing(4);
    v->addLayout(nav_row);
    v->addLayout(act_row);
    v->addWidget(table_, 1);
    v->addWidget(status_);

    connect(btn_back_,    &QPushButton::clicked, this, &FileBrowserView::onGoBack);
    connect(btn_fwd_,     &QPushButton::clicked, this, &FileBrowserView::onGoFwd);
    connect(btn_up_,      &QPushButton::clicked, this, &FileBrowserView::onGoUp);
    connect(btn_refresh_, &QPushButton::clicked, this, &FileBrowserView::onRefresh);
    connect(btn_download_,&QPushButton::clicked, this, &FileBrowserView::onDownload);
    connect(btn_upload_,  &QPushButton::clicked, this, &FileBrowserView::onUpload);
    connect(btn_delete_,  &QPushButton::clicked, this, &FileBrowserView::onDelete);
    connect(path_edit_, &QLineEdit::returnPressed, this, &FileBrowserView::onPathEntered);
    connect(table_, &QTableWidget::cellDoubleClicked,
            this, &FileBrowserView::onItemDoubleClicked);
    connect(table_, &QTableWidget::itemSelectionChanged, this, [this] {
        bool sel = (table_->currentRow() >= 0);
        bool dir = selectedIsDir();
        btn_download_->setEnabled(sel && !dir);
        btn_delete_->setEnabled(sel);
        btn_upload_->setEnabled(!beacon_id_.isEmpty());
    });
}

// ---- setBeacon -------------------------------------------------------------

void FileBrowserView::setBeacon(const QString& beacon_id) {
    if (beacon_id == beacon_id_) return;
    beacon_id_ = beacon_id;
    current_path_.clear();
    back_stack_.clear();
    fwd_stack_.clear();
    table_->setRowCount(0);
    updateNavButtons();
    status_->setText(beacon_id_.isEmpty() ? "No beacon selected"
                                          : QString("Beacon: %1").arg(beacon_id_));
    btn_upload_->setEnabled(!beacon_id_.isEmpty());
    if (!beacon_id_.isEmpty())
        navigate("", /*push_history=*/false);
}

// ---- navigate --------------------------------------------------------------

void FileBrowserView::navigate(const QString& path, bool push_history) {
    if (beacon_id_.isEmpty()) return;

    if (push_history && !current_path_.isNull()) {
        back_stack_.append(current_path_);
        fwd_stack_.clear();
    }

    current_path_ = path;
    path_edit_->setText(path);
    status_->setText(
        QString("Loading %1...").arg(path.isEmpty() ? "(current dir)" : path));
    table_->setRowCount(0);
    updateNavButtons();
    emit lsRequested(beacon_id_, path);
}

void FileBrowserView::updateNavButtons() {
    btn_back_->setEnabled(!back_stack_.isEmpty());
    btn_fwd_->setEnabled(!fwd_stack_.isEmpty());
    // "Вверх" активна, если текущий путь не пустой (не корень).
    bool has_parent = !current_path_.isEmpty();
    if (has_parent) {
        // Убираем возможный завершающий разделитель.
        QString p = current_path_;
        if (p.endsWith('\\') || p.endsWith('/')) p.chop(1);
        has_parent = p.contains('\\') || p.contains('/');
    }
    btn_up_->setEnabled(has_parent);
}

// ---- слоты навигации -------------------------------------------------------

void FileBrowserView::onGoBack() {
    if (back_stack_.isEmpty()) return;
    fwd_stack_.append(current_path_);
    const QString prev = back_stack_.takeLast();
    navigate(prev, /*push_history=*/false);
}

void FileBrowserView::onGoFwd() {
    if (fwd_stack_.isEmpty()) return;
    back_stack_.append(current_path_);
    const QString next = fwd_stack_.takeLast();
    navigate(next, /*push_history=*/false);
}

void FileBrowserView::onGoUp() {
    if (current_path_.isEmpty()) return;
    QString p = current_path_;
    if (p.endsWith('\\') || p.endsWith('/')) p.chop(1);
    int idx = p.lastIndexOf('\\');
    if (idx < 0) idx = p.lastIndexOf('/');
    // Если корневой диск (C:) — переходим в "текущий каталог" бикона.
    navigate(idx <= 0 ? QString{} : p.left(idx));
}

void FileBrowserView::onRefresh() {
    if (beacon_id_.isEmpty()) { status_->setText("No beacon selected"); return; }
    // Refresh не меняет историю.
    navigate(current_path_, /*push_history=*/false);
}

void FileBrowserView::onPathEntered() {
    navigate(path_edit_->text().trimmed());
}

// ---- двойной клик по строке ------------------------------------------------

void FileBrowserView::onItemDoubleClicked(int row, int /*col*/) {
    auto* item = table_->item(row, 0);
    if (!item) return;
    if (!item->data(Qt::UserRole).toBool()) return;  // не директория

    QString name = item->text();
    QString new_path;
    if (current_path_.isEmpty())
        new_path = name;
    else if (current_path_.endsWith('\\') || current_path_.endsWith('/'))
        new_path = current_path_ + name;
    else
        new_path = current_path_ + "\\" + name;

    navigate(new_path);
}

// ---- форматирование размера ------------------------------------------------

static QString fmtSize(const QString& bytes_str) {
    bool ok = false;
    qint64 n = bytes_str.toLongLong(&ok);
    if (!ok || n < 0) return bytes_str;
    if (n < 1024LL)
        return QString::number(n) + " B";
    if (n < 1024LL * 1024)
        return QString::number(n / 1024.0, 'f', 1) + " KB";
    if (n < 1024LL * 1024 * 1024)
        return QString::number(n / (1024.0 * 1024), 'f', 1) + " MB";
    return QString::number(n / (1024.0 * 1024 * 1024), 'f', 2) + " GB";
}

// ---- разбор вывода ls ------------------------------------------------------
// Формат строки: [d/-] [size 15 chars] [date 16 chars] [name]

void FileBrowserView::onLsOutput(const QByteArray& output) {
    table_->setSortingEnabled(false);
    table_->setRowCount(0);

    const QString text = QString::fromUtf8(output);
    QStringList lines = text.split('\n', Qt::SkipEmptyParts);

    // Пропускаем 2 строки заголовка.
    int start = 0;
    for (int i = 0; i < lines.size() && start < 2; ++i) {
        if (lines[i].startsWith("-----") || lines[i].startsWith("Type"))
            ++start;
    }

    int row = 0;
    for (int i = start; i < lines.size(); ++i) {
        const QString& ln = lines[i];
        if (ln.size() < 20) continue;

        bool is_dir = (ln[0] == 'd');

        QString size_str = ln.mid(2, 15).trimmed();
        QString date_str = ln.mid(18, 16).trimmed();

        QString name;
        if (ln.size() > 35) name = ln.mid(35).trimmed();
        if (name.isEmpty() || name == "." || name == "..") continue;

        table_->insertRow(row);

        auto* name_item = new FileSortItem(name);
        name_item->setIcon(is_dir
            ? glassyIcon(":/icons/folder.svg", QColor("#f59e0b"), {16, 16})
            : glassyIcon(":/icons/file.svg",   QColor("#94a3b8"), {16, 16}));
        name_item->setData(Qt::UserRole, is_dir);

        table_->setItem(row, 0, name_item);
        table_->setItem(row, 1, new QTableWidgetItem(is_dir ? "" : fmtSize(size_str)));
        table_->setItem(row, 2, new QTableWidgetItem(date_str));
        table_->setItem(row, 3, new QTableWidgetItem(is_dir ? "DIR" : "FILE"));

        if (auto* sz = table_->item(row, 1))
            sz->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        ++row;
    }

    table_->setSortingEnabled(true);
    table_->sortItems(0, Qt::AscendingOrder);

    status_->setText(QString("%1  |  %2 items")
        .arg(current_path_.isEmpty() ? "(current dir)" : current_path_)
        .arg(row));
    path_edit_->setText(current_path_);
    updateNavButtons();
}

void FileBrowserView::setLsError(const QString& err) {
    status_->setText(QString("Error: %1").arg(err));
}

// ---- Download / Upload / Delete --------------------------------------------

void FileBrowserView::onDownload() {
    QString name = selectedName();
    if (name.isEmpty() || selectedIsDir()) return;
    QString remote = current_path_.isEmpty() ? name : current_path_ + "\\" + name;
    QString local  = QFileDialog::getSaveFileName(this, "Save as", name);
    if (local.isEmpty()) return;
    emit downloadRequested(beacon_id_, remote, local);
    status_->setText(QString("Download queued: %1").arg(remote));
}

void FileBrowserView::onUpload() {
    if (beacon_id_.isEmpty()) return;
    QString local = QFileDialog::getOpenFileName(this, "Upload file");
    if (local.isEmpty()) return;
    QFileInfo fi(local);
    QString remote = current_path_.isEmpty()
        ? fi.fileName()
        : current_path_ + "\\" + fi.fileName();
    emit uploadRequested(beacon_id_, local, remote);
    status_->setText(QString("Upload queued: %1 -> %2").arg(fi.fileName(), remote));
}

void FileBrowserView::onDelete() {
    QString name = selectedName();
    if (name.isEmpty()) return;
    QString remote = current_path_.isEmpty() ? name : current_path_ + "\\" + name;
    auto ans = QMessageBox::question(this, "Delete",
        QString("Delete \"%1\" on target?").arg(remote),
        QMessageBox::Yes | QMessageBox::No);
    if (ans != QMessageBox::Yes) return;
    emit deleteRequested(beacon_id_, remote);
    status_->setText(QString("Delete queued: %1").arg(remote));
}

// ---- helpers ---------------------------------------------------------------

QString FileBrowserView::selectedName() const {
    int row = table_->currentRow();
    if (row < 0) return {};
    auto* item = table_->item(row, 0);
    return item ? item->text() : QString{};
}

bool FileBrowserView::selectedIsDir() const {
    int row = table_->currentRow();
    if (row < 0) return false;
    auto* item = table_->item(row, 0);
    return item ? item->data(Qt::UserRole).toBool() : false;
}

}
