#include "ProcessBrowserView.hpp"
#include "SvgIcon.hpp"
#include "../net/ServerClient.hpp"
#include "../models/SessionsModel.hpp"

#include <functional>

#include <QComboBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPainter>
#include <QProxyStyle>
#include <QPushButton>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>

// Custom tree branch style: orange dashed connector lines, blue +/- indicators.
class ProcessTreeStyle : public QProxyStyle {
public:
    using QProxyStyle::QProxyStyle;

    void drawPrimitive(PrimitiveElement element, const QStyleOption* option,
                       QPainter* painter, const QWidget* widget = nullptr) const override
    {
        if (element != PE_IndicatorBranch) {
            QProxyStyle::drawPrimitive(element, option, painter, widget);
            return;
        }

        const QRect r = option->rect;
        const int midX = r.center().x();
        const int midY = r.center().y();

        const bool hasSibling  = option->state & QStyle::State_Sibling;
        const bool hasItem     = option->state & QStyle::State_Item;
        const bool hasChildren = option->state & QStyle::State_Children;
        const bool isOpen      = option->state & QStyle::State_Open;

        painter->save();
        painter->setRenderHint(QPainter::Antialiasing, false);

        // Orange dashed pen for connector lines.
        QPen dashPen(QColor(255, 165, 0), 1, Qt::CustomDashLine);
        dashPen.setDashPattern({2.0, 2.0});
        painter->setPen(dashPen);

        if (hasChildren) {
            // +/- box dimensions.
            constexpr int sz = 9;
            const QRect box(midX - sz / 2, midY - sz / 2, sz, sz);

            // Vertical segments (stop at box edges).
            if (hasSibling || hasItem)
                painter->drawLine(midX, r.top(), midX, box.top() - 1);
            if (hasSibling)
                painter->drawLine(midX, box.bottom() + 2, midX, r.bottom());

            // Horizontal connector: box → item text.
            painter->drawLine(box.right() + 2, midY, r.right(), midY);

            // Draw the +/- box (blue outline, dark fill).
            painter->setPen(QPen(QColor(70, 150, 255), 1));
            painter->setBrush(QColor(25, 25, 32));
            painter->drawRect(box);

            // Horizontal bar (always).
            painter->drawLine(box.left() + 2, midY, box.right() - 2, midY);
            // Vertical bar (collapsed only → "+").
            if (!isOpen)
                painter->drawLine(midX, box.top() + 2, midX, box.bottom() - 2);
        } else {
            // No box — simple connector lines.
            if (hasSibling) {
                // Vertical pass-through (or T-junction if also hasItem).
                painter->drawLine(midX, r.top(), midX, r.bottom());
            } else if (hasItem) {
                // L-junction: last child.
                painter->drawLine(midX, r.top(), midX, midY);
            }
            if (hasItem)
                painter->drawLine(midX, midY, r.right(), midY);
        }

        painter->restore();
    }
};

namespace co2h::client::ui {

ProcessBrowserView::ProcessBrowserView(ServerClient* client,
                                       SessionsModel* sessions,
                                       QWidget* parent)
    : QWidget(parent), client_(client), sessions_model_(sessions)
{
    auto* top = new QHBoxLayout;

    beacon_combo_ = new QComboBox(this);
    beacon_combo_->setMinimumWidth(220);
    beacon_combo_->setPlaceholderText("Select beacon...");
    top->addWidget(new QLabel("Beacon:", this));
    top->addWidget(beacon_combo_);

    btn_refresh_ = new QPushButton("Refresh", this);
    btn_kill_    = new QPushButton("Kill", this);
    btn_kill_->setEnabled(false);

    top->addWidget(btn_refresh_);
    top->addWidget(btn_kill_);
    top->addStretch();

    filter_edit_ = new QLineEdit(this);
    filter_edit_->setPlaceholderText("Filter by name...");
    filter_edit_->setMaximumWidth(200);
    top->addWidget(filter_edit_);

    status_ = new QLabel(this);
    top->addWidget(status_);

    // Tree widget columns: PID, PPID, Session, Arch, Memory, User, Name.
    tree_ = new QTreeWidget(this);
    tree_->setHeaderLabels({"PID", "PPID", "Session", "Arch", "Memory", "User", "Name"});
    tree_->setColumnWidth(0, 70);
    tree_->setColumnWidth(1, 70);
    tree_->setColumnWidth(2, 55);
    tree_->setColumnWidth(3, 45);
    tree_->setColumnWidth(4, 80);
    tree_->setColumnWidth(5, 150);
    tree_->setColumnWidth(6, 200);
    tree_->setRootIsDecorated(true);
    tree_->setAlternatingRowColors(true);
    tree_->setStyle(new ProcessTreeStyle(tree_->style()));
    tree_->setSortingEnabled(true);
    tree_->sortByColumn(2, Qt::AscendingOrder);
    tree_->setSelectionMode(QAbstractItemView::SingleSelection);

    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(4, 4, 4, 4);
    layout->addLayout(top);
    layout->addWidget(tree_);
    setLayout(layout);

    connect(btn_refresh_, &QPushButton::clicked, this, &ProcessBrowserView::onRefresh);
    connect(btn_kill_,    &QPushButton::clicked, this, &ProcessBrowserView::onKillProcess);
    connect(filter_edit_, &QLineEdit::textChanged, this, &ProcessBrowserView::onFilterChanged);
    connect(beacon_combo_, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &ProcessBrowserView::onBeaconChanged);
    connect(tree_, &QTreeWidget::itemSelectionChanged, this, [this] {
        btn_kill_->setEnabled(!tree_->selectedItems().isEmpty());
    });
}

void ProcessBrowserView::refreshBeaconList() {
    const QString prev = beacon_combo_->currentData().toString();
    beacon_combo_->blockSignals(true);
    beacon_combo_->clear();

    const int count = sessions_model_->rowCount({});
    for (int i = 0; i < count; ++i) {
        const auto* r = sessions_model_->row(i);
        if (!r) continue;
        // Display: "user@host (short_id)"
        QString label = QString("%1@%2 (%3)")
            .arg(r->user, r->host, r->id.left(8));
        beacon_combo_->addItem(label, r->id);
    }

    // Restore previous selection if still valid.
    if (!prev.isEmpty()) {
        int idx = beacon_combo_->findData(prev);
        if (idx >= 0) beacon_combo_->setCurrentIndex(idx);
    }
    beacon_combo_->blockSignals(false);
}

void ProcessBrowserView::onBeaconChanged(int index) {
    if (index < 0) {
        beacon_id_.clear();
        return;
    }
    beacon_id_ = beacon_combo_->itemData(index).toString();
    tree_->clear();
    status_->setText("Select Refresh to load processes.");
}

void ProcessBrowserView::onRefresh() {
    if (beacon_id_.isEmpty()) {
        status_->setText("No beacon selected.");
        return;
    }
    status_->setText("Requesting...");
    emit psRequested(beacon_id_);
}

void ProcessBrowserView::onKillProcess() {
    auto items = tree_->selectedItems();
    if (items.isEmpty()) return;

    quint32 pid = items.first()->text(0).toUInt();
    if (pid == 0) return;

    if (beacon_id_.isEmpty()) return;
    emit killRequested(beacon_id_, pid);
    status_->setText(QString("Kill sent for PID %1").arg(pid));
}

void ProcessBrowserView::onPsOutput(const QByteArray& output) {
    buildTree(output);
    // Count all items (top-level + children recursively).
    int total = 0;
    std::function<void(QTreeWidgetItem*)> countAll = [&](QTreeWidgetItem* it) {
        ++total;
        for (int i = 0; i < it->childCount(); ++i)
            countAll(it->child(i));
    };
    for (int i = 0; i < tree_->topLevelItemCount(); ++i)
        countAll(tree_->topLevelItem(i));
    status_->setText(QString("%1 processes").arg(total));
    // Re-apply filter if set.
    if (!filter_edit_->text().isEmpty())
        applyFilter(filter_edit_->text());
}

void ProcessBrowserView::setPsError(const QString& err) {
    status_->setText("Error: " + err);
}

void ProcessBrowserView::buildTree(const QByteArray& raw) {
    tree_->clear();

    struct ProcInfo {
        quint32 pid;
        quint32 ppid;
        quint32 session;
        QString arch;
        quint32 mem_kb;
        QString user;
        QString name;
    };

    QVector<ProcInfo> procs;
    const QList<QByteArray> lines = raw.split('\n');

    // Skip header line (first line: "PID|PPID|SID|ARCH|MEM_KB|USER|NAME").
    for (int i = 1; i < lines.size(); ++i) {
        const QByteArray& line = lines[i];
        if (line.trimmed().isEmpty()) continue;

        // Format: PID|PPID|SID|ARCH|MEM_KB|USER|NAME (pipe-separated).
        QList<QByteArray> fields = line.split('|');
        if (fields.size() < 7) continue;

        ProcInfo pi;
        pi.pid     = fields[0].trimmed().toUInt();
        pi.ppid    = fields[1].trimmed().toUInt();
        pi.session = fields[2].trimmed().toUInt();
        pi.arch    = QString::fromLatin1(fields[3].trimmed());
        pi.mem_kb  = fields[4].trimmed().toUInt();
        pi.user    = QString::fromLocal8Bit(fields[5].trimmed());
        pi.name    = QString::fromLocal8Bit(fields[6].trimmed());
        procs.append(pi);
    }

    // Build tree: map PID -> item, then reparent by PPID.
    QHash<quint32, QTreeWidgetItem*> items;

    // First pass: create all items.
    for (const auto& p : procs) {
        auto* item = new QTreeWidgetItem();
        item->setText(0, QString::number(p.pid));
        item->setText(1, QString::number(p.ppid));
        item->setText(2, QString::number(p.session));
        item->setText(3, p.arch);
        // Format memory: KB -> human-readable.
        if (p.mem_kb >= 1024)
            item->setText(4, QString("%1 MB").arg(p.mem_kb / 1024));
        else
            item->setText(4, QString("%1 KB").arg(p.mem_kb));
        item->setText(5, p.user);
        item->setText(6, p.name);
        item->setData(0, Qt::UserRole, p.pid);
        item->setData(1, Qt::UserRole, p.ppid);
        items.insert(p.pid, item);
    }

    // Second pass: attach children to parents.
    for (const auto& p : procs) {
        auto* item = items.value(p.pid);
        if (!item) continue;

        auto* parent = items.value(p.ppid);
        if (parent && parent != item) {
            parent->addChild(item);
        } else {
            tree_->addTopLevelItem(item);
        }
    }

    // Expand all to show the full tree.
    tree_->expandAll();
}

void ProcessBrowserView::onFilterChanged(const QString& text) {
    applyFilter(text);
}

void ProcessBrowserView::applyFilter(const QString& text) {
    if (text.isEmpty()) {
        // Show all.
        for (int i = 0; i < tree_->topLevelItemCount(); ++i)
            setItemVisibleRecursive(tree_->topLevelItem(i), true);
        return;
    }

    // Hide items that don't match; show parents of matching items.
    for (int i = 0; i < tree_->topLevelItemCount(); ++i) {
        auto* item = tree_->topLevelItem(i);
        bool has_match = matchesFilter(item, text);
        item->setHidden(!has_match);
    }
}

bool ProcessBrowserView::matchesFilter(QTreeWidgetItem* item, const QString& filter) {
    bool self_match = item->text(6).contains(filter, Qt::CaseInsensitive)
                   || item->text(5).contains(filter, Qt::CaseInsensitive)
                   || item->text(0).contains(filter);

    bool child_match = false;
    for (int i = 0; i < item->childCount(); ++i) {
        if (matchesFilter(item->child(i), filter)) {
            child_match = true;
        } else {
            item->child(i)->setHidden(true);
        }
    }

    bool visible = self_match || child_match;
    item->setHidden(!visible);
    if (visible) item->setExpanded(true);
    return visible;
}

void ProcessBrowserView::setItemVisibleRecursive(QTreeWidgetItem* item, bool visible) {
    item->setHidden(!visible);
    for (int i = 0; i < item->childCount(); ++i)
        setItemVisibleRecursive(item->child(i), visible);
}

} // namespace co2h::client::ui
