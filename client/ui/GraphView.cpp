#include "GraphView.hpp"

#include "../models/ListenersModel.hpp"
#include "../models/SessionsModel.hpp"
#include "../net/ServerClient.hpp"
#include "SvgIcon.hpp"

#include <co2h/kv.hpp>
#include <co2h/proto.hpp>

#include <QApplication>
#include <QBrush>
#include <QClipboard>
#include <QContextMenuEvent>
#include <QDialog>
#include <QDialogButtonBox>
#include <QEvent>
#include <QFont>
#include <QFormLayout>
#include <QGraphicsEllipseItem>
#include <QGraphicsLineItem>
#include <QGraphicsScene>
#include <QGraphicsSimpleTextItem>
#include <QGraphicsView>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMouseEvent>
#include <QPen>
#include <QResizeEvent>
#include <QScrollBar>
#include <QSpinBox>
#include <QToolBar>
#include <QVBoxLayout>
#include <QWheelEvent>
#include <QtMath>

namespace co2h::client::ui {

namespace {

// ============================================================================
// ZoomableView — QGraphicsView с зумом колесом относительно курсора.
// wheelEvent обрабатывается внутри view, поэтому AnchorUnderMouse работает
// штатно без ручной арифметики скроллбаров.
// ============================================================================
class ZoomableView : public QGraphicsView {
public:
    using QGraphicsView::QGraphicsView;
protected:
    void wheelEvent(QWheelEvent* ev) override {
        const double factor = ev->angleDelta().y() > 0 ? 1.15 : (1.0 / 1.15);
        setTransformationAnchor(AnchorUnderMouse);
        scale(factor, factor);
        ev->accept();
    }
};

// ============================================================================
// GraphNode — перетаскиваемый узел с отслеживанием рёбер.
// Rect центрирован в локальном начале координат (0,0), поэтому
// pos() == scene-центр эллипса.
// ============================================================================
class GraphNode : public QGraphicsEllipseItem {
public:
    explicit GraphNode(qreal r) : QGraphicsEllipseItem(-r, -r, r * 2, r * 2) {
        setFlags(ItemIsMovable | ItemIsSelectable | ItemSendsGeometryChanges);
        setAcceptHoverEvents(true);
    }

    // Зарегистрировать ребро. asStart=true → этот узел — точка P1 линии.
    void addEdge(QGraphicsLineItem* edge, bool asStart) {
        edges_.push_back({edge, asStart});
    }

protected:
    QVariant itemChange(GraphicsItemChange change, const QVariant& value) override {
        if (change == ItemPositionHasChanged) {
            const QPointF c = value.toPointF(); // новый scene-центр
            for (auto& [edge, asStart] : edges_) {
                QLineF line = edge->line();
                if (asStart) line.setP1(c);
                else         line.setP2(c);
                edge->setLine(line);
            }
        }
        return QGraphicsEllipseItem::itemChange(change, value);
    }

private:
    struct EdgeRef { QGraphicsLineItem* edge; bool asStart; };
    QVector<EdgeRef> edges_;
};

// ============================================================================
// BeaconNode
// ============================================================================
class BeaconNode : public GraphNode {
public:
    BeaconNode(qreal r, QString id) : GraphNode(r), id_(std::move(id)) {
        setCursor(Qt::SizeAllCursor);
        setToolTip("beacon " + id_ +
                   "\n(double-click — interact, right-click — actions)");
    }
    QString id() const { return id_; }
private:
    QString id_;
};

// ============================================================================
// ListenerNode
// ============================================================================
class ListenerNode : public GraphNode {
public:
    ListenerNode(qreal r, QString name, QString kind, QString bind)
        : GraphNode(r), name_(std::move(name)), kind_(std::move(kind)), bind_(std::move(bind)) {
        setCursor(Qt::SizeAllCursor);
        setToolTip(QString("%1 (%2)\n%3\n(right-click — actions)")
                   .arg(name_, kind_, bind_));
    }
    QString name() const { return name_; }
private:
    QString name_, kind_, bind_;
};

// Создать текстовый дочерний элемент (двигается вместе с родителем).
static void addNodeLabel(GraphNode* node, const QString& text,
                         qreal r, const QColor& col) {
    auto* lbl = new QGraphicsSimpleTextItem(text, node);
    lbl->setBrush(col);
    lbl->setAcceptedMouseButtons(Qt::NoButton); // не перехватывать клики
    // Единый размер шрифта для всех узлов (teamserver / listener / beacon).
    QFont f = lbl->font();
    f.setPointSize(9);
    lbl->setFont(f);
    lbl->setPos(-lbl->boundingRect().width() / 2.0, r + 3.0);
}

} // namespace

// ============================================================================
// GraphView
// ============================================================================

GraphView::GraphView(SessionsModel* s, ListenersModel* l,
                     ServerClient* client, QWidget* parent)
    : QWidget(parent), sessions_(s), listeners_(l), client_(client) {

    // Коалесцирующий таймер: 150 мс гарантируют, что Qt успеет
    // зафиксировать item->pos() после отпускания мыши перед rebuild().
    rebuildTimer_ = new QTimer(this);
    rebuildTimer_->setSingleShot(true);
    rebuildTimer_->setInterval(150);
    connect(rebuildTimer_, &QTimer::timeout, this, &GraphView::rebuild);

    auto* tb     = new QToolBar(this);
    auto* resetA = tb->addAction("Reset");
    connect(resetA, &QAction::triggered, this, [this] {
        savedTeamPos_ = {0.0, 0.0};
        savedBeaconPos_.clear();
        savedListenerPos_.clear();
        rebuild();
    });

    scene_ = new QGraphicsScene(this);
    // Большой sceneRect нужен для AnchorUnderMouse и панорамирования —
    // зум и пан реализованы через скроллбары, им нужен диапазон.
    scene_->setSceneRect(-50000, -50000, 100000, 100000);
    view_  = new ZoomableView(scene_, this);
    view_->setRenderHint(QPainter::Antialiasing);
    view_->setBackgroundBrush(QBrush(QColor("#0f172a")));
    view_->setDragMode(QGraphicsView::NoDrag); // пан реализован вручную
    // Скроллбары скрыты визуально, но объекты живые — нужны для зума/пана.
    view_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    view_->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    view_->setTransformationAnchor(QGraphicsView::AnchorUnderMouse);
    view_->setResizeAnchor(QGraphicsView::AnchorUnderMouse);
    view_->viewport()->installEventFilter(this);
    view_->viewport()->setCursor(Qt::ArrowCursor);

    auto* v = new QVBoxLayout(this);
    v->setContentsMargins(0, 0, 0, 0);
    v->addWidget(tb);
    v->addWidget(view_, 1);

    // rebuild() вызывается только при изменении состава элементов:
    // добавился/удалился beacon или listener, либо полный сброс модели.
    // dataChanged (check-in, last_seen и т.п.) граф не трогает.
    auto scheduleRebuild = [this]{ rebuildTimer_->start(); };
    connect(sessions_,  &QAbstractItemModel::modelReset,    this, scheduleRebuild);
    connect(sessions_,  &QAbstractItemModel::rowsInserted,  this, scheduleRebuild);
    connect(sessions_,  &QAbstractItemModel::rowsRemoved,   this, scheduleRebuild);
    connect(listeners_, &QAbstractItemModel::modelReset,    this, scheduleRebuild);
    connect(listeners_, &QAbstractItemModel::rowsInserted,  this, scheduleRebuild);
    connect(listeners_, &QAbstractItemModel::rowsRemoved,   this, scheduleRebuild);
}

bool GraphView::eventFilter(QObject* obj, QEvent* ev) {
    if (obj != view_->viewport())
        return QWidget::eventFilter(obj, ev);

    // Зум обрабатывается в ZoomableView::wheelEvent (AnchorUnderMouse).

    // ── Двойной левый клик — открыть консоль ─────────────────────────────────
    if (ev->type() == QEvent::MouseButtonDblClick) {
        auto* me = static_cast<QMouseEvent*>(ev);
        if (me->button() == Qt::LeftButton) {
            auto* item = view_->itemAt(me->pos());
            if (auto* bn = dynamic_cast<BeaconNode*>(item)) {
                emit interactRequested(bn->id());
                return true;
            }
        }
    }

    // ── Контекстное меню (правый клик) ───────────────────────────────────────
    if (ev->type() == QEvent::ContextMenu) {
        auto* ce   = static_cast<QContextMenuEvent*>(ev);
        auto* item = view_->itemAt(ce->pos());
        // Поднимаемся по родителям — клик мог попасть в label-ребёнок узла.
        while (item && item->parentItem()) item = item->parentItem();
        if (auto* bn = dynamic_cast<BeaconNode*>(item)) {
            showBeaconMenu(bn->id(), ce->globalPos());
            return true;
        }
        if (auto* ln = dynamic_cast<ListenerNode*>(item)) {
            showListenerMenu(ln->name(), ce->globalPos());
            return true;
        }
        // Teamserver — это базовый GraphNode, не Beacon и не Listener.
        if (dynamic_cast<GraphNode*>(item)) {
            showTeamserverMenu(ce->globalPos());
            return true;
        }
        return false; // на пустом фоне — ничего
    }

    // ── Панорамирование: ЛКМ на пустом месте или СКМ ─────────────────────────
    if (ev->type() == QEvent::MouseButtonPress) {
        auto* me = static_cast<QMouseEvent*>(ev);
        const bool onEmpty = !view_->itemAt(me->pos());
        if ((me->button() == Qt::LeftButton  && onEmpty) ||
             me->button() == Qt::MiddleButton) {
            panning_  = true;
            panStart_ = me->pos();
            view_->viewport()->setCursor(Qt::ClosedHandCursor);
            return true;
        }
    }
    if (ev->type() == QEvent::MouseMove && panning_) {
        auto* me = static_cast<QMouseEvent*>(ev);
        const QPoint delta = me->pos() - panStart_;
        view_->horizontalScrollBar()->setValue(
            view_->horizontalScrollBar()->value() - delta.x());
        view_->verticalScrollBar()->setValue(
            view_->verticalScrollBar()->value() - delta.y());
        panStart_ = me->pos();
        return true;
    }
    if (ev->type() == QEvent::MouseButtonRelease && panning_) {
        panning_ = false;
        view_->viewport()->setCursor(Qt::ArrowCursor);
        return true;
    }

    return QWidget::eventFilter(obj, ev);
}

void GraphView::resizeEvent(QResizeEvent* e) {
    QWidget::resizeEvent(e);
}

void GraphView::rebuild() {
    // Пока пользователь тащит узел или панорамирует — откладываем rebuild,
    // иначе scene_->clear() сорвёт захват мыши и курсор уедет.
    if (panning_ || scene_->mouseGrabberItem() != nullptr ||
        QApplication::mouseButtons() != Qt::NoButton) {
        rebuildTimer_->start();
        return;
    }

    // Сохраняем текущие позиции перед очисткой сцены.
    for (auto* item : scene_->items()) {
        if (auto* bn = dynamic_cast<BeaconNode*>(item))
            savedBeaconPos_[bn->id()] = item->pos();
        else if (auto* ln = dynamic_cast<ListenerNode*>(item))
            savedListenerPos_[ln->name()] = item->pos();
        else if (dynamic_cast<GraphNode*>(item))   // teamserver
            savedTeamPos_ = item->pos();
    }
    scene_->clear();

    const QColor cTeam   = QColor("#3b82f6");
    const QColor cListen = QColor("#22d3ee");
    const QColor cBeacon = QColor("#10b981");
    const QColor cPivot  = QColor("#f59e0b");
    const QColor cLine   = QColor("#475569");
    const QColor cText   = QColor("#e2e8f0");

    constexpr qreal teamR         = 36.0;
    constexpr qreal listenerOrbit = 220.0;
    constexpr qreal listenerR     = 26.0;
    constexpr qreal beaconOrbit   = 110.0;
    constexpr qreal beaconR       = 16.0;

    // ── Teamserver (центральный узел) ─────────────────────────────────────────
    auto* teamNode = new GraphNode(teamR);
    teamNode->setPen(QPen(cTeam.lighter(140), 2));
    teamNode->setBrush(QBrush(cTeam.darker(120)));
    teamNode->setZValue(10);
    teamNode->setCursor(Qt::SizeAllCursor);
    teamNode->setToolTip("teamserver");
    teamNode->setPos(savedTeamPos_);
    addNodeLabel(teamNode, "teamserver", teamR, cText);
    scene_->addItem(teamNode);

    const int nList = listeners_->rowCount({});
    if (nList == 0) {
        return;
    }

    // ── Listener'ы по кругу вокруг центра ────────────────────────────────────
    QHash<QString, ListenerNode*> listenerNodeMap;
    QHash<QString, QPointF>       listenerDefaultPos;
    QHash<QString, qreal>         listenerAngle;

    for (int i = 0; i < nList; ++i) {
        const auto* l = listeners_->row(i);
        if (!l) continue;

        const qreal ang = (qreal(i) / qreal(nList)) * 2.0 * M_PI - M_PI_2;
        // Дефолтная позиция нового listener'а — орбита вокруг текущего teamserver'а.
        const QPointF defPos(savedTeamPos_.x() + qCos(ang) * listenerOrbit,
                             savedTeamPos_.y() + qSin(ang) * listenerOrbit);
        listenerDefaultPos[l->name] = defPos;
        listenerAngle[l->name]      = ang;

        auto* lNode = new ListenerNode(listenerR, l->name, l->kind, l->bind);
        lNode->setPen(QPen(cListen.lighter(140), 2));
        lNode->setBrush(QBrush(cListen.darker(120)));
        lNode->setZValue(8);
        lNode->setPos(savedListenerPos_.value(l->name, defPos));
        addNodeLabel(lNode, l->name, listenerR, cText);
        scene_->addItem(lNode);
        listenerNodeMap[l->name] = lNode;

        // Ребро teamserver → listener.
        auto* edge = scene_->addLine(QLineF(teamNode->pos(), lNode->pos()),
                                     QPen(cLine, 1.5));
        edge->setZValue(2);
        teamNode->addEdge(edge, true);
        lNode->addEdge(edge, false);
    }

    // ── Beacon'ы ──────────────────────────────────────────────────────────────
    const int nBeacons = sessions_->rowCount({});
    QHash<QString, const BeaconRow*>          beaconById;
    QHash<QString, QVector<const BeaconRow*>> childrenOf;
    QVector<const BeaconRow*>                 rootBeacons;

    for (int i = 0; i < nBeacons; ++i) {
        const auto* b = sessions_->row(i);
        if (!b || b->id.isEmpty()) continue;
        beaconById[b->id] = b;
    }
    for (int i = 0; i < nBeacons; ++i) {
        const auto* b = sessions_->row(i);
        if (!b || b->id.isEmpty()) continue;
        if (!b->parent_id.isEmpty() && beaconById.contains(b->parent_id))
            childrenOf[b->parent_id].append(b);
        else
            rootBeacons.append(b);
    }

    QHash<QString, BeaconNode*> beaconNodeMap;
    QHash<QString, QPointF>     beaconDefaultPos;

    // Лямбда создаёт BeaconNode, добавляет на сцену, восстанавливает позицию.
    auto addBeaconNode = [&](const BeaconRow* b, const QPointF& defPos) -> BeaconNode* {
        beaconDefaultPos[b->id] = defPos;

        // Псевдоним пользователя имеет приоритет, иначе — стандартное имя.
        const QString alias = beaconAliases_.value(b->id);
        const QString cap = !alias.isEmpty()
            ? alias
            : (b->host.isEmpty()
                ? b->id.left(8)
                : QString("%1\n%2@%3").arg(b->id.left(8), b->user, b->host));

        auto* node = new BeaconNode(beaconR, b->id);
        node->setPen(QPen(cBeacon.lighter(140), 2));
        node->setBrush(QBrush(cBeacon.darker(120)));
        node->setZValue(6);
        node->setPos(savedBeaconPos_.value(b->id, defPos));
        addNodeLabel(node, cap, beaconR, cText);
        scene_->addItem(node);
        beaconNodeMap[b->id] = node;
        return node;
    };

    // Корневые beacon'ы — дуга 120° вокруг своего listener'а.
    QHash<QString, QVector<const BeaconRow*>> byListener;
    for (const auto* b : rootBeacons)
        byListener[b->listener].append(b);

    for (auto it = byListener.constBegin(); it != byListener.constEnd(); ++it) {
        const QString& lname = it.key();
        const auto&    beacons = it.value();

        // Берём фактическую позицию listener'а (уже с учётом перемещения).
        QPointF lc;
        qreal   lang = 0.0;
        if (listenerNodeMap.contains(lname)) {
            lc   = listenerNodeMap[lname]->pos();
            lang = listenerAngle.value(lname, M_PI_2);
        } else {
            lc   = savedTeamPos_ + QPointF(0, listenerOrbit + 80);
            lang = M_PI_2;
        }

        const int   n    = beacons.size();
        const qreal arc  = qDegreesToRadians(120.0);
        const qreal step = (n > 1) ? arc / (n - 1) : 0.0;
        const qreal a0   = lang - arc / 2;

        for (int i = 0; i < n; ++i) {
            const auto*   b      = beacons[i];
            const qreal   a      = (n == 1) ? lang : (a0 + step * i);
            const QPointF defPos = lc + QPointF(qCos(a) * beaconOrbit,
                                                qSin(a) * beaconOrbit);
            auto* bNode = addBeaconNode(b, defPos);

            // Ребро listener → beacon.
            const QPointF lPos = listenerNodeMap.contains(lname)
                ? listenerNodeMap[lname]->pos() : lc;
            auto* edge = scene_->addLine(QLineF(lPos, bNode->pos()),
                                         QPen(cLine, 1.0, Qt::DashLine));
            edge->setZValue(2);
            if (listenerNodeMap.contains(lname))
                listenerNodeMap[lname]->addEdge(edge, true);
            bNode->addEdge(edge, false);
        }
    }

    // BFS: дочерние beacon'ы орбитируют вокруг родительского (pivot).
    QVector<const BeaconRow*> queue = rootBeacons;
    int qi = 0;
    while (qi < queue.size()) {
        const auto* parent = queue[qi++];
        if (!childrenOf.contains(parent->id)) continue;

        // Фактическая позиция родительского бикона (учитывает перемещение).
        auto* parentNode = beaconNodeMap.value(parent->id, nullptr);
        const QPointF parentPos = parentNode ? parentNode->pos()
                                             : beaconDefaultPos.value(parent->id);
        const auto& children = childrenOf[parent->id];
        const int   nc       = children.size();

        const qreal parentAng = qAtan2(parentPos.y(), parentPos.x());
        const qreal arc  = qDegreesToRadians(90.0);
        const qreal step = (nc > 1) ? arc / (nc - 1) : 0.0;
        const qreal a0   = parentAng - arc / 2;

        for (int i = 0; i < nc; ++i) {
            const auto*   child   = children[i];
            const qreal   a       = (nc == 1) ? parentAng : (a0 + step * i);
            const QPointF defPos  = parentPos +
                QPointF(qCos(a) * beaconOrbit, qSin(a) * beaconOrbit);
            auto* cNode  = addBeaconNode(child, defPos);
            auto* pNode  = beaconNodeMap.value(parent->id, nullptr);

            // Ребро parent → child (pivot — пунктир янтарным).
            auto* edge = scene_->addLine(
                QLineF(pNode ? pNode->pos() : parentPos, cNode->pos()),
                QPen(cPivot, 1.5, Qt::DotLine));
            edge->setZValue(2);
            if (pNode) pNode->addEdge(edge, true);
            cNode->addEdge(edge, false);
            queue.append(child);
        }
    }

    // sceneRect не фиксируем — сцена авторасширяется.
    // Это позволяет скроллбарам свободно компенсировать зум.
}

// ─────────────────────────────────────────────────────────────────────────────
// Контекстное меню beacon'а — полный набор команд из SessionsView
// ─────────────────────────────────────────────────────────────────────────────
void GraphView::showBeaconMenu(const QString& id, QPoint globalPos) {
    const BeaconRow* r = nullptr;
    for (int i = 0; i < sessions_->rowCount({}); ++i) {
        auto* b = sessions_->row(i);
        if (b && b->id == id) { r = b; break; }
    }
    if (!r) return;

    const QSize ico{16, 16};
    QMenu menu(this);

    menu.addAction(glassyIcon(":/icons/terminal.svg", QColor("#10b981"), ico),
                   "Interact", [this, id]{ emit interactRequested(id); });
    menu.addAction("Rename...", [this, id]{
        // Псевдоним хранится только в графе — beacon ID не меняется.
        bool ok = false;
        const QString cur  = beaconAliases_.value(id);
        const QString name = QInputDialog::getText(
            this, "Rename beacon", "New display name (empty — restore default):",
            QLineEdit::Normal, cur, &ok);
        if (!ok) return;
        if (name.isEmpty()) beaconAliases_.remove(id);
        else                beaconAliases_[id] = name;
        rebuild();
        emit beaconRenamed(id, name);
    });
    menu.addSeparator();
    menu.addAction(glassyIcon(":/icons/copy.svg", QColor("#94a3b8"), ico),
                   "Copy beacon ID",   [id]{ QApplication::clipboard()->setText(id); });
    menu.addAction(glassyIcon(":/icons/copy.svg", QColor("#94a3b8"), ico),
                   "Copy hostname",    [h = r->host]{ QApplication::clipboard()->setText(h); });
    menu.addAction(glassyIcon(":/icons/copy.svg", QColor("#94a3b8"), ico),
                   "Copy IP address",  [ip = r->internal_ip]{ QApplication::clipboard()->setText(ip); });
    menu.addAction(glassyIcon(":/icons/user.svg",  QColor("#94a3b8"), ico),
                   "Copy username",    [u = r->user]{ QApplication::clipboard()->setText(u); });
    menu.addSeparator();
    menu.addAction(glassyIcon(":/icons/connection.svg", QColor("#06b6d4"), ico),
                   "Start TCP pivot (fast SOCKS)…", [this, id]{
        auto* dlg = new QDialog(this);
        dlg->setWindowTitle("Start TCP pivot listener");
        auto* bindHost  = new QLineEdit("0.0.0.0", dlg);
        auto* socksPort = new QSpinBox(dlg);
        socksPort->setRange(1, 65535); socksPort->setValue(1080);
        auto* pivotPort = new QSpinBox(dlg);
        pivotPort->setRange(1, 65535); pivotPort->setValue(4446);
        auto* form = new QFormLayout;
        form->addRow("Bind host:", bindHost);
        form->addRow("SOCKS port:", socksPort);
        form->addRow("Pivot port (beacon connects here):", pivotPort);
        auto* btns = new QDialogButtonBox(
            QDialogButtonBox::Ok | QDialogButtonBox::Cancel, dlg);
        connect(btns, &QDialogButtonBox::accepted, dlg, &QDialog::accept);
        connect(btns, &QDialogButtonBox::rejected, dlg, &QDialog::reject);
        auto* v = new QVBoxLayout(dlg);
        v->addLayout(form); v->addWidget(btns);
        if (dlg->exec() == QDialog::Accepted) {
            client_->addPivotListener(
                QString("pivot-%1").arg(id.left(8)),
                bindHost->text(),
                static_cast<quint16>(socksPort->value()),
                static_cast<quint16>(pivotPort->value()));
            co2h::kv::Writer w;
            w.put_str("host", bindHost->text() == "0.0.0.0"
                ? "127.0.0.1" : bindHost->text().toStdString());
            w.put_u32("port", static_cast<std::uint32_t>(pivotPort->value()));
            auto pl = w.finish();
            client_->taskBeacon(id, co2h::proto::TaskOp::TcpPivot,
                QByteArray(reinterpret_cast<const char*>(pl.data()),
                           static_cast<int>(pl.size())));
        }
        dlg->deleteLater();
    });
    menu.addAction(glassyIcon(":/icons/connection.svg", QColor("#8b5cf6"), ico),
                   "Start relay port (chain pivot)…", [this, id]{
        auto* dlg = new QDialog(this);
        dlg->setWindowTitle("Start relay listener");
        auto* portSpin = new QSpinBox(dlg);
        portSpin->setRange(1, 65535); portSpin->setValue(4447);
        auto* form = new QFormLayout;
        form->addRow("Relay port (child beacons connect here):", portSpin);
        auto* btns = new QDialogButtonBox(
            QDialogButtonBox::Ok | QDialogButtonBox::Cancel, dlg);
        connect(btns, &QDialogButtonBox::accepted, dlg, &QDialog::accept);
        connect(btns, &QDialogButtonBox::rejected, dlg, &QDialog::reject);
        auto* v = new QVBoxLayout(dlg);
        v->addLayout(form); v->addWidget(btns);
        if (dlg->exec() == QDialog::Accepted) {
            co2h::kv::Writer w;
            w.put_u32("port", static_cast<std::uint32_t>(portSpin->value()));
            auto pl = w.finish();
            client_->taskBeacon(id, co2h::proto::TaskOp::RelayStart,
                QByteArray(reinterpret_cast<const char*>(pl.data()),
                           static_cast<int>(pl.size())));
        }
        dlg->deleteLater();
    });
    menu.addAction(glassyIcon(":/icons/connection.svg", QColor("#8b5cf6"), ico),
                   "Generate relay child beacon…", [this, id,
                                                    ip  = r->internal_ip,
                                                    lst = r->listener]{
        emit relayChildRequested(id, ip, lst);
    });
    menu.addSeparator();
    menu.addAction(glassyIcon(":/icons/socks.svg", QColor("#06b6d4"), ico),
                   "Start SOCKS5 listener (polling)…", [this, id]{
        auto* dlg = new QDialog(this);
        dlg->setWindowTitle("Start SOCKS5 listener");
        auto* bindHost = new QLineEdit("127.0.0.1", dlg);
        auto* bindPort = new QSpinBox(dlg);
        bindPort->setRange(1, 65535); bindPort->setValue(1080);
        auto* form = new QFormLayout;
        form->addRow("Bind host:", bindHost);
        form->addRow("Bind port:", bindPort);
        auto* btns = new QDialogButtonBox(
            QDialogButtonBox::Ok | QDialogButtonBox::Cancel, dlg);
        connect(btns, &QDialogButtonBox::accepted, dlg, &QDialog::accept);
        connect(btns, &QDialogButtonBox::rejected, dlg, &QDialog::reject);
        auto* v = new QVBoxLayout(dlg);
        v->addLayout(form); v->addWidget(btns);
        if (dlg->exec() == QDialog::Accepted) {
            client_->addSocks5Listener(
                QString("socks-%1").arg(id.left(8)),
                id, bindHost->text(),
                static_cast<quint16>(bindPort->value()));
        }
        dlg->deleteLater();
    });
    menu.addAction(glassyIcon(":/icons/connection.svg", QColor("#f59e0b"), ico),
                   "Start Reverse Port Forward…", [this, id]{
        auto* dlg = new QDialog(this);
        dlg->setWindowTitle("Start Reverse Port Forward");
        auto* bindHost = new QLineEdit("0.0.0.0", dlg);
        auto* bindPort = new QSpinBox(dlg);
        bindPort->setRange(1, 65535); bindPort->setValue(8080);
        auto* rHost = new QLineEdit("127.0.0.1", dlg);
        auto* rPort = new QSpinBox(dlg);
        rPort->setRange(1, 65535); rPort->setValue(80);
        auto* hint = new QLabel(
            "<i>Teamserver will open a TCP port (bind). "
            "Incoming connections are proxied through the beacon to rhost:rport.</i>", dlg);
        hint->setWordWrap(true);
        hint->setStyleSheet("color:#94a3b8;padding-top:4px;");
        auto* form = new QFormLayout;
        form->addRow("Bind host (server):", bindHost);
        form->addRow("Bind port (server):", bindPort);
        form->addRow("Rhost (beacon target):", rHost);
        form->addRow("Rport (beacon target):", rPort);
        auto* btns = new QDialogButtonBox(
            QDialogButtonBox::Ok | QDialogButtonBox::Cancel, dlg);
        connect(btns, &QDialogButtonBox::accepted, dlg, &QDialog::accept);
        connect(btns, &QDialogButtonBox::rejected, dlg, &QDialog::reject);
        auto* v = new QVBoxLayout(dlg);
        v->addLayout(form); v->addWidget(hint); v->addWidget(btns);
        if (dlg->exec() == QDialog::Accepted) {
            client_->addRportfwdListener(
                QString("rpf-%1").arg(id.left(8)), id,
                bindHost->text(), static_cast<quint16>(bindPort->value()),
                rHost->text(),    static_cast<quint16>(rPort->value()));
        }
        dlg->deleteLater();
    });

    menu.exec(globalPos);
}

// ─────────────────────────────────────────────────────────────────────────────
// Контекстное меню listener'а — команды из ListenersView
// ─────────────────────────────────────────────────────────────────────────────
void GraphView::showListenerMenu(const QString& name, QPoint globalPos) {
    const ListenerRow* r = nullptr;
    for (int i = 0; i < listeners_->rowCount({}); ++i) {
        auto* l = listeners_->row(i);
        if (l && l->name == name) { r = l; break; }
    }
    if (!r) return;

    QMenu menu(this);
    menu.addAction("Generate artifact for this listener", [this, name]{
        emit generateArtifactRequested(name);
    });
    menu.addSeparator();
    menu.addAction("Stop listener", [this, name]{
        client_->removeListener(name);
    });
    menu.exec(globalPos);
}

void GraphView::showTeamserverMenu(QPoint globalPos) {
    QMenu menu(this);
    menu.addAction("New listener", [this]{ emit newListenerRequested(); });
    menu.addSeparator();
    menu.addAction("Stop server",  [this]{ emit stopServerRequested(); });
    menu.exec(globalPos);
}

}
