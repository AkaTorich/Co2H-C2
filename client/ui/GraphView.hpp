#pragma once

#include <QHash>
#include <QPoint>
#include <QTimer>
#include <QWidget>

class QGraphicsScene;
class QGraphicsView;

namespace co2h::client {
class SessionsModel;
class ListenersModel;
class ServerClient;
}

namespace co2h::client::ui {

// Визуализатор инфраструктуры:
//   teamserver (центр) ─┬─ listener₁ ─┬─ beacon₁ ···> child_beacon
//                       │             ├─ beacon₂
//                       │             └─ ...
//                       └─ listener₂ ─── beacon₃
//
// Все узлы перетаскиваются мышью; рёбра следуют за узлами.
// Левая кнопка на пустом месте / средняя кнопка — панорамирование.
// Правый клик — контекстное меню (beacon: все команды из Sessions;
//                                  listener: команды из Listeners).
class GraphView : public QWidget {
    Q_OBJECT
public:
    GraphView(SessionsModel* sessions, ListenersModel* listeners,
              ServerClient* client, QWidget* parent = nullptr);

    // Получить псевдоним бикона (пустая строка если не задан).
    QString beaconAlias(const QString& beaconId) const {
        return beaconAliases_.value(beaconId);
    }

signals:
    void interactRequested(const QString& beaconId);
    void relayChildRequested(const QString& parentId, const QString& parentIp,
                             const QString& listener);
    // Запросы к MainWindow для открытия диалогов:
    void newListenerRequested();                              // teamserver → New listener
    void stopServerRequested();                               // teamserver → Stop server
    void generateArtifactRequested(const QString& listener);  // listener → Generate artifact
    // Переименование бикона на графе.
    void beaconRenamed(const QString& beaconId, const QString& newName);

private slots:
    void rebuild();

protected:
    void resizeEvent(QResizeEvent*) override;
    bool eventFilter(QObject* obj, QEvent* ev) override;

private:
    void showTeamserverMenu(QPoint globalPos);
    void showBeaconMenu(const QString& beaconId, QPoint globalPos);
    void showListenerMenu(const QString& listenerName, QPoint globalPos);

    SessionsModel*  sessions_;
    ListenersModel* listeners_;
    ServerClient*   client_;
    QGraphicsScene* scene_;
    QGraphicsView*  view_;

    bool   panning_    = false;
    QPoint panStart_;

    // Коалесцирующий таймер: множественные dataChanged схлопываются в один rebuild().
    // Задержка 150 мс гарантирует, что Qt успевает зафиксировать финальную
    // позицию узла после отпускания мыши, прежде чем мы читаем item->pos().
    QTimer* rebuildTimer_;

    // Сохранённые позиции узлов — восстанавливаются при rebuild()
    QPointF                 savedTeamPos_     = {0.0, 0.0};
    QHash<QString, QPointF> savedBeaconPos_;
    QHash<QString, QPointF> savedListenerPos_;

    // Псевдонимы биконов: id → отображаемое имя. Не влияет на beacon ID.
    QHash<QString, QString> beaconAliases_;
};

}
