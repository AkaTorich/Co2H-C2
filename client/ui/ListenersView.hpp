#pragma once

#include <QPoint>
#include <QWidget>

class QTableView;

namespace co2h::client { class ListenersModel; }

namespace co2h::client::ui {

class ListenersView : public QWidget {
    Q_OBJECT
public:
    explicit ListenersView(ListenersModel* model, QWidget* parent = nullptr);

signals:
    void addRequested();
    void removeRequested(const QString& name);
    void refreshRequested();

private slots:
    void showContextMenu(const QPoint& pos);

private:
    ListenersModel* model_;
    QTableView*     view_;
};

}
