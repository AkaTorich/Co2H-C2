#pragma once

#include "../models/AuditModel.hpp"

#include <QWidget>

class QTableView;
class QLineEdit;
class QSortFilterProxyModel;

namespace co2h::client {
class AuditModel;
}

namespace co2h::client::ui {

// Вкладка Audit Log: таблица всех команд операторов с фильтрацией.
class AuditView : public QWidget {
    Q_OBJECT
public:
    explicit AuditView(AuditModel* model, QWidget* parent = nullptr);

private slots:
    void onClear();
    void onCopyRow();
    void onExport();
    void onContextMenu(const QPoint&);
    void onFilterChanged(const QString& text);

private:
    AuditModel*              model_;
    QSortFilterProxyModel*   proxy_;
    QTableView*              view_;
    QLineEdit*               filter_;
};

}
