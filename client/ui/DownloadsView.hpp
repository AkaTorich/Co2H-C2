#pragma once

#include <QWidget>

class QTableView;

namespace co2h::client {
class DownloadsModel;
}

namespace co2h::client::ui {

class DownloadsView : public QWidget {
    Q_OBJECT
public:
    explicit DownloadsView(DownloadsModel* model, QWidget* parent = nullptr);

private slots:
    void onContextMenu(const QPoint& pos);
    void openSelected();
    void openFolderSelected();
    void copyPathSelected();
    void removeSelected();

private:
    DownloadsModel* model_;
    QTableView*     view_;
};

}
