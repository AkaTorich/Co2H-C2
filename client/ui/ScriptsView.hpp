#pragma once

#include <QHash>
#include <QWidget>

class QLabel;
class QListWidget;
class QListWidgetItem;
class QPlainTextEdit;

namespace co2h::client::script {
class ScriptEngine;
}

namespace co2h::client::ui {

// Vkladka Scripts: spisok zagruzhennyh skriptov, log i vstroennyj redaktor.
// Levaya panel: QListWidget (skriptov) + QPlainTextEdit (log).
// Pravaya panel: QPlainTextEdit (redaktor) s knopkami New / Save / Save & Reload.
class ScriptsView : public QWidget {
    Q_OBJECT
public:
    explicit ScriptsView(script::ScriptEngine* engine, QWidget* parent = nullptr);

    // Dobavit stroku v log skriptovogo dvizka.
    void appendLog(const QString& text);

private slots:
    void onLoad();
    void onReload();
    void onOpenFolder();
    void onNew();
    void onSave();
    void onSaveReload();
    void onListItemClicked(QListWidgetItem* item);

private:
    void openInEditor(const QString& path);

    script::ScriptEngine*   engine_;
    QListWidget*            list_;              // zagruzhennye skriptov
    QPlainTextEdit*         log_;               // vyvod log() iz skriptov
    QPlainTextEdit*         editor_;            // redaktor
    QLabel*                 editor_label_;      // imya tekushchego fayla
    QString                 current_edit_path_; // polnyj put k redaktiruemomu fajlu
    QHash<QString, QString> name_to_path_;      // imya fajla -> polnyj put
};

}
