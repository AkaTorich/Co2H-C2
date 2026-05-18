#pragma once

#include <QColor>
#include <QHash>
#include <QStringList>
#include <QWidget>

class QPlainTextEdit;
class QLineEdit;
class QLabel;
class QFrame;
class QScrollArea;
class QTextCharFormat;

namespace co2h::client::ui {

class ConsoleWidget : public QWidget {
    Q_OBJECT
public:
    explicit ConsoleWidget(QWidget* parent = nullptr);
    ~ConsoleWidget() = default;

    void setBeaconId(const QString& id);
    void setBeaconAlias(const QString& alias);
    QString beaconId() const { return beacon_id_; }
    QString beaconAlias() const { return beacon_alias_; }

    bool isInteractiveShell() const { return ishell_mode_; }
    void enterInteractiveShell();
    void exitInteractiveShell();

    // Register an external command (from plugins) for autocomplete/help.
    void registerExternalCommand(const QString& name, const QString& args,
                                 const QString& desc);

public slots:
    void appendOutput(const QString& text);
    void appendError(const QString& text);
    // Добавить вывод для конкретного бикона (если не текущий — сохранить в буфер).
    void appendOutputForBeacon(const QString& beaconId, const QString& text);
    void appendErrorForBeacon(const QString& beaconId, const QString& text);

signals:
    void commandEntered(const QString& beaconId, const QString& cmd);
    void ishellInput(const QString& beaconId, const QString& line);
    void ishellStop(const QString& beaconId);

private slots:
    void onSubmit();
    void onInputChanged(const QString& text);

protected:
    bool eventFilter(QObject* obj, QEvent* ev) override;

private:
    void updateHeader();
    void updateHintPopup(const QString& text);
    void hideHint();
    void positionHint();

    // ANSI SGR парсер — рендер цветов терминала в QPlainTextEdit.
    void appendAnsiText(const QString& text);
    void resetAnsiState();
    QTextCharFormat ansiFormat() const;
    void parseAnsiSGR(const QVector<int>& params);
    static QColor ansiColor(int idx, bool bright);
    static QColor ansi256Color(int idx);

    // ANSI терминальное состояние (между чанками вывода).
    struct AnsiState {
        QColor fg  = QColor("#c8d4e8");
        QColor bg;           // invalid = прозрачный
        bool bold      = false;
        bool dim       = false;
        bool italic    = false;
        bool underline = false;
        bool reverse   = false;
    } ansi_;

    QString         beacon_id_;
    QString         beacon_alias_;
    QLabel*         header_    = nullptr;
    QPlainTextEdit* output_    = nullptr;
    QLineEdit*      input_     = nullptr;
    QStringList     history_;
    int             histIdx_   = -1;
    bool            ishell_mode_ = false;

    // Сохранённый вывод и история команд для каждого бикона.
    // output_by_beacon_ хранит сырой текст с ANSI-кодами для перерисовки.
    QHash<QString, QString>     output_by_beacon_;
    QHash<QString, QStringList> history_by_beacon_;
    QHash<QString, bool>        ishell_by_beacon_;   // ishell_mode_ для каждого бикона
    QHash<QString, AnsiState>   ansi_by_beacon_;     // ANSI-состояние для каждого бикона
    QString         raw_output_;   // сырой ANSI-вывод текущего бикона

    QFrame*         hint_       = nullptr;
    QScrollArea*    hint_scroll_= nullptr;
    QLabel*         hint_label_ = nullptr;
    QString         hint_complete_;   // первый кандидат для Tab/Enter-автодополнения

    // Plugin-registered commands (for autocomplete/help popup).
    struct ExtCmdHelp { QString name; QString args; QString desc; };
    QVector<ExtCmdHelp> ext_commands_;
};

}
