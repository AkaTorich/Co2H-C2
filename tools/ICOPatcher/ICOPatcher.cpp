// ICOPatcher.cpp -- minimalist WinAPI utility to embed an .ico file
// into an existing PE executable as RT_ICON / RT_GROUP_ICON resources.
//
// Build (MSVC):
//   build.bat
//
// Look & feel matches Co2H Kit Editor: black background, green accent,
// red border, Consolas font. Selected icon is displayed live in a preview
// pane on the left side of the window.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>
#include <shellapi.h>
#include <stdio.h>

// Без /DUNICODE макрос RT_ICON раскрывается в MAKEINTRESOURCEA (LPSTR),
// а UpdateResourceW требует LPCWSTR. Объявим явные wide-варианты.
#define RT_ICON_W        MAKEINTRESOURCEW(3)
#define RT_GROUP_ICON_W  MAKEINTRESOURCEW(14)

// ============================================================================
//  Colors / style (mirror of kit-editor palette)
// ============================================================================
#define COL_BG       RGB(0x0A, 0x0A, 0x0A)
#define COL_PANEL    RGB(0x18, 0x18, 0x18)
#define COL_PANEL2   RGB(0x22, 0x22, 0x22)
#define COL_ACCENT   RGB(0x00, 0xFF, 0x41)
#define COL_ACC_DIM  RGB(0x00, 0x80, 0x20)
#define COL_RED      RGB(0xFF, 0x00, 0x00)
#define COL_TEXT     RGB(0xE8, 0xE8, 0xE8)
#define COL_DIM      RGB(0x80, 0x80, 0x80)

static HBRUSH g_brBg     = NULL;
static HBRUSH g_brPanel  = NULL;
static HBRUSH g_brPanel2 = NULL;
static HFONT  g_hFont    = NULL;
static HFONT  g_hFontBold= NULL;
static HFONT  g_hFontBig = NULL;
static HFONT  g_hFontDim = NULL;

// ============================================================================
//  Control IDs
// ============================================================================
#define IDC_EXE_PATH    1001
#define IDC_ICO_PATH    1002
#define IDC_EXE_BROWSE  1003
#define IDC_ICO_BROWSE  1004
#define IDC_PATCH       1005
#define IDC_STATUS      1006

// Превью-зона рисуется напрямую в WM_PAINT основного окна.
#define PREVIEW_X       20
#define PREVIEW_Y       20
#define PREVIEW_SIZE    96

// ============================================================================
//  .ico file structures
// ============================================================================
#pragma pack(push, 1)
typedef struct {
    WORD Reserved; WORD Type; WORD Count;
} ICONDIR;

typedef struct {
    BYTE  Width, Height, ColorCount, Reserved;
    WORD  Planes, BitCount;
    DWORD BytesInRes, ImageOffset;
} ICONDIRENTRY;

typedef struct {
    BYTE  Width, Height, ColorCount, Reserved;
    WORD  Planes, BitCount;
    DWORD BytesInRes;
    WORD  nID;
} GRPICONDIRENTRY;

typedef struct {
    WORD Reserved, Type, Count;
} GRPICONDIR;
#pragma pack(pop)

// ============================================================================
//  Globals
// ============================================================================
static HWND  g_hwnd        = NULL;
static HWND  g_hExePath    = NULL;
static HWND  g_hIcoPath    = NULL;
static HWND  g_hStatus     = NULL;
static HICON g_hPreviewIco = NULL;
static int   g_iconImages  = 0;   // сколько изображений в выбранном .ico

// ============================================================================
//  File I/O
// ============================================================================
static BYTE *ReadFileAll(const wchar_t *path, DWORD *outSize) {
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    DWORD sz = GetFileSize(h, NULL);
    if (sz == INVALID_FILE_SIZE) { CloseHandle(h); return NULL; }
    BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, sz);
    if (!buf) { CloseHandle(h); return NULL; }
    DWORD read = 0;
    if (!ReadFile(h, buf, sz, &read, NULL) || read != sz) {
        HeapFree(GetProcessHeap(), 0, buf);
        CloseHandle(h);
        return NULL;
    }
    CloseHandle(h);
    *outSize = sz;
    return buf;
}

// ============================================================================
//  Status helpers
// ============================================================================
static void Status(const char *msg) {
    SetWindowTextA(g_hStatus, msg);
}
static void StatusF(const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    wvsprintfA(buf, fmt, ap);
    va_end(ap);
    SetWindowTextA(g_hStatus, buf);
}

// ============================================================================
//  Load .ico for preview
// ============================================================================
static void LoadPreview(const wchar_t *path) {
    if (g_hPreviewIco) {
        DestroyIcon(g_hPreviewIco);
        g_hPreviewIco = NULL;
    }
    g_iconImages = 0;

    if (path && path[0]) {
        // Сначала считаем число изображений в .ico — для статусной строки
        DWORD sz = 0;
        BYTE *buf = ReadFileAll(path, &sz);
        if (buf && sz >= sizeof(ICONDIR)) {
            ICONDIR *d = (ICONDIR *)buf;
            if (d->Reserved == 0 && d->Type == 1) g_iconImages = d->Count;
        }
        if (buf) HeapFree(GetProcessHeap(), 0, buf);

        // Загружаем превью на PREVIEW_SIZE; Windows сам выберет ближайший
        g_hPreviewIco = (HICON)LoadImageW(NULL, path, IMAGE_ICON,
                                          PREVIEW_SIZE, PREVIEW_SIZE,
                                          LR_LOADFROMFILE | LR_DEFAULTSIZE);
    }

    // Триггерим перерисовку превью-зоны
    RECT rc = { PREVIEW_X - 2, PREVIEW_Y - 2,
                PREVIEW_X + PREVIEW_SIZE + 2, PREVIEW_Y + PREVIEW_SIZE + 2 };
    InvalidateRect(g_hwnd, &rc, TRUE);
}

// ============================================================================
//  Core: patch EXE
// ============================================================================
static BOOL PatchIcon(const wchar_t *exePath, const wchar_t *icoPath) {
    DWORD icoSize = 0;
    BYTE *ico = ReadFileAll(icoPath, &icoSize);
    if (!ico) { Status("[X] Cannot read icon file"); return FALSE; }

    if (icoSize < sizeof(ICONDIR)) {
        HeapFree(GetProcessHeap(), 0, ico);
        Status("[X] Icon file too small");
        return FALSE;
    }
    ICONDIR *dir = (ICONDIR *)ico;
    if (dir->Reserved != 0 || dir->Type != 1 || dir->Count == 0) {
        HeapFree(GetProcessHeap(), 0, ico);
        Status("[X] Not a valid .ico file");
        return FALSE;
    }
    DWORD entriesSize = sizeof(ICONDIRENTRY) * dir->Count;
    if (icoSize < sizeof(ICONDIR) + entriesSize) {
        HeapFree(GetProcessHeap(), 0, ico);
        Status("[X] Truncated icon directory");
        return FALSE;
    }
    ICONDIRENTRY *entries = (ICONDIRENTRY *)(ico + sizeof(ICONDIR));

    DWORD grpSize = sizeof(GRPICONDIR) + sizeof(GRPICONDIRENTRY) * dir->Count;
    BYTE *grpData = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, grpSize);
    if (!grpData) {
        HeapFree(GetProcessHeap(), 0, ico);
        Status("[X] HeapAlloc failed");
        return FALSE;
    }
    GRPICONDIR *grpDir = (GRPICONDIR *)grpData;
    grpDir->Reserved = 0;
    grpDir->Type     = 1;
    grpDir->Count    = dir->Count;
    GRPICONDIRENTRY *grpEntries = (GRPICONDIRENTRY *)(grpData + sizeof(GRPICONDIR));

    HANDLE hUpdate = BeginUpdateResourceW(exePath, FALSE);
    if (!hUpdate) {
        HeapFree(GetProcessHeap(), 0, grpData);
        HeapFree(GetProcessHeap(), 0, ico);
        StatusF("[X] BeginUpdateResource failed (err=%lu)", GetLastError());
        return FALSE;
    }

    BOOL ok = TRUE;
    for (WORD i = 0; i < dir->Count; ++i) {
        ICONDIRENTRY *e = &entries[i];
        if ((DWORD)(e->ImageOffset + e->BytesInRes) > icoSize) {
            Status("[X] Icon entry out of bounds");
            ok = FALSE; break;
        }
        WORD iconId = (WORD)(i + 1);
        if (!UpdateResourceW(hUpdate, RT_ICON_W, MAKEINTRESOURCEW(iconId),
                             MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                             ico + e->ImageOffset, e->BytesInRes)) {
            StatusF("[X] UpdateResource RT_ICON failed (err=%lu)", GetLastError());
            ok = FALSE; break;
        }
        grpEntries[i].Width      = e->Width;
        grpEntries[i].Height     = e->Height;
        grpEntries[i].ColorCount = e->ColorCount;
        grpEntries[i].Reserved   = e->Reserved;
        grpEntries[i].Planes     = e->Planes;
        grpEntries[i].BitCount   = e->BitCount;
        grpEntries[i].BytesInRes = e->BytesInRes;
        grpEntries[i].nID        = iconId;
    }

    if (ok) {
        if (!UpdateResourceW(hUpdate, RT_GROUP_ICON_W, MAKEINTRESOURCEW(1),
                             MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                             grpData, grpSize)) {
            StatusF("[X] UpdateResource RT_GROUP_ICON failed (err=%lu)", GetLastError());
            ok = FALSE;
        }
    }
    if (!EndUpdateResourceW(hUpdate, !ok)) {
        StatusF("[X] EndUpdateResource failed (err=%lu)", GetLastError());
        ok = FALSE;
    }

    HeapFree(GetProcessHeap(), 0, grpData);
    HeapFree(GetProcessHeap(), 0, ico);

    if (ok) StatusF("[+] OK -- embedded %u image(s) into the EXE",
                    (unsigned)dir->Count);
    return ok;
}

// ============================================================================
//  Browse dialog
// ============================================================================
static BOOL BrowseFile(HWND owner, const wchar_t *filter,
                       wchar_t *out, DWORD outLen) {
    OPENFILENAMEW ofn = { 0 };
    out[0] = 0;
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = owner;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile   = out;
    ofn.nMaxFile    = outLen;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    return GetOpenFileNameW(&ofn);
}

// ============================================================================
//  Window procedure
// ============================================================================
static void DrawPreview(HDC hdc) {
    RECT rcOuter = { PREVIEW_X - 2, PREVIEW_Y - 2,
                     PREVIEW_X + PREVIEW_SIZE + 2,
                     PREVIEW_Y + PREVIEW_SIZE + 2 };
    RECT rcInner = { PREVIEW_X, PREVIEW_Y,
                     PREVIEW_X + PREVIEW_SIZE,
                     PREVIEW_Y + PREVIEW_SIZE };

    // Зелёная рамка
    HBRUSH frame = CreateSolidBrush(g_hPreviewIco ? COL_ACCENT : COL_ACC_DIM);
    FrameRect(hdc, &rcOuter, frame);
    DeleteObject(frame);

    // Фон превью
    FillRect(hdc, &rcInner, g_brPanel2);

    if (g_hPreviewIco) {
        DrawIconEx(hdc, PREVIEW_X, PREVIEW_Y, g_hPreviewIco,
                   PREVIEW_SIZE, PREVIEW_SIZE, 0, NULL, DI_NORMAL);
    } else {
        // Текст-плейсхолдер
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, COL_DIM);
        HFONT old = (HFONT)SelectObject(hdc, g_hFontDim);
        DrawTextW(hdc, L"(no icon)", -1, &rcInner,
                  DT_SINGLELINE | DT_CENTER | DT_VCENTER);
        SelectObject(hdc, old);
    }
}

static void DrawTitle(HDC hdc) {
    SetBkMode(hdc, TRANSPARENT);

    // Большой заголовок справа от превью
    SetTextColor(hdc, COL_ACCENT);
    HFONT old = (HFONT)SelectObject(hdc, g_hFontBig);
    RECT rc1 = { 140, 22, 700, 50 };
    DrawTextW(hdc, L"ICOPatcher", -1, &rc1, DT_SINGLELINE | DT_LEFT | DT_VCENTER);

    // Подзаголовок
    SetTextColor(hdc, COL_DIM);
    SelectObject(hdc, g_hFontDim);
    RECT rc2 = { 140, 52, 700, 76 };
    DrawTextW(hdc, L"Embed icon into PE executable (RT_ICON + RT_GROUP_ICON)",
              -1, &rc2, DT_SINGLELINE | DT_LEFT | DT_VCENTER);

    // Количество изображений в .ico
    if (g_iconImages > 0) {
        SetTextColor(hdc, COL_ACCENT);
        SelectObject(hdc, g_hFont);
        wchar_t buf[64];
        wsprintfW(buf, L"%d image(s) in .ico", g_iconImages);
        RECT rc3 = { 140, 80, 700, 102 };
        DrawTextW(hdc, buf, -1, &rc3, DT_SINGLELINE | DT_LEFT | DT_VCENTER);
    }

    SelectObject(hdc, old);
}

static void DrawSeparator(HDC hdc, int y) {
    HPEN pen = CreatePen(PS_SOLID, 1, COL_PANEL);
    HPEN oldP = (HPEN)SelectObject(hdc, pen);
    MoveToEx(hdc, 20, y, NULL);
    LineTo(hdc, 700, y);
    SelectObject(hdc, oldP);
    DeleteObject(pen);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        DrawPreview(hdc);
        DrawTitle(hdc);
        DrawSeparator(hdc, 130);
        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wp;
        SetBkMode(hdc, TRANSPARENT);
        HWND hCtl = (HWND)lp;
        int id = GetDlgCtrlID(hCtl);
        SetTextColor(hdc, id == IDC_STATUS ? COL_TEXT : COL_ACCENT);
        return (LRESULT)g_brBg;
    }

    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wp;
        SetBkColor(hdc, COL_PANEL2);
        SetTextColor(hdc, COL_TEXT);
        return (LRESULT)g_brPanel2;
    }

    case WM_CTLCOLORBTN:
        return (LRESULT)g_brBg;

    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT dis = (LPDRAWITEMSTRUCT)lp;
        BOOL primary = (dis->CtlID == IDC_PATCH);
        BOOL pressed = (dis->itemState & ODS_SELECTED) != 0;

        // Фон
        COLORREF fillCol = pressed
            ? COL_ACCENT
            : (primary ? COL_PANEL : COL_PANEL2);
        HBRUSH br = CreateSolidBrush(fillCol);
        FillRect(dis->hDC, &dis->rcItem, br);
        DeleteObject(br);

        // Граница
        HPEN pen = CreatePen(PS_SOLID, 1, primary ? COL_ACCENT : COL_DIM);
        HPEN oldP = (HPEN)SelectObject(dis->hDC, pen);
        HBRUSH oldB = (HBRUSH)SelectObject(dis->hDC, (HBRUSH)GetStockObject(NULL_BRUSH));
        Rectangle(dis->hDC, dis->rcItem.left, dis->rcItem.top,
                  dis->rcItem.right, dis->rcItem.bottom);
        SelectObject(dis->hDC, oldP);
        SelectObject(dis->hDC, oldB);
        DeleteObject(pen);

        // Текст
        wchar_t text[64];
        GetWindowTextW(dis->hwndItem, text, 64);
        SetBkMode(dis->hDC, TRANSPARENT);
        SetTextColor(dis->hDC, pressed ? COL_BG : (primary ? COL_ACCENT : COL_TEXT));
        HFONT oldF = (HFONT)SelectObject(dis->hDC,
                                         primary ? g_hFontBold : g_hFont);
        DrawTextW(dis->hDC, text, -1, &dis->rcItem,
                  DT_SINGLELINE | DT_CENTER | DT_VCENTER);
        SelectObject(dis->hDC, oldF);
        return TRUE;
    }

    case WM_COMMAND: {
        WORD id = LOWORD(wp);
        if (id == IDC_EXE_BROWSE) {
            wchar_t path[MAX_PATH];
            if (BrowseFile(hwnd, L"Executables\0*.exe;*.dll\0All files\0*.*\0",
                           path, MAX_PATH)) {
                SetWindowTextW(g_hExePath, path);
            }
        } else if (id == IDC_ICO_BROWSE) {
            wchar_t path[MAX_PATH];
            if (BrowseFile(hwnd, L"Icon files\0*.ico\0All files\0*.*\0",
                           path, MAX_PATH)) {
                SetWindowTextW(g_hIcoPath, path);
                LoadPreview(path);
            }
        } else if (id == IDC_ICO_PATH && HIWORD(wp) == EN_KILLFOCUS) {
            wchar_t path[MAX_PATH];
            GetWindowTextW(g_hIcoPath, path, MAX_PATH);
            LoadPreview(path);
        } else if (id == IDC_PATCH) {
            wchar_t exePath[MAX_PATH], icoPath[MAX_PATH];
            GetWindowTextW(g_hExePath, exePath, MAX_PATH);
            GetWindowTextW(g_hIcoPath, icoPath, MAX_PATH);
            if (!exePath[0] || !icoPath[0]) {
                Status("[!] Specify both EXE and .ico paths");
                break;
            }
            Status("[*] Patching...");
            PatchIcon(exePath, icoPath);
        }
        break;
    }

    case WM_ERASEBKGND: {
        RECT rc; GetClientRect(hwnd, &rc);
        FillRect((HDC)wp, &rc, g_brBg);
        return 1;
    }

    case WM_DESTROY:
        if (g_hPreviewIco) DestroyIcon(g_hPreviewIco);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

// ============================================================================
//  Helpers
// ============================================================================
static HWND MakeCtl(const wchar_t *cls, const wchar_t *txt, DWORD style,
                    int x, int y, int w, int h, HWND parent, int id, HFONT f) {
    HWND c = CreateWindowExW(0, cls, txt, WS_CHILD | WS_VISIBLE | style,
                             x, y, w, h, parent, (HMENU)(LONG_PTR)id,
                             GetModuleHandleW(NULL), NULL);
    SendMessageW(c, WM_SETFONT, (WPARAM)f, TRUE);
    return c;
}

// ============================================================================
//  WinMain
// ============================================================================
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nCmd) {
    (void)hPrev; (void)lpCmd; (void)nCmd;

    g_brBg     = CreateSolidBrush(COL_BG);
    g_brPanel  = CreateSolidBrush(COL_PANEL);
    g_brPanel2 = CreateSolidBrush(COL_PANEL2);

    g_hFont = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                          DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                          CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                          FIXED_PITCH | FF_MODERN, L"Consolas");
    g_hFontBold = CreateFontW(15, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                              DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                              CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                              FIXED_PITCH | FF_MODERN, L"Consolas");
    g_hFontBig = CreateFontW(26, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                             DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                             CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                             FIXED_PITCH | FF_MODERN, L"Consolas");
    g_hFontDim = CreateFontW(13, 0, 0, 0, FW_NORMAL, TRUE, FALSE, FALSE,
                             DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                             CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                             FIXED_PITCH | FF_MODERN, L"Consolas");

    WNDCLASSW wc = { 0 };
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = g_brBg;
    wc.lpszClassName = L"ICOPatcherWnd";
    wc.hIcon         = LoadIconW(hInst, MAKEINTRESOURCEW(1));
    RegisterClassW(&wc);

    // Окно фиксированного размера. Высота учитывает title bar (~32px)
    // и нижний padding под статус-строку.
    g_hwnd = CreateWindowExW(
        0, L"ICOPatcherWnd", L"ICOPatcher",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 740, 430,
        NULL, NULL, hInst, NULL);
    if (!g_hwnd) return 1;

    // --- Поля ввода + кнопки ---
    int y = 150;
    MakeCtl(L"STATIC", L" TARGET EXE", SS_LEFT,
            20, y, 600, 18, g_hwnd, -1, g_hFontBold);
    y += 22;
    g_hExePath = MakeCtl(L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL,
                         20, y, 580, 26, g_hwnd, IDC_EXE_PATH, g_hFont);
    MakeCtl(L"BUTTON", L"Browse", BS_OWNERDRAW,
            610, y, 100, 26, g_hwnd, IDC_EXE_BROWSE, g_hFont);
    y += 38;

    MakeCtl(L"STATIC", L" ICON (.ico)", SS_LEFT,
            20, y, 600, 18, g_hwnd, -1, g_hFontBold);
    y += 22;
    g_hIcoPath = MakeCtl(L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL,
                         20, y, 580, 26, g_hwnd, IDC_ICO_PATH, g_hFont);
    MakeCtl(L"BUTTON", L"Browse", BS_OWNERDRAW,
            610, y, 100, 26, g_hwnd, IDC_ICO_BROWSE, g_hFont);
    y += 38;

    MakeCtl(L"BUTTON", L"[ PATCH ]", BS_OWNERDRAW,
            20, y, 690, 36, g_hwnd, IDC_PATCH, g_hFontBold);
    y += 44;

    g_hStatus = MakeCtl(L"STATIC", L"Ready -- select EXE and .ico, then click PATCH",
                        SS_LEFT, 20, y, 690, 22, g_hwnd, IDC_STATUS, g_hFont);

    ShowWindow(g_hwnd, SW_SHOW);
    UpdateWindow(g_hwnd);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        if (!IsDialogMessageW(g_hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    DeleteObject(g_brBg);
    DeleteObject(g_brPanel);
    DeleteObject(g_brPanel2);
    DeleteObject(g_hFont);
    DeleteObject(g_hFontBold);
    DeleteObject(g_hFontBig);
    DeleteObject(g_hFontDim);
    return 0;
}
