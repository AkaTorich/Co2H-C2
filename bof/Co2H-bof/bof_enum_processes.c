// bof_enum_processes.c — детальное перечисление процессов.
//
// Показывает PID, PPID, имя процесса, путь к исполняемому файлу,
// владельца процесса и integrity level. Более информативно чем `ps`.
// Полезно для lateral movement - поиск GUI процессов, сервисов,
// процессов под высокими привилегиями.

#include "bof_api.h"

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Process32First(HANDLE hSnapshot, LPVOID lppe);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Process32Next(HANDLE hSnapshot, LPVOID lppe);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$QueryFullProcessImageNameA(HANDLE hProcess, DWORD dwFlags, LPSTR lpExeName, PDWORD lpdwSize);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE TokenHandle, DWORD TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupAccountSidA(LPCSTR lpSystemName, PSID Sid, LPSTR Name, LPDWORD cchName, LPSTR DomainName, LPDWORD cchDomainName, PSID_NAME_USE peUse);

#define TH32CS_SNAPPROCESS  0x00000002
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#define TOKEN_QUERY 0x0008

typedef struct tagPROCESSENTRY32 {
    DWORD dwSize;
    DWORD cntUsage;
    DWORD th32ProcessID;
    ULONG_PTR th32DefaultHeapID;
    DWORD th32ModuleID;
    DWORD cntThreads;
    DWORD th32ParentProcessID;
    LONG pcPriClassBase;
    DWORD dwFlags;
    CHAR szExeFile[260];
} PROCESSENTRY32;

static const char* get_integrity_level(HANDLE proc) {
    HANDLE token;
    if (!KERNEL32$OpenProcessToken(proc, TOKEN_QUERY, &token)) return "?";

    DWORD len;
    ADVAPI32$GetTokenInformation(token, 25, NULL, 0, &len); // TokenIntegrityLevel = 25

    char buffer[256];
    if (len > sizeof(buffer)) {
        KERNEL32$CloseHandle(token);
        return "?";
    }

    if (!ADVAPI32$GetTokenInformation(token, 25, buffer, len, &len)) {
        KERNEL32$CloseHandle(token);
        return "?";
    }

    // TOKEN_MANDATORY_LABEL structure: SID_AND_ATTRIBUTES
    PSID sid = *(PSID*)(buffer + 4); // Skip Attributes, get Sid
    KERNEL32$CloseHandle(token);

    // Check well-known integrity SIDs
    BYTE* pAuth = (BYTE*)sid + 2; // Skip Revision and SubAuthorityCount
    if (pAuth[5] == 0x10) {
        DWORD* subAuth = (DWORD*)(pAuth + 8);
        switch (subAuth[0]) {
            case 0x1000: return "Low";
            case 0x2000: return "Medium";
            case 0x2100: return "Medium+";
            case 0x3000: return "High";
            case 0x4000: return "System";
            default: return "Unknown";
        }
    }
    return "?";
}

static void get_process_owner(DWORD pid, char* owner, int owner_size) {
    HANDLE proc = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!proc) {
        owner[0] = '?'; owner[1] = '\0';
        return;
    }

    HANDLE token;
    if (!KERNEL32$OpenProcessToken(proc, TOKEN_QUERY, &token)) {
        KERNEL32$CloseHandle(proc);
        owner[0] = '?'; owner[1] = '\0';
        return;
    }

    DWORD len;
    ADVAPI32$GetTokenInformation(token, 1, NULL, 0, &len); // TokenUser = 1

    char buffer[512];
    if (len > sizeof(buffer) || !ADVAPI32$GetTokenInformation(token, 1, buffer, len, &len)) {
        KERNEL32$CloseHandle(token);
        KERNEL32$CloseHandle(proc);
        owner[0] = '?'; owner[1] = '\0';
        return;
    }

    // TOKEN_USER structure: SID_AND_ATTRIBUTES
    PSID user_sid = *(PSID*)(buffer + 4); // Skip Attributes

    char name[128], domain[128];
    DWORD name_len = sizeof(name), domain_len = sizeof(domain);
    SID_NAME_USE name_use;

    if (ADVAPI32$LookupAccountSidA(NULL, user_sid, name, &name_len, domain, &domain_len, &name_use)) {
        int pos = 0;
        for (int i = 0; domain[i] && pos < owner_size - 1; i++) {
            owner[pos++] = domain[i];
        }
        if (pos < owner_size - 1) owner[pos++] = '\\';
        for (int i = 0; name[i] && pos < owner_size - 1; i++) {
            owner[pos++] = name[i];
        }
        owner[pos] = '\0';
    } else {
        owner[0] = '?'; owner[1] = '\0';
    }

    KERNEL32$CloseHandle(token);
    KERNEL32$CloseHandle(proc);
}

void go(char* args, int alen) {
    (void)args; (void)alen;

    HANDLE snapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[enum_processes] CreateToolhelp32Snapshot failed\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\nProcesses:\n");
    BeaconPrintf(CALLBACK_OUTPUT, "%-6s %-6s %-20s %-10s %-25s %s\n", "PID", "PPID", "Name", "Integrity", "Owner", "Path");
    BeaconPrintf(CALLBACK_OUTPUT, "%-6s %-6s %-20s %-10s %-25s %s\n", "---", "----", "----", "---------", "-----", "----");

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!KERNEL32$Process32First(snapshot, &pe32)) {
        BeaconPrintf(CALLBACK_ERROR, "[enum_processes] Process32First failed\n");
        KERNEL32$CloseHandle(snapshot);
        return;
    }

    do {
        char owner[128];
        get_process_owner(pe32.th32ProcessID, owner, sizeof(owner));

        char full_path[512] = {0};
        HANDLE proc = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
        if (proc) {
            DWORD path_len = sizeof(full_path);
            if (!KERNEL32$QueryFullProcessImageNameA(proc, 0, full_path, &path_len)) {
                full_path[0] = '\0';
            }
        }
        const char* integrity = "?";
        if (proc) {
            integrity = get_integrity_level(proc);
            KERNEL32$CloseHandle(proc);
        }

        BeaconPrintf(CALLBACK_OUTPUT, "%-6d %-6d %-20s %-10s %-25s %s\n",
                     pe32.th32ProcessID,
                     pe32.th32ParentProcessID,
                     pe32.szExeFile,
                     integrity,
                     owner,
                     full_path[0] ? full_path : pe32.szExeFile);

    } while (KERNEL32$Process32Next(snapshot, &pe32));

    KERNEL32$CloseHandle(snapshot);
}