// bof_netstat.c — enumerate TCP connections via WinAPI.
//
// Real-world alternative to `netstat -ano`: shows active TCP connections
// with PID/process name without spawning cmd.exe. Useful for network
// reconnaissance and finding listening services on the target.

#include "bof_api.h"

DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetExtendedTcpTable(PVOID pTcpTable, PDWORD pdwSize, BOOL bOrder, ULONG ulAf, ULONG TableClass, ULONG Reserved);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetModuleBaseNameA(HANDLE hProcess, HMODULE hModule, LPSTR lpBaseName, DWORD nSize);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);

#define TCP_TABLE_OWNER_PID_ALL 5
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000

typedef struct {
    DWORD dwState;
    DWORD dwLocalAddr;
    DWORD dwLocalPort;
    DWORD dwRemoteAddr;
    DWORD dwRemotePort;
    DWORD dwOwningPid;
} MIB_TCPROW_OWNER_PID;

typedef struct {
    DWORD dwNumEntries;
    MIB_TCPROW_OWNER_PID table[1];
} MIB_TCPTABLE_OWNER_PID;

static const char* tcp_state_name(DWORD state) {
    switch (state) {
        case 1:  return "CLOSED";
        case 2:  return "LISTEN";
        case 3:  return "SYN_SENT";
        case 4:  return "SYN_RCVD";
        case 5:  return "ESTABLISHED";
        case 6:  return "FIN_WAIT1";
        case 7:  return "FIN_WAIT2";
        case 8:  return "CLOSE_WAIT";
        case 9:  return "CLOSING";
        case 10: return "LAST_ACK";
        case 11: return "TIME_WAIT";
        case 12: return "DELETE_TCB";
        default: return "UNKNOWN";
    }
}

static void print_addr(DWORD addr, DWORD port) {
    BeaconPrintf(CALLBACK_OUTPUT, "%d.%d.%d.%d:%d",
                 addr & 0xFF, (addr >> 8) & 0xFF,
                 (addr >> 16) & 0xFF, (addr >> 24) & 0xFF,
                 (port >> 8) | ((port & 0xFF) << 8));
}

void go(char* args, int alen) {
    (void)args; (void)alen;

    DWORD size = 0;
    DWORD ret = IPHLPAPI$GetExtendedTcpTable(NULL, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (ret != ERROR_INSUFFICIENT_BUFFER) {
        BeaconPrintf(CALLBACK_ERROR, "[netstat] GetExtendedTcpTable sizing failed: %d\n", ret);
        return;
    }

    HANDLE heap = KERNEL32$GetProcessHeap();
    MIB_TCPTABLE_OWNER_PID* table = (MIB_TCPTABLE_OWNER_PID*)KERNEL32$HeapAlloc(heap, 0, size);
    if (!table) {
        BeaconPrintf(CALLBACK_ERROR, "[netstat] HeapAlloc failed\n");
        return;
    }

    ret = IPHLPAPI$GetExtendedTcpTable(table, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (ret != NO_ERROR) {
        BeaconPrintf(CALLBACK_ERROR, "[netstat] GetExtendedTcpTable failed: %d\n", ret);
        KERNEL32$HeapFree(heap, 0, table);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\nTCP Connections:\n");
    BeaconPrintf(CALLBACK_OUTPUT, "%-15s %-15s %-12s %-6s %s\n", "Local", "Remote", "State", "PID", "Process");
    BeaconPrintf(CALLBACK_OUTPUT, "%-15s %-15s %-12s %-6s %s\n", "-----", "------", "-----", "---", "-------");

    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID* row = &table->table[i];

        BeaconPrintf(CALLBACK_OUTPUT, "");
        print_addr(row->dwLocalAddr, row->dwLocalPort);
        BeaconPrintf(CALLBACK_OUTPUT, " ");

        if (row->dwRemoteAddr == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "%-15s ", "*:*");
        } else {
            print_addr(row->dwRemoteAddr, row->dwRemotePort);
        }

        BeaconPrintf(CALLBACK_OUTPUT, " %-12s %-6d ", tcp_state_name(row->dwState), row->dwOwningPid);

        // Get process name
        char proc_name[64] = "?";
        HANDLE proc = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, row->dwOwningPid);
        if (proc) {
            KERNEL32$GetModuleBaseNameA(proc, NULL, proc_name, sizeof(proc_name));
            KERNEL32$CloseHandle(proc);
        }
        BeaconPrintf(CALLBACK_OUTPUT, "%s\n", proc_name);
    }

    KERNEL32$HeapFree(heap, 0, table);
}