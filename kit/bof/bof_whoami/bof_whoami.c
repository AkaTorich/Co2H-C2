// bof_whoami.c — print current user name.
//
// Useful next to `getuid` to compare results: `getuid` reads the
// thread token through OpenThreadToken and prints the SID, while a
// BOF runs in-process and calls GetUserNameA which reads the
// effective primary token. After `make_token` or `steal_token` both
// outputs should reflect the impersonated identity.

#include "..\bof_api.h"

DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$GetUserNameA(LPSTR  lpBuffer, LPDWORD pcbBuffer);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(VOID);

void go(char* args, int alen) {
    (void)args; (void)alen;
    char  name[256];
    DWORD len = sizeof(name);
    if (ADVAPI32$GetUserNameA(name, &len)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[whoami] %s\n", name);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[whoami] GetUserNameA failed (gle=%d)\n",
                     (int)KERNEL32$GetLastError());
    }
}
