// bof_hello.c — minimal "is it alive?" BOF.
//
// Verifies the loader chain end-to-end: COFF parse, .text/.rdata/.bss
// section allocation, REL32 relocations against an embedded string,
// __imp_ resolution against the Beacon-API symbol table, and entry
// dispatch. If `bof bof_hello.x64.o` produces "[hello] pid=<n>" in
// the operator console, every part of the loader is working.

#include "bof_api.h"

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetCurrentProcessId(VOID);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetCurrentThreadId(VOID);

void go(char* args, int alen) {
    (void)args; (void)alen;
    BeaconPrintf(CALLBACK_OUTPUT, "[hello] pid=%d tid=%d\n",
                 (int)KERNEL32$GetCurrentProcessId(),
                 (int)KERNEL32$GetCurrentThreadId());
}
