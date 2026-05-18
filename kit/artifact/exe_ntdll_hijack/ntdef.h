#pragma once

// Definitions of NT structures for EntryPoint Hijacking
// Verified offsets for Windows 10/11 x64

#include <windows.h>
#include <winternl.h>

#define MAX_ARGS 11

// Data structure used to pass arguments to runner
// And to save backup values of EntryPoint and OriginalBase
typedef struct _DATA_T {
    ULONG_PTR   runner;             // pointer to runner function
    ULONG_PTR   bakOriginalBase;    // backup of original OriginalBase
    ULONG_PTR   bakEntryPoint;      // backup of original EntryPoint
    HANDLE      event;              // event signal after runner execution
    ULONG_PTR   ret;                // return value
    DWORD       createThread;       // run API call in new thread
    ULONG_PTR   function;           // address of called API
    DWORD       dwArgs;             // number of arguments
    ULONG_PTR   args[MAX_ARGS];     // array of arguments
} DATA_T, *PDATA_T;

// Extended PEB_LDR_DATA (more fields than in winternl.h)
typedef struct _PEB_LDR_DATA_FULL {
    ULONG       Length;
    BOOLEAN     Initialized;
    PVOID       SsHandle;
    LIST_ENTRY  InLoadOrderModuleList;
    LIST_ENTRY  InMemoryOrderModuleList;
    LIST_ENTRY  InInitializationOrderModuleList;
} PEB_LDR_DATA_FULL, *PPEB_LDR_DATA_FULL;

// Full LDR_DATA_TABLE_ENTRY for Windows 10/11 x64
// Offsets verified through WinDbg (dt nt!_LDR_DATA_TABLE_ENTRY)
typedef struct _LDR_DATA_TABLE_ENTRY2 {
    LIST_ENTRY      InLoadOrderLinks;           // +0x000
    LIST_ENTRY      InMemoryOrderLinks;         // +0x010
    LIST_ENTRY      InInitializationOrderLinks; // +0x020
    PVOID           DllBase;                    // +0x030
    PVOID           EntryPoint;                 // +0x038
    ULONG           SizeOfImage;                // +0x040
    UNICODE_STRING  FullDllName;                // +0x048
    UNICODE_STRING  BaseDllName;                // +0x058
    union {                                     // +0x068
        UCHAR FlagGroup[4];
        ULONG Flags;
        struct {
            ULONG PackagedBinary : 1;
            ULONG MarkedForRemoval : 1;
            ULONG ImageDll : 1;
            ULONG LoadNotificationsSent : 1;
            ULONG TelemetryEntryProcessed : 1;
            ULONG ProcessStaticImport : 1;
            ULONG InLegacyLists : 1;
            ULONG InIndexes : 1;
            ULONG ShimDll : 1;
            ULONG InExceptionTable : 1;
            ULONG ReservedFlags1 : 2;
            ULONG LoadInProgress : 1;
            ULONG LoadConfigProcessed : 1;
            ULONG EntryProcessed : 1;
            ULONG ProtectDelayLoad : 1;
            ULONG ReservedFlags3 : 2;
            ULONG DontCallForThreads : 1;
            ULONG ProcessAttachCalled : 1;
            ULONG ProcessAttachFailed : 1;
            ULONG CorDeferredValidate : 1;
            ULONG CorImage : 1;
            ULONG DontRelocate : 1;
            ULONG CorILOnly : 1;
            ULONG ChpeImage : 1;
            ULONG ReservedFlags5 : 2;
            ULONG Redirected : 1;
            ULONG ReservedFlags6 : 2;
            ULONG CompatDatabaseProcessed : 1;
        };
    };
    USHORT          ObsoleteLoadCount;          // +0x06c
    USHORT          TlsIndex;                   // +0x06e
    LIST_ENTRY      HashLinks;                  // +0x070
    ULONG           TimeDateStamp;              // +0x080
    PVOID           EntryPointActivationContext;// +0x088
    PVOID           Lock;                       // +0x090
    PVOID           DdagNode;                   // +0x098
    LIST_ENTRY      NodeModuleLink;             // +0x0a0
    PVOID           LoadContext;                // +0x0b0
    PVOID           ParentDllBase;              // +0x0b8
    PVOID           SwitchBackContext;          // +0x0c0
    PVOID           BaseAddressIndexNode[3];    // +0x0c8 (RTL_BALANCED_NODE)
    PVOID           MappingInfoIndexNode[3];    // +0x0e0 (RTL_BALANCED_NODE)
    ULONG_PTR       OriginalBase;               // +0x0f8 <-- target field
    LARGE_INTEGER   LoadTime;                   // +0x100
    ULONG           BaseNameHashValue;          // +0x108
    ULONG           LoadReason;                 // +0x10c
    ULONG           ImplicitPathOptions;        // +0x110
    ULONG           ReferenceCount;             // +0x114
    ULONG           DependentLoadFlags;         // +0x118
    UCHAR           SigningLevel;               // +0x11c
} LDR_DATA_TABLE_ENTRY2, *PLDR_DATA_TABLE_ENTRY2;

// PROCESS_BASIC_INFORMATION for NtQueryInformationProcess
typedef struct _PROCESS_BASIC_INFORMATION_T {
    NTSTATUS    ExitStatus;
    PPEB        PebBaseAddress;
    ULONG_PTR   AffinityMask;
    LONG        BasePriority;
    ULONG_PTR   UniqueProcessId;
    ULONG_PTR   InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION_T, *PPROCESS_BASIC_INFORMATION_T;

// NtQueryInformationProcess signature
typedef NTSTATUS (NTAPI *NtQueryInformationProcess_t)(
    HANDLE          ProcessHandle,
    ULONG           ProcessInformationClass,
    PVOID           ProcessInformation,
    ULONG           ProcessInformationLength,
    PULONG          ReturnLength
);
