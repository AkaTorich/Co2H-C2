/*
 * Co2H Beacon Object File (BOF) API
 * -----------------------------------
 * Заголовочный файл для разработки BOF под Co2H.
 * Полностью совместим с Cobalt Strike 4.12 beacon.h —
 * любой публичный CS BOF соберётся без изменений.
 *
 * Дополнительно: AxDownloadMemory, AxAddScreenshot (Adaptix-совместимые).
 *
 * Использование:
 *   #include "beacon.h"
 *   void go(char* args, int len) {
 *       datap parser;
 *       BeaconDataParse(&parser, args, len);
 *       ...
 *       BeaconPrintf(CALLBACK_OUTPUT, "done\n");
 *   }
 *
 * Сборка (MSVC):
 *   cl /c /GS- /Os /Zl /TC /Fo bof_example.x64.o bof_example.c
 *
 * Загрузка в бикон:
 *   bof bof_example -- z arg1
 */
#ifndef _BEACON_H_
#define _BEACON_H_
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================== */
/*  Data API                                                                  */
/*  Разбор аргументов, переданных из клиента (bof cmd -- fmt arg1 arg2 ...).  */
/*  Формат буфера: последовательность записей, каждая —                       */
/*    i: 4 байта LE (BeaconDataInt)                                           */
/*    s: 2 байта LE (BeaconDataShort)                                         */
/*    z: [u32 len][ANSI\0]  (BeaconDataExtract)                               */
/*    Z: [u32 len][UTF16LE\0\0] (BeaconDataExtract)                           */
/*    b: [u32 len][raw bytes]   (BeaconDataExtract)                           */
/* ========================================================================== */

typedef struct {
    char * original;  /* исходный указатель на буфер (для освобождения) */
    char * buffer;    /* текущая позиция чтения */
    int    length;    /* оставшееся количество байт */
    int    size;      /* полный размер буфера */
} datap;

DECLSPEC_IMPORT void    BeaconDataParse(datap * parser, char * buffer, int size);
DECLSPEC_IMPORT char *  BeaconDataPtr(datap * parser, int size);
DECLSPEC_IMPORT int     BeaconDataInt(datap * parser);
DECLSPEC_IMPORT short   BeaconDataShort(datap * parser);
DECLSPEC_IMPORT int     BeaconDataLength(datap * parser);
DECLSPEC_IMPORT char *  BeaconDataExtract(datap * parser, int * size);

/* ========================================================================== */
/*  Format API                                                                */
/*  Формирование структурированных данных для отправки оператору.             */
/*  BeaconFormatAlloc выделяет буфер, BeaconFormatPrintf/Append/Int заполняют,*/
/*  BeaconFormatToString возвращает указатель + длину, BeaconFormatFree чистит.*/
/* ========================================================================== */

typedef struct {
    char * original;  /* выделенный буфер */
    char * buffer;    /* не используется (CS-совместимость) */
    int    length;    /* текущая длина данных */
    int    size;      /* максимальный размер буфера */
} formatp;

DECLSPEC_IMPORT void    BeaconFormatAlloc(formatp * format, int maxsz);
DECLSPEC_IMPORT void    BeaconFormatReset(formatp * format);
DECLSPEC_IMPORT void    BeaconFormatAppend(formatp * format, const char * text, int len);
DECLSPEC_IMPORT void    BeaconFormatPrintf(formatp * format, const char * fmt, ...);
DECLSPEC_IMPORT char *  BeaconFormatToString(formatp * format, int * size);
DECLSPEC_IMPORT void    BeaconFormatFree(formatp * format);
DECLSPEC_IMPORT void    BeaconFormatInt(formatp * format, int value);

/* ========================================================================== */
/*  Output                                                                    */
/*  Вывод текста/данных оператору. type определяет кодировку и назначение.    */
/* ========================================================================== */

#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_OUTPUT_UTF8 0x20
#define CALLBACK_ERROR       0x0d
#define CALLBACK_CUSTOM      0x1000
#define CALLBACK_CUSTOM_LAST 0x13ff

DECLSPEC_IMPORT void   BeaconOutput(int type, const char * data, int len);
DECLSPEC_IMPORT void   BeaconPrintf(int type, const char * fmt, ...);
DECLSPEC_IMPORT BOOL   BeaconDownload(const char * filename, const char * buffer, unsigned int length);

/* ========================================================================== */
/*  Token                                                                     */
/*  Имперсонализация токена в текущем потоке бикона.                          */
/* ========================================================================== */

DECLSPEC_IMPORT BOOL   BeaconUseToken(HANDLE token);
DECLSPEC_IMPORT void   BeaconRevertToken();
DECLSPEC_IMPORT BOOL   BeaconIsAdmin();

/* ========================================================================== */
/*  Spawn + Inject                                                            */
/*  Создание дочернего процесса и инжект payload через NtCreateSection.       */
/* ========================================================================== */

DECLSPEC_IMPORT void   BeaconGetSpawnTo(BOOL x86, char * buffer, int length);
DECLSPEC_IMPORT void   BeaconInjectProcess(HANDLE hProc, int pid,
                           char * payload, int p_len, int p_offset,
                           char * arg, int a_len);
DECLSPEC_IMPORT void   BeaconInjectTemporaryProcess(PROCESS_INFORMATION * pInfo,
                           char * payload, int p_len, int p_offset,
                           char * arg, int a_len);
DECLSPEC_IMPORT BOOL   BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken,
                           STARTUPINFO * si, PROCESS_INFORMATION * pInfo);
DECLSPEC_IMPORT void   BeaconCleanupProcess(PROCESS_INFORMATION * pInfo);

/* ========================================================================== */
/*  Utility                                                                   */
/* ========================================================================== */

DECLSPEC_IMPORT BOOL   toWideChar(char * src, wchar_t * dst, int max);

/* ========================================================================== */
/*  Beacon Information (CS 4.9+)                                              */
/*  Информация о бикон-процессе: версия, sleep mask, память.                 */
/* ========================================================================== */

typedef struct {
    char * ptr;
    size_t size;
} HEAP_RECORD;

#define MASK_SIZE 13

typedef enum {
    PURPOSE_EMPTY,
    PURPOSE_GENERIC_BUFFER,
    PURPOSE_BEACON_MEMORY,
    PURPOSE_SLEEPMASK_MEMORY,
    PURPOSE_BOF_MEMORY,
    PURPOSE_UDC2_MEMORY,
    PURPOSE_USER_DEFINED_MEMORY = 1000
} ALLOCATED_MEMORY_PURPOSE;

typedef enum {
    LABEL_EMPTY,
    LABEL_BUFFER,
    LABEL_PEHEADER,
    LABEL_TEXT,
    LABEL_RDATA,
    LABEL_DATA,
    LABEL_PDATA,
    LABEL_RELOC,
    LABEL_USER_DEFINED = 1000
} ALLOCATED_MEMORY_LABEL;

typedef enum {
    METHOD_UNKNOWN,
    METHOD_VIRTUALALLOC,
    METHOD_HEAPALLOC,
    METHOD_MODULESTOMP,
    METHOD_NTMAPVIEW,
    METHOD_USER_DEFINED = 1000,
} ALLOCATED_MEMORY_ALLOCATION_METHOD;

typedef struct _HEAPALLOC_INFO {
    PVOID HeapHandle;
    BOOL  DestroyHeap;
} HEAPALLOC_INFO, *PHEAPALLOC_INFO;

typedef struct _MODULESTOMP_INFO {
    HMODULE ModuleHandle;
} MODULESTOMP_INFO, *PMODULESTOMP_INFO;

typedef union _ALLOCATED_MEMORY_ADDITIONAL_CLEANUP_INFORMATION {
    HEAPALLOC_INFO   HeapAllocInfo;
    MODULESTOMP_INFO ModuleStompInfo;
    PVOID            Custom;
} ALLOCATED_MEMORY_ADDITIONAL_CLEANUP_INFORMATION,
  *PALLOCATED_MEMORY_ADDITIONAL_CLEANUP_INFORMATION;

typedef struct _ALLOCATED_MEMORY_CLEANUP_INFORMATION {
    BOOL Cleanup;
    ALLOCATED_MEMORY_ALLOCATION_METHOD AllocationMethod;
    ALLOCATED_MEMORY_ADDITIONAL_CLEANUP_INFORMATION AdditionalCleanupInformation;
} ALLOCATED_MEMORY_CLEANUP_INFORMATION, *PALLOCATED_MEMORY_CLEANUP_INFORMATION;

typedef struct _ALLOCATED_MEMORY_SECTION {
    ALLOCATED_MEMORY_LABEL Label;
    PVOID  BaseAddress;
    SIZE_T VirtualSize;
    DWORD  CurrentProtect;
    DWORD  PreviousProtect;
    BOOL   MaskSection;
    DWORD  DripLoadPageSize;
} ALLOCATED_MEMORY_SECTION, *PALLOCATED_MEMORY_SECTION;

typedef struct _ALLOCATED_MEMORY_REGION {
    ALLOCATED_MEMORY_PURPOSE Purpose;
    PVOID  AllocationBase;
    SIZE_T RegionSize;
    DWORD  Type;
    DWORD  DripLoadAllocationGranularity;
    ALLOCATED_MEMORY_SECTION Sections[8];
    ALLOCATED_MEMORY_CLEANUP_INFORMATION CleanupInformation;
} ALLOCATED_MEMORY_REGION, *PALLOCATED_MEMORY_REGION;

typedef struct {
    ALLOCATED_MEMORY_REGION AllocatedMemoryRegions[6];
} ALLOCATED_MEMORY, *PALLOCATED_MEMORY;

/*
 * BEACON_INFO — информация о бикон-процессе.
 *   version              — 0xMMmmPP (напр. 0x041200 = Co2H / CS 4.12)
 *   sleep_mask_ptr       — базовый адрес sleep mask (NULL если нет)
 *   beacon_ptr           — базовый адрес бикона в памяти
 *   heap_records         — список аллокаций на куче (terminated by ptr=NULL)
 *   mask[MASK_SIZE]      — маска для XOR-шифрования (13 байт)
 *   allocatedMemory      — описание выделенных регионов памяти
 */
typedef struct {
    unsigned int    version;
    char          * sleep_mask_ptr;
    DWORD           sleep_mask_text_size;
    DWORD           sleep_mask_total_size;
    char          * beacon_ptr;
    HEAP_RECORD   * heap_records;
    char            mask[MASK_SIZE];
    ALLOCATED_MEMORY allocatedMemory;
} BEACON_INFO, *PBEACON_INFO;

DECLSPEC_IMPORT BOOL   BeaconInformation(PBEACON_INFO info);

/* ========================================================================== */
/*  Key/Value Store (CS 4.9+)                                                 */
/*  Персистентное (между вызовами BOF) хранилище указателей по строковому     */
/*  ключу. Бикон НЕ освобождает и НЕ маскирует содержимое по адресу ptr.      */
/* ========================================================================== */

DECLSPEC_IMPORT BOOL   BeaconAddValue(const char * key, void * ptr);
DECLSPEC_IMPORT void * BeaconGetValue(const char * key);
DECLSPEC_IMPORT BOOL   BeaconRemoveValue(const char * key);

/* ========================================================================== */
/*  Data Store (CS 4.9+)                                                      */
/*  Доступ к хранилищу данных бикона (файлы, буферы).                        */
/*  Содержимое маскировано по умолчанию — Unprotect перед чтением,           */
/*  Protect после.                                                            */
/* ========================================================================== */

#define DATA_STORE_TYPE_EMPTY        0
#define DATA_STORE_TYPE_GENERAL_FILE 1

typedef struct {
    int      type;
    DWORD64  hash;
    BOOL     masked;
    char   * buffer;
    size_t   length;
} DATA_STORE_OBJECT, *PDATA_STORE_OBJECT;

DECLSPEC_IMPORT PDATA_STORE_OBJECT BeaconDataStoreGetItem(size_t index);
DECLSPEC_IMPORT void   BeaconDataStoreProtectItem(size_t index);
DECLSPEC_IMPORT void   BeaconDataStoreUnprotectItem(size_t index);
DECLSPEC_IMPORT size_t BeaconDataStoreMaxEntries();

/* ========================================================================== */
/*  Custom User Data (CS 4.9+)                                                */
/* ========================================================================== */

DECLSPEC_IMPORT char * BeaconGetCustomUserData();

/* ========================================================================== */
/*  Syscall Information (CS 4.10+, обновлено в 4.11)                          */
/*  Получение адресов Nt-функций из ntdll.dll.                               */
/* ========================================================================== */

typedef struct {
    PVOID fnAddr;    /* адрес функции в ntdll */
    PVOID jmpAddr;   /* адрес jmp-инструкции (для indirect syscall) */
    DWORD sysnum;    /* номер сисколла (SSN) */
} SYSCALL_API_ENTRY, *PSYSCALL_API_ENTRY;

typedef struct {
    SYSCALL_API_ENTRY ntAllocateVirtualMemory;
    SYSCALL_API_ENTRY ntProtectVirtualMemory;
    SYSCALL_API_ENTRY ntFreeVirtualMemory;
    SYSCALL_API_ENTRY ntGetContextThread;
    SYSCALL_API_ENTRY ntSetContextThread;
    SYSCALL_API_ENTRY ntResumeThread;
    SYSCALL_API_ENTRY ntCreateThreadEx;
    SYSCALL_API_ENTRY ntOpenProcess;
    SYSCALL_API_ENTRY ntOpenThread;
    SYSCALL_API_ENTRY ntClose;
    SYSCALL_API_ENTRY ntCreateSection;
    SYSCALL_API_ENTRY ntMapViewOfSection;
    SYSCALL_API_ENTRY ntUnmapViewOfSection;
    SYSCALL_API_ENTRY ntQueryVirtualMemory;
    SYSCALL_API_ENTRY ntDuplicateObject;
    SYSCALL_API_ENTRY ntReadVirtualMemory;
    SYSCALL_API_ENTRY ntWriteVirtualMemory;
    SYSCALL_API_ENTRY ntReadFile;
    SYSCALL_API_ENTRY ntWriteFile;
    SYSCALL_API_ENTRY ntCreateFile;
    SYSCALL_API_ENTRY ntQueueApcThread;
    SYSCALL_API_ENTRY ntCreateProcess;
    SYSCALL_API_ENTRY ntOpenProcessToken;
    SYSCALL_API_ENTRY ntTestAlert;
    SYSCALL_API_ENTRY ntSuspendProcess;
    SYSCALL_API_ENTRY ntResumeProcess;
    SYSCALL_API_ENTRY ntQuerySystemInformation;
    SYSCALL_API_ENTRY ntQueryDirectoryFile;
    SYSCALL_API_ENTRY ntSetInformationProcess;
    SYSCALL_API_ENTRY ntSetInformationThread;
    SYSCALL_API_ENTRY ntQueryInformationProcess;
    SYSCALL_API_ENTRY ntQueryInformationThread;
    SYSCALL_API_ENTRY ntOpenSection;
    SYSCALL_API_ENTRY ntAdjustPrivilegesToken;
    SYSCALL_API_ENTRY ntDeviceIoControlFile;
    SYSCALL_API_ENTRY ntWaitForMultipleObjects;
} SYSCALL_API, *PSYSCALL_API;

typedef struct {
    PVOID rtlDosPathNameToNtPathNameUWithStatusAddr;
    PVOID rtlFreeHeapAddr;
    PVOID rtlGetProcessHeapAddr;
} RTL_API, *PRTL_API;

typedef struct {
    SYSCALL_API syscalls;
    RTL_API     rtls;
} BEACON_SYSCALLS, *PBEACON_SYSCALLS;

DECLSPEC_IMPORT BOOL BeaconGetSyscallInformation(PBEACON_SYSCALLS info,
                         SIZE_T infoSize, BOOL resolveIfNotInitialized);

/* ========================================================================== */
/*  Syscall Wrappers (CS 4.10+)                                               */
/*  Обёртки вокруг WinAPI, использующие текущий метод сисколлов бикона.       */
/*  В Co2H проксируют на стандартные WinAPI (VirtualAlloc и т.д.).            */
/* ========================================================================== */

DECLSPEC_IMPORT LPVOID BeaconVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize,
                           DWORD flAllocationType, DWORD flProtect);
DECLSPEC_IMPORT LPVOID BeaconVirtualAllocEx(HANDLE processHandle,
                           LPVOID lpAddress, SIZE_T dwSize,
                           DWORD flAllocationType, DWORD flProtect);
DECLSPEC_IMPORT BOOL   BeaconVirtualProtect(LPVOID lpAddress, SIZE_T dwSize,
                           DWORD flNewProtect, PDWORD lpflOldProtect);
DECLSPEC_IMPORT BOOL   BeaconVirtualProtectEx(HANDLE processHandle,
                           LPVOID lpAddress, SIZE_T dwSize,
                           DWORD flNewProtect, PDWORD lpflOldProtect);
DECLSPEC_IMPORT BOOL   BeaconVirtualFree(LPVOID lpAddress, SIZE_T dwSize,
                           DWORD dwFreeType);
DECLSPEC_IMPORT BOOL   BeaconGetThreadContext(HANDLE threadHandle,
                           PCONTEXT threadContext);
DECLSPEC_IMPORT BOOL   BeaconSetThreadContext(HANDLE threadHandle,
                           PCONTEXT threadContext);
DECLSPEC_IMPORT DWORD  BeaconResumeThread(HANDLE threadHandle);
DECLSPEC_IMPORT HANDLE BeaconOpenProcess(DWORD desiredAccess,
                           BOOL inheritHandle, DWORD processId);
DECLSPEC_IMPORT HANDLE BeaconOpenThread(DWORD desiredAccess,
                           BOOL inheritHandle, DWORD threadId);
DECLSPEC_IMPORT BOOL   BeaconCloseHandle(HANDLE object);
DECLSPEC_IMPORT BOOL   BeaconUnmapViewOfFile(LPCVOID baseAddress);
DECLSPEC_IMPORT SIZE_T BeaconVirtualQuery(LPCVOID address,
                           PMEMORY_BASIC_INFORMATION buffer, SIZE_T length);
DECLSPEC_IMPORT BOOL   BeaconDuplicateHandle(HANDLE hSourceProcessHandle,
                           HANDLE hSourceHandle,
                           HANDLE hTargetProcessHandle,
                           LPHANDLE lpTargetHandle,
                           DWORD dwDesiredAccess,
                           BOOL bInheritHandle, DWORD dwOptions);
DECLSPEC_IMPORT BOOL   BeaconReadProcessMemory(HANDLE hProcess,
                           LPCVOID lpBaseAddress, LPVOID lpBuffer,
                           SIZE_T nSize, SIZE_T * lpNumberOfBytesRead);
DECLSPEC_IMPORT BOOL   BeaconWriteProcessMemory(HANDLE hProcess,
                           LPVOID lpBaseAddress, LPCVOID lpBuffer,
                           SIZE_T nSize, SIZE_T * lpNumberOfBytesWritten);

/* ========================================================================== */
/*  Beacon Gate (CS 4.10+)                                                    */
/*  Управление механизмом Beacon Gate (indirect syscall routing).             */
/*  В Co2H — заглушки (gate не реализован).                                  */
/* ========================================================================== */

DECLSPEC_IMPORT VOID BeaconDisableBeaconGate();
DECLSPEC_IMPORT VOID BeaconEnableBeaconGate();
DECLSPEC_IMPORT VOID BeaconDisableBeaconGateMasking();
DECLSPEC_IMPORT VOID BeaconEnableBeaconGateMasking();

/* ========================================================================== */
/*  User Data (CS 4.10+)                                                      */
/*  Структура для UDRL (User Defined Reflective Loader).                     */
/* ========================================================================== */

#define DLL_BEACON_USER_DATA     0x0d
#define BEACON_USER_DATA_CUSTOM_SIZE 32

typedef struct {
    unsigned int      version;
    PSYSCALL_API      syscalls;
    char              custom[BEACON_USER_DATA_CUSTOM_SIZE];
    PRTL_API          rtls;
    PALLOCATED_MEMORY allocatedMemory;
} USER_DATA, *PUSER_DATA;

/* ========================================================================== */
/*  Co2H Extensions (Adaptix-совместимые)                                     */
/*  Дополнительные функции, отсутствующие в оригинальном CS beacon.h.         */
/* ========================================================================== */

/* Отправить буфер оператору как файл (filename — имя для сохранения). */
DECLSPEC_IMPORT void AxDownloadMemory(char * filename, char * data, int len);

/* Отправить скриншот/картинку оператору (note — описание). */
DECLSPEC_IMPORT void AxAddScreenshot(char * note, char * data, int len);

#ifdef __cplusplus
}
#endif
#endif /* _BEACON_H_ */
