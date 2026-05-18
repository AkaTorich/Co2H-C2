// sw4_shims.c -- minimal CRT shims for SW4 with /NODEFAULTLIB.
//
// SysWhispers4 при некоторых флагах (--unhook-ntdll, --sleep-encrypt,
// --stack-spoof) ссылается на CRT-функции и неопределённые data-символы.
// Этот файл предоставляет минимальные реализации, чтобы линковка прошла
// без подключения libcmt.
//
// Файл автоматически линкуется build_all.bat, если у стаба есть маркер
// .syscalls. Регенерации не требует — статичный.

#include <windows.h>

// --- memcpy --------------------------------------------------------------
// Нужен SW4_UnhookNtdll: копирует clean ntdll .text поверх hooked.
// Простая байтовая копия — без оптимизаций.
#pragma function(memcpy)
void *memcpy(void *dst, const void *src, size_t n) {
    BYTE       *d = (BYTE *)dst;
    const BYTE *s = (const BYTE *)src;
    while (n--) *d++ = *s++;
    return dst;
}

// --- __chkstk (x64) ------------------------------------------------------
// MSVC вставляет вызов __chkstk при выделении стека > ~4KB на функцию.
// Без CRT этот символ unresolved. Делаем noop — у нас /GS- и нет глубоких
// фреймов, проба страниц не нужна.
//
// Контракт: rax = размер выделения, не должен меняться. Регистры сохраняем.
#ifdef _M_X64
void __chkstk(void) { /* nop */ }
#elif defined(_M_IX86)
// На x86 имя экспортируется как _chkstk (без __cdecl decoration ABI'а
// конкретно для этого helper-а). Поскольку он вызывается явно компилятором
// с особой соглашением, делаем naked-стаб.
__declspec(naked) void _chkstk(void) {
    __asm { ret }
}
#endif

// --- SW4_SpoofReturnAddr -------------------------------------------------
// SW4 c флагом --stack-spoof декларирует этот data-символ как EXTERN в .asm,
// но не генерирует его C-определение (баг SW4 в текущей версии).
// Должно содержать адрес "хорошего" gadget'а внутри ntdll, например адрес
// инструкции `ret` после какого-нибудь экспорта.
//
// Здесь оставляем 0 — при вызове CallWithSpoofedStack произойдёт jmp в null,
// что свалит процесс. Для реальной операции нужно инициализировать этот
// указатель адресом из ntdll. Минимальная инициализация:
//
//     SW4_SpoofReturnAddr = (ULONG_PTR)GetProcAddress(
//         GetModuleHandleA("ntdll.dll"), "RtlExitUserThread") + offset;
//
// Если флаг --stack-spoof не нужен, перегенерируйте без него.
#ifdef _M_X64
ULONGLONG SW4_SpoofReturnAddr = 0;
#endif
