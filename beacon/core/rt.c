// Minimal runtime helpers (the beacon is built without the CRT).
#include "beacon.h"

#pragma function(memset)
void* memset(void* dst, int c, size_t n) {
    unsigned char* p = (unsigned char*)dst;
    while (n--) *p++ = (unsigned char)c;
    return dst;
}

#pragma function(memcpy)
void* memcpy(void* dst, const void* src, size_t n) {
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    while (n--) *d++ = *s++;
    return dst;
}

#pragma function(memcmp)
int memcmp(const void* a, const void* b, size_t n) {
    const unsigned char* x = (const unsigned char*)a;
    const unsigned char* y = (const unsigned char*)b;
    for (size_t i = 0; i < n; ++i) if (x[i] != y[i]) return x[i] - y[i];
    return 0;
}

void  rt_memset(void* dst, int c, size_t n)            { memset(dst, c, n); }
void  rt_memcpy(void* dst, const void* src, size_t n)  { memcpy(dst, src, n); }
int   rt_memcmp(const void* a, const void* b, size_t n){ return memcmp(a, b, n); }

size_t rt_strlen(const char* s) {
    const char* p = s;
    while (*p) ++p;
    return (size_t)(p - s);
}

size_t rt_wstrlen(const wchar_t* s) {
    const wchar_t* p = s;
    while (*p) ++p;
    return (size_t)(p - s);
}

/* ---- x86 без CRT: 64-битные арифметические хелперы -----------------------
   MSVC x86 генерирует вызовы этих функций для 64-битных операций.
   Соглашения вызова нестандартные (регистровые), поэтому naked.
   Реализации повторяют Microsoft CRT (VC/crt/src/i386/ll*.asm). */
#ifndef _WIN64


/* _aullshr: беззнаковый сдвиг вправо.
   Вход: EDX:EAX = значение, CL = кол-во бит.
   Выход: EDX:EAX = результат. */
__declspec(naked) void _aullshr(void) {
    __asm {
        cmp  cl, 64
        jae  retzero
        cmp  cl, 32
        jae  shifthigh
        shrd eax, edx, cl
        shr  edx, cl
        ret
    shifthigh:
        mov  eax, edx
        xor  edx, edx
        and  cl, 31
        shr  eax, cl
        ret
    retzero:
        xor  eax, eax
        xor  edx, edx
        ret
    }
}

/* _allmul: знаковое/беззнаковое умножение 64×64 → младшие 64 бита.
   Вход: на стеке [esp+4..+20] = a_lo, a_hi, b_lo, b_hi (callee-pops 16).
   Выход: EDX:EAX = результат. */
__declspec(naked) void _allmul(void) {
    __asm {
        mov  eax, [esp+8]        /* a_hi */
        mov  ecx, [esp+16]       /* b_hi */
        or   ecx, eax
        mov  ecx, [esp+12]       /* b_lo */
        jnz  hard
        /* простой случай: оба числа < 2^32 */
        mov  eax, [esp+4]        /* a_lo */
        mul  ecx                  /* a_lo × b_lo → EDX:EAX */
        ret  16
    hard:
        push ebx
        mul  ecx                  /* a_hi × b_lo */
        mov  ebx, eax
        mov  eax, [esp+8]        /* a_lo (смещение +4 из-за push ebx) */
        mul  dword ptr [esp+20]  /* a_lo × b_hi */
        add  ebx, eax
        mov  eax, [esp+8]        /* a_lo */
        mul  ecx                  /* a_lo × b_lo → EDX:EAX */
        add  edx, ebx
        pop  ebx
        ret  16
    }
}

/* _aulldvrm: беззнаковое деление 64/64 с остатком.
   Вход: на стеке [esp+4..+20] = dvd_lo, dvd_hi, dvs_lo, dvs_hi (callee-pops 16).
   Выход: EDX:EAX = частное, EBX:ECX = остаток. */
__declspec(naked) void _aulldvrm(void) {
    __asm {
        push esi

        /* dvs_hi == 0? → быстрый путь (делитель 32-бит) */
        mov  ecx, [esp+20]       /* dvs_hi */
        test ecx, ecx
        jnz  big_divisor

        /* делитель < 2^32 */
        mov  ecx, [esp+16]       /* dvs_lo */
        mov  eax, [esp+12]       /* dvd_hi */
        xor  edx, edx
        div  ecx                  /* dvd_hi / dvs_lo */
        mov  esi, eax             /* частное_hi */
        mov  eax, [esp+8]        /* dvd_lo */
        div  ecx                  /* (остаток:dvd_lo) / dvs_lo */
        mov  ecx, edx             /* остаток_lo */
        mov  edx, esi             /* частное_hi */
        xor  ebx, ebx             /* остаток_hi = 0 */

        pop  esi
        ret  16

    big_divisor:
        /* делитель >= 2^32: частное гарантированно < 2^32.
           Нормализуем делитель сдвигом влево, выполняем пробное деление,
           одна коррекция вниз если промахнулись. */
        push edi
        push ebp

        mov  ebp, [esp+28]       /* dvs_hi (+8 из-за двух push) */
        mov  edi, [esp+24]       /* dvs_lo */
        mov  edx, [esp+20]       /* dvd_hi */
        mov  eax, [esp+16]       /* dvd_lo */

        bsr  ecx, ebp
        xor  ecx, 31             /* кол-во ведущих нулей */
        jz   skip_norm

        /* нормализация: сдвигаем делитель влево,
           делимое вправо на то же кол-во бит */
        shld ebp, edi, cl
        shrd eax, edx, cl
        shr  edx, cl
    skip_norm:
        div  ebp                  /* пробное деление */

        mov  esi, eax             /* пробное частное */

        /* проверка: q * divisor <= dividend? */
        mul  dword ptr [esp+28]  /* q × dvs_hi */
        mov  ecx, eax
        mov  eax, esi
        mul  dword ptr [esp+24]  /* q × dvs_lo */
        add  edx, ecx

        /* вычитаем из делимого */
        mov  ecx, [esp+16]       /* dvd_lo */
        mov  ebp, [esp+20]       /* dvd_hi */
        sub  ecx, eax
        sbb  ebp, edx
        jnc  no_adj

        /* коррекция: частное на 1 меньше, остаток += делитель */
        dec  esi
        add  ecx, [esp+24]       /* + dvs_lo */
        adc  ebp, [esp+28]       /* + dvs_hi */
    no_adj:
        mov  eax, esi             /* частное_lo */
        xor  edx, edx             /* частное_hi = 0 */
        mov  ebx, ebp             /* остаток_hi */
        /* ecx уже содержит остаток_lo */

        pop  ebp
        pop  edi
        pop  esi
        ret  16
    }
}

/* /DYNAMICBASE без CRT: линкер ищет __load_config_used. */
int _load_config_used = 0;

#endif /* !_WIN64 */
