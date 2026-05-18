// x86_helpers.c -- CRT 64-bit math helpers for x86 no-CRT builds.
//
// On x86, MSVC generates calls to __allmul (and friends) for 64-bit
// integer arithmetic. Normally these live in the CRT, but PIC shellcode
// is built with /NODEFAULTLIB. This file provides minimal implementations.
//
// Only compiled for x86 targets (_M_IX86).

#ifdef _M_IX86

// __allmul: signed 64-bit multiply.
// Stack (cdecl): [ret][A_lo][A_hi][B_lo][B_hi]
// Returns: EDX:EAX = A * B (low 64 bits)
__declspec(naked) void __cdecl _allmul(void) {
    __asm {
        // Callee-pops convention: 4 DWORD args on stack (16 bytes).
        // Must use "ret 16" to clean up — MSVC does NOT add esp,16 after call.
        // Stack on entry: [esp+0]=ret [esp+4]=A_lo [esp+8]=A_hi
        //                 [esp+12]=B_lo [esp+16]=B_hi
        mov     eax, dword ptr [esp+8]      // A_hi
        mov     ecx, dword ptr [esp+16]     // B_hi
        or      ecx, eax                    // both high parts zero?
        mov     ecx, dword ptr [esp+12]     // B_lo
        jnz     short _hard

        // Simple: 32x32 -> 64
        mov     eax, dword ptr [esp+4]      // A_lo
        mul     ecx                         // EDX:EAX = A_lo * B_lo
        ret     16

    _hard:
        // Full: (A_hi*B_lo + A_lo*B_hi)<<32 + A_lo*B_lo
        push    ebx
        mul     ecx                         // A_hi * B_lo (eax still = A_hi)
        mov     ebx, eax                    // save low part

        mov     eax, dword ptr [esp+8]      // A_lo (+4 for push ebx)
        mul     dword ptr [esp+20]          // A_lo * B_hi
        add     ebx, eax                    // cross terms

        mov     eax, dword ptr [esp+8]      // A_lo
        mul     ecx                         // A_lo * B_lo -> EDX:EAX
        add     edx, ebx                    // add cross to high

        pop     ebx
        ret     16
    }
}

// __allshr: arithmetic (signed) right shift of 64-bit value.
// EDX:EAX = value, CL = shift count.
// Returns: EDX:EAX shifted right.
__declspec(naked) void __cdecl _allshr(void) {
    __asm {
        cmp     cl, 64
        jae     short _ret_sign

        cmp     cl, 32
        jae     short _high

        // shift < 32
        shrd    eax, edx, cl
        sar     edx, cl
        ret

    _high:
        // 32 <= shift < 64
        mov     eax, edx
        sar     edx, 31                     // sign-extend
        sub     cl, 32
        sar     eax, cl
        ret

    _ret_sign:
        sar     edx, 31
        mov     eax, edx
        ret
    }
}

// __aullshr: logical (unsigned) right shift of 64-bit value.
// EDX:EAX = value, CL = shift count.
// Returns: EDX:EAX shifted right (zero-fill).
__declspec(naked) void __cdecl _aullshr(void) {
    __asm {
        cmp     cl, 64
        jae     short _zero

        cmp     cl, 32
        jae     short _high

        shrd    eax, edx, cl
        shr     edx, cl
        ret

    _high:
        mov     eax, edx
        xor     edx, edx
        sub     cl, 32
        shr     eax, cl
        ret

    _zero:
        xor     eax, eax
        xor     edx, edx
        ret
    }
}

#endif // _M_IX86
