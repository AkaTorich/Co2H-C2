; Self-locating x64 prologue. Linked to .text; extract_text prepends a
; 5-byte JMP rel32 in front so the blob starts with execution at offset 0.
;
; The polymorphic region is bracketed by 16-byte unique sentinels so that
; the generator's pattern search cannot hit a false positive inside the
; surrounding compiled code (CC int3 padding makes short sentinels unsafe).
EXTERN  Start:PROC

_TEXT SEGMENT

PUBLIC _scelot_entry
_scelot_entry PROC
    call    L1
L1: pop     rax
    sub     rax, 5
    mov     rcx, rax
    sub     rsp, 28h

    ; POLY_BEGIN id=1: 16-byte sentinel, then 32 NOP bytes, then END sentinel.
    ; Total region = 64 bytes. Generator overwrites the entire 64 bytes with
    ; a random valid NOP-equivalent sequence at build time.
    DB  00h,11h,22h,33h,44h,55h,66h,77h,88h,99h,0AAh,0BBh,0CCh,0DDh,0EEh,01h
    DB  90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h
    DB  90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h
    DB  0EEh,0DDh,0CCh,0BBh,0AAh,99h,88h,77h,66h,55h,44h,33h,22h,11h,00h,01h

    call    Start
    add     rsp, 28h
    xor     eax, eax
    ret
_scelot_entry ENDP

_TEXT ENDS
END
