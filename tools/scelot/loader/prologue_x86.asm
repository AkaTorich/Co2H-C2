.MODEL FLAT, C
EXTERN  Start:PROC

_TEXT SEGMENT

PUBLIC _scelot_entry
_scelot_entry PROC
    call    L1
L1: pop     eax
    sub     eax, 5

    ; POLY region: 16+32+16 = 64 bytes. See prologue_x64.asm for details.
    DB  00h,11h,22h,33h,44h,55h,66h,77h,88h,99h,0AAh,0BBh,0CCh,0DDh,0EEh,01h
    DB  90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h
    DB  90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h
    DB  0EEh,0DDh,0CCh,0BBh,0AAh,99h,88h,77h,66h,55h,44h,33h,22h,11h,00h,01h

    push    eax
    call    Start
    add     esp, 4
    xor     eax, eax
    ret
_scelot_entry ENDP

_TEXT ENDS
END
