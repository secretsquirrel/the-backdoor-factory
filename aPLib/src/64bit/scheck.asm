;;
;; aPLib compression library  -  the smaller the better :)
;;
;; fasm 64-bit safe assembler crc checker
;;
;; Copyright (c) 1998-2014 Joergen Ibsen
;; All Rights Reserved
;;
;; http://www.ibsensoftware.com/
;;

format MS64 COFF

public aPsafe_check

extrn aP_crc32

; =============================================================

section '.text' code readable executable

aPsafe_check:
    ; aPsafe_check(const void *source)

    push   rdi
    sub    rsp, 32

    mov    rdi, rcx           ; rdi -> source

    test   rcx, rcx
    jz     .return_error

    mov    eax, [rdi]         ; eax = header.tag

    cmp    eax, 032335041h    ; check tag == 'AP32'
    jne    .return_error

    mov    eax, [rdi + 4]     ; rax = header.header_size
    cmp    eax, 24            ; check header_size >= 24
    jb     .return_error

    add    rcx, rax           ; rcx -> packed data
    mov    edx, [rdi + 8]     ; rdx = header.packed_size

    call   aP_crc32

    cmp    eax, [rdi + 12]    ; check eax == header.packed_crc

    mov    eax, [rdi + 16]    ; rax = header.orig_size

    je     .return_rax

  .return_error:
    or     rax, -1            ; rax = -1

  .return_rax:
    add    rsp, 32
    pop    rdi

    ret

; =============================================================
