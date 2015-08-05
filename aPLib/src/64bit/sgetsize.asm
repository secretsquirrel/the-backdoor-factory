;;
;; aPLib compression library  -  the smaller the better :)
;;
;; fasm 64-bit safe assembler header access
;;
;; Copyright (c) 1998-2014 Joergen Ibsen
;; All Rights Reserved
;;
;; http://www.ibsensoftware.com/
;;

format MS64 COFF

public aPsafe_get_orig_size

; =============================================================

section '.text' code readable executable

aPsafe_get_orig_size:
    ; aPsafe_get_orig_size(const void *source)

    mov    edx, [rcx]         ; edx = header.tag

    or     rax, -1            ; rax = -1

    cmp    edx, 032335041h    ; check tag == 'AP32'
    jne    .return_rax

    mov    edx, [rcx + 4]     ; edx = header.header_size
    cmp    edx, 24            ; check header_size >= 24
    jb     .return_rax

    mov    eax, [rcx + 16]    ; rax = header.orig_size

  .return_rax:
    ret

; =============================================================
