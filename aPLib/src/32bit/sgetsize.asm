;;
;; aPLib compression library  -  the smaller the better :)
;;
;; fasm safe assembler header access
;;
;; Copyright (c) 1998-2014 Joergen Ibsen
;; All Rights Reserved
;;
;; http://www.ibsensoftware.com/
;;

format MS COFF

public aPsafe_get_orig_size as '_aPsafe_get_orig_size'

; =============================================================

section '.text' code readable executable

aPsafe_get_orig_size:
    ; aPsafe_get_orig_size(const void *source)

    .ret$  equ 7*4
    .src$  equ 8*4 + 4

    pushad

    mov    esi, [esp + .src$] ; esi -> buffer

    mov    ebx, [esi]         ; ebx = header.tag

    or     eax, -1            ; eax = -1

    cmp    ebx, 032335041h    ; check tag == 'AP32'
    jne    .return_eax

    mov    ebx, [esi + 4]     ; ebx = header.header_size
    cmp    ebx, 24            ; check header_size >= 24
    jb     .return_eax

    mov    eax, [esi + 16]    ; eax = header.orig_size

  .return_eax:
    mov    [esp + .ret$], eax ; return unpacked length in eax

    popad

    ret

; =============================================================
