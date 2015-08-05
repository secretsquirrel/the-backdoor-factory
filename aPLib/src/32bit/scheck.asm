;;
;; aPLib compression library  -  the smaller the better :)
;;
;; fasm safe assembler crc checker
;;
;; Copyright (c) 1998-2014 Joergen Ibsen
;; All Rights Reserved
;;
;; http://www.ibsensoftware.com/
;;

format MS COFF

public aPsafe_check as '_aPsafe_check'

extrn '_aP_crc32' as aP_crc32

; =============================================================

section '.text' code readable executable

aPsafe_check:
    ; aPsafe_check(const void *source)

    .ret$  equ 7*4
    .src$  equ 8*4 + 4

    pushad

    mov    esi, [esp + .src$] ; esi -> buffer

    test   esi, esi
    jz     .return_error

    mov    ebx, [esi]         ; ebx = header.tag

    cmp    ebx, 032335041h    ; check tag == 'AP32'
    jne    .return_error

    mov    ebx, [esi + 4]     ; ebx = header.header_size
    cmp    ebx, 24            ; check header_size >= 24
    jb     .return_error

    add    ebx, esi           ; ebx -> packed data

    push   dword [esi + 8]    ; push header.packed_size
    push   ebx
    call   aP_crc32
    add    esp, 8

    cmp    eax, [esi + 12]    ; check eax == header.packed_crc

    mov    eax, [esi + 16]    ; eax = header.orig_size

    je     .return_eax

  .return_error:
    or     eax, -1            ; eax = -1

  .return_eax:
    mov    [esp + .ret$], eax ; return unpacked length in eax

    popad

    ret

; =============================================================
