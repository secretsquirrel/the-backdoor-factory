;;
;; aPLib compression library  -  the smaller the better :)
;;
;; fasm safe assembler wrapper for aP_depack_asm_safe
;;
;; Copyright (c) 1998-2014 Joergen Ibsen
;; All Rights Reserved
;;
;; http://www.ibsensoftware.com/
;;

format MS COFF

public aPsafe_depack as '_aPsafe_depack'

extrn '_aP_depack_asm_safe' as aP_depack_asm_safe
extrn '_aP_crc32' as aP_crc32

; =============================================================

section '.text' code readable executable

aPsafe_depack:
    ; aPsafe_depack(const void *source,
    ;               size_t srclen,
    ;               void *destination
    ;               size_t dstlen)

    .ret$  equ 7*4
    .src$  equ 8*4 + 4
    .slen$ equ 8*4 + 8
    .dst$  equ 8*4 + 12
    .dlen$ equ 8*4 + 16

    pushad

    mov    esi, [esp + .src$]  ; esi -> inbuffer
    mov    ecx, [esp + .slen$] ; ecx =  srclen
    mov    edi, [esp + .dst$]  ; edi -> outbuffer

    test   esi, esi
    jz     .return_error

    test   edi, edi
    jz     .return_error

    cmp    ecx, 24            ; check srclen >= 24
    jb     .return_error

    mov    ebx, [esi]         ; ebx = header.tag

    cmp    ebx, 032335041h    ; check tag == 'AP32'
    jne    .return_error

    mov    ebx, [esi + 4]     ; ebx = header.header_size
    cmp    ebx, 24            ; check header_size >= 24
    jb     .return_error

    sub    ecx, ebx           ; ecx = srclen without header
    jc     .return_error

    cmp    [esi + 8], ecx     ; check header.packed_size is
    ja     .return_error      ; within remaining srclen

    add    ebx, esi           ; ebx -> packed data

    push   dword [esi + 8]    ; push header.packed_size
    push   ebx
    call   aP_crc32
    add    esp, 8

    cmp    eax, [esi + 12]    ; check eax == header.packed_crc
    jne    .return_error

    mov    ecx, [esp + .dlen$] ; ecx = dstlen
    cmp    [esi + 16], ecx     ; check header.orig_size is ok
    ja     .return_error

    push   ecx                ; push dstlen
    push   edi
    push   dword [esi + 8]    ; push header.packed_size
    push   ebx
    call   aP_depack_asm_safe
    add    esp, 16

    cmp    eax, [esi + 16]    ; check eax == header.orig_size
    jne    .return_error

    mov    ebx, eax           ; ebx = unpacked size

    push   eax
    push   edi
    call   aP_crc32
    add    esp, 8

    cmp    eax, [esi + 20]    ; check eax == header.orig_crc

    mov    eax, ebx           ; eax = unpacked size

    je     .return_eax

  .return_error:
    or     eax, -1            ; eax = -1

  .return_eax:
    mov    [esp + .ret$], eax ; return unpacked length in eax

    popad

    ret

; =============================================================
