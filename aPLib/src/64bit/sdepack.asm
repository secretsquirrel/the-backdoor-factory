;;
;; aPLib compression library  -  the smaller the better :)
;;
;; fasm 64-bit safe assembler wrapper for aP_depack_asm_safe
;;
;; Copyright (c) 1998-2014 Joergen Ibsen
;; All Rights Reserved
;;
;; http://www.ibsensoftware.com/
;;

format MS64 COFF

public aPsafe_depack

extrn aP_depack_asm_safe
extrn aP_crc32

; =============================================================

section '.text' code readable executable

aPsafe_depack:
    ; aPsafe_depack(const void *source,
    ;               size_t srclen,
    ;               void *destination
    ;               size_t dstlen)

    mov    [rsp + 8], rcx
    mov    [rsp + 16], rdx
    mov    [rsp + 24], r8
    mov    [rsp + 32], r9
    push   rdi
    sub    rsp, 32

    mov    rdi, rcx           ; rdi -> source

    test   rcx, rcx
    jz     .return_error

    test   r8, r8
    jz     .return_error

    cmp    rdx, 24            ; check srclen >= 24
    jb     .return_error      ;

    mov    eax, [rdi]         ; eax = header.tag

    cmp    eax, 032335041h    ; check tag == 'AP32'
    jne    .return_error

    mov    eax, [rdi + 4]     ; rax = header.header_size
    cmp    eax, 24            ; check header_size >= 24
    jb     .return_error

    sub    rdx, rax           ; rdx = srclen without header
    jc     .return_error      ;

    cmp    [rdi + 8], edx     ; check header.packed_size is
    ja     .return_error      ; within remaining srclen

    add    rcx, rax           ; rcx -> packed data

    mov    edx, [rdi + 8]     ; rdx = header.packed_size

    call   aP_crc32

    cmp    eax, [rdi + 12]    ; check eax == header.packed_crc
    jne    .return_error

    mov    r9, [rsp + 72]     ; r9 = dstlen

    mov    edx, [rdi + 16]    ; rdx = header.orig_size
    cmp    rdx, r9            ; check header.orig_size is ok
    ja     .return_error

    mov    eax, [rdi + 4]     ; rax = header.header_size

    mov    rcx, [rsp + 48]    ; rcx -> source
    mov    edx, [rdi + 8]     ; rdx = header.packed_size
    mov    r8, [rsp + 64]     ; r8 -> destination

    add    rcx, rax           ; rcx -> compressed data

    call   aP_depack_asm_safe

    mov    edx, [rdi + 16]    ; rdx = header.orig_size

    cmp    rax, rdx           ; check rax == header.orig_size
    jne    .return_error

    mov    rcx, [rsp + 64]    ; rcx -> destination

    call   aP_crc32

    cmp    eax, [rdi + 20]    ; check eax = header.orig_crc

    mov    eax, [rdi + 16]    ; rax = header.orig_size

    je     .return_rax

  .return_error:
    or     rax, -1            ; rax = -1

  .return_rax:
    add    rsp, 32
    pop    rdi

    ret

; =============================================================
