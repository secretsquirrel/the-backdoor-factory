;;
;; aPLib compression library  -  the smaller the better :)
;;
;; fasm 64-bit safe assembler wrapper for aP_pack
;;
;; Copyright (c) 1998-2014 Joergen Ibsen
;; All Rights Reserved
;;
;; http://www.ibsensoftware.com/
;;

; header format:
;
;  offs  size    data
; --------------------------------------
;    0   dword   tag ('AP32')
;    4   dword   header_size (24 bytes)
;    8   dword   packed_size
;   12   dword   packed_crc
;   16   dword   orig_size
;   20   dword   orig_crc

format MS64 COFF

public aPsafe_pack

extrn aP_pack
extrn aP_crc32

; =============================================================

section '.text' code readable executable

aPsafe_pack:
    ; aPsafe_pack(const void *source,
    ;             void *destination,
    ;             unsigned int length,
    ;             void *workmem,
    ;             int (*callback)(unsigned int, unsigned int, void *),
    ;             void *cbparam)

    mov    [rsp + 8], rcx
    mov    [rsp + 16], rdx
    mov    [rsp + 24], r8
    mov    [rsp + 32], r9
    push   rdi
    sub    rsp, 48

    mov    rdi, rdx           ; rdi -> destination

    or     rax, -1            ; rax = -1

    test   rcx, rcx           ; check parameters
    jz     .return_rax        ;
    test   rdx, rdx           ;
    jz     .return_rax        ;
    test   r8, r8             ;
    jz     .return_rax        ;

    mov    edx, 032335041h
    mov    [rdi], edx         ; set header.tag

    mov    edx, 24
    mov    [rdi + 4], edx     ; set header.header_size

    mov    rdx, r8
    mov    [rdi + 16], edx    ; set header.orig_size

    call   aP_crc32

    mov    [rdi + 20], eax    ; set header.orig_crc

    mov    r10, [rsp + 96]    ; r10 -> callback
    mov    r11, [rsp + 104]   ; r11 = cbparam

    mov    rcx, [rsp + 64]
    mov    rdx, [rsp + 72]
    mov    r8, [rsp + 80]
    mov    r9, [rsp + 88]
    mov    [rsp + 32], r10
    mov    [rsp + 40], r11
    add    rdx, 24            ; rdx -> after header

    call   aP_pack

    cmp    eax, -1
    je     .return_rax

    mov    [rdi + 8], eax     ; set header.packed_size

    mov    rcx, [rsp + 72]    ; rcx -> destination
    mov    rdx, rax           ; rdx = packed size
    add    rcx, 24            ; rcx -> after header

    call   aP_crc32

    mov    [rdi + 12], eax    ; set header.packed_crc

    mov    eax, [rdi + 8]     ; eax = header.packed_size
    add    rax, 24            ; rax = final size

  .return_rax:
    add    rsp, 48
    pop    rdi

    ret

; =============================================================
