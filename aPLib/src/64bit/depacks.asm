;;
;; aPLib compression library  -  the smaller the better :)
;;
;; fasm 64-bit safe assembler depacker
;;
;; Copyright (c) 1998-2014 Joergen Ibsen
;; All Rights Reserved
;;
;; http://www.ibsensoftware.com/
;;

format MS64 COFF

public aP_depack_asm_safe

; =============================================================

macro getbitM
{
    local .stillbitsleft

    add    dl, dl
    jnz    .stillbitsleft

    sub    r10, 1             ; read one byte from source
    jc     return_error       ;

    mov    dl, [rsi]
    add    rsi, 1

    add    dl, dl
    inc    dl
  .stillbitsleft:
}

macro domatchM reg
{
    local .more

    mov    r8, [rsp + 32]     ; r8 = dstlen
    sub    r8, r11            ; r8 = num written
    cmp    reg, r8
    ja     return_error

    sub    r11, rcx           ; write rcx bytes to destination
    jc     return_error       ;

    mov    r8, rdi
    sub    r8, reg

  .more:
    mov    al, [r8]
    add    r8, 1
    mov    [rdi], al
    add    rdi, 1
    sub    rcx, 1
    jnz    .more
}

macro getgammaM reg
{
    local .getmore
    mov    reg, 1
  .getmore:
    getbitM
    adc    reg, reg
    jc     return_error
    getbitM
    jc     .getmore
}

; =============================================================

section '.text' code readable executable

aP_depack_asm_safe:
    ; aP_depack_asm_safe(const void *source,
    ;                    unsigned int srclen,
    ;                    void *destination,
    ;                    unsigned int dstlen)

    mov    [rsp + 8], r9
    mov    [rsp + 16], r8
    mov    [rsp + 24], rbp
    push   rbx
    push   rsi
    push   rdi

    mov    rsi, rcx
    mov    r10, rdx
    mov    rdi, r8
    mov    r11, r9

    test   rsi, rsi
    jz     return_error

    test   rdi, rdi
    jz     return_error

    or     rbp, -1

    cld
    xor    rdx, rdx

literal:
    sub    r10, 1             ; read one byte from source
    jc     return_error       ;

    mov    al, [rsi]
    add    rsi, 1

    sub    r11, 1             ; write one byte to destination
    jc     return_error       ;

    mov    [rdi], al
    add    rdi, 1

    mov    rbx, 2

nexttag:
    getbitM
    jnc    literal

    getbitM
    jnc    codepair

    xor    rax, rax

    getbitM
    jnc    shortmatch

    getbitM
    adc    rax, rax
    getbitM
    adc    rax, rax
    getbitM
    adc    rax, rax
    getbitM
    adc    rax, rax
    jz     .thewrite

    mov    r8, [rsp + 32]     ; r8 = dstlen
    sub    r8, r11            ; r8 = num written
    cmp    rax, r8
    ja     return_error

    mov    r8, rdi
    sub    r8, rax
    mov    al, [r8]

  .thewrite:
    sub    r11, 1             ; write one byte to destination
    jc     return_error       ;

    mov    [rdi], al
    add    rdi, 1

    mov    rbx, 2

    jmp    nexttag

codepair:
    getgammaM rax

    sub    rax, rbx

    mov    rbx, 1

    jnz    normalcodepair

    getgammaM rcx

    domatchM rbp

    jmp    nexttag

normalcodepair:
    add    rax, -1

    cmp    rax, 0x00fffffe
    ja     return_error

    shl    rax, 8

    sub    r10, 1             ; read one byte from source
    jc     return_error       ;

    mov    al, [rsi]
    add    rsi, 1

    mov    rbp, rax

    getgammaM ecx

    cmp    rax, 32000
    sbb    rcx, -1

    cmp    rax, 1280
    sbb    rcx, -1

    cmp    rax, 128
    adc    rcx, 0

    cmp    rax, 128
    adc    rcx, 0

    domatchM rax
    jmp    nexttag

shortmatch:
    sub    r10, 1             ; read one byte from source
    jc     return_error       ;

    mov    al, [rsi]
    add    rsi, 1

    xor    rcx, rcx
    db     0c0h, 0e8h, 001h
    jz     donedepacking

    adc    rcx, 2

    mov    rbp, rax

    domatchM rax

    mov    rbx, 1

    jmp    nexttag

return_error:
    or     rax, -1            ; return APLIB_ERROR in rax

    jmp    exit

donedepacking:
    mov    rax, rdi
    sub    rax, [rsp + 40]

exit:
    mov    rbp, [rsp + 48]
    pop    rdi
    pop    rsi
    pop    rbx

    ret

; =============================================================
