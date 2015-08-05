;;
;; aPLib compression library  -  the smaller the better :)
;;
;; fasm 64-bit fast assembler depacker
;;
;; Copyright (c) 1998-2014 Joergen Ibsen
;; All Rights Reserved
;;
;; http://www.ibsensoftware.com/
;;

format MS64 COFF

public aP_depack_asm_fast

; =============================================================

macro getbitM
{
    local .stillbitsleft

    add    dl, dl
    jnz    .stillbitsleft
    mov    dl, [rsi]
    inc    rsi
    adc    dl, dl
  .stillbitsleft:
}

macro domatchM reg
{
    local .more

    mov    r10, rdi
    sub    r10, reg

  .more:
    mov    al, [r10]
    add    r10, 1
    mov    [rdi], al
    add    rdi, 1
    sub    rcx, 1
    jnz    .more
}

macro getgammaM reg
{
    local .getmorebits

    mov    reg, 1
  .getmorebits:
    getbitM
    adc    reg, reg
    getbitM
    jc     .getmorebits
}

; =============================================================

section '.text' code readable executable

aP_depack_asm_fast:
    ; aP_depack_asm_fast(const void *source, void *destination)

    mov    [rsp + 8], rsi
    mov    [rsp + 16], rdx
    push   rdi

    mov    rsi, rcx
    mov    rdi, rdx

    cld
    mov    dl, 80h

literal:
    mov    al, [rsi]
    add    rsi, 1
    mov    [rdi], al
    add    rdi, 1

    mov    r9, 2

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
    jz     thewrite

    mov    r9, rdi
    sub    r9, rax
    mov    al, [r9]

thewrite:
    mov    [rdi], al
    add    rdi, 1

    mov    r9, 2
    jmp    short nexttag

codepair:
    getgammaM rax
    sub    rax, r9
    mov    r9, 1
    jnz    normalcodepair

    getgammaM rcx
    domatchM r8

    jmp    nexttag

normalcodepair:
    add    rax, -1

    shl    rax, 8
    mov    al, [rsi]
    add    rsi, 1

    mov    r8, rax

    getgammaM rcx

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
    mov    al, [rsi]
    add    rsi, 1

    xor    rcx, rcx
    db     0c0h, 0e8h, 001h
    jz     donedepacking

    adc    rcx, 2

    mov    r8, rax

    domatchM rax

    mov    r9, 1
    jmp    nexttag

donedepacking:
    mov    rax, rdi
    sub    rax, [rsp + 24]

    mov    rsi, [rsp + 16]
    pop    rdi

    ret

; =============================================================
