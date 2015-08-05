;;
;; aPLib compression library  -  the smaller the better :)
;;
;; fasm fast assembler depacker
;;
;; Copyright (c) 1998-2014 Joergen Ibsen
;; All Rights Reserved
;;
;; http://www.ibsensoftware.com/
;;

format MS COFF

public aP_depack_asm_fast as '_aP_depack_asm_fast'

; =============================================================

macro getbitM
{
    local .stillbitsleft
    add    dl, dl
    jnz    .stillbitsleft
    mov    dl, [esi]
    inc    esi
    adc    dl, dl
  .stillbitsleft:
}

macro domatchM reg
{
    push   esi
    mov    esi, edi
    sub    esi, reg
    rep    movsb
    pop    esi
}

macro getgammaM reg
{
    local .getmore

    mov    reg, 1
  .getmore:
    getbitM
    adc    reg, reg
    getbitM
    jc     .getmore
}

; =============================================================

section '.text' code readable executable

aP_depack_asm_fast:
    ; aP_depack_asm_fast(const void *source, void *destination)

    _ret$  equ 7*4
    _src$  equ 8*4 + 4
    _dst$  equ 8*4 + 8

    pushad

    mov    esi, [esp + _src$] ; C calling convention
    mov    edi, [esp + _dst$]

    cld
    mov    dl, 80h

literal:
    mov    al, [esi]
    add    esi, 1
    mov    [edi], al
    add    edi, 1

    mov    ebx, 2

nexttag:
    getbitM
    jnc    literal

    getbitM
    jnc    codepair

    xor    eax, eax
    getbitM
    jnc    shortmatch

    getbitM
    adc    eax, eax
    getbitM
    adc    eax, eax
    getbitM
    adc    eax, eax
    getbitM
    adc    eax, eax
    jz     .thewrite

    mov    ebx, edi
    sub    ebx, eax
    mov    al, [ebx]

  .thewrite:
    mov    [edi], al
    inc    edi

    mov    ebx, 2
    jmp    nexttag

codepair:
    getgammaM eax
    sub    eax, ebx
    mov    ebx, 1
    jnz    normalcodepair

    getgammaM ecx
    domatchM ebp

    jmp    nexttag

normalcodepair:
    dec    eax

    shl    eax, 8
    mov    al, [esi]
    inc    esi

    mov    ebp, eax

    getgammaM ecx

    cmp    eax, 32000
    sbb    ecx, -1

    cmp    eax, 1280
    sbb    ecx, -1

    cmp    eax, 128
    adc    ecx, 0

    cmp    eax, 128
    adc    ecx, 0

    domatchM eax
    jmp    nexttag

shortmatch:
    mov    al, [esi]
    inc    esi

    xor    ecx, ecx
    db     0c0h, 0e8h, 001h
    jz     donedepacking

    adc    ecx, 2

    mov    ebp, eax

    domatchM eax

    mov    ebx, 1
    jmp    nexttag

donedepacking:
    sub    edi, [esp + _dst$]
    mov    [esp + _ret$], edi ; return unpacked length in eax

    popad

    ret

; =============================================================
