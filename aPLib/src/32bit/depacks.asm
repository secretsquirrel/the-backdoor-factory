;;
;; aPLib compression library  -  the smaller the better :)
;;
;; fasm safe assembler depacker
;;
;; Copyright (c) 1998-2014 Joergen Ibsen
;; All Rights Reserved
;;
;; http://www.ibsensoftware.com/
;;

format MS COFF

public aP_depack_asm_safe as '_aP_depack_asm_safe'

; =============================================================

macro getbitM
{
    local .stillbitsleft
    add    dl, dl
    jnz    .stillbitsleft

    sub    dword [esp + 4], 1 ; read one byte from source
    jc     return_error       ;

    mov    dl, [esi]
    inc    esi

    add    dl, dl
    inc    dl
  .stillbitsleft:
}

macro domatchM reg
{
    push   ecx
    mov    ecx, [esp + 12 + _dlen$] ; ecx = dstlen
    sub    ecx, [esp + 4]           ; ecx = num written
    cmp    reg, ecx
    pop    ecx
    ja     return_error

    sub    [esp], ecx         ; write ecx bytes to destination
    jc     return_error       ;

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

    _ret$  equ 7*4
    _src$  equ 8*4 + 4
    _slen$ equ 8*4 + 8
    _dst$  equ 8*4 + 12
    _dlen$ equ 8*4 + 16

    pushad

    mov    esi, [esp + _src$] ; C calling convention
    mov    eax, [esp + _slen$]
    mov    edi, [esp + _dst$]
    mov    ecx, [esp + _dlen$]

    push   eax
    push   ecx

    test   esi, esi
    jz     return_error

    test   edi, edi
    jz     return_error

    or     ebp, -1

    cld
    xor    edx, edx

literal:
    sub    dword [esp + 4], 1 ; read one byte from source
    jc     return_error       ;

    mov    al, [esi]
    add    esi, 1

    sub    dword [esp], 1     ; write one byte to destination
    jc     return_error       ;

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

    mov    ebx, [esp + 8 + _dlen$] ; ebx = dstlen
    sub    ebx, [esp]              ; ebx = num written
    cmp    eax, ebx
    ja     return_error

    mov    ebx, edi
    sub    ebx, eax
    mov    al, [ebx]

  .thewrite:
    sub    dword [esp], 1     ; write one byte to destination
    jc     return_error       ;

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

    test   eax, 0xff000000
    jnz    return_error

    shl    eax, 8

    sub    dword [esp + 4], 1 ; read one byte from source
    jc     return_error       ;

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
    sub    dword [esp + 4], 1 ; read one byte from source
    jc     return_error       ;

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

return_error:
    add    esp, 8

    popad

    or     eax, -1            ; return APLIB_ERROR in eax

    ret

donedepacking:
    add    esp, 8

    sub    edi, [esp + _dst$]
    mov    [esp + _ret$], edi ; return unpacked length in eax

    popad

    ret

; =============================================================
