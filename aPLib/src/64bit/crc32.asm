;;
;; aPLib compression library  -  the smaller the better :)
;;
;; fasm 64-bit assembler crc32
;;
;; Copyright (c) 1998-2014 Joergen Ibsen
;; All Rights Reserved
;;
;; http://www.ibsensoftware.com/
;;

; CRC32 calculation taken from the zlib source, which is
; Copyright (C) 1995-1998 Jean-loup Gailly and Mark Adler

format MS64 COFF

public aP_crc32

; =============================================================

macro docrcM
{
    mov    r9, 0x000000ff
    and    r9, rax
    shr    eax, 8
    xor    eax, [r8+r9*4]
}

macro docrcbyteM
{
    xor    al, [rcx]
    add    rcx, 1
    docrcM
}

macro docrcdwordM
{
    xor    eax, [rcx]
    add    rcx, 4
    docrcM
    docrcM
    docrcM
    docrcM
}

; =============================================================

section '.text' code readable executable

aP_crc32:
    ; aP_crc32(const void *source, unsigned int length)

    lea    r8, [aP_crctab]    ; r8 -> crctab

    sub    rax, rax

    test   rcx, rcx
    jz     .c_exit

    dec    rax

    test   rdx, rdx
    jz     .c_done

  .c_align_loop:
    test   rcx, 3
    jz     .c_aligned_now
    docrcbyteM
    add    rdx, -1
    jnz    .c_align_loop

  .c_aligned_now:
    mov    r10, rdx
    and    r10, 7
    shr    rdx, 3
    jz     .c_LT_eight

  .c_next_eight:
    docrcdwordM
    docrcdwordM
    add    rdx, -1
    jnz    .c_next_eight

  .c_LT_eight:
    mov    rdx, r10
    test   rdx, rdx
    jz     .c_done

  .c_last_loop:
    docrcbyteM
    add    rdx, -1
    jnz    .c_last_loop

  .c_done:
    not    eax

  .c_exit:
    ret

; =============================================================

section '.rdata' data readable

aP_crctab  dd 000000000h, 077073096h, 0ee0e612ch, 0990951bah, 0076dc419h
           dd 0706af48fh, 0e963a535h, 09e6495a3h, 00edb8832h, 079dcb8a4h
           dd 0e0d5e91eh, 097d2d988h, 009b64c2bh, 07eb17cbdh, 0e7b82d07h
           dd 090bf1d91h, 01db71064h, 06ab020f2h, 0f3b97148h, 084be41deh
           dd 01adad47dh, 06ddde4ebh, 0f4d4b551h, 083d385c7h, 0136c9856h
           dd 0646ba8c0h, 0fd62f97ah, 08a65c9ech, 014015c4fh, 063066cd9h
           dd 0fa0f3d63h, 08d080df5h, 03b6e20c8h, 04c69105eh, 0d56041e4h
           dd 0a2677172h, 03c03e4d1h, 04b04d447h, 0d20d85fdh, 0a50ab56bh
           dd 035b5a8fah, 042b2986ch, 0dbbbc9d6h, 0acbcf940h, 032d86ce3h
           dd 045df5c75h, 0dcd60dcfh, 0abd13d59h, 026d930ach, 051de003ah
           dd 0c8d75180h, 0bfd06116h, 021b4f4b5h, 056b3c423h, 0cfba9599h
           dd 0b8bda50fh, 02802b89eh, 05f058808h, 0c60cd9b2h, 0b10be924h
           dd 02f6f7c87h, 058684c11h, 0c1611dabh, 0b6662d3dh, 076dc4190h
           dd 001db7106h, 098d220bch, 0efd5102ah, 071b18589h, 006b6b51fh
           dd 09fbfe4a5h, 0e8b8d433h, 07807c9a2h, 00f00f934h, 09609a88eh
           dd 0e10e9818h, 07f6a0dbbh, 0086d3d2dh, 091646c97h, 0e6635c01h
           dd 06b6b51f4h, 01c6c6162h, 0856530d8h, 0f262004eh, 06c0695edh
           dd 01b01a57bh, 08208f4c1h, 0f50fc457h, 065b0d9c6h, 012b7e950h
           dd 08bbeb8eah, 0fcb9887ch, 062dd1ddfh, 015da2d49h, 08cd37cf3h
           dd 0fbd44c65h, 04db26158h, 03ab551ceh, 0a3bc0074h, 0d4bb30e2h
           dd 04adfa541h, 03dd895d7h, 0a4d1c46dh, 0d3d6f4fbh, 04369e96ah
           dd 0346ed9fch, 0ad678846h, 0da60b8d0h, 044042d73h, 033031de5h
           dd 0aa0a4c5fh, 0dd0d7cc9h, 05005713ch, 0270241aah, 0be0b1010h
           dd 0c90c2086h, 05768b525h, 0206f85b3h, 0b966d409h, 0ce61e49fh
           dd 05edef90eh, 029d9c998h, 0b0d09822h, 0c7d7a8b4h, 059b33d17h
           dd 02eb40d81h, 0b7bd5c3bh, 0c0ba6cadh, 0edb88320h, 09abfb3b6h
           dd 003b6e20ch, 074b1d29ah, 0ead54739h, 09dd277afh, 004db2615h
           dd 073dc1683h, 0e3630b12h, 094643b84h, 00d6d6a3eh, 07a6a5aa8h
           dd 0e40ecf0bh, 09309ff9dh, 00a00ae27h, 07d079eb1h, 0f00f9344h
           dd 08708a3d2h, 01e01f268h, 06906c2feh, 0f762575dh, 0806567cbh
           dd 0196c3671h, 06e6b06e7h, 0fed41b76h, 089d32be0h, 010da7a5ah
           dd 067dd4acch, 0f9b9df6fh, 08ebeeff9h, 017b7be43h, 060b08ed5h
           dd 0d6d6a3e8h, 0a1d1937eh, 038d8c2c4h, 04fdff252h, 0d1bb67f1h
           dd 0a6bc5767h, 03fb506ddh, 048b2364bh, 0d80d2bdah, 0af0a1b4ch
           dd 036034af6h, 041047a60h, 0df60efc3h, 0a867df55h, 0316e8eefh
           dd 04669be79h, 0cb61b38ch, 0bc66831ah, 0256fd2a0h, 05268e236h
           dd 0cc0c7795h, 0bb0b4703h, 0220216b9h, 05505262fh, 0c5ba3bbeh
           dd 0b2bd0b28h, 02bb45a92h, 05cb36a04h, 0c2d7ffa7h, 0b5d0cf31h
           dd 02cd99e8bh, 05bdeae1dh, 09b64c2b0h, 0ec63f226h, 0756aa39ch
           dd 0026d930ah, 09c0906a9h, 0eb0e363fh, 072076785h, 005005713h
           dd 095bf4a82h, 0e2b87a14h, 07bb12baeh, 00cb61b38h, 092d28e9bh
           dd 0e5d5be0dh, 07cdcefb7h, 00bdbdf21h, 086d3d2d4h, 0f1d4e242h
           dd 068ddb3f8h, 01fda836eh, 081be16cdh, 0f6b9265bh, 06fb077e1h
           dd 018b74777h, 088085ae6h, 0ff0f6a70h, 066063bcah, 011010b5ch
           dd 08f659effh, 0f862ae69h, 0616bffd3h, 0166ccf45h, 0a00ae278h
           dd 0d70dd2eeh, 04e048354h, 03903b3c2h, 0a7672661h, 0d06016f7h
           dd 04969474dh, 03e6e77dbh, 0aed16a4ah, 0d9d65adch, 040df0b66h
           dd 037d83bf0h, 0a9bcae53h, 0debb9ec5h, 047b2cf7fh, 030b5ffe9h
           dd 0bdbdf21ch, 0cabac28ah, 053b39330h, 024b4a3a6h, 0bad03605h
           dd 0cdd70693h, 054de5729h, 023d967bfh, 0b3667a2eh, 0c4614ab8h
           dd 05d681b02h, 02a6f2b94h, 0b40bbe37h, 0c30c8ea1h, 05a05df1bh
           dd 02d02ef8dh

; =============================================================
