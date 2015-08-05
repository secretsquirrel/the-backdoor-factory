;;
;; aPLib compression library  -  the smaller the better :)
;;
;; NASM 16bit assembler depacker example
;;
;; Copyright (c) 1998-2009 by Joergen Ibsen / Jibz
;; All Rights Reserved
;;
;; http://www.ibsensoftware.com/
;;
;; -> 16bit by Metalbrain (metalbrain_coder@gmx.net)
;;

                org     256

                cld                     ;Clear direction flag for safety
                mov     ah,4ah          ;Modify memory block size (on start,
                                        ; the .COM program is given all free
                                        ; memory, but this could be less than
                                        ; the needed amount (162K). As a nice
                                        ; side effect, we are freeing unused
                                        ; memory, but who cares under DOS?
                mov     bh,41           ;Number of needed paragraphs
                                        ; (rounded up)
                int     33              ;Resize
                jnc     not_error008    ;Continue if no error
                call    final           ;Exit with message below
                db      "Not enough memory$"
not_error008    mov     si,129          ;Arguments from PSP start here
                pop     cx              ;CX=0 (useful later)
                mov     di,testitnow    ;This will be called quite a few times
                                        ; and later will be used to place
                                        ; variables
                mov     bx,rub+1
space1          mov     dx,si           ;Keep it start infile name in DX
                call    di              ;Parse...
                jz      space1          ;Search for non-space
space2          call    di              ;Keep parsing
                jnz     space2          ;Till a space appears
                mov     [si-1],dh       ;Make infile ASCIIZ
space3          push    si              ;Keep start outfile name in stack
                call    di              ;Still parsing
                jz      space3          ;Now search a non-space again
                mov     [unitoutfile],al;Set unit for temporal outfile
space4          lodsb                   ;Final parse
                cmp     al,":"          ;Is there's a unit in outfile name?
                jnz     nounit          ;No-> skip next
                sub     byte [bx],bh    ;Yes-> temporal outfile includes unit
nounit          cmp     al," "
                ja      space4          ;Space or below means end of filename
                mov     [si-1],dh       ;Make ASCIIZ this one too
                mov     ax,3d00h        ;Function to open infile
                int     33              ;Open infile
                jnc     not_error001    ;Continue if no error
                call    final           ;Exit with message below
                db "Can't open infile$"
not_error001    stosw                   ;Store infile handle at handlein

                pushad
                mov     dx,header
                mov     cl,8            ;Header first part
                mov     bh,3fh
                xchg    ax,bx
                int     33              ;Read 1st part header. No error check
                cmp     dword [header],'AP32'
                jz      not_error009    ;Test for bad infile #3: Header
                call    final
err004          db "Bad infile$"
not_error009    mov     cx,[headersize]
                sub     cx,byte 8
                mov     ah,3fh
                int     33              ;Read 2nd part header
                popad
                mov     dx,[bx]         ;Get outfile name position
                mov     ah,3ch
                int     33              ;Create temporal outfile: "ÿ"
                jnc     not_error007    ;Continue if no error
                call    final           ;Exit with message below
                db "Can't open temporal outfile$"
not_error007    stosw                   ;Store temporal outfile handle
                xchg    ax,dx           ;And place it in DX
                xor     ebx,ebx         ;EBX=0
                pop     si              ;Pop outfile name address from stack
                mov     bh,8            ;BX=inbuff
                mov     sp,bx           ;Set stack before inbuff
                mov     ax,es           ;Segment
                add     ax,bx           ; +32K in AX
                imul    eax,eax,byte 16 ;32 bit start of segment address+32K
                add     eax,ebx         ;EAX=freemem 32 bit address
                push    si              ;Push again outfile name address
                mov     dl,128          ;Reset bit counter in DL, and DX=0080h
                stosd                   ;Set EAX at freemem32
                stosd                   ;  and limit32
                add     [di-2],byte 2   ;Now limit32=freemem32+128K
                xchg    eax,edi         ;Set freemem32 at EDI
                mov     esi,edi         ;And ESI
                                        ;Starting point for DEPACK16
                push    edi             ;Store freemem32
literal         call    getesi          ;Copy a byte from [esi] to [edi]
putedi_nexttag  call    putedi2
                mov     dh,1            ;Set lastwasmatch marker in dh
                call    newtest         ;Here EAX=0
                jmp     short nexttag   ;Decode next tag bits...

normalcodepair  xchg    ax,cx           ;High part of distance in AX
                dec     ax              ;Subtract 1. Min value is 0
                shl     eax,8           ;EAX=00dddd00h
                call    getesi          ;Fill distance in AL
                call    getgamma        ;Take gamma encoded ECX
                cmp     eax,32000
                jae     domatch_with_2inc ;Above 31999: ECX+=2
                cmp     ah,5
                jae     domatch_with_inc ;1279<EAX<32000: ECX=+1
                cmp     ax,byte 127
                ja      domatch_new_lastpos ;EAX<128: ECX+=2
domatch_with_2inc
                inc     ecx
domatch_with_inc
                inc     ecx
domatch_new_lastpos
                xchg    eax,ebp         ;Store EAX in EBP (lastpos)
domatch_lastpos mov     eax,ebp         ;Take EAX from last EBP (lastpos)

                mov     dh,0            ;Clear lastwasmatch marker

domatch                                 ;Here EAX=match distance
                                        ;     ECX=match lenght

                push    esi             ;Store current read pointer
                mov     esi,edi
                sub     esi,eax         ;ESI=EDI-EAX > origin pointer
                cmp     esi,[freemem32] ;Test for bad infile #1: Limit crossed
                jc      near badinfile  ;Exit if error
repmovsb        call    dontread        ;getesi without checking limit
                call    putedi2         ;and with putedi completes the movsb
                mov     ah,128          ;Here EAX=32768 (in case of writing
                call    newtest         ;  data, update esi too)
                loop    repmovsb,ecx    ;Do it ecx times
                pop     esi             ;Recover read pointer
nexttag         call    getbit          ;Get a bit
                jnc     literal         ;0: literal, go for it
                xor     ecx,ecx         ;Clear ECX
                cbw                     ;and AX (AX was 0 or 32K)
                call    getbit          ;Get another bit
                jnc     codepair        ;10: codepair, go for it
                call    getbit          ;Get yet another one
                jnc     shortmatch      ;110: shortmatch
                mov     dh,1            ;Set lastwasmatch marker in dh
                inc     cx              ;CX=1
                mov     al,16           ;Set marker bit
getmorebits     call    getbit          ;Get a bit
                adc     al,al           ;Set it in AL
                jnc     getmorebits     ;Do it till marker is out (4 times)
                jnz     domatch         ;111xxxx: continue, AL has distance
                jmp     short putedi_nexttag  ;1110000: Put a zero byte

codepair        call    getgamma        ;Get gamma encoded first part of
                                        ; distance in CX. Min value is 2
                shr     dh,1            ;Fix distance taking lastwasmatch
                sbb     cx,byte 1       ; marker in consideration
                jnz     normalcodepair  ;If not zero, it's a normal codepair

                push    word domatch_lastpos ;Get gamma encoded lenght in ECX
                                        ; then jump to domatch_lastpos (use
                                        ; last distance)

getgamma        inc     cx              ;First bit is always 1
getgammaloop    call    getbit          ;Get next bit
                adc     ecx,ecx         ;Put it in ECX
                call    getbit          ;Get gamma bit
                jc      getgammaloop    ;If it's 1, continue growing ECX
                ret

shortmatch      call    getesi          ;Get a byte
                shr     ax,1            ;Distance = AL/2, Lenght in carry flag
                jz      donedepacking   ;If zero, end packing
                adc     cx,cx           ;Lenght = 1 or 0
                jmp     short domatch_with_2inc ; Decode with lenght 2 or 3

getbit          add     dl,dl           ;Get a tag bit
                jnz     stillbitsleft   ;If zero, that bit was the marker, so
                                        ; we must read a new tag byte from
                xchg    ax,dx           ;\ the infile buffer
                call    getesi          ; >Emulate mov dl,[esi], inc esi
                xchg    ax,dx           ;/
                stc                     ;Carry flag is end marker
                adc     dl,dl           ;Get first bit and set marker
stillbitsleft   ret                     ;Return with bit read in flag C

donedepacking   pop     esi             ;ESI=freemem32
                sub     edi,esi         ;And here finish DEPACK 16
                                        ;Now edi has the number of depacked
                                        ; bytes left to be written
                push    ds              ;Preserve data segment
                mov     ch,080h         ;Write using 32K chunks to enable
                                        ; the sign optimization
                mov     dx,freemem      ;Flush everything from here to end
more            cmp     edi,ecx
                ja      notlast         ;If EDI > 32K, write 32K bytes
                mov     cx,di           ;If EDI <= 32K, write EDI bytes
notlast         call    writefile       ;Write chunk
                mov     ax,ds
                add     ah,8
                mov     ds,ax           ;Advance 32K
                sub     edi,ecx         ;Update number of bytes to be written
                ja      more            ;Above zero, continue writing
                pop     ds              ;Recover data segment
                cmp     dword [uncompsize],0 ; Test for bad infile #4: Is
                jnz     near badinfile  ;      number of decoded bytes the
                                        ;      specified in header?
                push    bx              ;Keep handletmp
                mov     bx,[handlein]
                mov     ax,5700h
                int     33              ;Get timestamp from infile
                inc     ax
                pop     bx              ;Get handletmp
                int     33              ;Set timestamp to temporal outfile

                push    ds
                pop     es              ;Set es=ds
                pop     dx              ;Get nameout
                call    close_del       ;Close temporal outfile and try to
                                        ; delete the file named with our
                                        ; outfile name, in case it exists
                jnc     renameit        ;If that file existed and was deleted,
                                        ; go ahead and rename the temporal one
                cmp     al,5            ;If it didn't exist, rename it too
                jz      error002b       ;In case of Access denied, it must
                                        ; be that outfile was protected, so
                                        ; that's an error...
renameit        mov     ah,56h
                mov     di,dx
                mov     dx,[rub+1]
                int     33              ;Rename temporal outfile to outfile
                jc      error002        ;Can't open outfile
                push    word noerr      ;Final message
final           push    ss
                pop     ds              ;Set a good data segment
                pop     dx              ;Get message offset
final_dxok      mov     ah,9
                int     33              ;Show final message
                int     20h             ;Exit program
writefile       mov     bx,[ss:handletmp] ;Get temporal outfile handle
                mov     ah,40h
                int     33              ;Write to temporal outfile
                jc      error005        ;Can't write
                dec     ax
                js      error006        ;Disk is full
                ret
error002b       push    word err002b    ;Set appropiate message
                jmp     short rub       ;Exit erasing temporal file
error002        push    word err002     ;Set appropiate message
                jmp     short rub       ;Exit erasing temporal file
error005        push    word err005     ;Set appropiate message
                jmp     short rub       ;Exit erasing temporal file
error006        push    word err006     ;Set appropiate message
rub             mov     dx,tmpname      ;Temporal file name to be erased
                push    word final      ;Return point to exit with error
close_del       mov     ah,3eh
                int     33              ;Close temporal outfile
                mov     ah,41h
                int     33              ;Delete it
                ret

getesi          cmp     esi,[freemem32] ; If esi is at freemem32, we must
                jnz     dontread        ;load 32k of compressed data
                mov     bh,128          ;BL was 0, EBX=32K
                pushad                  ;Keep all registers (32bit because
                mov     ah,3fh          ; DOS function may modify EAX!!!)
                mov     cx,bx           ;Number of bytes
                mov     bx,[handlein]   ;Take infile handle
                mov     dx,inbuff       ;Place to read
                int     33              ;Read, AX=number of bytes read
                jc      error003        ;If error, go to exit
noerror003      dec     ax              ;Test for bad infile #2: 0 bytes read
                                        ; (a good infile will finish and won't
                                        ; ask for more data)
                jns     noerror004      ;No error, continue
badinfile       push    word err004     ;Set appropiate message
                jmp     short error004
error003        push    word err003     ;Set appropiate message
error004        mov     bx,[handletmp]  ;Get handle to close temporal file
                jmp     short rub       ;Exit erasing temporal file
noerror004      popad                   ;Restore all registers
                sub     esi,ebx         ;esi at beginning of buffer again
dontread        push    esi             ;----->Emulates mov al,[esi] in 16 bit
                pop     bx              ;    /   code (as mov al,[esi] gives
                pop     bx              ;   /    a nasty fault)
                ror     bx,4            ;  /
                mov     es,bx           ; /
                mov     al,[es:si]      ;/
                inc     esi             ;Update read pointer
                ret

newtest         cmp     edi,[limit32]   ;Check if we've run out of memory
                jc      endtest         ;NO: end test
                pushad                  ;Keep registers
                mov     dx,freemem
                mov     ecx,32768+65536 ;CX=32K will be written first
                                        ;ECX=96K data will be moved then
                call    writefile       ;Write 32K of data
                sub     edi,ecx         ;Set pointer to origin32=limit32-96K
                mov     esi,[freemem32] ;Output data will be moved 32K back
                xchg    edi,esi         ;Swap source and destination pointers

otherrepmovsb   call    getesi          ;  \
                call    putedi          ;   >Emulates rep movsb
                loop    otherrepmovsb,ecx ;/
                popad                   ;Restore registers
                sub     esi,eax         ;Update read pointer (sub 32K if
                                        ;   we are in the repmovsb loop)
                mov     ah,128          ;EAX=32K
                sub     edi,eax         ;Update write pointer
endtest         ret

putedi2         dec     dword [uncompsize] ;One less byte to be written
putedi          push    edi             ;----->Emulate mov [edi],al in 16 bit
                pop     bx              ;    /  code (as mov [edi],al gives
                pop     bx              ;   /   a nasty fault)
                ror     bx,4            ;  /
                mov     es,bx           ; /
                mov     [es:di],al      ;/
                inc     edi             ;Update write pointer
                xor     eax,eax         ;Clear EAX
noerror000      ret
testitnow       lodsb                   ;Parse one byte
                cmp     al,32           ;Is it space?
                jnc     noerror000      ;If valid char (above 31), return
                call    final           ;Exit with message below
                db "Usage: DEPPACK infile outfile",13,10,10
                db "infile must be an aPPACKed file",13,10
                db "wildcards are not allowed",13,10,10
                db "DEPPACK v1.1 Copyright (c) 1998-2005 by Metalbrain",13,10
                db "aPLib v0.36  Copyright (c) 1998-2005 by Jibz, All Rights Reserved$"
err005          db "Can't write temporal outfile$"
err002b         db "Outfile is protected, so...",13,10
err002          db "Can't open outfile$"
err003          db "Can't read from infile$"
err006          db "Disk full$"
noerr           db "Deppackin"
                db "g ok$"
unitoutfile     db "c:"
tmpname         db "ÿ",0
handlein        EQU     testitnow
handletmp       EQU     testitnow+2
freemem32       EQU     testitnow+4
limit32         EQU     testitnow+8
header          EQU     testitnow+12
headersize      EQU     testitnow+16
packedsize      EQU     testitnow+12
packedcrc       EQU     testitnow+16
uncompsize      EQU     testitnow+20
uncompcrc       EQU     testitnow+24

                                        ;Stack is between program and 2048
inbuff          EQU     2048            ;Place for 32K infile reading buffer
freemem         EQU     inbuff+32768
