unit aplibu;

(*
 * aPLib compression library  -  the smaller the better :)
 *
 * TMT Pascal interface to aPLib Delphi objects
 *
 * Copyright (c) 1998-2009 by Joergen Ibsen / Jibz
 * All Rights Reserved
 *
 * http://www.ibsensoftware.com/
 *
 * -> VPascal by Veit Kannegieser, 23.09.1998
 * -> TMT Pascal by Oleg Prokhorov
 *)

(* To enable aborting compression with Esc, define ESC_ABORT *)

interface

const
  aP_pack_continue=1;
  aP_pack_break   =0;

  aPLib_Error     =-1; (* indicates error compressing/decompressing *)

function aP_pack(var source;
                 var destination;
                 length:longint;
                 var workmem;
                 callback:pointer;
                 cbparam:pointer):longint;

function aP_workmem_size(inputsize:longint):longint;

function aP_max_packed_size(inputsize:longint):longint;

function aP_depack_asm(var source,destination):longint;

function aP_depack_asm_fast(var source,destination):longint;

function aP_depack_asm_safe(var source;
                            srclen:longint;
                            var destination;
                            dstlen:longint):longint;

function aP_crc32(var source;
                  length:longint):longint;

function aPsafe_pack(var source;
                     var destination;
                     length:longint;
                     var workmem;
                     callback:pointer;
                     cbparam:pointer):longint;

function aPsafe_check(var source):longint;

function aPsafe_get_orig_size(var source):longint;

function aPsafe_depack(var source;
                       srclen:longint;
                       var destination;
                       dstlen:longint):longint;

function cb0:longint;
function cb1:longint;

implementation

(*$IFDEF ESC_ABORT*)
uses crt;
(*$ENDIF ESC_ABORT*)

function _aP_pack:longint;external;
function _aP_workmem_size:longint;external;
function _aP_max_packed_size:longint;external;
function _aP_depack_asm:longint;external;
function _aP_depack_asm_fast:longint;external;
function _aP_depack_asm_safe:longint;external;
function _aP_crc32:longint;external;
function _aPsafe_pack:longint;external;
function _aPsafe_check:longint;external;
function _aPsafe_get_orig_size:longint;external;
function _aPsafe_depack:longint;external;

(*$l ..\..\lib\omf\aplib.obj    *)
(*$l ..\..\lib\omf\depack.obj   *)
(*$l ..\..\lib\omf\depackf.obj  *)
(*$l ..\..\lib\omf\depacks.obj  *)
(*$l ..\..\lib\omf\crc32.obj    *)
(*$l ..\..\lib\omf\spack.obj    *)
(*$l ..\..\lib\omf\scheck.obj   *)
(*$l ..\..\lib\omf\sgetsize.obj *)
(*$l ..\..\lib\omf\sdepack.obj  *)

function aP_pack(var source;
                 var destination;
                 length:longint;
                 var workmem;
                 callback:pointer;
                 cbparam:pointer):longint;assembler;
  asm
      push cbparam
       push callback
        push workmem
         push length
          push destination
           push source
            call _aP_pack
  end;

function aP_workmem_size(inputsize:longint):longint;assembler;
  asm
     push inputsize
      call _aP_workmem_size
  end;

function aP_max_packed_size(inputsize:longint):longint;assembler;
  asm
     push inputsize
      call _aP_max_packed_size
  end;

function aP_depack_asm(var source,destination):longint;assembler;
  asm
     push destination
      push source
       call _aP_depack_asm
  end;

function aP_depack_asm_fast(var source,destination):longint;assembler;
  asm
     push destination
      push source
       call _aP_depack_asm_fast
  end;

function aP_depack_asm_safe(var source;
                            srclen:longint;
                            var destination;
                            dstlen:longint):longint;assembler;
  asm
     push dstlen
      push destination
       push srclen
        push source
         call _aP_depack_asm_safe
  end;

function aP_crc32(var source;
                  length:longint):longint;assembler;
  asm
     push length
      push source
       call _aP_crc32
  end;

function aPsafe_pack(var source;
                     var destination;
                     length:longint;
                     var workmem;
                     callback:pointer;
                     cbparam:pointer):longint;assembler;
  asm
      push cbparam
       push callback
        push workmem
         push length
          push destination
           push source
            call _aPsafe_pack
  end;

function aPsafe_check(var source):longint;assembler;
  asm
     push source
      call _aPsafe_check
  end;

function aPsafe_get_orig_size(var source):longint;assembler;
  asm
     push source
      call _aPsafe_get_orig_size
  end;

function aPsafe_depack(var source;
                       srclen:longint;
                       var destination;
                       dstlen:longint):longint;assembler;
  asm
     push dstlen
      push destination
       push srclen
        push source
         call _aPsafe_depack
  end;


(* callback samples for _aP_pack *)

function cb0:longint;assembler;
  asm
    mov eax,aP_pack_continue
  end;

function cb1_(w1,w2:longint):longint;
  begin
    write(w1:8,' -> ',w2:8,^m);
    cb1_:=aP_pack_continue;
    (*$IFDEF ESC_ABORT*)
    if keypressed then
      if readkey=#27 then
        cb1_:=aP_pack_break;
    (*$ENDIF ESC_ABORT*)
  end;

function cb1:longint;assembler;
  asm
    pushad
      push dword [ebp+0Ch]
        push dword [ ebp+10h]
          call cb1_
      mov [esp+1ch],eax (* POPAD restores EAX *)
    popad
  end;

end.
