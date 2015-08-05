unit aplibu;

(*
 * aPLib compression library  -  the smaller the better :)
 *
 * VPascal interface to aplib.lib
 *
 * Copyright (c) 1998-2009 by Joergen Ibsen / Jibz
 * All Rights Reserved
 *
 * http://www.ibsensoftware.com/
 *
 * -> VPascal by Veit Kannegieser, 23.09.1998
 *)

interface

const
  aP_pack_continue      =1;
  aP_pack_break         =0;

  aPLib_Error           =-1; (* indicates error compressing/decompressing *)

(* compression status callback functions *)
{&Saves EBX,ECX,EDX,ESI,EDI}
{&Cdecl+}
type
  apack_status          =function(const w0,w1,w2:longint;
                                  const cbparam:pointer):longint;

function cb0(const w0,w1,w2:longint; const cbparam:pointer):longint;
function cb1(const w0,w1,w2:longint; const cbparam:pointer):longint;

{&Saves EBX,ESI,EDI}
{&Cdecl-}


(* library functions *)
{&Cdecl+}{&OrgName+} (* aplibu@_aP_pack -> _aP_pack *)

function _aP_pack(
                const source;
                const destination;
                const length            :longint;
                const workmem;
                const callback          :apack_status;
                const cbparam:pointer)                  :longint;

function _aP_workmem_size(
                const inputsize         :longint)       :longint;

function _aP_max_packed_size(
                const inputsize         :longint)       :longint;

function _aP_depack_asm(
                const source;
                const destination)                      :longint;

function _aP_depack_asm_fast(
                const source;
                const destination)                      :longint;

function _aP_depack_asm_safe(
                const source;
                const srclen            :longint;
                const destination;
                const dstlen            :longint)       :longint;

function _aP_crc32(
                const source;
                const length            :longint)       :longint;

function _aPsafe_pack(
                const source;
                const destination;
                const length            :longint;
                const workmem;
                const callback          :apack_status;
                const cbparam:pointer)                  :longint;

function _aPsafe_check(
                const source)                           :longint;

function _aPsafe_get_orig_size(
                const source)                           :longint;

function _aPsafe_depack(
                const source;
                const srclen            :longint;
                const destination;
                const dstlen            :longint)       :longint;

{&Cdecl-}{&OrgName-}


implementation

{$IFDEF ESC_ABORT}
uses
  VpSysLow;
{$ENDIF ESC_ABORT}

function _aP_pack                ;external;
function _aP_workmem_size        ;external;
function _aP_max_packed_size     ;external;
function _aP_depack_asm          ;external;
function _aP_depack_asm_fast     ;external;
function _aP_depack_asm_safe     ;external;
function _aP_crc32               ;external;
function _aPsafe_pack            ;external;
function _aPsafe_check           ;external;
function _aPsafe_get_orig_size   ;external;
function _aPsafe_depack          ;external;

{$L ..\..\lib\omf\aplib.lib}

(* callback samples for _aP_pack *)

function cb0(const w0,w1,w2:longint;
             const cbparam:pointer):longint;assembler;{&Frame-}{&Uses None}
  asm
    mov eax,aP_pack_continue
  end;

function cb1(const w0,w1,w2:longint;
             const cbparam:pointer):longint;
  begin
    Write(w1:8,' -> ',w2:8,^m);
    cb1:=aP_pack_continue;
    {$IfDef ESC_ABORT}
    if SysKeyPressed then
      if SysReadKey=#27 then
        cb1:=aP_pack_break;
    {$EndIf ESC_ABORT}
  end;

end.
