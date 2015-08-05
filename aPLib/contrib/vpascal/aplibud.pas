unit aplibud;

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
{$IfDef Win32} {&StdCall+} {$Else} {&Cdecl+} {$EndIf}
type
  apack_status          =function(const w0,w1,w2:longint;
                                  const cbparam:pointer):longint;

function cb0(const w0,w1,w2:longint; const cbparam:pointer):longint;
function cb1(const w0,w1,w2:longint; const cbparam:pointer):longint;

{&Saves EBX,ESI,EDI}
{&StdCall-}


(* DLL interface functions *)
{&OrgName+} (* aplibu@_aP_pack -> _aP_pack *)
{$IfDef Win32} {&StdCall+} {$Else} {&Cdecl+} {$EndIf}


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

{&Cdecl-}{&StdCall-}{&OrgName-}


implementation

{$IfDef ESC_ABORT}
uses
  VpSysLow;
{$EndIf ESC_ABORT}

const
  aplib_dll_name={$IfDef OS2  }'aplib.dll'{$EndIf}
                 {$IfDef Win32}'aplib.dll'{$EndIf}
                 {$IfDef Linux}'aplib.so' {$EndIf};


function _aP_pack                ;external aplib_dll_name {$IfDef Linux}name 'aP_pack'               {$EndIf};
function _aP_workmem_size        ;external aplib_dll_name {$IfDef Linux}name 'aP_workmem_size'       {$EndIf};
function _aP_max_packed_size     ;external aplib_dll_name {$IfDef Linux}name 'aP_max_packed_size'    {$EndIf};
function _aP_depack_asm          ;external aplib_dll_name {$IfDef Linux}name 'aP_depack_asm'         {$EndIf};
function _aP_depack_asm_fast     ;external aplib_dll_name {$IfDef Linux}name 'aP_depack_asm_fast'    {$EndIf};
function _aP_depack_asm_safe     ;external aplib_dll_name {$IfDef Linux}name 'aP_depack_asm_safe'    {$EndIf};
function _aP_crc32               ;external aplib_dll_name {$IfDef Linux}name 'aP_crc32'              {$EndIf};
function _aPsafe_pack            ;external aplib_dll_name {$IfDef Linux}name 'aPsafe_pack'           {$EndIf};
function _aPsafe_check           ;external aplib_dll_name {$IfDef Linux}name 'aPsafe_check'          {$EndIf};
function _aPsafe_get_orig_size   ;external aplib_dll_name {$IfDef Linux}name 'aPsafe_get_orig_size'  {$EndIf};
function _aPsafe_depack          ;external aplib_dll_name {$IfDef Linux}name 'aPsafe_depack'         {$EndIf};


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
