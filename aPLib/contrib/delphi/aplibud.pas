(*
 * aPLib compression library  -  the smaller the better :)
 *
 * Delphi interface to aPLib dll
 *
 * Copyright (c) 1998-2009 by Joergen Ibsen / Jibz
 * All Rights Reserved
 *
 * http://www.ibsensoftware.com/
 *
 * -> Delphi by Solodovnikov Alexey 21.03.1999 (alenka@mail.line.ru)
 *)

unit aPLibud;

interface

uses
  Windows;

const
  aP_pack_break    : DWORD = 0;
  aP_pack_continue : DWORD = 1;

  aPLib_Error      : DWORD = DWORD(-1); (* indicates error compressing/decompressing *)

type

  TaPack_Status = function(w0, w1, w2 : DWORD;
                           cbparam : Pointer) : DWORD;stdcall;

  function _aP_pack(var Source;
                    var Destination;
                    Length : DWORD;
                    var WorkMem;
                    Callback : TaPack_Status;
                    cbparam : Pointer) : DWORD;stdcall;
  function _aP_workmem_size(InputSize : DWORD) : DWORD;stdcall;
  function _aP_max_packed_size(InputSize : DWORD) : DWORD;stdcall;
  function _aP_depack_asm(var Source, Destination) : DWORD;stdcall;
  function _aP_depack_asm_fast(var Source, Destination) : DWORD;stdcall;
  function _aP_depack_asm_safe(var Source;
                               SrcLen : DWORD;
                               var Destination;
                               DstLen :DWORD) : DWORD;stdcall;
  function _aP_crc32(var Source; Length : DWORD) : DWORD;stdcall;
  function _aPsafe_pack(var Source;
                        var Destination;
                        Length : DWORD;
                        var WorkMem;
                        Callback : TaPack_Status;
                        cbparam : Pointer) : DWORD;stdcall;
  function _aPsafe_check(var Source) : DWORD;stdcall;
  function _aPsafe_get_orig_size(var Source) : DWORD;stdcall;
  function _aPsafe_depack(var Source;
                          SrcLen : DWORD;
                          var Destination;
                          DstLen :DWORD) : DWORD;stdcall;

implementation

const
  DLL = 'aplib.dll';

  function _aP_pack(var Source;
                    var Destination;
                    Length : DWORD;
                    var WorkMem;
                    CallBack : TaPack_Status;
                    cbparam : Pointer) : DWORD;stdcall;external DLL;

  function _aP_workmem_size(InputSize : DWORD) : DWORD;stdcall;external DLL;

  function _aP_max_packed_size(InputSize : DWORD) : DWORD;stdcall;external DLL;

  function _aP_depack_asm(var Source, Destination) : DWORD;stdcall;external DLL;

  function _aP_depack_asm_fast(var Source, Destination) : DWORD;stdcall;external DLL;

  function _aP_depack_asm_safe(var Source;
                               SrcLen : DWORD;
                               var Destination;
                               DstLen :DWORD) : DWORD;external DLL;

  function _aP_crc32(var Source; Length : DWORD) : DWORD;stdcall;external DLL;

  function _aPsafe_pack(var Source;
                        var Destination;
                        Length : DWORD;
                        var WorkMem;
                        CallBack : TaPack_Status;
                        cbparam : Pointer) : DWORD;stdcall;external DLL;

  function _aPsafe_check(var Source) : DWORD;stdcall;external DLL;

  function _aPsafe_get_orig_size(var Source) : DWORD;stdcall;external DLL;

  function _aPsafe_depack(var Source;
                          SrcLen : DWORD;
                          var Destination;
                          DstLen :DWORD) : DWORD;external DLL;

end.
