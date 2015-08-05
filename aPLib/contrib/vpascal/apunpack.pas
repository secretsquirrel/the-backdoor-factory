program test__aplib_depack;

(*
 * aPLib compression library  -  the smaller the better :)
 *
 * VPascal depacking example
 *
 * Copyright (c) 1998-2009 by Joergen Ibsen / Jibz
 * All Rights Reserved
 *
 * http://www.ibsensoftware.com/
 *
 * -> VPascal by Veit Kannegieser, 23.09.1998
 *)

{$IfDef DYNAMIC_VERSION}
uses aplibud;
{$Else}
uses aplibu;
{$EndIf}

var
  infile   ,outfile     :file;
  inbuffer ,outbuffer   :pointer;
  insize   ,outsize     :longint;
  outmemsize            :longint;

begin
  (* check number of parameters *)
  if ParamCount<1 then
    begin
      WriteLn;
      WriteLn('Syntax:   APUNPACK <input file> [output file]');
      WriteLn;
      Halt(1);
    end;

  (* open input file and read header *)
  Assign(infile,ParamStr(1));
  FileMode:=$40; (* open_access_ReadOnly OR open_share_DenyNone *)
  Reset(infile,1);
  insize:=FileSize(infile);

  (* get mem and read input file *)
  GetMem(inbuffer,insize);
  BlockRead(infile,inbuffer^,insize);
  Close(infile);

  (* get original size from header and get mem *)
  outmemsize := _aPsafe_get_orig_size(inbuffer^);
  GetMem(outbuffer,outmemsize);

  (* unpack data *)
  outsize:=_aPsafe_depack(inbuffer^,insize,outbuffer^,outmemsize);

  if outsize=aPLib_Error then
    begin
      WriteLn;
      WriteLn('ERR: compressed data error');
      WriteLn;
      Halt(1);
    end;

  if outsize<>outmemsize then Halt(1);

  (* write unpacked data *)
  if ParamCount<2 then
    begin
      Assign(outfile,'out.dat');
      WriteLn;
      WriteLn('No output file specified, writing to ''out.dat''');
    end
  else
    Assign(outfile,ParamStr(2));
  FileModeReadWrite:=$42; (* open_access_ReadWrite OR open_share_DenyNone *)
  Rewrite(outfile,1);
  BlockWrite(outfile,outbuffer^,outsize);
  Close(outfile);

  (* free mem *)
  Dispose(inbuffer);
  Dispose(outbuffer);

end.

