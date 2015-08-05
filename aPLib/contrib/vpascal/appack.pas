{$M 32000}
{$I+}
program test__aplib_pack;

(*
 * aPLib compression library  -  the smaller the better :)
 *
 * VPascal packing example
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
  workmem               :pointer;
  insize   ,outsize     :longint;

begin
  (* check number of parameters *)
  if ParamCount<1 then
    begin
      WriteLn;
      WriteLn('Syntax:   APPACK <input file> [output file]');
      WriteLn;
      Halt(1);
    end;

  (* open input file and read data *)
  Assign(infile,ParamStr(1));
  FileMode:=$40; (* open_access_ReadOnly OR open_share_DenyNone *)
  Reset(infile,1);
  insize:=FileSize(infile);
  GetMem(inbuffer,insize);
  BlockRead(infile,inbuffer^,insize);
  Close(infile);

  (* get output mem and workmem *)
  GetMem(outbuffer,_aP_max_packed_size(insize));
  GetMem(workmem,_aP_workmem_size(insize));

  (* pack data *)
  outsize:=_aPsafe_pack(inbuffer^,outbuffer^,insize,workmem^,cb1,nil);
  Writeln;

  if outsize=aPLib_Error then
    begin
      WriteLn;
      WriteLn('ERR: an error occured while compressing');
      WriteLn;
      Halt(1);
    end;

  (* write packed data *)
  if ParamCount<2 then
    begin
      Assign(outfile,'out.apk');
      WriteLn;
      WriteLn('No output file specified, writing to ''out.apk''');
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
  Dispose(workmem);

end.

