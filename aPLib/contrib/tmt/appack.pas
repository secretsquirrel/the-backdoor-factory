(*
 * aPLib compression library  -  the smaller the better :)
 *
 * TMT Pascal packing example
 *
 * Copyright (c) 1998-2009 by Joergen Ibsen / Jibz
 * All Rights Reserved
 *
 * http://www.ibsensoftware.com/
 *
 * -> VPascal by Veit Kannegieser, 23.09.1998
 * -> TMT Pascal by Oleg Prokhorov
 *)

uses aplibu;

var
  infile,outfile     :file;
  inbuffer,outbuffer :pointer;
  workmem            :pointer;
  insize,outsize     :longint;

begin
  (* check number of parameters *)
  if paramcount<1 then
    begin
      writeln;
      writeln('Syntax:   APPACK <input file> [output file]');
      writeln;
      halt(1);
    end;

  (* open input file and read data *)
  assign(infile,paramstr(1));
  reset(infile,1);
  insize:=filesize(infile);
  getmem(inbuffer,insize);
  blockread(infile,inbuffer^,insize);
  close(infile);

  (* get output mem and workmem *)
  getmem(outbuffer,aP_max_packed_size(insize));
  getmem(workmem,aP_workmem_size(insize));

  (* pack data *)
  outsize:=aPsafe_pack(inbuffer^,outbuffer^,insize,workmem^,@cb1,nil);
  writeln;

  if outsize=aPLib_Error then
    begin
      WriteLn;
      WriteLn('ERR: an error occured while compressing');
      WriteLn;
      Halt(1);
    end;

  (* write packed data *)
  if paramcount<2 then
    begin
      assign(outfile,'out.apk');
      writeln;
      writeln('No output file specified, writing to ''out.apk''');
    end else assign(outfile,paramstr(2));
  rewrite(outfile,1);
  blockwrite(outfile,outbuffer^,outsize);
  close(outfile);

  (* free mem *)
  freemem(inbuffer,insize);
  freemem(outbuffer,aP_max_packed_size(insize));
  freemem(workmem,aP_workmem_size(insize));

end.
