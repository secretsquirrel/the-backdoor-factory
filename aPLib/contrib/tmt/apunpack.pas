(*
 * aPLib compression library  -  the smaller the better :)
 *
 * TMT Pascal depacking example
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
  insize,outsize     :longint;
  outmemsize         :longint;

begin
  (* check number of parameters *)
  if paramcount<1 then
    begin
      writeln;
      writeln('Syntax:   APUNPACK <input file> [output file]');
      writeln;
      halt(1);
    end;

  (* open input file and read header *)
  assign(infile,paramstr(1));
  reset(infile,1);
  insize:=filesize(infile);

  (* get mem and read input file *)
  getmem(inbuffer,insize);
  blockread(infile,inbuffer^,insize);
  close(infile);

  (* check header and get original size *)
  outmemsize := aPsafe_get_orig_size(inbuffer^);
  if outmemsize=aPLib_Error then
    begin
      writeln('File is not packed with aPPack.');
      halt(0);
    end;

  (* get mem for unpacked data *)
  getmem(outbuffer,outmemsize);

  (* unpack data *)
  outsize:=aPsafe_depack(inbuffer^,insize,outbuffer^,outmemsize);

  if outsize=aPLib_Error then
    begin
      WriteLn;
      WriteLn('ERR: compressed data error');
      WriteLn;
      Halt(1);
    end;

  if outsize<>outmemsize then halt(1);

  (* write unpacked data *)
  if paramcount<2 then
    begin
      assign(outfile,'out.dat');
      writeln;
      writeln('No output file specified, writing to ''out.dat''');
    end else assign(outfile,paramstr(2));
  rewrite(outfile,1);
  blockwrite(outfile,outbuffer^,outsize);
  close(outfile);

  (* free memory *)
  freemem(inbuffer,insize);
  freemem(outbuffer,outmemsize);

end.
