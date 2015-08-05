------------------------------------------------------------------------------
--  File:            apackdemo.adb
--  Description:     aPLib binding demo (Q&D!)
--  Date/version:    24-Feb-2001 ; ... ; 9.III.1999
--  Author:          Gautier de Montmollin - gdemont@hotmail.com
------------------------------------------------------------------------------

with APLib;
with Ada.Calendar;                      use Ada.Calendar;
with Ada.Command_Line;                  use Ada.Command_Line;
with Ada.Text_IO;                       use Ada.Text_IO;
with Ada.Integer_Text_IO;               use Ada.Integer_Text_IO;
with Ada.Float_Text_IO;                 use Ada.Float_Text_IO;
with Ada.Direct_IO;

procedure APacDemo is
  type byte is mod 2 ** 8; for byte'size use 8; -- could be any basic data

  type t_data_array is array(integer range <>) of byte;
  type p_data_array is access t_data_array;
  
  -- NB: File management is simpler with Ada95 Stream_IO - it's to test...
  
  package DBIO is new Ada.Direct_IO(byte); use DBIO;
  subtype file_of_byte is DBIO.File_type;

  procedure Read_file(n: String; d: out p_data_array) is
  f : file_of_byte; b: byte;
  begin
    d:= null;
    Open(f, in_file, n);
    d:= New t_data_array(1..integer(size(f)));
    for i in d'range loop Read(f,b); d(i):= b; end loop;
    Close(f);
  exception
    when DBIO.Name_Error => Put_Line("File " & n & " not found !");
  end;
  
  procedure Write_file(n: String; d: t_data_array) is
  f : file_of_byte;
  begin
    Create(f, out_file, n);
    for i in d'range loop Write(f,d(i)); end loop;
    Close(f);
  end;

  procedure Test_pack_unpack(name: string; id: natural) is
    ext1: constant string:= integer'image(id+1000);
    ext:  constant string:= ext1(ext1'last-2..ext1'last); -- 000 001 002 etc.
    name_p:  constant string:= "packed." & ext;
    name_pu: constant string:= "pack_unp." & ext;
  
    frog, frog2, frog3: p_data_array;
    pl, ul, plmax: integer; -- packed / unpacked sizes in _bytes_

    pack_occur: natural:= 0;
    
    T0, T1, T2, T3: Time;

    procedure Packometer(u,p: integer; continue: out boolean) is
      li: constant:= 50;
      pli: constant integer:= (p*li)/ul;
      uli: constant integer:= (u*li)/ul;
      fancy_1: constant string:=" .oO";
      fancy_2: constant string:="|/-\";
      fancy: string renames fancy_2; -- choose one...
      begin
        Put("     [");
        for i in 0..pli-1 loop put('='); end loop;
        put(fancy(fancy'first+pack_occur mod fancy'length));
        pack_occur:= pack_occur + 1;
        for i in pli+1..uli loop put('.'); end loop;
        for i in uli+1..li loop put(' '); end loop;
        Put("] " & integer'image((100*p)/u)); Put("%     " & ASCII.CR);
        continue:= true;
      end Packometer;

    procedure Pack(u: t_data_array; p: out t_data_array; pl: out integer) is
      subtype tp is t_data_array(p'range);
      subtype tu is t_data_array(u'range);
      procedure Pa is new APLib.Pack(tp, tu, Packometer);

    begin
      Pa(u,p,pl);
    end Pack;
  
    procedure Depack(p: t_data_array; u: out t_data_array) is
      subtype tp is t_data_array(p'range);
      subtype tu is t_data_array(u'range);
      procedure De is new APLib.Depack(tp, tu);
  
    begin
      De(p,u);
    end Depack;
 
  bytes_per_element: constant integer:= byte'size/8;

  begin
    New_Line; 

    Read_file(name, frog);

    if frog /= null then
      ul:= frog.all'size / 8;  -- frog.all is the array; ul= size in bytes
      plmax:= aPLib.Evaluate_max_packed_space(ul);
      frog2:= New t_data_array( 1 .. plmax / bytes_per_element );
  
      Put_Line("File name: " & name);
      New_Line;

      T0:= Clock;
      Pack(frog.all, frog2.all, pl);
      T1:= Clock;
  
      New_Line; 
      New_Line; 
      Put("Unpacked size    : "); Put(ul);    New_Line;
      Put("Res. for packing : "); Put(plmax); New_Line;
      Put("Packed size      : "); Put(pl);    New_Line;
      Put("Work memory size : "); Put(aPLib.aP_workmem_size(ul)); New_Line;
      Put("Compression ratio: "); Put((100*pl)/ul,0); Put_Line("%");
      Put_Line("Packed file name           : " & name_p);
      Put_Line("Re-depacked file name      : " & name_pu);
      New_Line; 

      Put_Line("Real time for compression  : " & Duration'Image(T1-T0));
      Write_file(name_p, frog2(1..pl));
  
      frog3:= New t_data_array(frog'range);
      T2:= Clock;
      Depack( frog2(1..pl), frog3.all );
      T3:= Clock;
      Put("Real time for decompression: " & Duration'Image(T3-T2) &
           " - time ratio :" );
      Put(Float(T3-T2) / Float(T1-T0),2,4,0);
      New_Line;
  
      Write_file(name_pu, frog3.all);
      
      Put_Line("Are unpacked and original files identical ? " &
               Boolean'image( frog.all = frog3.all ));
    end if;

  end Test_pack_unpack;

begin
  Put_Line("APack_Demo");
  New_Line; 
  Put_Line("Command: apacdemo file1 file2 file3 ...");
  Put_Line("In a GUI drop the file(s) on the apacdemo application");
  New_Line; 
  Put_Line("When no file is specified, 'apacdemo.exe' is used");
  Put_Line("The data are packed, unpacked and compared with originals.");

  if Argument_count=0 then
    Test_pack_unpack( "apacdemo.exe",0 );
  else
    for i in 1..Argument_count loop
      Test_pack_unpack( Argument(i),i );
    end loop;
  end if;
  
  New_Line; 
  Put("Finished - press return please"); Skip_Line;
end APacDemo;
