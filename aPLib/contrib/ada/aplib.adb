-----------------------------------------------------------------------------
--  File: aplib.adb; see specification (aplib.ads)
-----------------------------------------------------------------------------
with System, Ada.Unchecked_Deallocation;

-- with Ada.Text_IO;                       use Ada.Text_IO; -- OA debug

package body aPLib is

  procedure Pack( source       : in  unpacked_data;
                  destination  : out packed_data;
                  packed_length: out integer ) is

    type byte is mod 2 ** 8; for byte'size use 8;
    type twa is array( 0..aP_workmem_size(source'size / 8) ) of byte;
    pragma pack(twa);

    type pwa is access twa;
    procedure Dispose is new Ada.Unchecked_Deallocation( twa, pwa );

    type p_cb is access function (unpacked, packed: integer) return integer;

    function aP_pack(source: unpacked_data;
                     destination_addr: System.Address; -- trick for "in" par.
                     length: integer;
                     work_mem: twa;
                     cb: p_cb)
        return integer;

     pragma Import(C, aP_pack, "aP_pack");

    function cb(unpacked, packed: integer) return integer is
      cont: boolean;
    begin
      Call_back(unpacked, packed, cont);
      return Boolean'Pos(cont); -- 0 false, 1 true
    end cb;

    p_to_cb: p_cb:= cb'access;
    tmp_work_mem: pwa:= New twa;
  begin
--    Put_Line("OA3 ");
--    packed_length:=
--      aP_pack( source'Address, destination'Address,
--               source'size / 8, tmp_work_mem.all'Address, cb'Address );
--    Put_Line("OA4 ");

    packed_length:=
      aP_pack( source, destination'Address,
               source'size / 8, tmp_work_mem.all, p_to_cb );

    Dispose( tmp_work_mem ); -- we immediately free the work memory

    if packed_length=0 then  -- 0 means error
      raise Pack_failed;
    end if;
  end Pack;

  procedure Depack( source     : in  packed_data;
                    destination: out unpacked_data ) is

    function aP_depack_asm_fast(
               source: packed_data;
               destination_addr: System.Address  -- trick for "in" par.
               ) return integer;
     pragma Import(C, aP_depack_asm_fast, "aP_depack_asm_fast");

  begin
    if aP_depack_asm_fast( source, destination'Address )=0 then
      raise Unpack_failed;
    end if;
  end Depack;

end aPLib;
