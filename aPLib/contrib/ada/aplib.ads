--
-- aPLib compression library  -  the smaller the better :)
--
-- Ada binding for aplib.a
--
-- Copyright (c) 1998-2009 by Joergen Ibsen / Jibz
-- All Rights Reserved
--
-- http://www.ibsensoftware.com/
--
-- Ada binding by Gautier de Montmollin - gdemont@hotmail.com, gdm@mydiax.ch
--


package aPLib is

  -- Give the maximum "packed" size possible - it can be more than
  -- the unpacked size in case of uncompressible data:

  function Evaluate_max_packed_space( unpacked_size: Integer ) return Integer;
  pragma Import(C, Evaluate_max_packed_space, "aP_max_packed_size");
  -- Was, before v0.34 b4: (((unpacked_size * 9) / 8) + 16)


  -- A template for packing data:

  generic
    type packed_data is private;
    type unpacked_data is private;
    with procedure Call_back( unpacked_bytes, packed_bytes:  in integer;
                              continue                    : out boolean );

  procedure Pack( source       : in  unpacked_data;
                  destination  : out packed_data;
                  packed_length: out integer );

  -- A template for unpacking data:

  generic
    type packed_data is private;
    type unpacked_data is private;

  procedure Depack( source     : in  packed_data;
                    destination: out unpacked_data );

  -- Exceptions for errors that could occur:

  pack_failed, unpack_failed: exception;

  -- Just for information

  function aP_workmem_size(inputsize: integer) return integer;
  pragma Import(C, aP_workmem_size, "aP_workmem_size");

end aPLib;
