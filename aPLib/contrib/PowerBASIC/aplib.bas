'// Simple demo using the aPLib compression library to compress and decompress a string buffer.
'
'// aPLib - a free, highly-refined C++/asm implementation of a pure Lempel–Ziv LZ77-based lossless data compression library. See aPLib.inc for more info.
'// aPLib is Copyright (c) 1998-2014 Joergen Ibsen, All Rights Reserved. Website: http://www.ibsensoftware.com
'// Free to use for both commercial and non-commercial use. Please see the aPLib License in \aPLib\readme.txt
'
'// This demo uses the aPLib SAFE-version pack/depack functions.
'// Using the Safe pack function aPsafe_pack() prepends a 24-byte header to the compressed data, which not only makes the data safer to
'// decompress with aPsafe_depack() or aP_depack_asm_safe() in regards to their internal error-trapping, but also makes more info available:
'   ADDR   SIZE    TYPE    DATA
'      0   dword   Const   String "AP32" (dword &h41503332)
'      4   dword   Const*  Size of header (24 bytes in v1.1.0, dword &h18000000) *Size may change in future releases
'      8   dword   Var     Size of compressed data
'     12   dword   Var     CRC32 checksum of compressed data
'     16   dword   Var     Size of original data
'     20   dword   Var     CRC32 checksum original data
 
 
#COMPILE EXE
#INCLUDE "aPLib.inc"
 
%HEAP_NO_SERIALIZE          = &h00000001  '// not used
%HEAP_GENERATE_EXCEPTIONS   = &h00000004
%HEAP_ZERO_MEMORY           = &h00000008
%HEAP_ALLOC_FLAGS           = %HEAP_ZERO_MEMORY OR %HEAP_GENERATE_EXCEPTIONS
%HEAP_FREE_FLAGS            = 0
 
DECLARE FUNCTION GetProcessHeap LIB "kernel32.dll" ALIAS "GetProcessHeap" () AS LONG
DECLARE FUNCTION HeapAlloc LIB "kernel32.dll" ALIAS "HeapAlloc" (BYVAL hHeap AS DWORD, BYVAL dwFlags AS DWORD, BYVAL dwBytes AS DWORD) AS DWORD
DECLARE FUNCTION HeapFree LIB "kernel32.dll" ALIAS "HeapFree" (BYVAL hHeap AS DWORD, BYVAL dwFlags AS DWORD, BYVAL lpMem AS DWORD) AS LONG
 
 
FUNCTION PBMAIN() AS LONG
LOCAL srcbuf AS STRING, workmem AS DWORD, dstbuf AS DWORD, srclen AS DWORD, packlen AS DWORD, depacklen AS DWORD
 
srcbuf = REPEAT$(100000, "ABC 12345 AAAAA")  '// data to compress
srclen = LEN(srcbuf)                         '// length of data to compress
 
'// Allocate buffers
workmem = HeapAlloc (GetProcessHeap(), %HEAP_ALLOC_FLAGS, BYVAL aP_workmem_size(BYVAL srclen))    '// Temp working buffer
dstbuf = HeapAlloc (GetProcessHeap(), %HEAP_ALLOC_FLAGS, BYVAL aP_max_packed_size(BYVAL srclen))  '// Destination buffer for packed data
 
'// Compress srcbuf into dstbuf
packlen = aPsafe_pack (BYVAL STRPTR(srcbuf), BYVAL dstbuf, BYVAL srclen, BYVAL workmem, BYVAL 0, BYVAL 0)
HeapFree (GetProcessHeap(), %HEAP_FREE_FLAGS, workmem)                                            '// Free temp working buffer
IF packlen = %APLIB_ERROR THEN
    STDOUT "APLIB_ERROR"
ELSE
    STDOUT "Compressed" & STR$(srclen) & " bytes down to" & STR$(packlen)
END IF
 
'// Decompress dstbuf back into srcbuf
depacklen = aPsafe_depack (BYVAL dstbuf, BYVAL packlen, BYVAL STRPTR(srcbuf), BYVAL srclen)
IF depacklen = %APLIB_ERROR THEN
    STDOUT "APLIB_ERROR"
ELSE
    STDOUT "Decompressed" & STR$(packlen) & " bytes back to" & STR$(depacklen)
END IF
 
HeapFree (GetProcessHeap(), %HEAP_FREE_FLAGS, dstbuf)
STDOUT "Done": WAITKEY$
END FUNCTION
