'// APLIB.INC
#IF NOT %DEF (%APLIB_H_INCLUDED)
'--
'// aPLib - a free, highly-refined C++/asm implementation of a pure Lempel–Ziv LZ77-based lossless data compression library.
'// aPLib is Copyright (c) 1998-2014 Joergen Ibsen, All Rights Reserved. Website: http://www.ibsensoftware.com
'// Free to use for both commercial and non-commercial use. Please see the aPLib License in \aPLib\readme.txt
'
'// This aPLib.inc Powerbasic header file is based on \aPLib-v1.1.1\lib\dll\aplib.h (July 2014)
'// Translation of aPLib v1.1.1 to Powerbasic (PBWin/PBCC/PBDLL) by Wayne Diamond (July 2014)
'
'// aPLib, since first released in 1998 and still as of its 2014 update, has been one of the top pure LZ-based compression libraries.
'// As a custom assembly language implementation of the famous LZ77 algorithm, aPLib has the primary characteristics of 1) very good
'// compression ratios (often compressing better than PKZIP), 2) reasonable compression speed, and 3) VERY fast decompression speed.
'// This makes it highly suitable for installers, databases and other similar applications where decompression speed is critical.
'// aPLib also has a famously tiny footprint: the entire v1.1.1 DLL is just 11264 bytes, and decompression code as small as 169 bytes.
'// aPLib is used in a wide range of products including protection software, archivers, games, embedded systems, and handheld devices.
'--

 %APLIB_H_INCLUDED = 1
 %APLIB_ERROR      = &h0FFFFFFFF  '-1

 '// ### COMPRESS
 DECLARE FUNCTION aP_pack LIB "aplib.dll" ALIAS "_aP_pack" (BYVAL src AS BYTE PTR, BYVAL dst AS BYTE PTR, BYVAL srclen AS DWORD, BYVAL workmem AS BYTE PTR, BYVAL ptrCallback AS DWORD, cbparam AS DWORD) AS DWORD
 DECLARE FUNCTION aPsafe_pack LIB "aplib.dll" ALIAS "_aPsafe_pack" (BYVAL src AS BYTE PTR, BYVAL dst AS BYTE PTR, BYVAL srclen AS DWORD, BYVAL workmem AS BYTE PTR, BYVAL ptrCallback AS DWORD, cbparam AS DWORD) AS DWORD  '// Wrapper of aP_pack
 DECLARE FUNCTION aP_workmem_size LIB "aplib.dll" ALIAS "_aP_workmem_size" (BYVAL inputsize AS DWORD) AS DWORD
 DECLARE FUNCTION aP_max_packed_size LIB "aplib.dll" ALIAS "_aP_max_packed_size" (BYVAL inputsize AS DWORD) AS DWORD

 '// ### DECOMPRESS
 DECLARE FUNCTION aP_depack_asm LIB "aplib.dll" ALIAS "_aP_depack_asm" (BYVAL src AS BYTE PTR, BYVAL dst AS BYTE PTR) AS DWORD
 DECLARE FUNCTION aP_depack_asm_fast LIB "aplib.dll" ALIAS "_aP_depack_asm_fast" (BYVAL src AS BYTE PTR, BYVAL dst AS BYTE PTR) AS DWORD
 DECLARE FUNCTION aP_depack_asm_safe LIB "aplib.dll" ALIAS "_aP_depack_asm_safe" (BYVAL src AS BYTE PTR, BYVAL srclen AS DWORD, BYVAL dst AS BYTE PTR, BYVAL dstlen AS DWORD) AS DWORD
 DECLARE FUNCTION aPsafe_depack LIB "aplib.dll" ALIAS "_aPsafe_depack" (BYVAL src AS BYTE PTR, BYVAL srclen AS DWORD, BYVAL dst AS BYTE PTR, BYVAL dstlen AS DWORD) AS DWORD '// Wrapper of aP_depack_asm_safe
 '// not included in the DLL, but source is included in the aPLib package (see Helpfile > Decompression) ...
 ' DECLARE FUNCTION aP_depack (BYVAL src AS BYTE PTR, BYVAL dst AS BYTE PTR) AS DWORD
 ' DECLARE FUNCTION aP_depack_safe (BYVAL src as BYTE PTR, BYVAL srclen AS DWORD, BYVAL dst AS BYTE PTR, BYVAL dstlen AS DWORD) AS DWORD

 '// ### Helpers
 DECLARE FUNCTION aP_crc32 LIB "aplib.dll" ALIAS "_aP_crc32" (BYVAL src AS BYTE PTR, BYVAL srclen AS DWORD) AS DWORD
 DECLARE FUNCTION aPsafe_get_orig_size LIB "aplib.dll" ALIAS "_aPsafe_get_orig_size" (BYVAL src AS BYTE PTR) AS DWORD
 DECLARE FUNCTION aPsafe_check LIB "aplib.dll" ALIAS "_aPsafe_check" (BYVAL src AS BYTE PTR) AS DWORD
 DECLARE FUNCTION aP_callback (BYVAL insize AS DWORD, BYVAL inpos AS DWORD, BYVAL outpos AS DWORD, cbparam AS DWORD) AS DWORD '// callback function in the app (not in aplib.dll)

#ENDIF  '// End aplib.inc
