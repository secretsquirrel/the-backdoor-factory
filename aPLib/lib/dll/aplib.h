/*
 * aPLib compression library  -  the smaller the better :)
 *
 * DLL header file
 *
 * Copyright (c) 1998-2014 Joergen Ibsen
 * All Rights Reserved
 *
 * http://www.ibsensoftware.com/
 */

#ifndef APLIB_H_INCLUDED
#define APLIB_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#ifndef APLIB_ERROR
# define APLIB_ERROR ((unsigned int) (-1))
#endif

__declspec(dllimport) unsigned int __stdcall aP_pack(const void *source,
                             void *destination,
                             unsigned int length,
                             void *workmem,
                             int (__stdcall *callback)(unsigned int, unsigned int, unsigned int, void *),
                             void *cbparam);

__declspec(dllimport) unsigned int __stdcall aP_workmem_size(unsigned int inputsize);

__declspec(dllimport) unsigned int __stdcall aP_max_packed_size(unsigned int inputsize);

__declspec(dllimport) unsigned int __stdcall aP_depack_asm(const void *source, void *destination);

__declspec(dllimport) unsigned int __stdcall aP_depack_asm_fast(const void *source, void *destination);

__declspec(dllimport) unsigned int __stdcall aP_depack_asm_safe(const void *source,
                             unsigned int srclen,
                             void *destination,
                             unsigned int dstlen);

__declspec(dllimport) unsigned int __stdcall aP_crc32(const void *source, unsigned int length);

__declspec(dllimport) unsigned int __stdcall aPsafe_pack(const void *source,
                             void *destination,
                             unsigned int length,
                             void *workmem,
                             int (__stdcall *callback)(unsigned int, unsigned int, unsigned int, void *),
                             void *cbparam);

__declspec(dllimport) unsigned int __stdcall aPsafe_check(const void *source);

__declspec(dllimport) unsigned int __stdcall aPsafe_get_orig_size(const void *source);

__declspec(dllimport) unsigned int __stdcall aPsafe_depack(const void *source,
                             unsigned int srclen,
                             void *destination,
                             unsigned int dstlen);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* APLIB_H_INCLUDED */
