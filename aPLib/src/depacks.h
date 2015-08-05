/*
 * aPLib compression library  -  the smaller the better :)
 *
 * C safe depacker, header file
 *
 * Copyright (c) 1998-2014 Joergen Ibsen
 * All Rights Reserved
 *
 * http://www.ibsensoftware.com/
 */

#ifndef DEPACKS_H_INCLUDED
#define DEPACKS_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#ifndef APLIB_ERROR
# define APLIB_ERROR ((unsigned int) (-1))
#endif

/* function prototype */
unsigned int aP_depack_safe(const void *source,
                            unsigned int srclen,
                            void *destination,
                            unsigned int dstlen);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DEPACKS_H_INCLUDED */
