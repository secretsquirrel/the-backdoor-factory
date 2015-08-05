//---------------------------------------------------------------------------
// apacksamplec.c
// Code from c/apack.c
//---------------------------------------------------------------------------

//---------------------------------------------------------------------------
/*
 * aPLib compression library  -  the smaller the better :)
 *
 * C example
 *
 * Copyright (c) 1998-2009 by Joergen Ibsen / Jibz
 * All Rights Reserved
 *
 * http://www.ibsensoftware.com/
 */
//---------------------------------------------------------------------------


//---------------------------------------------------------------------------
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stddef.h>
#include <limits.h>

#include "apacksamplec.h"

#include "aplib.h"
//---------------------------------------------------------------------------






//---------------------------------------------------------------------------
/*
 * Unsigned char type.
 */
typedef unsigned char byte;
//---------------------------------------------------------------------------


//---------------------------------------------------------------------------
/*
 * Compute ratio between two numbers.
 */
unsigned int ratio(unsigned int x, unsigned int y)
{
    if (x <= UINT_MAX / 100) x *= 100; else y /= 100;

    if (y == 0) y = 1;

    return x / y;
}
//---------------------------------------------------------------------------





//---------------------------------------------------------------------------
// Compression callback sample
int STDPREFIX samplecallback(unsigned int insize, unsigned int inpos, unsigned int outpos, void *cbparam)
{
   printf("\rcompressed %u -> %u bytes (%u%% done)", inpos, outpos, ratio(inpos, insize));
   return 1;
}

// result callback
void STDPREFIX sampleresultcallback(char *resultstr, int errorcode)
{
   printf("%s\n", resultstr);
}
//---------------------------------------------------------------------------





//---------------------------------------------------------------------------
/*
 * Compress a file.
 */
int compress_file(const char *oldname, const char *packedname,callbackfuncdef *callbackfp,resultcallbackfundef *resultcallbackfp)
{
    FILE *oldfile;
    FILE *packedfile;
    size_t insize = 0;
    size_t outsize = 0;
    clock_t clocks;
    byte *data, *packed, *workmem;

    /* open input file */
    if ((oldfile = fopen(oldname, "rb")) == NULL)
    {
        resultcallbackfp("ERR: unable to open input file",1);
        return 1;
    }

    /* get size of input file */
    fseek(oldfile, 0, SEEK_END);
    insize = (size_t) ftell(oldfile);
    fseek(oldfile, 0, SEEK_SET);

    /* allocate memory */
    if ((data    = (byte *) malloc(insize))                     == NULL ||
        (packed  = (byte *) malloc(aP_max_packed_size(insize))) == NULL ||
        (workmem = (byte *) malloc(aP_workmem_size(insize)))    == NULL)
    {
        resultcallbackfp("ERR: not enough memory",1);
        return 1;
    }

    if (fread(data, 1, insize, oldfile) != insize)
    {
        resultcallbackfp("ERR: error reading from input file",1);
        return 1;
    }

    clocks = clock();

    /* compress data block */
    outsize = aPsafe_pack(data, packed, insize, workmem, callbackfp, NULL);

    clocks = clock() - clocks;

    /* check for compression error */
    if (outsize == APLIB_ERROR)
    {
        resultcallbackfp("ERR: an error occured while compressing",1);
        return 1;
    }

    /* create output file */
    if ((packedfile = fopen(packedname, "wb")) == NULL)
    {
        resultcallbackfp("ERR: unable to create output file",1);
        return 1;
    }

    fwrite(packed, 1, outsize, packedfile);

    /* show result */
    char resultstr[255];
    sprintf(resultstr,"compressed %u -> %u bytes (%u%%) in %.2f seconds",
           insize, outsize, ratio(outsize, insize),
           (double)clocks / (double)CLOCKS_PER_SEC);
    resultcallbackfp(resultstr,0);

    /* close files */
    fclose(packedfile);
    fclose(oldfile);

    /* free memory */
    free(workmem);
    free(packed);
    free(data);

    return 0;
}

/*
 * Decompress a file.
 */
int decompress_file(const char *packedname, const char *newname,callbackfuncdef *callbackfp,resultcallbackfundef *resultcallbackfp)
{
    FILE *newfile;
    FILE *packedfile;
    size_t insize = 0;
    size_t outsize = 0;
    clock_t clocks;
    byte *data, *packed;
    size_t depackedsize;

    /* open input file */
    if ((packedfile = fopen(packedname, "rb")) == NULL)
    {
        resultcallbackfp("ERR: unable to open input file",1);
        return 1;
    }

    /* get size of input file */
    fseek(packedfile, 0, SEEK_END);
    insize = (size_t) ftell(packedfile);
    fseek(packedfile, 0, SEEK_SET);

    /* allocate memory */
    if ((packed = (byte *) malloc(insize)) == NULL)
    {
        resultcallbackfp("ERR: not enough memory",1);
        return 1;
    }

    if (fread(packed, 1, insize, packedfile) != insize)
    {
        resultcallbackfp("ERR: error reading from input file",1);
        return 1;
    }

    depackedsize = aPsafe_get_orig_size(packed);

    if (depackedsize == APLIB_ERROR)
    {
        resultcallbackfp("ERR: compressed data error",1);
        return 1;
    }

    /* allocate memory */
    if ((data = (byte *) malloc(depackedsize)) == NULL)
    {
        resultcallbackfp("ERR: not enough memory",1);
        return 1;
    }

    clocks = clock();

    /* decompress data */
    outsize = aPsafe_depack(packed, insize, data, depackedsize);

    clocks = clock() - clocks;

    /* check for decompression error */
    if (outsize != depackedsize)
    {
        resultcallbackfp("ERR: an error occured while decompressing",1);
        return 1;
    }

    /* create output file */
    if ((newfile = fopen(newname, "wb")) == NULL)
    {
        resultcallbackfp("ERR: unable to create output file",1);
        return 1;
    }

    /* write decompressed data */
    fwrite(data, 1, outsize, newfile);

    /* show result */
    char resultstr[255];
    sprintf(resultstr,"decompressed %u -> %u bytes in %.2f seconds",
           insize, outsize,
           (double)clocks / (double)CLOCKS_PER_SEC);
    resultcallbackfp(resultstr,0);

    /* close files */
    fclose(packedfile);
    fclose(newfile);

    /* free memory */
    free(packed);
    free(data);

    return 0;
}


/*
 * Show program syntax.
 */
void show_syntax(void)
{
    printf("syntax:\n\n"
           "   compress    :  appack c <file> <packed_file>\n"
           "   decompress  :  appack d <packed_file> <depacked_file>\n\n");
}
//---------------------------------------------------------------------------




//---------------------------------------------------------------------------
/*
 * Main.
 */
int samplemain(int argc, char *argv[])
{
    /* show banner */
    printf("===============================================================================\n"
           "aPLib example                   Copyright (c) 1998-2009 by Joergen Ibsen / Jibz\n"
           "                                                            All Rights Reserved\n\n"
           "                                                  http://www.ibsensoftware.com/\n"
           "===============================================================================\n\n");

    /* check number of arguments */
    if (argc != 4)
    {
        show_syntax();
        return 1;
    }

#ifdef __WATCOMC__
    /* OpenWatcom 1.2 line buffers stdout, so we unbuffer stdout manually
       to make the progress indication in the callback work.
    */
    setbuf(stdout, NULL);
#endif

    /* check first character of first argument to determine action */
    if (argv[1][0] && argv[1][1] == '\0')
    {
        switch (argv[1][0])
        {
        /* compress file */
        case 'c':
        case 'C': return compress_file(argv[2], argv[3],samplecallback,sampleresultcallback);

        /* decompress file */
        case 'd':
        case 'D': return decompress_file(argv[2], argv[3],samplecallback,sampleresultcallback);
        }
    }

    /* show program syntax */
    show_syntax();
    return 1;
}
//---------------------------------------------------------------------------
