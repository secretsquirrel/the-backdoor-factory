/*
 * aPLib compression library  -  the smaller the better :)
 *
 * C example
 *
 * Copyright (c) 1998-2014 Joergen Ibsen
 * All Rights Reserved
 *
 * http://www.ibsensoftware.com/
 */

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stddef.h>
#include <limits.h>

#include "aplib.h"

/*
 * Calling convention for the callback.
 */
#ifndef CB_CALLCONV
# if defined(AP_DLL)
#  define CB_CALLCONV __stdcall
# elif defined(__GNUC__)
#  define CB_CALLCONV
# else
#  define CB_CALLCONV __cdecl
# endif
#endif

/*
 * Unsigned char type.
 */
typedef unsigned char byte;

/*
 * Compute ratio between two numbers.
 */
static unsigned int ratio(unsigned int x, unsigned int y)
{
	if (x <= UINT_MAX / 100) {
		x *= 100;
	}
	else {
		y /= 100;
	}

	if (y == 0) {
		y = 1;
	}

	return x / y;
}

/*
 * Compression callback.
 */
int CB_CALLCONV callback(unsigned int insize, unsigned int inpos,
                         unsigned int outpos, void *cbparam)
{
	(void) cbparam;

	printf("\rcompressed %u -> %u bytes (%u%% done)", inpos, outpos,
	       ratio(inpos, insize));

	return 1;
}

/*
 * Compress a file.
 */
static int compress_file(const char *oldname, const char *packedname)
{
	FILE *oldfile;
	FILE *packedfile;
	unsigned int insize, outsize;
	clock_t clocks;
	byte *data, *packed, *workmem;

	/* open input file */
	if ((oldfile = fopen(oldname, "rb")) == NULL) {
		printf("\nERR: unable to open input file\n");
		return 1;
	}

	/* get size of input file */
	fseek(oldfile, 0, SEEK_END);
	insize = (unsigned int) ftell(oldfile);
	fseek(oldfile, 0, SEEK_SET);

	/* allocate memory */
	if ((data = (byte *) malloc(insize)) == NULL ||
	    (packed = (byte *) malloc(aP_max_packed_size(insize))) == NULL ||
	    (workmem = (byte *) malloc(aP_workmem_size(insize))) == NULL) {
		printf("\nERR: not enough memory\n");
		return 1;
	}

	if (fread(data, 1, insize, oldfile) != insize) {
		printf("\nERR: error reading from input file\n");
		return 1;
	}

	clocks = clock();

	/* compress data block */
	outsize = aPsafe_pack(data, packed, insize, workmem, callback, NULL);

	clocks = clock() - clocks;

	/* check for compression error */
	if (outsize == APLIB_ERROR) {
		printf("\nERR: an error occured while compressing\n");
		return 1;
	}

	/* create output file */
	if ((packedfile = fopen(packedname, "wb")) == NULL) {
		printf("\nERR: unable to create output file\n");
		return 1;
	}

	fwrite(packed, 1, outsize, packedfile);

	/* show result */
	printf("\rCompressed %u -> %u bytes (%u%%) in %.2f seconds\n",
	       insize, outsize, ratio(outsize, insize),
	       (double) clocks / (double) CLOCKS_PER_SEC);

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
static int decompress_file(const char *packedname, const char *newname)
{
	FILE *newfile;
	FILE *packedfile;
	unsigned int insize, outsize;
	clock_t clocks;
	byte *data, *packed;
	unsigned int depackedsize;

	/* open input file */
	if ((packedfile = fopen(packedname, "rb")) == NULL) {
		printf("\nERR: unable to open input file\n");
		return 1;
	}

	/* get size of input file */
	fseek(packedfile, 0, SEEK_END);
	insize = (unsigned int) ftell(packedfile);
	fseek(packedfile, 0, SEEK_SET);

	/* allocate memory */
	if ((packed = (byte *) malloc(insize)) == NULL) {
		printf("\nERR: not enough memory\n");
		return 1;
	}

	if (fread(packed, 1, insize, packedfile) != insize) {
		printf("\nERR: error reading from input file\n");
		return 1;
	}

	depackedsize = aPsafe_get_orig_size(packed);

	if (depackedsize == APLIB_ERROR) {
		printf("\nERR: compressed data error\n");
		return 1;
	}

	/* allocate memory */
	if ((data = (byte *) malloc(depackedsize)) == NULL) {
		printf("\nERR: not enough memory\n");
		return 1;
	}

	clocks = clock();

	/* decompress data */
	outsize = aPsafe_depack(packed, insize, data, depackedsize);

	clocks = clock() - clocks;

	/* check for decompression error */
	if (outsize != depackedsize) {
		printf("\nERR: an error occured while decompressing\n");
		return 1;
	}

	/* create output file */
	if ((newfile = fopen(newname, "wb")) == NULL) {
		printf("\nERR: unable to create output file\n");
		return 1;
	}

	/* write decompressed data */
	fwrite(data, 1, outsize, newfile);

	/* show result */
	printf("Decompressed %u -> %u bytes in %.2f seconds\n",
	       insize, outsize,
	       (double) clocks / (double) CLOCKS_PER_SEC);

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
static void show_syntax(void)
{
	printf("  Syntax:\n\n"
	       "    Compress    :  appack c <file> <packed_file>\n"
	       "    Decompress  :  appack d <packed_file> <depacked_file>\n\n");
}

/*
 * Main.
 */
int main(int argc, char *argv[])
{
	/* show banner */
	printf("appack, aPLib compression library example\n"
	       "Copyright 1998-2014 Joergen Ibsen (www.ibsensoftware.com)\n\n");

	/* check number of arguments */
	if (argc != 4) {
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
	if (argv[1][0] && argv[1][1] == '\0') {
		switch (argv[1][0]) {
		/* compress file */
		case 'c':
		case 'C': return compress_file(argv[2], argv[3]);

		/* decompress file */
		case 'd':
		case 'D': return decompress_file(argv[2], argv[3]);
		}
	}

	/* show program syntax */
	show_syntax();
	return 1;
}
