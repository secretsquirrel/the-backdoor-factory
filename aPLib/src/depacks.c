/*
 * aPLib compression library  -  the smaller the better :)
 *
 * C safe depacker
 *
 * Copyright (c) 1998-2014 Joergen Ibsen
 * All Rights Reserved
 *
 * http://www.ibsensoftware.com/
 */

#include "depacks.h"

/* internal data structure */
struct APDSSTATE {
	const unsigned char *source;
	unsigned int srclen;
	unsigned char *destination;
	unsigned int dstlen;
	unsigned int tag;
	unsigned int bitcount;
};

static int aP_getbit_safe(struct APDSSTATE *ud, unsigned int *result)
{
	unsigned int bit;

	/* check if tag is empty */
	if (!ud->bitcount--) {
		if (!ud->srclen--) {
			return 0;
		}

		/* load next tag */
		ud->tag = *ud->source++;
		ud->bitcount = 7;
	}

	/* shift bit out of tag */
	bit = (ud->tag >> 7) & 0x01;
	ud->tag <<= 1;

	*result = bit;

	return 1;
}

static int aP_getgamma_safe(struct APDSSTATE *ud, unsigned int *result)
{
	unsigned int bit;
	unsigned int v = 1;

	/* input gamma2-encoded bits */
	do {
		if (!aP_getbit_safe(ud, &bit)) {
			return 0;
		}

		if (v & 0x80000000) {
			return 0;
		}

		v = (v << 1) + bit;

		if (!aP_getbit_safe(ud, &bit)) {
			return 0;
		}
	} while (bit);

	*result = v;

	return 1;
}

unsigned int aP_depack_safe(const void *source,
                            unsigned int srclen,
                            void *destination,
                            unsigned int dstlen)
{
	struct APDSSTATE ud;
	unsigned int offs, len, R0, LWM, bit;
	int done;
	int i;

	if (!source || !destination) {
		return APLIB_ERROR;
	}

	ud.source = (const unsigned char *) source;
	ud.srclen = srclen;
	ud.destination = (unsigned char *) destination;
	ud.dstlen = dstlen;
	ud.bitcount = 0;

	R0 = (unsigned int) -1;
	LWM = 0;
	done = 0;

	/* first byte verbatim */
	if (!ud.srclen-- || !ud.dstlen--) {
		return APLIB_ERROR;
	}
	*ud.destination++ = *ud.source++;

	/* main decompression loop */
	while (!done) {
		if (!aP_getbit_safe(&ud, &bit)) {
			return APLIB_ERROR;
		}

		if (bit) {
			if (!aP_getbit_safe(&ud, &bit)) {
				return APLIB_ERROR;
			}

			if (bit) {
				if (!aP_getbit_safe(&ud, &bit)) {
					return APLIB_ERROR;
				}

				if (bit) {
					offs = 0;

					for (i = 4; i; i--) {
						if (!aP_getbit_safe(&ud, &bit)) {
							return APLIB_ERROR;
						}
						offs = (offs << 1) + bit;
					}

					if (offs) {
						if (offs > (dstlen - ud.dstlen)) {
							return APLIB_ERROR;
						}

						if (!ud.dstlen--) {
							return APLIB_ERROR;
						}

						*ud.destination = *(ud.destination - offs);
						ud.destination++;
					}
					else {
						if (!ud.dstlen--) {
							return APLIB_ERROR;
						}

						*ud.destination++ = 0x00;
					}

					LWM = 0;
				}
				else {
					if (!ud.srclen--) {
						return APLIB_ERROR;
					}

					offs = *ud.source++;

					len = 2 + (offs & 0x0001);

					offs >>= 1;

					if (offs) {
						if (offs > (dstlen - ud.dstlen)) {
							return APLIB_ERROR;
						}

						if (len > ud.dstlen) {
							return APLIB_ERROR;
						}

						ud.dstlen -= len;

						for (; len; len--) {
							*ud.destination = *(ud.destination - offs);
							ud.destination++;
						}
					}
					else {
						done = 1;
					}

					R0 = offs;
					LWM = 1;
				}
			}
			else {
				if (!aP_getgamma_safe(&ud, &offs)) {
					return APLIB_ERROR;
				}

				if ((LWM == 0) && (offs == 2)) {
					offs = R0;

					if (!aP_getgamma_safe(&ud, &len)) {
						return APLIB_ERROR;
					}

					if (offs > (dstlen - ud.dstlen)) {
						return APLIB_ERROR;
					}

					if (len > ud.dstlen) {
						return APLIB_ERROR;
					}

					ud.dstlen -= len;

					for (; len; len--) {
						*ud.destination = *(ud.destination - offs);
						ud.destination++;
					}
				}
				else {
					if (LWM == 0) {
						offs -= 3;
					}
					else {
						offs -= 2;
					}

					if (offs > 0x00fffffe) {
						return APLIB_ERROR;
					}

					if (!ud.srclen--) {
						return APLIB_ERROR;
					}

					offs <<= 8;
					offs += *ud.source++;

					if (!aP_getgamma_safe(&ud, &len)) {
						return APLIB_ERROR;
					}

					if (offs >= 32000) {
						len++;
					}
					if (offs >= 1280) {
						len++;
					}
					if (offs < 128) {
						len += 2;
					}

					if (offs > (dstlen - ud.dstlen)) {
						return APLIB_ERROR;
					}

					if (len > ud.dstlen) {
						return APLIB_ERROR;
					}

					ud.dstlen -= len;

					for (; len; len--) {
						*ud.destination = *(ud.destination - offs);
						ud.destination++;
					}

					R0 = offs;
				}

				LWM = 1;
			}
		}
		else {
			if (!ud.srclen-- || !ud.dstlen--) {
				return APLIB_ERROR;
			}
			*ud.destination++ = *ud.source++;
			LWM = 0;
		}
	}

	return (unsigned int) (ud.destination - (unsigned char *) destination);
}
