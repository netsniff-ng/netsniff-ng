/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef TWOFISH_H
#define TWOFISH_H

#include <stdint.h>

struct twofish {
	int len;             /* Key length in 64-bit units: 2, 3 or 4 */
	uint32_t K[40];      /* Expanded key                          */
	uint32_t S[4][256];  /* Key-dependent S-boxes                 */
};

struct twofish *twofish_setup(unsigned char *key, int len);
void twofish_free(struct twofish *self);
void twofish_crypt(struct twofish *self, unsigned char *input,
		   unsigned char *output, int decrypt);

#endif /* TWOFISH_H */
