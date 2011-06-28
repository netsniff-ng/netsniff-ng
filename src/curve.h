/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef CURVE_H
#define CURVE_H

#include "locking.h"

struct curve25519_struct {
	/* Encode buffer */
	size_t enc_buf_size;
	unsigned char *enc_buf;
	struct spinlock enc_lock;
	/* Decode buffer */
	unsigned char *dec_buf;
	size_t dec_buf_size;
	struct spinlock dec_lock;
};

extern void curve25519_selftest(void);

#endif /* CURVE_H */
