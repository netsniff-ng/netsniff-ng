/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef CURVE_H
#define CURVE_H

#include "locking.h"
#include "crypto_box_curve25519xsalsa20poly1305.h"

struct tai {
	uint64_t x;
};

struct taia {
	struct tai sec;
	uint32_t nano;  /* 0...999999999 */
	uint32_t atto;  /* 0...999999999 */
};

/* Per connection */
struct curve25519_proto {
	unsigned char enonce[crypto_box_curve25519xsalsa20poly1305_NONCEBYTES];
	unsigned char dnonce[crypto_box_curve25519xsalsa20poly1305_NONCEBYTES];
	unsigned char key[crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES];
	struct taia dtaip;
	struct taia dtaie;
};

/* Per thread */
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
