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

#define crypto_box_noncebytes crypto_box_curve25519xsalsa20poly1305_NONCEBYTES
#define crypto_box_beforenmbytes crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES

/* Per connection */
struct curve25519_proto {
	unsigned char enonce[crypto_box_noncebytes] __attribute__((aligned(16)));
	unsigned char dnonce[crypto_box_noncebytes] __attribute__((aligned(16)));
	unsigned char key[crypto_box_noncebytes] __attribute__((aligned(16)));
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
extern int curve25519_pubkey_hexparse_32(unsigned char *y, size_t ylen,
					 const char *x, size_t len);
extern int curve25519_alloc_or_maybe_die(struct curve25519_struct *c);
extern void curve25519_free(void *vc);
extern int curve25519_proto_init(struct curve25519_proto *p);
extern ssize_t curve25519_encode(struct curve25519_struct *c,
				 struct curve25519_proto *p,
				 unsigned char *plaintext, size_t size,
				 unsigned char **chipertext);
extern ssize_t curve25519_decode(struct curve25519_struct *c,
				 struct curve25519_proto *p,
				 unsigned char *chipertext, size_t size,
				 unsigned char **plaintext);

#endif /* CURVE_H */
