/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2011 - 2013 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef CURVE_H
#define CURVE_H

#include <stdint.h>
#include <sys/time.h>

#include "locking.h"
#include "built_in.h"
#include "ioops.h"
#include "rnd.h"
#include "taia.h"
#include "crypto.h"

static struct taia tolerance_taia = {
	.sec.x = 0,
	.nano = 700000000ULL,
	.atto = 0,
};

struct curve25519_proto {
	unsigned char enonce[crypto_box_noncebytes] __aligned_16;
	unsigned char dnonce[crypto_box_noncebytes] __aligned_16;
	unsigned char key[crypto_box_noncebytes] __aligned_16;
};

struct curve25519_struct {
	unsigned char *enc_buf;
	unsigned char *dec_buf;
	size_t enc_buf_size;
	size_t dec_buf_size;
	struct spinlock enc_lock;
	struct spinlock dec_lock;
};

extern void curve25519_selftest(void);
extern void curve25519_alloc_or_maybe_die(struct curve25519_struct *curve);
extern void curve25519_free(void *curve);
extern int curve25519_pubkey_hexparse_32(unsigned char *bin, size_t blen, const char *ascii, size_t alen);
extern int curve25519_proto_init(struct curve25519_proto *proto, unsigned char *pubkey_remote, size_t len,
				 char *home, int server);
extern ssize_t curve25519_encode(struct curve25519_struct *curve, struct curve25519_proto *proto,
				 unsigned char *plaintext, size_t size, unsigned char **chipertext);
extern ssize_t curve25519_decode(struct curve25519_struct *curve, struct curve25519_proto *proto,
				 unsigned char *chipertext, size_t size, unsigned char **plaintext,
				 struct taia *arrival_taia);

static inline int is_good_taia(struct taia *arrival_taia, struct taia *packet_taia)
{
	int is_ts_good = 0;
	struct taia sub_res;

	if (taia_less(arrival_taia, packet_taia)) {
		taia_sub(&sub_res, packet_taia, arrival_taia);
		if (taia_less(&sub_res, &tolerance_taia))
			is_ts_good = 1;
		else
			is_ts_good = 0;
	} else {
		taia_sub(&sub_res, arrival_taia, packet_taia);
		if (taia_less(&sub_res, &tolerance_taia))
			is_ts_good = 1;
		else
			is_ts_good = 0;
	}

	return is_ts_good;
}

#endif /* CURVE_H */
