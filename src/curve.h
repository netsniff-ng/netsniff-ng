/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef CURVE_H
#define CURVE_H

#include <stdint.h>
#include <sys/time.h>

#include "locking.h"
#include "mtrand.h"
#include "built_in.h"
#include "crypto_box_curve25519xsalsa20poly1305.h"

/* Some parts derived from public domain code from curveprotect project */

struct tai {
	uint64_t x;
};

struct taia {
	struct tai sec;
	uint32_t nano;  /* 0...999999999 */
	uint32_t atto;  /* 0...999999999 */
};

/* Delay tolerance for packets! */
static struct taia tolerance_taia = {
	.sec.x = 0,
	.nano = 700000000ULL,
	.atto = 0,
};

#define crypto_box_zerobytes    crypto_box_curve25519xsalsa20poly1305_ZEROBYTES
#define crypto_box_boxzerobytes crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES

#define crypto_box_noncebytes crypto_box_curve25519xsalsa20poly1305_NONCEBYTES
#define crypto_box_beforenmbytes crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES

/* Per connection */
struct curve25519_proto {
	unsigned char enonce[crypto_box_noncebytes] __aligned_16;
	unsigned char dnonce[crypto_box_noncebytes] __aligned_16;
	unsigned char key[crypto_box_noncebytes] __aligned_16;
};

/* Per thread */
struct curve25519_struct {
	/* Encode buffer */
	size_t enc_buf_size;
	unsigned char *enc_buf;
	struct spinlock enc_lock;
	/* Decode buffer */
	size_t dec_buf_size;
	unsigned char *dec_buf;
	struct spinlock dec_lock;
};

extern void curve25519_selftest(void);
extern int curve25519_pubkey_hexparse_32(unsigned char *y, size_t ylen,
					 const char *x, size_t len);
extern int curve25519_alloc_or_maybe_die(struct curve25519_struct *c);
extern void curve25519_free(void *vc);
extern int curve25519_proto_init(struct curve25519_proto *p,
				 unsigned char *pubkey_remote, size_t len,
				 char *home, int server);
extern ssize_t curve25519_encode(struct curve25519_struct *c,
				 struct curve25519_proto *p,
				 unsigned char *plaintext, size_t size,
				 unsigned char **chipertext);
extern ssize_t curve25519_decode(struct curve25519_struct *c,
				 struct curve25519_proto *p,
				 unsigned char *chipertext, size_t size,
				 unsigned char **plaintext,
				 struct taia *arrival_taia);

static inline void tai_pack(unsigned char *s, struct tai *t)
{
	uint64_t x;

	x = t->x;
	s[7] = x & 255; x >>= 8;
	s[6] = x & 255; x >>= 8;
	s[5] = x & 255; x >>= 8;
	s[4] = x & 255; x >>= 8;
	s[3] = x & 255; x >>= 8;
	s[2] = x & 255; x >>= 8;
	s[1] = x & 255; x >>= 8;
	s[0] = x;
}

static inline void tai_unpack(unsigned char *s, struct tai *t)
{
	uint64_t x;

	x = (unsigned char) s[0];
	x <<= 8; x += (unsigned char) s[1];
	x <<= 8; x += (unsigned char) s[2];
	x <<= 8; x += (unsigned char) s[3];
	x <<= 8; x += (unsigned char) s[4];
	x <<= 8; x += (unsigned char) s[5];
	x <<= 8; x += (unsigned char) s[6];
	x <<= 8; x += (unsigned char) s[7];
	t->x = x;
}

static inline void taia_pack(unsigned char *s, struct taia *t)
{
	unsigned long x;

	tai_pack(s, &t->sec);
	s += 8;
	x = t->atto;
	s[7] = x & 255; x >>= 8;
	s[6] = x & 255; x >>= 8;
	s[5] = x & 255; x >>= 8;
	s[4] = x;
	x = t->nano;
	s[3] = x & 255; x >>= 8;
	s[2] = x & 255; x >>= 8;
	s[1] = x & 255; x >>= 8;
	s[0] = x;
} 

static inline void taia_unpack(unsigned char *s, struct taia *t)
{
	unsigned long x;

	tai_unpack(s, &t->sec);
	s += 8;
	x = (unsigned char) s[4];
	x <<= 8; x += (unsigned char) s[5];
	x <<= 8; x += (unsigned char) s[6];
	x <<= 8; x += (unsigned char) s[7];
	t->atto = x;
	x = (unsigned char) s[0];
	x <<= 8; x += (unsigned char) s[1];
	x <<= 8; x += (unsigned char) s[2];
	x <<= 8; x += (unsigned char) s[3];
	t->nano = x;
}

#define tai_unix(t, u) ((void) ((t)->x = 4611686018427387914ULL + (uint64_t) (u)))

static inline void taia_now(struct taia *t)
{
	struct timeval now;

	gettimeofday(&now, NULL);
	tai_unix(&t->sec, now.tv_sec);
	t->nano = 1000 * now.tv_usec + 500;
	t->atto = mt_rand_int32();
}

/* XXX: breaks tai encapsulation */

/* calcs u - v */
static inline void taia_sub(struct taia *res,
			    const struct taia *u,
			    const struct taia *v)
{
	unsigned long unano = u->nano;
	unsigned long uatto = u->atto;

	res->sec.x = u->sec.x - v->sec.x;
	res->nano = unano - v->nano;
	res->atto = uatto - v->atto;

	if (res->atto > uatto) {
		res->atto += 1000000000UL;
		--res->nano;
	}

	if (res->nano > unano) {
		res->nano += 1000000000UL;
		--res->sec.x;
	}
}

/* XXX: breaks tai encapsulation */

/* calcs u + v */
static inline void taia_add(struct taia *res,
			    const struct taia *u,
			    const struct taia *v)
{
	res->sec.x = u->sec.x + v->sec.x;
	res->nano = u->nano + v->nano;
	res->atto = u->atto + v->atto;

	if (res->atto > 999999999UL) {
		res->atto -= 1000000000UL;
		++res->nano;
	}

	if (res->nano > 999999999UL) {
		res->nano -= 1000000000UL;
		++res->sec.x;
	}
}

/* 1 if t is less than u, 0 otherwise */
static inline int taia_less(const struct taia *t, const struct taia *u)
{
	if (t->sec.x < u->sec.x)
		return 1;
	if (t->sec.x > u->sec.x)
		return 0;
	if (t->nano < u->nano)
		return 1;
	if (t->nano > u->nano)
		return 0;
	return t->atto < u->atto;
}

static inline int is_good_taia(struct taia *arrival_taia,
			       struct taia *packet_taia)
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
