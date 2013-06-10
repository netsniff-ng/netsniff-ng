#ifndef TAIA_H
#define TAIA_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/time.h>

#include "rnd.h"

struct tai {
	uint64_t x;
};

struct taia {
	struct tai sec;
	uint32_t nano;
	uint32_t atto;
};

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

#define tai_unix(t, u) \
		((void) ((t)->x = 4611686018427387914ULL + \
				  (uint64_t) (u)))

static inline void taia_now(struct taia *t)
{
	struct timeval now;

	gettimeofday(&now, NULL);

	tai_unix(&t->sec, now.tv_sec);
	t->nano = 1000 * now.tv_usec + 500;
	/* We don't really have it, but bring some noise in. */
	t->atto = secrand();
}

static inline void taia_sub(struct taia *res, const struct taia *u,
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

static inline void taia_add(struct taia *res, const struct taia *u,
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

extern bool taia_looks_good(struct taia *arr_taia, struct taia *pkt_taia);

#endif /* TAIA_H */
