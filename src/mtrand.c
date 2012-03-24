/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Copyright (C) 1997-2004, Makoto Matsumoto, Takuji Nishimura, and
 * Eric Landry; All rights reserved. (3-clause BSD license)
 * Daniel Borkmann: Refactored, added initialization functions.
 * Subject to the GPL, version 2.
 * Reference: M. Matsumoto and T. Nishimura, "Mersenne Twister:
 * A 623-Dimensionally Equidistributed Uniform Pseudo-Random Number
 * Generator", ACM Transactions on Modeling and Computer Simulation,
 * Vol. 8, No. 1, January 1998, pp 3--30.
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

#include "mtrand.h"
#include "xio.h"

#define N           624
#define M           397
#define LEN_INIT    256

#define MATRIX_A    0x9908b0dfUL
#define UPPER_MASK  0x80000000UL
#define LOWER_MASK  0x7fffffffUL

static unsigned long x[N];
static unsigned long *p0, *p1, *pm;

void mt_init_by_seed_rand(unsigned long s)
{
	int i;
	x[0] = s & 0xffffffffUL;
	for (i = 1; i < N; ++i) {
		x[i] = (1812433253UL * (x[i - 1] ^ (x[i - 1] >> 30)) + i) &
		       0xffffffffUL;
	}
	p0 = x;
	p1 = x + 1;
	pm = x + M;
}

void mt_init_by_seed_time(void)
{
	int i;
	x[0] = ((unsigned long) time(NULL)) & 0xffffffffUL;
	for (i = 1; i < N; ++i) {
		x[i] = (1812433253UL * (x[i - 1] ^ (x[i - 1] >> 30)) + i) &
		       0xffffffffUL;
	}
	p0 = x;
	p1 = x + 1;
	pm = x + M;
}

void mt_init_by_seed_array(unsigned long key[], int len)
{
	int i, j, k;
	mt_init_by_seed_rand(19650218UL);
	i = 1;
	j = 0;
	for (k = (N > len ? N : len); k; --k) {
		/* Non linear */
		x[i] = ((x[i] ^ ((x[i - 1] ^ (x[i - 1] >> 30)) * 
		       1664525UL)) + key[j] + j) & 0xffffffffUL;
		if (++i >= N) {
			x[0] = x[N - 1];
			i = 1;
		}
		if (++j >= len)
			j = 0;
	}
	for (k = N - 1; k; --k) {
		/* Non linear */
		x[i] = ((x[i] ^ ((x[i - 1] ^ (x[i - 1] >> 30)) *
		       1566083941UL)) - i) & 0xffffffffUL;
		if (++i >= N) {
			x[0] = x[N - 1];
			i = 1;
		}
	}
	x[0] = 0x80000000UL;
}

void mt_init_by_seed_rand_array(void)
{
	int i;
	unsigned long k[LEN_INIT];
	srand((unsigned int) time(NULL));
	for (i = 0; i < LEN_INIT; i++)
		k[i] = rand();
	mt_init_by_seed_array(k, LEN_INIT);
}

void mt_init_by_random_device(void)
{
	int fd;
	unsigned long k[LEN_INIT];
	fd = open_or_die("/dev/random", O_RDONLY);
	read_or_die(fd, k, sizeof(unsigned long) * LEN_INIT);
	close(fd);
	mt_init_by_seed_array(k, LEN_INIT);
}

unsigned long mt_rand_int32(void)
{
	/* Interval [0,0xffffffff] */
	unsigned long y;
	/* Default seed */
	if (p0 == NULL)
		mt_init_by_seed_rand(5489UL);
	/* Twisted feedback */
	y = *p0 = *pm++ ^ (((*p0 & UPPER_MASK) | (*p1 & LOWER_MASK)) >> 1) ^
		  (-(*p1 & 1) & MATRIX_A);
	p0 = p1++;
	if (pm == x + N)
		pm = x;
	if (p1 == x + N)
		p1 = x;
	/* Temper */
	y ^= y >> 11;
	y ^= y << 7 & 0x9d2c5680UL;
	y ^= y << 15 & 0xefc60000UL;
	y ^= y >> 18;
	return y;
}

long mt_rand_int31(void)
{
	/* Interval [0,0x7fffffff] */
	return (long) mt_rand_int32() >> 1;
}

double mt_rand_real1(void)
{
	/* Interval [0,1]; Divided by 2^32-1 */
	return mt_rand_int32() * (1.0 / 4294967295.0);
}

double mt_rand_real2(void)
{
	/* Interval [0,1); Divided by 2^32 */
	return mt_rand_int32() * (1.0 / 4294967296.0);
}

double mt_rand_real3(void)
{
	/* Interval (0,1); Divided by 2^32 */
	return (((double) mt_rand_int32()) + 0.5) * (1.0 / 4294967296.0);
}

double mt_rand_res53(void)
{
	/* 53-bit random number on the real interval [0,1) */
	unsigned long a = mt_rand_int32() >> 5, b = mt_rand_int32() >> 6;
	return (a * 67108864.0 + b) * (1.0 / 9007199254740992.0);
}

