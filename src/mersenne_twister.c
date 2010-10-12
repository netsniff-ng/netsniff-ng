/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

/*
 * Copyright (C) 1997-2004, Makoto Matsumoto, Takuji Nishimura, and
 * Eric Landry; All rights reserved.
 * Daniel Borkmann: Refactored, added two initialization functions.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
 *
 *   3. The names of its contributors may not be used to endorse or
 *      promote products derived from this software without specific
 *      prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Any feedback is very welcome.
 * http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/emt.html
 * email: m-mat @ math.sci.hiroshima-u.ac.jp (remove space)
 *
 * Reference: M. Matsumoto and T. Nishimura, "Mersenne Twister:
 * A 623-Dimensionally Equidistributed Uniform Pseudo-Random Number
 * Generator", ACM Transactions on Modeling and Computer Simulation,
 * Vol. 8, No. 1, January 1998, pp 3--30.
 */

#include <stdlib.h>
#include <time.h>

#include "mersenne_twister.h"

#define N           624
#define M           397
#define LEN_INIT    256

#define MATRIX_A    0x9908b0dfUL
#define UPPER_MASK  0x80000000UL
#define LOWER_MASK  0x7fffffffUL

static unsigned long x[N];
static unsigned long *p0, *p1, *pm;

/*
 *  Initialize with a seed.
 *
 *  See Knuth TAOCP Vol2. 3rd Ed. P.106 for multiplier.
 *  In the previous versions, MSBs of the seed affect only MSBs of
 *  the state.
 *  2002-01-09 modified by Makoto Matsumoto
 */
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

/*
 *  Initialize with time as seed.
 */
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

/*
 * Initialize by an array with array-length.
 */
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

/*
 * Initialize by an random array.
 */
void mt_init_by_seed_rand_array(void)
{
	int i;
	unsigned long k[LEN_INIT];

	srand((unsigned int) time(NULL));
	for (i = 0; i < LEN_INIT; i++)
		k[i] = rand();
	mt_init_by_seed_array(k, LEN_INIT);
}

/*
 * Generates a random number on the interval [0,0xffffffff]
 */
unsigned long mt_rand_int32(void)
{
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

/*
 * Generates a random number on the interval [0,0x7fffffff]
 */
long mt_rand_int31(void)
{
	return (long) mt_rand_int32() >> 1;
}

/*
 * Generates a random number on the real interval [0,1]
 */
double mt_rand_real1(void)
{
	return mt_rand_int32() * (1.0 / 4294967295.0);
	/* Divided by 2^32-1 */
}

/*
 * Generates a random number on the real interval [0,1)
 */
double mt_rand_real2(void)
{
	return mt_rand_int32() * (1.0 / 4294967296.0);
	/* Divided by 2^32 */
}

/*
 * Generates a random number on the real interval (0,1)
 */
double mt_rand_real3(void)
{
	return (((double) mt_rand_int32()) + 0.5) * (1.0 / 4294967296.0);
	/* Divided by 2^32 */
}

/*
 * Generates a 53-bit random number on the real interval [0,1)
 */
double mt_rand_res53(void)
{
	unsigned long a = mt_rand_int32() >> 5, b = mt_rand_int32() >> 6;
	return (a * 67108864.0 + b) * (1.0 / 9007199254740992.0);
}

