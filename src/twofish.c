/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

/*
 * Copyright 1999 Dr. Brian Gladman <brian.gladman@btinternet.com>
 * Copyright 2001 Abhijit Menon-Sen <ams@wiw.org>
 *
 * This module is free software; you can redistribute it and/or modify
 * it under the same terms as Perl itself.
 *
 * Used for pcap packet payload encryption.
 */

#include <stdio.h>

#include "twofish.h"
#include "twofish_tables.h"
#include "xmalloc.h"

/* Extract the n'th byte from a 32-bit word */
#define byte(x,n) ((unsigned char)((x) >> (8 * n)))

/* 32 bit rotate-left and right macros */
#define ror(x,n) (((x) >> ((int)(n))) | ((x) << (32 - (int)(n))))
#define rol(x,n) (((x) << ((int)(n))) | ((x) >> (32 - (int)(n))))

/* Endian-independent byte -> word conversion */
#define strtonl(s) (uint32_t)(*(s)|*(s+1)<<8|*(s+2)<<16|*(s+3)<<24)

#define nltostr(l, s)                               \
	do {                                        \
		*(s  )=(unsigned char)((l)      );  \
		*(s+1)=(unsigned char)((l) >>  8);  \
		*(s+2)=(unsigned char)((l) >> 16);  \
		*(s+3)=(unsigned char)((l) >> 24);  \
	} while (0)

static uint32_t mds_rem(uint32_t a, uint32_t b);
static uint32_t h(int len, const int x, unsigned char *key, int odd);

/*
 * The key schedule takes a 128, 192, or 256-bit key, and provides 40
 * 32-bit words of expanded key K0,...,K39 and the 4 key-dependent
 * S-boxes used in the g function.
 */
struct twofish *twofish_setup(unsigned char *key, int len)
{
	int i;
	uint32_t a, b, x;
	struct twofish *t;
	unsigned char *s, skey[16];

	t = xmalloc(sizeof(struct twofish));

	/* The key consists of k=len/8 (2, 3 or 4) 64-bit units. */
	t->len = len /= 8;

	/*
	 * We must derive three vectors Me, Mo, and S, each with k 32-bit
	 * words, from the 2k words in the key.
	 *
	 * Me = (key[0], key[2], ..., key[2k-2]) (even words)
	 * Mo = (key[1], key[3], ..., key[2k-1]) (odd  words)
	 *
	 * The third vector is derived by multiplying each of the k groups
	 * of 8 bytes from the key by a 4x8 matrix, to get k 32-bit words.
	 *
	 * S = (S[k-1], S[k-2], ..., S[0])
	 *
	 * where S[i] are the 4 bytes from the multiplication, interpreted
	 * as a 32-bit word. As described later, mds_rem is equivalent to
	 * the matrix multiplication, but faster.
	 *
	 * Since all these vectors are going to be used byte-by-byte, we
	 * avoid converting them to words altogether, and write the bytes of
	 * S into the array skey below:
	 */

	s = skey + 4*(len - 1);
	for (i = 0; i < len; i++) {
		x = mds_rem(strtonl(key+8*i), strtonl(key+8*i+4));
		nltostr(x, s);
		s -= 4;
	}
	s = skey;

	/*
	 * The words of the expanded key K are defined using the h function:
	 *
	 *  rho     = 2^24 + 2^16 + 2^8 + 2^0 (0x01010101)
	 *  A[i]    = h(2i*rho, Me)
	 *  B[i]    = ROL(h(2(i+1)*rho, Mo), 8)
	 *  K[2i]   = (A[i] + B[i]) mod 2^32
	 *  K[2i+1] = ROL((A[i] + 2B[i]) mod 2^32, 9)
	 *
	 * rho has the property that, for i = 0..255, the word i*rho
	 * consists of four equal bytes, each with the value i. The function
	 * h is only applied to words of this type, so we only pass it the
	 * value of i.
	 *
	 * We also didn't generate the vectors Me and Mo separately: we pass
	 * the entire key, and indicate whether we want the even or odd
	 * words to be used.
	 */

	for (i = 0; i < 40; i += 2) {
		a = h(len, i, key, 0);
		b = rol(h(len, i+1, key, 1), 8);

		t->K[i]   = a+b;
		t->K[i+1] = rol(a+2*b, 9);
	} 

	/*
	 * The key-dependent S-boxes used in the g() function are created
	 * below. They are defined by g(X) = h(X, S), where S is the vector
	 * derived from the key. That is, for i=0..3, the S-box S[i] is
	 * formed by mapping from x[i] to y[i] in the h function.
	 *
	 * The relevant lookup tables qN have been precomputed and stored in
	 * tables.h; we also perform full key precomputations incorporating
	 * the MDS matrix multiplications.
	 */

	switch (len) {
	case 2:
		for (i = 0; i < 256; i++) {
			x = (unsigned char)i;
			t->S[0][i] = m[0][q[0][q[0][x]^s[4]]^s[0]];
			t->S[1][i] = m[1][q[0][q[1][x]^s[5]]^s[1]];
			t->S[2][i] = m[2][q[1][q[0][x]^s[6]]^s[2]];
			t->S[3][i] = m[3][q[1][q[1][x]^s[7]]^s[3]];
		}
		break;
	case 3:
		for (i = 0; i < 256; i++) {
			x = (unsigned char)i;
			t->S[0][i] = m[0][q[0][q[0][q[1][x]^s[ 8]]^s[4]]^s[0]];
			t->S[1][i] = m[1][q[0][q[1][q[1][x]^s[ 9]]^s[5]]^s[1]];
			t->S[2][i] = m[2][q[1][q[0][q[0][x]^s[10]]^s[6]]^s[2]];
			t->S[3][i] = m[3][q[1][q[1][q[0][x]^s[11]]^s[7]]^s[3]];

		}
		break;
	case 4:
		for (i = 0; i < 256; i++) {
			x = (unsigned char)i;
			t->S[0][i] = m[0][q[0][q[0][q[1][q[1][x]^s[12]]^s[ 8]]^s[4]]^s[0]];
			t->S[1][i] = m[1][q[0][q[1][q[1][q[0][x]^s[13]]^s[ 9]]^s[5]]^s[1]];
			t->S[2][i] = m[2][q[1][q[0][q[0][q[0][x]^s[14]]^s[10]]^s[6]]^s[2]];
			t->S[3][i] = m[3][q[1][q[1][q[0][q[1][x]^s[15]]^s[11]]^s[7]]^s[3]];
		}
		break;
	}

	return t;
}

void twofish_free(struct twofish *self)
{
	xfree(self);
}

/*
 * The function g splits the input word x into four bytes; each byte is
 * run through its own key-dependent S-box. Each S-box is bijective,
 * takes 8 bits of input and produces 8 bits of output. The four results
 * are interpreted as a vector of length 4 over GF(2^8), and multiplied
 * by the 4x4 MDS matrix. The resulting vector is interpreted as a
 * 32-bit word.
 *
 * Since we have performed the full key precomputations, g consists only
 * of four lookups and three XORs. g0 is g; g1 is a shortcut for
 * g(ROL(x, 8)).
 */

#define g0(x) \
    t->S[0][byte(x,0)]^t->S[1][byte(x,1)]^t->S[2][byte(x,2)]^t->S[3][byte(x,3)]

#define g1(x) \
    t->S[0][byte(x,3)]^t->S[1][byte(x,0)]^t->S[2][byte(x,1)]^t->S[3][byte(x,2)]

/*
 * F is a key-dependent permutation on 64-bit values. It takes two input
 * words R0 and R1, and a round number r:
 *
 *      T0 = g(R0)
 *      T1 = g(ROL(R1, 8))
 *      F0 = (T0 + T1 + K[2r+8])
 *      F1 = (T0 + 2*T1 + K[2r+9])
 *
 * Each of the 16 encryption rounds consists of the following operations:
 *
 *      (F0, F1) = F(R0, R1, r)
 *      R0       = ROR(R2 ^ F0, 1)
 *      R1       = ROL(R3, 1) ^ F1
 *      R2       = R0
 *      R3       = R1
 *
 * For efficiency, two rounds are combined into one in the macros below.
 */

#define f_2rounds(i)                                        \
	t0   = g0(R[0]);                                    \
	t1   = g1(R[1]);                                    \
	R[2] = ror(R[2] ^ (t0 + t1 + t->K[4*i+8]), 1);      \
	R[3] = rol(R[3], 1) ^ (t0 + 2*t1 + t->K[4*i+9]);    \
	t0   = g0(R[2]);                                    \
	t1   = g1(R[3]);                                    \
	R[0] = ror(R[0] ^ (t0 + t1 + t->K[4*i+10]), 1);     \
	R[1] = rol(R[1], 1) ^ (t0 + 2*t1 + t->K[4*i+11]);

/* This is the inverse of f_2rounds */
#define i_2rounds(i)                                        \
	t0   = g0(R[0]);                                    \
	t1   = g1(R[1]);                                    \
	R[2] = rol(R[2], 1) ^ (t0 + t1 + t->K[4*i+10]);     \
	R[3] = ror(R[3] ^ (t0 + 2*t1 + t->K[4*i+11]), 1);   \
	t0   = g0(R[2]);                                    \
	t1   = g1(R[3]);                                    \
	R[0] = rol(R[0], 1) ^ (t0 + t1 + t->K[4*i+8]);      \
	R[1] = ror(R[1] ^ (t0 + 2*t1 + t->K[4*i+9]), 1)

/*
 * This function encrypts or decrypts 16 bytes of input data and writes
 * it to output, using the key defined in t.
 */
void twofish_crypt(struct twofish *t, unsigned char *input,
		   unsigned char *output, int decrypt)
{
	uint32_t t0, t1, R[4], out[4];

	if (!decrypt) {
		/* Whiten four 32-bit input words. */
		R[0] = t->K[0] ^ strtonl(input);
		R[1] = t->K[1] ^ strtonl(input+4);
		R[2] = t->K[2] ^ strtonl(input+8);
		R[3] = t->K[3] ^ strtonl(input+12);

		/* 16 rounds of encryption, combined into 8 pairs. */
		f_2rounds(0); f_2rounds(1); f_2rounds(2); f_2rounds(3);
		f_2rounds(4); f_2rounds(5); f_2rounds(6); f_2rounds(7);

		/* Output whitening; The order of R[n] undoes the last swap. */
		out[0] = t->K[4] ^ R[2];
		out[1] = t->K[5] ^ R[3];
		out[2] = t->K[6] ^ R[0];
		out[3] = t->K[7] ^ R[1];
	} else {
		R[0] = t->K[4] ^ strtonl(input);
		R[1] = t->K[5] ^ strtonl(input+4);
		R[2] = t->K[6] ^ strtonl(input+8);
		R[3] = t->K[7] ^ strtonl(input+12);

		i_2rounds(7); i_2rounds(6); i_2rounds(5); i_2rounds(4);
		i_2rounds(3); i_2rounds(2); i_2rounds(1); i_2rounds(0);

		out[0] = t->K[0] ^ R[2];
		out[1] = t->K[1] ^ R[3];
		out[2] = t->K[2] ^ R[0];
		out[3] = t->K[3] ^ R[1];
	}

	/* Write 16 output bytes. */
	nltostr(out[0], output);
	nltostr(out[1], output+4);
	nltostr(out[2], output+8);
	nltostr(out[3], output+12);
}

/*
 * h takes a 32-bit word X, and a list, L = (L[0],...,L[k-1]), of 32-bit
 * words, and produces one word of output. During each of the k stages
 * of the function, the four bytes from X are each passed through a
 * fixed S-box, and XORed with a byte derived from the list. Finally,
 * the bytes are once again passed through an S-box and multiplied by
 * the MDS matrix, just as in g.
 *
 * We use the Lbyte macro to extract a given byte from the list L
 * (expressed in little endian).
 */

#define Lbyte(w, b) L[4*(2*w+odd)+b]

static uint32_t h(int len, const int X, unsigned char *L, int odd)
{
	unsigned char b0, b1, b2, b3;

	b0 = b1 = b2 = b3 = (unsigned char)X;

	switch (len) {
	case 4:
		b0 = q[1][b0] ^ Lbyte(3, 0);
		b1 = q[0][b1] ^ Lbyte(3, 1);
		b2 = q[0][b2] ^ Lbyte(3, 2);
		b3 = q[1][b3] ^ Lbyte(3, 3);
	case 3:
		b0 = q[1][b0] ^ Lbyte(2, 0);
		b1 = q[1][b1] ^ Lbyte(2, 1);
		b2 = q[0][b2] ^ Lbyte(2, 2);
		b3 = q[0][b3] ^ Lbyte(2, 3);
	case 2:
		b0 = q[0][q[0][b0] ^ Lbyte(1, 0)] ^ Lbyte(0, 0);
		b1 = q[0][q[1][b1] ^ Lbyte(1, 1)] ^ Lbyte(0, 1);
		b2 = q[1][q[0][b2] ^ Lbyte(1, 2)] ^ Lbyte(0, 2);
		b3 = q[1][q[1][b3] ^ Lbyte(1, 3)] ^ Lbyte(0, 3);
	}

	return m[0][b0] ^ m[1][b1] ^ m[2][b2] ^ m[3][b3];
}

/*
 * The (12, 8) Reed Solomon code has the generator polynomial:
 *
 *      g(x) = x^4 + (a + 1/a) * x^3 + a * x^2 + (a + 1/a) * x + 1
 *
 * where the coefficients are in the finite field GF(2^8) with a modular
 * polynomial a^8+a^6+a^3+a^2+1. To generate the remainder, we have to
 * start with a 12th order polynomial with our eight input bytes as the
 * coefficients of the 4th to 11th terms:
 *
 *      m[7] * x^11 + m[6] * x^10 ... + m[0] * x^4 + 0 * x^3 +... + 0
 *
 * We then multiply the generator polynomial by m[7]*x^7 and subtract it
 * (XOR in GF(2^8)) from the above to eliminate the x^7 term (the
 * arithmetic on the coefficients is done in GF(2^8)). We then multiply
 * the generator polynomial by m[6]*x^6 and use this to remove the x^10
 * term, and so on until the x^4 term is removed, and we are left with:
 *
 *      r[3] * x^3 + r[2] * x^2 + r[1] 8 x^1 + r[0]
 *
 * which give the resulting 4 bytes of the remainder. This is equivalent
 * to the matrix multiplication described in the Twofish paper, but is
 * much faster.
 */

static uint32_t mds_rem(uint32_t a, uint32_t b)
{
	int i;
	uint32_t t, u;
	enum { G_MOD = 0x0000014d };

	for (i = 0; i < 8; i++) {
		/* Get most significant coefficient */
		t = b >> 24;

		/* Shift the others up */
		b = (b << 8) | (a >> 24);
		a <<= 8;

		u = t << 1;

		/* Subtract the modular polynomial on overflow */
		if (t & 0x80)
			u ^= G_MOD;

		/* Remove t * (a * x^2 + 1) */
		b ^= t ^ (u << 16);

		/* Form u = a*t + t/a = t*(a + 1/a) */
		u ^= t >> 1;

		/* Add the modular polynomial on underflow */
		if (t & 0x01)
			u ^= G_MOD >> 1;

		/* Remove t * (a + 1/a) * (x^3 + x) */
		b ^= (u << 24) | (u << 8);
	}

	return b;
}
