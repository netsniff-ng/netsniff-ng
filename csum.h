#ifndef CSUM_H
#define	CSUM_H

#include <netinet/in.h>
#include <netinet/ip.h>

#include "built_in.h"

static inline unsigned short csum(unsigned short *buf, int nwords)
{
	unsigned long sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return ~sum;
}

static inline uint16_t calc_csum(void *addr, size_t len,
				 int ccsum __maybe_unused)
{
	return csum(addr, len >> 1);
}

static inline uint16_t csum_expected(uint16_t sum, uint16_t computed_sum)
{
	uint32_t shouldbe;

	shouldbe = sum;
	shouldbe += ntohs(computed_sum);
	shouldbe = (shouldbe & 0xFFFF) + (shouldbe >> 16);
	shouldbe = (shouldbe & 0xFFFF) + (shouldbe >> 16);

	return shouldbe;
}

/* Taken and modified from tcpdump, Copyright belongs to them! */

struct cksum_vec {
	const u8 *ptr;
	int len;
};

#define ADDCARRY(x)		\
	do { if ((x) > 65535)	\
		(x) -= 65535;	\
	} while (0)

#define REDUCE						\
	do {						\
		l_util.l = sum;				\
		sum = l_util.s[0] + l_util.s[1];	\
		ADDCARRY(sum);				\
	} while (0)

static inline u16 __in_cksum(const struct cksum_vec *vec, int veclen)
{
	const u16 *w;
	int sum = 0, mlen = 0;
	int byte_swapped = 0;
	union {
		u8 c[2];
		u16 s;
	} s_util;
	union {
		u16 s[2];
		u32 l;
	} l_util;

	for (; veclen != 0; vec++, veclen--) {
		if (vec->len == 0)
			continue;

		w = (const u16 *) (void *) vec->ptr;

		if (mlen == -1) {
			s_util.c[1] = *(const u8 *) w;
			sum += s_util.s;
			w = (const u16 *) (void *) ((const u8 *) w + 1);
			mlen = vec->len - 1;
		} else
			mlen = vec->len;

		if ((1 & (unsigned long) w) && (mlen > 0)) {
			REDUCE;
			sum <<= 8;
			s_util.c[0] = *(const u8 *) w;
			w = (const u16 *) (void *) ((const u8 *) w + 1);
			mlen--;
			byte_swapped = 1;
		}

		while ((mlen -= 32) >= 0) {
			sum +=  w[0]; sum +=  w[1]; sum +=  w[2]; sum +=  w[3];
			sum +=  w[4]; sum +=  w[5]; sum +=  w[6]; sum +=  w[7];
			sum +=  w[8]; sum +=  w[9]; sum += w[10]; sum += w[11];
			sum += w[12]; sum += w[13]; sum += w[14]; sum += w[15];
			w += 16;
		}

		mlen += 32;

		while ((mlen -= 8) >= 0) {
			sum += w[0]; sum += w[1]; sum += w[2]; sum += w[3];
			w += 4;
		}

		mlen += 8;

		if (mlen == 0 && byte_swapped == 0)
			continue;

		REDUCE;

		while ((mlen -= 2) >= 0) {
			sum += *w++;
		}

		if (byte_swapped) {
			REDUCE;
			sum <<= 8;
			byte_swapped = 0;

			if (mlen == -1) {
				s_util.c[1] = *(const u8 *) w;
				sum += s_util.s;
				mlen = 0;
			} else
				mlen = -1;
		} else if (mlen == -1)
			s_util.c[0] = *(const u8 *) w;
	}

	if (mlen == -1) {
		s_util.c[1] = 0;
		sum += s_util.s;
	}

	REDUCE;

	return (~sum & 0xffff);
}

static inline u16 p4_csum(const struct ip *ip, const u8 *data, u16 len,
			  u8 next_proto)
{
	struct cksum_vec vec[2];
	struct pseudo_hdr {
		u32 src;
		u32 dst;
		u8 mbz;
		u8 proto;
		u16 len;
	} ph;

	memset(&ph, 0, sizeof(ph));
	ph.len = htons(len);
	ph.mbz = 0;
	ph.proto = next_proto;
	ph.src = ip->ip_src.s_addr;
	ph.dst = ip->ip_dst.s_addr;

	vec[0].ptr = (const u8 *) (void *) &ph;
	vec[0].len = sizeof(ph);

	vec[1].ptr = data;
	vec[1].len = len;

	return __in_cksum(vec, 2);
}

#endif /* CSUM_H */
