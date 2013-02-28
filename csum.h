/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2010 Emmanuel Roullit.
 * Subject to the GPL, version 2.
 */

#ifndef CSUM_H
#define	CSUM_H

#include <netinet/in.h>

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

static inline uint16_t calc_csum(void *addr, size_t len, int ccsum)
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

#endif /* CSUM_H */
