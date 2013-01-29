/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2010 Emmanuel Roullit.
 * Subject to the GPL, version 2.
 */

#ifndef CSUM_H
#define	CSUM_H

#include <netinet/in.h>    /* for htons() */

/* Shamelessly taken and adapted from tcpdump */

/*
 * Compute an IP header checksum.
 * Don't modifiy the packet.
 */
static inline uint16_t calc_csum(void *addr, size_t len, int csum)
{
	int nleft = len;
	int sum = csum;
	uint16_t answer;
	const uint16_t *w = (const uint16_t *) addr;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum),
	 * we add sequential 16 bit words to it, and at the end, fold
	 * back all the carry bits from the top 16 bits into the lower
	 * 16 bits.
	 */
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
		sum += htons(*(const uint8_t *) w << 8);

	/*
	 * Add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xFFFF); /* add hi 16 to low 16 */
	sum += (sum >> 16);                 /* add carry */
	answer = ~sum;                      /* truncate to 16 bits */

	return answer;
}

/*
 * Given the host-byte-order value of the checksum field in a packet
 * header, and the network-byte-order computed checksum of the data
 * that the checksum covers (including the checksum itself), compute
 * what the checksum field *should* have been.
 */
static inline uint16_t csum_expected(uint16_t sum, uint16_t computed_sum)
{
	uint32_t shouldbe;

	/*
	 * The value that should have gone into the checksum field
	 * is the negative of the value gotten by summing up everything
	 * *but* the checksum field.
	 *
	 * We can compute that by subtracting the value of the checksum
	 * field from the sum of all the data in the packet, and then
	 * computing the negative of that value.
	 *
	 * "sum" is the value of the checksum field, and "computed_sum"
	 * is the negative of the sum of all the data in the packets,
	 * so that's -(-computed_sum - sum), or (sum + computed_sum).
	 *
	 * All the arithmetic in question is one's complement, so the
	 * addition must include an end-around carry; we do this by
	 * doing the arithmetic in 32 bits (with no sign-extension),
	 * and then adding the upper 16 bits of the sum, which contain
	 * the carry, to the lower 16 bits of the sum, and then do it
	 * again in case *that* sum produced a carry.
	 *
	 * As RFC 1071 notes, the checksum can be computed without
	 * byte-swapping the 16-bit words; summing 16-bit words
	 * on a big-endian machine gives a big-endian checksum, which
	 * can be directly stuffed into the big-endian checksum fields
	 * in protocol headers, and summing words on a little-endian
	 * machine gives a little-endian checksum, which must be
	 * byte-swapped before being stuffed into a big-endian checksum
	 * field.
	 *
	 * "computed_sum" is a network-byte-order value, so we must put
	 * it in host byte order before subtracting it from the
	 * host-byte-order value from the header; the adjusted checksum
	 * will be in host byte order, which is what we'll return.
	 */

	shouldbe = sum;
	shouldbe += ntohs(computed_sum);
	shouldbe = (shouldbe & 0xFFFF) + (shouldbe >> 16);
	shouldbe = (shouldbe & 0xFFFF) + (shouldbe >> 16);

	return shouldbe;
}

static inline uint16_t tcp_sum_calc(uint16_t len_tcp, uint16_t src_addr[], 
				    uint16_t dest_addr[], uint8_t padding,
				    uint16_t buff[])
{
	uint32_t i;
	uint16_t padd = 0;
	uint16_t word16;
	uint32_t sum = 0;
	uint16_t prot_tcp = IPPROTO_TCP;

	/*
	 * Find out if the length of data is even or odd number. If odd,
	 * add a padding byte = 0 at the end of packet.
	 */
	if ((padding & 1) == 1) {
		padd = 1;
		buff[len_tcp] = 0;
	}

	/*
	 * Make 16 bit words out of every two adjacent 8 bit words and 
	 * calculate the sum of all 16 vit words.
	 */
	for (i = 0; i < len_tcp + padd; i = i + 2) {
		word16 = ((buff[i] << 8) & 0xFF00) + (buff[i + 1] & 0xFF);
		sum += (unsigned long) word16;
	}

	/*
	 * Add the TCP pseudo header which contains: the IP source and 
	 * destinationn addresses.
	 */
	for (i = 0; i < 4; i = i + 2) {
		word16 = ((src_addr[i] << 8) & 0xFF00) +
			 (src_addr[i + 1] & 0xFF);
		sum += word16;
	}

	for (i = 0; i < 4; i = i + 2) {
		word16 = ((dest_addr[i] << 8) & 0xFF00) +
			 (dest_addr[i + 1] & 0xFF);
		sum += word16;
	}

	/* The protocol number and the length of the TCP packet. */
	sum += (prot_tcp + len_tcp);

	/*
	 * Keep only the last 16 bits of the 32 bit calculated sum and 
	 * add the carries.
	 */
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	/* Take the one's complement of sum. */
	sum = ~sum;

	return (uint16_t) sum;
}

#endif /* CSUM_H */
