/*
 * Copyright (C) 2009, 2010  Daniel Borkmann <daniel@netsniff-ng.org> and 
 *                           Emmanuel Roullit <emmanuel@netsniff-ng.org>
 *
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation; either version 2 of the License, or (at 
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License 
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
 */

#ifndef	__PROTO_IPV6_H__
#define __PROTO_IPV6_H__

#include <stdint.h>
#include <assert.h>

#include <netinet/in.h>

#include "macros.h"

/*
 *	IPv6 fixed header
 *
 *	BEWARE, it is incorrect. The first 4 bits of flow_lbl
 *	are glued to priority now, forming "class".
 */

/*
 * Bitfield implementation according to ISO C99:
 *    http://gcc.gnu.org/onlinedocs/gcc/Structures-unions-enumerations-and-bit_002dfields-implementation.html
 */

struct ipv6hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	unsigned int priority:4, version:4;	/* FIXME? */
#elif defined(__BIG_ENDIAN_BITFIELD)
	unsigned int version:4, priority:4;	/* FIXME? */
#else
# error	"Please fix <asm/byteorder.h>"
#endif
	__u8 flow_lbl[3];

	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;

	struct in6_addr saddr;
	struct in6_addr daddr;
};

static inline struct ipv6hdr *get_ipv6hdr(uint8_t ** pkt, uint32_t * pkt_len)
{
	struct ipv6hdr *ipv6_header;

	assert(pkt);
	assert(*pkt);
	assert(*pkt_len > sizeof(*ipv6_header));

	ipv6_header = (struct ipv6hdr *)*pkt;

	*pkt += sizeof(*ipv6_header);
	*pkt_len -= sizeof(*ipv6_header);

	return (ipv6_header);
}

static inline uint16_t get_l4_type_from_ipv6(const struct ipv6hdr *header)
{
	assert(header);
	return (header->nexthdr);
}

/*
 * print_ipv6hdr - Just plain dumb formatting
 * @ip:            ip header
 */
/* TODO To improve */
void print_ipv6hdr(struct ipv6hdr *ip)
{
	assert(ip);

	char src_ip[INET6_ADDRSTRLEN] = { 0 };
	char dst_ip[INET6_ADDRSTRLEN] = { 0 };

	if ((ip->version & 0x0110) == 0x0110) {
		info("Version is %u\n", ip->version);
		return;
	}

	inet_ntop(AF_INET6, &ip->saddr, src_ip, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &ip->daddr, dst_ip, INET6_ADDRSTRLEN);

	info(" [ IPv6 ");
	info("Addr (%s => %s), ", src_ip, dst_ip);
	info("Payload len (%u), ", ntohs(ip->payload_len));
	info("Next header (%u), ", ip->nexthdr);
	info("Hop limit (%u), ", ip->hop_limit);

	info(" ] \n");
}

/*
 * print_ipv6hdr_less - Just plain dumb formatting
 * @ip:                ip header
 */
/* TODO To improve */
void print_ipv6hdr_less(struct ipv6hdr *ip)
{
	assert(ip);

	char src_ip[INET6_ADDRSTRLEN] = { 0 };
	char dst_ip[INET6_ADDRSTRLEN] = { 0 };

	inet_ntop(AF_INET6, &ip->saddr, src_ip, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &ip->daddr, dst_ip, INET6_ADDRSTRLEN);

	info("%s => %s, ", src_ip, dst_ip);
}

#endif				/* __PROTO_IPV6_H__ */
