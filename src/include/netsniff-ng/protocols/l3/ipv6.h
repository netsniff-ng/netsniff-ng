/* XXX: Coding Style - use the tool indent with the following (Linux kernel
 *                     code indents)
 *
 * indent -nbad -bap -nbc -bbo -hnl -br -brs -c33 -cd33 -ncdb -ce -ci4   \
 *        -cli0 -d0 -di1 -nfc1 -i8 -ip0 -l120 -lp -npcs -nprs -npsl -sai \
 *        -saf -saw -ncs -nsc -sob -nfca -cp33 -ss -ts8 -il1
 *
 *
 * netsniff-ng
 *
 * High performance network sniffer for packet inspection
 *
 * Copyright (C) 2009, 2010  Daniel Borkmann <danborkmann@googlemail.com> and 
 *                           Emmanuel Roullit <emmanuel.roullit@googlemail.com>
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
 *
 * Note: Your kernel has to be compiled with CONFIG_PACKET_MMAP=y option in 
 *       order to use this.
 */

#ifndef	__PROTO_IPV6_H__
#define __PROTO_IPV6_H__

#include <stdint.h>
#include <assert.h>

#include <netinet/in.h>
/*
 *	IPv6 fixed header
 *
 *	BEWARE, it is incorrect. The first 4 bits of flow_lbl
 *	are glued to priority now, forming "class".
 */

struct ipv6hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8 priority:4, version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8 version:4, priority:4;
#else
#error	"Please fix <asm/byteorder.h>"
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

#endif				/* __PROTO_IPV6_H__ */
