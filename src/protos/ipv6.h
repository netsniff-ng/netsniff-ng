/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Copyright 2010 Emmanuel Roullit.
 * Subject to the GPL.
 */

#ifndef IPV6_H
#define IPV6_H

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */
#include <arpa/inet.h>     /* for inet_ntop() */
#include <asm/byteorder.h>

#include "csum.h"
#include "proto_struct.h"
#include "dissector_eth.h"

/*
 * IPv6 fixed header
 *
 * BEWARE, it is incorrect. The first 4 bits of flow_lbl
 * are glued to priority now, forming "class".
 */
struct ipv6hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__extension__ uint8_t priority:4,
			      version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__extension__ uint8_t version:4,
			      priority:4;
#else
# error	"Please fix <asm/byteorder.h>"
#endif
	uint8_t flow_lbl[3];
	uint16_t payload_len;
	uint8_t nexthdr;
	uint8_t hop_limit;
	struct in6_addr saddr;
	struct in6_addr daddr;
} __attribute__((packed));

static inline void ipv6(uint8_t *packet, size_t len)
{
	uint8_t traffic_class;
	uint32_t flow_label;
	char src_ip[INET6_ADDRSTRLEN];
	char dst_ip[INET6_ADDRSTRLEN];
	struct ipv6hdr *ip = (struct ipv6hdr *) packet;

	if (len < sizeof(struct ipv6hdr))
		return;

	traffic_class = (ip->priority << 4) | 
			((ip->flow_lbl[0] & 0xF0) >> 4);
	flow_label = ((ip->flow_lbl[0] & 0x0F) << 8) |
		     (ip->flow_lbl[1] << 4) | ip->flow_lbl[2];

	inet_ntop(AF_INET6, &ip->saddr, src_ip, sizeof(src_ip));
	inet_ntop(AF_INET6, &ip->daddr, dst_ip, sizeof(dst_ip));

	tprintf(" [ IPv6 ");
	tprintf("Addr (%s => %s), ", src_ip, dst_ip);
	tprintf("Version (%u), ", ip->version);
	tprintf("TrafficClass (%u), ", traffic_class);
	tprintf("FlowLabel (%u), ", flow_label);
	tprintf("Len (%u), ", ntohs(ip->payload_len));
	tprintf("NextHdr (%u), ", ip->nexthdr);
	tprintf("HopLimit (%u)", ip->hop_limit);
	tprintf(" ]\n");
}

static inline void ipv6_less(uint8_t *packet, size_t len)
{
	char src_ip[INET6_ADDRSTRLEN];
	char dst_ip[INET6_ADDRSTRLEN];
	struct ipv6hdr *ip = (struct ipv6hdr *) packet;

	if (len < sizeof(struct ipv6hdr))
		return;

	inet_ntop(AF_INET6, &ip->saddr, src_ip, sizeof(src_ip));
	inet_ntop(AF_INET6, &ip->daddr, dst_ip, sizeof(dst_ip));

	tprintf(" IPv6 %s/%s Len %u", src_ip, dst_ip,
		ntohs(ip->payload_len));
}

static inline void ipv6_next(uint8_t *packet, size_t len,
			     struct hash_table **table,
			     unsigned int *key, size_t *off)
{
	struct ipv6hdr *ip = (struct ipv6hdr *) packet;

	if (len < sizeof(struct ipv6hdr))
		goto invalid;

	(*off) = sizeof(struct ipv6hdr);
	(*key) = ip->nexthdr;
	(*table) = &ethernet_level3;

	return;
invalid:
	(*off) = 0;
	(*key) = 0;
	(*table) = NULL;
}

struct protocol ipv6_ops = {
	.key = 0x86DD,
	.print_full = ipv6,
	.print_less = ipv6_less,
	.proto_next = ipv6_next,
};

#endif /* IPV6_H */
