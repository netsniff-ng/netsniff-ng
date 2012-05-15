/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Copyright 2010 Emmanuel Roullit.
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */
#include <arpa/inet.h>     /* for inet_ntop() */
#include <asm/byteorder.h>

#include "proto.h"
#include "protos.h"
#include "csum.h"
#include "dissector_eth.h"
#include "pkt_buff.h"
#include "built_in.h"

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
} __packed;

extern void ipv6(struct pkt_buff *pkt);
extern void ipv6_less(struct pkt_buff *pkt);

void ipv6(struct pkt_buff *pkt)
{
	uint8_t traffic_class;
	uint32_t flow_label;
	char src_ip[INET6_ADDRSTRLEN];
	char dst_ip[INET6_ADDRSTRLEN];
	struct ipv6hdr *ip = (struct ipv6hdr *) pkt_pull(pkt, sizeof(*ip));

	if (ip == NULL)
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

	pkt_set_proto(pkt, &eth_lay3, ip->nexthdr);
}

void ipv6_less(struct pkt_buff *pkt)
{
	char src_ip[INET6_ADDRSTRLEN];
	char dst_ip[INET6_ADDRSTRLEN];
	struct ipv6hdr *ip = (struct ipv6hdr *) pkt_pull(pkt, sizeof(*ip));

	if (ip == NULL)
		return;

	inet_ntop(AF_INET6, &ip->saddr, src_ip, sizeof(src_ip));
	inet_ntop(AF_INET6, &ip->daddr, dst_ip, sizeof(dst_ip));

	tprintf(" %s/%s Len %u", src_ip, dst_ip,
		ntohs(ip->payload_len));

	pkt_set_proto(pkt, &eth_lay3, ip->nexthdr);
}

struct protocol ipv6_ops = {
	.key = 0x86DD,
	.print_full = ipv6,
	.print_less = ipv6_less,
};

EXPORT_SYMBOL(ipv6_ops);
