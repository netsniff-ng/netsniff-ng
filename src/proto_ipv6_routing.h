/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2012 Markus Amend <markus@netsniff-ng.org>
 * Subject to the GPL, version 2.
 *
 * IPv6 Routing Header described in RFC2460
 */

#ifndef PROTO_IPV6_ROUTING_H
#define PROTO_IPV6_ROUTING_H

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */
#include <arpa/inet.h>     /* for inet_ntop() */

#include "proto_struct.h"
#include "dissector_eth.h"
#include "built_in.h"

#define ROUTING_HEADER_TYPE_0	0x00

struct routinghdr {
	uint8_t h_next_header;
	uint8_t h_hdr_ext_len;
	uint8_t h_routing_type;
	uint8_t h_segments_left;
} __packed;

struct routinghdr_0 {
	uint32_t reserved;
	uint32_t addresses[0];
} __packed;

struct ipv6_adrr {
	uint32_t first_block;
	uint32_t second_block;
	uint32_t third_block;
	uint32_t fourth_block;
} __packed;

static inline void dissect_routinghdr_type_0(struct pkt_buff *pkt,
					     uint8_t *hdr_ext_len)
{
	uint8_t num_addr;
	char address[INET6_ADDRSTRLEN];
	struct ipv6_adrr *addr;
	struct routinghdr_0 *routing_0;

  	routing_0 = (struct routinghdr_0 *) pkt_pull(pkt, sizeof(*routing_0));
	if (routing_0 == NULL)
		return;

	tprintf("Res (%x)", routing_0->reserved);

	num_addr = *hdr_ext_len * 8 / sizeof(*addr);
	while (num_addr--) {
		addr = (struct ipv6_adrr *) pkt_pull(pkt, sizeof(*addr));
		if (addr == NULL)
			return;

		tprintf("\n\t   Address: %s",
			inet_ntop(AF_INET6, addr, address,
				  sizeof(address)));
	}
}

static inline void routing(struct pkt_buff *pkt)
{
	uint8_t hdr_ext_len;
	struct routinghdr *routing;

	routing = (struct routinghdr *) pkt_pull(pkt, sizeof(*routing));

	/* Total Header Length in Bytes */
	hdr_ext_len = (routing->h_hdr_ext_len + 1) * 8;
	if (routing == NULL)
		return;

	tprintf("\t [ Routing ");
	tprintf("NextHdr (%u), ", routing->h_next_header);
	tprintf("HdrExtLen (%u, %u Bytes), ", routing->h_hdr_ext_len,
		hdr_ext_len);
	tprintf("Type (%u), ", routing->h_routing_type);
	tprintf("Left (%u), ", routing->h_segments_left);

	switch (routing->h_routing_type) {
	case ROUTING_HEADER_TYPE_0:
		dissect_routinghdr_type_0(pkt, &routing->h_hdr_ext_len);
		break;
	default:
		tprintf("Type %u is unknown", routing->h_routing_type);
	}

	tprintf(" ]\n");

	pkt_set_proto(pkt, &eth_lay3, routing->h_next_header);
}

static inline void routing_less(struct pkt_buff *pkt)
{
	struct routinghdr *routing;

	routing = (struct routinghdr *) pkt_pull(pkt, sizeof(*routing));
	if (routing == NULL)
		return;

	tprintf(" Routing ");
	tprintf("Addresses (%u)",
		routing->h_hdr_ext_len * 8 / sizeof(struct ipv6_adrr));

	pkt_set_proto(pkt, &eth_lay3, routing->h_next_header);
}

struct protocol ipv6_routing_ops = {
	.key = 0x2B,
	.print_full = routing,
	.print_less = routing_less,
};

#endif /* PROTO_IPV6_ROUTING_H */
