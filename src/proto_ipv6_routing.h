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
#include <netinet/in.h>    /* for ntohs() and "struct in6_addr" */
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

static inline void dissect_routinghdr_type_0(struct pkt_buff *pkt,
					     uint16_t *data_len, int less)
{
	uint8_t num_addr;
	char address[INET6_ADDRSTRLEN];
	struct in6_addr *addr;
	struct routinghdr_0 *routing_0;

  	routing_0 = (struct routinghdr_0 *) pkt_pull(pkt, sizeof(*routing_0));
	*data_len -= sizeof(*routing_0);
	if (routing_0 == NULL || *data_len > pkt_len(pkt))
		return;

	if (less) {
		tprintf("Addresses (%u)", *data_len / sizeof(struct in6_addr));
		return;
	}

	tprintf("Res (0x%x)", routing_0->reserved);

	num_addr = *data_len / sizeof(*addr);

	while (num_addr--) {
		addr = (struct in6_addr *) pkt_pull(pkt, sizeof(*addr));
		*data_len -= sizeof(*addr);
		if (addr == NULL || *data_len > pkt_len(pkt))
			return;

		tprintf("\n\t   Address: %s",
			inet_ntop(AF_INET6, addr, address,
				  sizeof(address)));
	}
}

static inline void dissect_routinghdr_type_0_norm(struct pkt_buff *pkt,
						  uint16_t *data_len)
{
	dissect_routinghdr_type_0(pkt, data_len, 0);
}

static inline void dissect_routinghdr_type_0_less(struct pkt_buff *pkt,
						  uint16_t *data_len)
{
	dissect_routinghdr_type_0(pkt, data_len, 1);
}

static inline void routing(struct pkt_buff *pkt)
{
	uint16_t hdr_ext_len, data_len;
	struct routinghdr *routing;

	routing = (struct routinghdr *) pkt_pull(pkt, sizeof(*routing));

	/* Total Header Length in Bytes */
	hdr_ext_len = (routing->h_hdr_ext_len + 1) * 8;
	/* Data length in Bytes */
	data_len = hdr_ext_len - sizeof(*routing);
	if (routing == NULL || data_len > pkt_len(pkt))
		return;

	tprintf("\t [ Routing ");
	tprintf("NextHdr (%u), ", routing->h_next_header);
	tprintf("HdrExtLen (%u, %u Bytes), ", routing->h_hdr_ext_len,
		hdr_ext_len);
	tprintf("Type (%u), ", routing->h_routing_type);
	tprintf("Left (%u), ", routing->h_segments_left);

	switch (routing->h_routing_type) {
	case ROUTING_HEADER_TYPE_0:
		dissect_routinghdr_type_0_norm(pkt, &data_len);
		break;
	default:
		tprintf("Type %u is unknown", routing->h_routing_type);
	}

	tprintf(" ]\n");

	pkt_pull(pkt, data_len);
	pkt_set_proto(pkt, &eth_lay3, routing->h_next_header);
}

static inline void routing_less(struct pkt_buff *pkt)
{
	uint16_t hdr_ext_len, data_len;
	struct routinghdr *routing;

	routing = (struct routinghdr *) pkt_pull(pkt, sizeof(*routing));

	/* Total Header Length in Bytes */
	hdr_ext_len = (routing->h_hdr_ext_len + 1) * 8;
	/* Data length in Bytes */
	data_len = hdr_ext_len - sizeof(*routing);
	if (routing == NULL || data_len > pkt_len(pkt))
		return;

	tprintf(" Routing ");
	
	switch (routing->h_routing_type) {
	case ROUTING_HEADER_TYPE_0:
		dissect_routinghdr_type_0_less(pkt, &data_len);
		break;
	default:
		tprintf("Type %u is unknown", routing->h_routing_type);
	}

	pkt_pull(pkt, data_len);
	pkt_set_proto(pkt, &eth_lay3, routing->h_next_header);
}

struct protocol ipv6_routing_ops = {
	.key = 0x2B,
	.print_full = routing,
	.print_less = routing_less,
};

#endif /* PROTO_IPV6_ROUTING_H */
