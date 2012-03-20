/*
 * IPv6 Routing Header described in RFC2460
 * programmed by Markus Amend 2012 as a contribution to
 * netsniff-ng - the packet sniffing beast
 * Copyright 2012 Markus Amend.
 * Subject to the GPL, version 2.
 */

#ifndef ROUTING_H
#define ROUTING_H

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */
#include <arpa/inet.h>     /* for inet_ntop() */

#include "proto_struct.h"
#include "dissector_eth.h"

struct routinghdr {
	uint8_t h_next_header;
	uint8_t h_hdr_ext_len;
	uint8_t h_routing_type;
	uint8_t h_segments_left;
} __attribute__((packed));

static inline void routing(uint8_t *packet, size_t len)
{
	uint8_t hdr_ext_len;
	struct routinghdr *routing = (struct routinghdr *) packet;
	
	hdr_ext_len = (routing->h_hdr_ext_len + 1) * 8;
	if (len < hdr_ext_len || len < sizeof(struct routinghdr))
		return;

	tprintf("\t [ Routing ");
	tprintf("NextHdr (%u), ", routing->h_next_header);
	tprintf("HdrExtLen (%u), ", hdr_ext_len);
	tprintf("Type (%u), ", routing->h_routing_type);
	tprintf("Left (%u), ", routing->h_segments_left);
	if(routing->h_routing_type == 0) {
		char address[INET6_ADDRSTRLEN];
		for (uint8_t i = sizeof(struct routinghdr) + 4;
		     i < hdr_ext_len; i += 16) {
			tprintf("\n\tAdress: ");
			inet_ntop(AF_INET6, &packet[i], address,
				  sizeof(address));
			tprintf("%s %u", address ,INET6_ADDRSTRLEN);
		}
	} else {
		tprintf("Appendix 0x");
		for (uint8_t i = sizeof(struct routinghdr);
		     i < hdr_ext_len; i++)
			tprintf("%02x",(uint8_t) packet[i]);
	}
	tprintf(" ]\n");
}

static inline void routing_less(uint8_t *packet, size_t len)
{
	uint8_t hdr_ext_len;
	struct routinghdr *routing = (struct routinghdr *) packet;

	hdr_ext_len = (routing->h_hdr_ext_len + 1) * 8;
	if (len < hdr_ext_len || len < sizeof(struct routinghdr))
		return;

	tprintf(" Routing Type %u", routing->h_routing_type);
}

static inline void routing_next(uint8_t *packet, size_t len,
			     struct hash_table **table,
			     unsigned int *key, size_t *off)
{
	uint8_t hdr_ext_len;
	struct routinghdr *routing = (struct routinghdr *) packet;

	hdr_ext_len = (routing->h_hdr_ext_len + 1) * 8;
	if (len < hdr_ext_len || len < sizeof(struct routinghdr))
		goto invalid;

	(*off) = hdr_ext_len;
	(*key) = routing->h_next_header;
	(*table) = &eth_lay3;
	return;
invalid:
	(*off) = 0;
	(*key) = 0;
	(*table) = NULL;
}

struct protocol ipv6_routing_ops = {
	.key = 0x2B,
	.print_full = routing,
	.print_less = routing_less,
	.print_pay_ascii = empty,
	.print_pay_hex = empty,
	.print_pay_none = routing,
	.print_all_cstyle = __hex2,
	.print_all_hex = __hex,
	.proto_next = routing_next,
};

#endif /* ROUTING_H */
