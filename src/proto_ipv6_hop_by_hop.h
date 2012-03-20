/*
 * IPv6 Hop-By-Hop Header described in RFC2460
 * programmed by Markus Amend 2012 as a contribution to
 * netsniff-ng - the packet sniffing beast
 * Copyright 2012 Markus Amend.
 * Subject to the GPL, version 2.
 */

#ifndef HOP_BY_HOP_H
#define HOP_BY_HOP_H

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */

#include "proto_struct.h"
#include "dissector_eth.h"

struct hop_by_hophdr {
	uint8_t h_next_header;
	uint8_t h_hdr_ext_len;
	uint8_t h_hdr_option_type;
} __attribute__((packed));

static inline void hop_by_hop(uint8_t *packet, size_t len)
{
	uint8_t hdr_ext_len;
	struct hop_by_hophdr *hop_by_hop = (struct hop_by_hophdr *) packet;

	hdr_ext_len = (hop_by_hop->h_hdr_ext_len + 1) * 8;
	if (len < hdr_ext_len || len < sizeof(struct hop_by_hophdr))
		return;

	tprintf("\t [ Hop-By-Hop ");
	tprintf("NextHdr (%u), ", hop_by_hop->h_next_header);
	tprintf("HdrExtLen (%u), ", hdr_ext_len);
	tprintf("Opt (%u), ", hop_by_hop->h_hdr_option_type);
	tprintf("Appendix 0x");
	for (uint8_t i = sizeof(struct hop_by_hophdr); i < hdr_ext_len; i++)
		tprintf("%02x",(uint8_t) packet[i]);
	tprintf(" ]\n");
}

static inline void hop_by_hop_less(uint8_t *packet, size_t len)
{
  	uint8_t hdr_ext_len;
	struct hop_by_hophdr *hop_by_hop = (struct hop_by_hophdr *) packet;

	hdr_ext_len = (hop_by_hop->h_hdr_ext_len + 1) * 8;
	if (len < hdr_ext_len || len < sizeof(struct hop_by_hophdr))
		return;

	tprintf(" Hop-By-Hop Opt %u", hop_by_hop->h_hdr_option_type);
}

static inline void hop_by_hop_next(uint8_t *packet, size_t len,
			     struct hash_table **table,
			     unsigned int *key, size_t *off)
{
	uint8_t hdr_ext_len;
	struct hop_by_hophdr *hop_by_hop = (struct hop_by_hophdr *) packet;
	
	hdr_ext_len = (hop_by_hop->h_hdr_ext_len + 1) * 8;
	if (len < hdr_ext_len || len < sizeof(struct hop_by_hophdr))
		goto invalid;

	(*off) = hdr_ext_len;
	(*key) = hop_by_hop->h_next_header;
	(*table) = &eth_lay3;
	return;
invalid:
	(*off) = 0;
	(*key) = 0;
	(*table) = NULL;
}

struct protocol ipv6_hop_by_hop_ops = {
	.key = 0x0,
	.print_full = hop_by_hop,
	.print_less = hop_by_hop_less,
	.print_pay_ascii = empty,
	.print_pay_hex = empty,
	.print_pay_none = hop_by_hop,
	.print_all_cstyle = __hex2,
	.print_all_hex = __hex,
	.proto_next = hop_by_hop_next,
};

#endif /* HOP_BY_HOP_H */
