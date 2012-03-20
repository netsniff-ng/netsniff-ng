/*
 * IPv6 Mobility Header described in RFC6275
 * programmed by Markus Amend 2012 as a contribution to
 * netsniff-ng - the packet sniffing beast
 * Copyright 2012 Markus Amend.
 * Subject to the GPL, version 2.
 */

#ifndef MOBILITY_HEADER_H
#define MOBILITY_HEADER_H

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */

#include "proto_struct.h"
#include "dissector_eth.h"

struct mobilityhdr {
	uint8_t h_next_header;
	uint8_t h_hdr_ext_len;
	uint8_t h_MH_type;
	uint8_t h_reserved;
	uint16_t h_checksum;
} __attribute__((packed));

static inline void mobility(uint8_t *packet, size_t len)
{
	uint8_t hdr_ext_len;	
	struct mobilityhdr *mobility = (struct mobilityhdr *) packet;
	
	hdr_ext_len = (mobility->h_hdr_ext_len + 1) * 8;
	if (len < hdr_ext_len || len < sizeof(struct mobilityhdr))
		return;

	tprintf("\t [ Mobility Header ");
	tprintf("NextHdr (%u), ", mobility->h_next_header);
	tprintf("HdrLen (%u), ", hdr_ext_len);
	tprintf("MH (%u), ", mobility->h_MH_type);
	tprintf("Res (0x%x), ", mobility->h_reserved);
	tprintf("Chk (0x%x), ", ntohs(mobility->h_checksum));
	tprintf("Appendix 0x");
	for (uint8_t i = sizeof(struct mobilityhdr); i < hdr_ext_len; i++)
		tprintf("%02x",(uint8_t) packet[i]);
	tprintf(" ]\n");
}

static inline void mobility_less(uint8_t *packet, size_t len)
{
  	uint8_t hdr_ext_len;
	struct mobilityhdr *mobility = (struct mobilityhdr *) packet;
	
	hdr_ext_len = (mobility->h_hdr_ext_len + 1) * 8;
	if (len < hdr_ext_len || len < sizeof(struct mobilityhdr))
		return;

	tprintf(" MH Type %u", mobility->h_MH_type);
}

static inline void mobility_next(uint8_t *packet, size_t len,
			     struct hash_table **table,
			     unsigned int *key, size_t *off)
{
	uint8_t hdr_ext_len;	
	struct mobilityhdr *mobility = (struct mobilityhdr *) packet;

	hdr_ext_len = (mobility->h_hdr_ext_len + 1) * 8;	
	if (len < hdr_ext_len || len < sizeof(struct mobilityhdr))
		return;

	(*off) = hdr_ext_len;
	(*key) = mobility->h_next_header;
	(*table) = &eth_lay3;
}

struct protocol ipv6_mobility_hdr_ops = {
	.key = 0x87,
	.print_full = mobility,
	.print_less = mobility_less,
	.print_pay_ascii = empty,
	.print_pay_hex = empty,
	.print_pay_none = mobility,
	.print_all_cstyle = __hex2,
	.print_all_hex = __hex,
	.proto_next = mobility_next,
};

#endif /* MOBILITY_HEADER_H */
