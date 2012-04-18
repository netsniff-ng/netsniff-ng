/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2012 Markus Amend <markus@netsniff-ng.org>
 * Subject to the GPL, version 2.
 *
 * IPv6 Fragmentation Header described in RFC2460
 */

#ifndef PROTO_IPV6_FRAGM_H
#define PROTO_IPV6_FRAGM_H

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */

#include "proto_struct.h"
#include "dissector_eth.h"
#include "built_in.h"

struct fragmhdr {
	uint8_t h_fragm_next_header;
	uint8_t h_fragm_reserved;
	uint16_t h_fragm_off_res_M;	
	uint32_t h_fragm_identification;
} __packed;

static inline void fragm(uint8_t *packet, size_t len)
{
	uint16_t off_res_M;
	struct fragmhdr *fragm = (struct fragmhdr *) packet;

	if (len < sizeof(struct fragmhdr))
		return;

	off_res_M = ntohs(fragm->h_fragm_off_res_M);
	
	tprintf("\t [ Fragment ");
	tprintf("NextHdr (%u), ", fragm->h_fragm_next_header);
	tprintf("Reserved (%u), ", fragm->h_fragm_reserved);
	tprintf("Offset (%u), ", off_res_M >> 3);
	tprintf("Res (%u), ", (off_res_M >> 1) & 0x3);
	tprintf("M flag (%u), ", off_res_M & 0x1);
	tprintf("Identification (%u) ", ntohs(fragm->h_fragm_identification));
	tprintf(" ]\n");
}

static inline void fragm_less(uint8_t *packet, size_t len)
{
	uint16_t off_res_M;	
	struct fragmhdr *fragm = (struct fragmhdr *) packet;

	if (len < sizeof(struct fragmhdr))
		return;

	off_res_M = ntohs(fragm->h_fragm_off_res_M);

	tprintf(" FragmOffs %u", off_res_M >> 3);
}

static inline void fragm_next(uint8_t *packet, size_t len,
			     struct hash_table **table,
			     unsigned int *key, size_t *off)
{
	struct fragmhdr *fragm = (struct fragmhdr *) packet;
	if (len < sizeof(struct fragmhdr))
		return;
	(*off) = sizeof(struct fragmhdr);
	(*key) = fragm->h_fragm_next_header;
	(*table) = &eth_lay3;
}

struct protocol ipv6_fragm_ops = {
	.key = 0x2C,
	.print_full = fragm,
	.print_less = fragm_less,
	.proto_next = fragm_next,
};

#endif /* PROTO_IPV6_FRAGM_H */
