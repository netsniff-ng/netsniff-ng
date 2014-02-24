/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2012 Markus Amend <markus@netsniff-ng.org>, Deutsche Flugsicherung GmbH
 * Subject to the GPL, version 2.
 *
 * IPv6 Fragmentation Header described in RFC2460
 */

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */

#include "proto.h"
#include "dissector_eth.h"
#include "built_in.h"
#include "pkt_buff.h"

struct fragmhdr {
	uint8_t h_fragm_next_header;
	uint8_t h_fragm_reserved;
	uint16_t h_fragm_off_res_M;	
	uint32_t h_fragm_identification;
} __packed;

static void fragm(struct pkt_buff *pkt)
{
	uint16_t off_res_M;
	struct fragmhdr *fragm_ops;

	fragm_ops = (struct fragmhdr *) pkt_pull(pkt, sizeof(*fragm_ops));
	if (fragm_ops == NULL)
		return;

	off_res_M = ntohs(fragm_ops->h_fragm_off_res_M);
	
	tprintf("\t [ Fragment ");
	tprintf("NextHdr (%u), ", fragm_ops->h_fragm_next_header);
	tprintf("Reserved (%u), ", fragm_ops->h_fragm_reserved);
	tprintf("Offset (%u), ", off_res_M >> 3);
	tprintf("Res (%u), ", (off_res_M >> 1) & 0x3);
	tprintf("M flag (%u), ", off_res_M & 0x1);
	tprintf("Identification (%u)",
		ntohl(fragm_ops->h_fragm_identification));
	tprintf(" ]\n");

	pkt_set_proto(pkt, &eth_lay3, fragm_ops->h_fragm_next_header);
}

static void fragm_less(struct pkt_buff *pkt)
{
	uint16_t off_res_M;
	struct fragmhdr *fragm_ops;

	fragm_ops = (struct fragmhdr *) pkt_pull(pkt, sizeof(*fragm_ops));
	if (fragm_ops == NULL)
		return;

	off_res_M = ntohs(fragm_ops->h_fragm_off_res_M);

	tprintf(" FragmOffs %u", off_res_M >> 3);

	pkt_set_proto(pkt, &eth_lay3, fragm_ops->h_fragm_next_header);
}

struct protocol ipv6_fragm_ops = {
	.key = 0x2C,
	.print_full = fragm,
	.print_less = fragm_less,
};
