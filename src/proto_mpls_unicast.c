/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2012 Markus Amend <markus@netsniff-ng.org>
 * Subject to the GPL, version 2.
 *
 * http://tools.ietf.org/html/rfc3032
 */

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */

#include "proto.h"
#include "protos.h"
#include "dissector_eth.h"
#include "pkt_buff.h"

struct mpls_uchdr {
	uint32_t mpls_uc_hdr;
} __attribute__((packed));

static void mpls_uc_full(struct pkt_buff *pkt)
{
	uint8_t s = 0;
	uint32_t mpls_uc_data;

	do {
		struct mpls_uchdr *mpls_uc = (struct mpls_uchdr *) pkt_pull(pkt,
							      sizeof(*mpls_uc));

		if (mpls_uc == NULL)
			return;

		mpls_uc_data = ntohl(mpls_uc->mpls_uc_hdr);
		s = (mpls_uc_data >> 8) & 0x1;

		tprintf(" [ MPLS ");
		tprintf("Label (%u), ", mpls_uc_data >> 12);
		tprintf("Exp (%u), ", (mpls_uc_data >> 9) & 0x7);
		tprintf("S (%u), ", s);
		tprintf("TTL (%u), ", (mpls_uc_data & 0xFF));
		tprintf(" ]\n");
	}while(!s);

// 	pkt_set_proto(pkt, &eth_lay2, ntohs(mpls_uc->TPID));
}

static void mpls_uc_less(struct pkt_buff *pkt)
{
// 	uint16_t mpls_uc_data;
// 	struct mpls_uchdr *mpls_uc = (struct mpls_uchdr *) pkt_pull(pkt,
// sizeof(*mpls_uc));
// 
// 	if (mpls_uc == NULL)
// 		return;
// 
// 	mpls_uc_data = ntohs(mpls_uc->TCI);
// 
// 	tprintf(" VLAN%d", (mpls_uc_data & 0x0FFF));
// 
// 	pkt_set_proto(pkt, &eth_lay2, ntohs(mpls_uc->TPID));
}

struct protocol mpls_uc_ops = {
	.key = 0x8847,
	.print_full = mpls_uc_full,
	.print_less = mpls_uc_less,
};

EXPORT_SYMBOL(mpls_uc_ops);
