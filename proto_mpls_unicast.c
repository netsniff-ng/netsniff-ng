/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2012 Markus Amend <markus@netsniff-ng.org>, Deutsche Flugsicherung GmbH
 * Subject to the GPL, version 2.
 *
 * http://tools.ietf.org/html/rfc3032
 */

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */
#include <errno.h>

#include "proto.h"
#include "dissector_eth.h"
#include "built_in.h"
#include "pkt_buff.h"

struct mpls_uchdr {
	uint32_t mpls_uc_hdr;
} __packed;

static int mpls_uc_next_proto(struct pkt_buff *pkt)
{
	uint8_t proto;
	uint16_t key = 0;

	if (pkt_len(pkt))
		proto = *(pkt->data);
	else
		return -EIO;

	/* FIXME: Right now only test for IP Version field */
	switch (proto >> 4) {
	case 4:
		key = 0x0800; /* IPv4*/
		break;
	case 6:
		key = 0x86DD; /* IPv6*/
		break;
	default:
		/* Nothing detected ... */
		return -ENOENT;
	}

	return key;
}

static void mpls_uc_full(struct pkt_buff *pkt)
{
	int next;
	uint32_t mpls_uc_data;
	struct mpls_uchdr *mpls_uc;
	uint8_t s = 0;

	do {
		mpls_uc = (struct mpls_uchdr *) pkt_pull(pkt, sizeof(*mpls_uc));
		if (mpls_uc == NULL)
			return;

		mpls_uc_data = ntohl(mpls_uc->mpls_uc_hdr);
		s = (mpls_uc_data >> 8) & 0x1;

		tprintf(" [ MPLS ");
		tprintf("Label (%u), ", mpls_uc_data >> 12);
		tprintf("Exp (%u), ", (mpls_uc_data >> 9) & 0x7);
		tprintf("S (%u), ", s);
		tprintf("TTL (%u)", (mpls_uc_data & 0xFF));
		tprintf(" ]\n");
	} while (!s);

	next = mpls_uc_next_proto(pkt);
	if (next < 0)
		return;

	pkt_set_proto(pkt, &eth_lay2, (uint16_t) next);
}

static void mpls_uc_less(struct pkt_buff *pkt)
{
	int next;
	uint32_t mpls_uc_data;
	struct mpls_uchdr *mpls_uc;
	uint8_t s = 0;

	do {
		mpls_uc = (struct mpls_uchdr *) pkt_pull(pkt, sizeof(*mpls_uc));
		if (mpls_uc == NULL)
			return;

		mpls_uc_data = ntohl(mpls_uc->mpls_uc_hdr);
		s = (mpls_uc_data >> 8) & 0x1;

		tprintf(" MPLS/%u", mpls_uc_data >> 12);
	} while (!s);

	next = mpls_uc_next_proto(pkt);
	if (next < 0)
		return;

	pkt_set_proto(pkt, &eth_lay2, (uint16_t) next);
}

struct protocol mpls_uc_ops = {
	.key = 0x8847,
	.print_full = mpls_uc_full,
	.print_less = mpls_uc_less,
};
