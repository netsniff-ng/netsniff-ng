/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */

#include "proto.h"
#include "protos.h"
#include "dissector_eth.h"
#include "pkt_buff.h"
#include "built_in.h"

struct icmphdr {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	union {
		struct {
			uint16_t id;
			uint16_t sequence;
		} echo;
		uint32_t gateway;
		struct {
			uint16_t ____unused;
			uint16_t mtu;
		} frag;
	} un;
} __packed;

static void icmp(struct pkt_buff *pkt)
{
	struct icmphdr *icmp = (struct icmphdr *) pkt_pull(pkt, sizeof(*icmp));

	if (icmp == NULL)
		return;

	tprintf(" [ ICMP ");
	tprintf("Type (%u), ", icmp->type);
	tprintf("Code (%u), ", icmp->code);
	tprintf("CSum (0x%.4x)", ntohs(icmp->checksum));
	tprintf(" ]\n");
}

static void icmp_less(struct pkt_buff *pkt)
{
	struct icmphdr *icmp = (struct icmphdr *) pkt_pull(pkt, sizeof(*icmp));

	if (icmp == NULL)
		return;

	tprintf(" Type %u Code %u", icmp->type, icmp->code);
}

struct protocol icmpv4_ops = {
	.key = 0x01,
	.print_full = icmp,
	.print_less = icmp_less,
};

EXPORT_SYMBOL(icmp_ops);
