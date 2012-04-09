/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef ICMP_H
#define ICMP_H

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */

#include "proto_struct.h"
#include "dissector_eth.h"

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
} __attribute__((packed));

static inline void icmp(uint8_t *packet, size_t len)
{
	struct icmphdr *icmp = (struct icmphdr *) packet;

	if (len < sizeof(struct icmphdr))
		return;

	tprintf(" [ ICMP ");
	tprintf("Type (%u), ", icmp->type);
	tprintf("Code (%u), ", icmp->code);
	tprintf("CSum (0x%.4x)", ntohs(icmp->checksum));
	tprintf(" ]\n");
}

static inline void icmp_less(uint8_t *packet, size_t len)
{
	struct icmphdr *icmp = (struct icmphdr *) packet;

	if (len < sizeof(struct icmphdr))
		return;

	tprintf(" Type %u Code %u", icmp->type, icmp->code);
}

struct protocol icmp_ops = {
	.key = 0x01,
	.offset = sizeof(struct icmphdr),
	.print_full = icmp,
	.print_less = icmp_less,
	.proto_next = NULL,
};

#endif /* ICMP_H */
