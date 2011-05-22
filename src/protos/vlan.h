/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Copyright 2010 Emmanuel Roullit.
 * Subject to the GPL.
 */

#ifndef VLAN_H
#define VLAN_H

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */

#include "proto_struct.h"
#include "dissector_eth.h"

struct vlanhdr {
	uint16_t h_vlan_TCI;
	uint16_t h_vlan_encapsulated_proto;
} __attribute__((packed));

static inline void vlan(uint8_t *packet, size_t len)
{
	uint16_t tci;
	struct vlanhdr *vlan = (struct vlanhdr *) packet;

	if (len < sizeof(struct vlanhdr))
		return;

	tci = ntohs(vlan->h_vlan_TCI);

	tprintf(" [ VLAN ");
	tprintf("Prio (%d), ", (tci & 0xE000) >> 13);
	tprintf("CFI (%d), ", (tci & 0x1000) >> 12);
	tprintf("ID (%d), ", (tci & 0x0FFF));
	tprintf("Proto (0x%.4x)", ntohs(vlan->h_vlan_encapsulated_proto));
	tprintf(" ]\n");
}

static inline void vlan_less(uint8_t *packet, size_t len)
{
	uint16_t tci;
	struct vlanhdr *vlan = (struct vlanhdr *) packet;

	if (len < sizeof(struct vlanhdr))
		return;

	tci = ntohs(vlan->h_vlan_TCI);

	tprintf(" VLAN%d", (tci & 0x0FFF));
}

static inline void vlan_next(uint8_t *packet, size_t len,
			     struct hash_table **table,
			     unsigned int *key, size_t *off)
{
	struct vlanhdr *vlan = (struct vlanhdr *) packet;

	if (len < sizeof(struct vlanhdr))
		goto invalid;

	(*off) = sizeof(struct vlanhdr);
	(*key) = ntohs(vlan->h_vlan_encapsulated_proto);
	(*table) = &eth_lay2;

	return;
invalid:
	(*off) = 0;
	(*key) = 0;
	(*table) = NULL;
}

struct protocol vlan_ops = {
	.key = 0x8100,
	.offset = sizeof(struct vlanhdr),
	.print_full = vlan,
	.print_less = vlan_less,
	.print_pay_ascii = empty,
	.print_pay_hex = empty,
	.print_pay_none = vlan,
	.print_all_cstyle = __hex2,
	.print_all_hex = __hex,
	.proto_next = vlan_next,
};

#endif /* VLAN_H */
