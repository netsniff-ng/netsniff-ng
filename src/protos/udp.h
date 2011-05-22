/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef UDP_H
#define UDP_H

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */

#include "proto_struct.h"
#include "dissector_eth.h"

struct udphdr {
	uint16_t source;
	uint16_t dest;
	uint16_t len;
	uint16_t check;
} __attribute__((packed));

static inline uint16_t udp_port(uint16_t src, uint16_t dst)
{
	char *tmp1, *tmp2;

	src = ntohs(src);
	dst = ntohs(dst);

	/* XXX: Is there a better way to determine? */
	if (src < dst && src < 1024) {
		return src;
	} else if (dst < src && dst < 1024) {
		return dst;
	} else {
		tmp1 = lookup_port_udp(src);
		tmp2 = lookup_port_udp(dst);
		if (tmp1 && !tmp2) {
			return src;
		} else if (!tmp1 && tmp2) {
			return dst;
		} else {
			if (src < dst)
				return src;
			else
				return dst;
		}
	}
}

static inline void udp(uint8_t *packet, size_t len)
{
	struct udphdr *udp = (struct udphdr *) packet;

	if (len < sizeof(struct udphdr))
		return;

	tprintf(" [ UDP ");
	tprintf("Port (%u => %u, %s%s%s), ", 
		ntohs(udp->source), ntohs(udp->dest),
		colorize_start(bold),
		lookup_port_udp(udp_port(udp->source, udp->dest)),
		colorize_end());
	tprintf("Len (%u), ", ntohs(udp->len));
	tprintf("CSum (0x%.4x)", ntohs(udp->check));
	tprintf(" ]\n");
}

static inline void udp_less(uint8_t *packet, size_t len)
{
	struct udphdr *udp = (struct udphdr *) packet;

	if (len < sizeof(struct udphdr))
		return;

	tprintf(" UDP %s%s%s %u/%u", 
		colorize_start(bold),
		lookup_port_udp(udp_port(udp->source, udp->dest)),
		colorize_end(), ntohs(udp->source), ntohs(udp->dest));
}

static inline void udp_next(uint8_t *packet, size_t len,
			    struct hash_table **table,
			    unsigned int *key, size_t *off)
{
	struct udphdr *udp = (struct udphdr *) packet;

	if (len < sizeof(struct udphdr))
		goto invalid;

	(*off) = sizeof(struct udphdr);
	(*key) = udp_port(udp->source, udp->dest);
	(*table) = &eth_lay4;

	return;
invalid:
	(*off) = 0;
	(*key) = 0;
	(*table) = NULL;
}

struct protocol udp_ops = {
	.key = 0x11,
	.print_full = udp,
	.print_less = udp_less,
	.print_pay_ascii = empty,
	.print_pay_hex = empty,
	.print_pay_none = udp,
	.print_all_cstyle = NULL,
	.print_all_hex = __hex,
	.proto_next = udp_next,
};

#endif /* UDP_H */
