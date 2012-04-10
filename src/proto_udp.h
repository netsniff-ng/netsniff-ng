/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef UDP_H
#define UDP_H

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */

#include "proto_struct.h"
#include "dissector_eth.h"
#include "pkt_buff.h"

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

static inline void udp(struct pkt_buff *pkt)
{
	struct udphdr *udp = (struct udphdr *) pkt_pull(pkt, sizeof(*udp));

	if (udp == NULL)
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

	pkt_set_proto(pkt, &eth_lay4, udp_port(udp->source, udp->dest));
}

static inline void udp_less(struct pkt_buff *pkt)
{
	struct udphdr *udp = (struct udphdr *) pkt_pull(pkt, sizeof(*udp));

	if (udp == NULL)
		return;

	tprintf(" UDP %s%s%s %u/%u",
		colorize_start(bold),
		lookup_port_udp(udp_port(udp->source, udp->dest)),
		colorize_end(), ntohs(udp->source), ntohs(udp->dest));

	pkt_set_proto(pkt, &eth_lay4, udp_port(udp->source, udp->dest));
}

struct protocol udp_ops = {
	.key = 0x11,
	.print_full = udp,
	.print_less = udp_less,
};

#endif /* UDP_H */
