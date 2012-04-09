/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef ETHERNET_H
#define ETHERNET_H

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
#include <linux/if_ether.h>

#include "proto_struct.h"
#include "dissector_eth.h"
#include "pkt_buff.h"

static inline void ethernet(struct pkt_buff *pkt)
{
	uint8_t *src_mac, *dst_mac;
	struct ethhdr *eth = (struct ethhdr *) pkt_pull_head(pkt, sizeof(*eth));

	if (eth == NULL)
		return;

	src_mac = eth->h_source;
	dst_mac = eth->h_dest;
	tprintf(" [ Eth ");
	tprintf("MAC (%.2x:%.2x:%.2x:%.2x:%.2x:%.2x => ",
		src_mac[0], src_mac[1], src_mac[2],
		src_mac[3], src_mac[4], src_mac[5]);
	tprintf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x), ",
		dst_mac[0], dst_mac[1], dst_mac[2],
		dst_mac[3], dst_mac[4], dst_mac[5]);
	tprintf("Proto (0x%.4x, %s%s%s)",
		ntohs(eth->h_proto), colorize_start(bold), 
		lookup_ether_type(ntohs(eth->h_proto)), colorize_end());
	tprintf(" ]\n");

	tprintf(" [ Vendor ");
	tprintf("(%s => %s)",
		lookup_vendor((src_mac[0] << 16) | (src_mac[1] << 8) |
			      src_mac[2]),
		lookup_vendor((dst_mac[0] << 16) | (dst_mac[1] << 8) |
			      dst_mac[2]));
	tprintf(" ]\n");

	pkt_set_proto(pkt, &eth_lay2, ntohs(eth->h_proto));
}

static inline void ethernet_hex_all(struct pkt_buff *pkt)
{
	tprintf("   ");
	hex(pkt);
}

static inline void ethernet_less(struct pkt_buff *pkt)
{
	uint8_t *src_mac, *dst_mac;
	struct ethhdr *eth = (struct ethhdr *) pkt_pull_head(pkt, sizeof(*eth));

	if (eth == NULL)
		return;

	src_mac = eth->h_source;
	dst_mac = eth->h_dest;
	tprintf(" %s => %s ", 
		lookup_vendor((src_mac[0] << 16) | (src_mac[1] << 8) |
			      src_mac[2]),
		lookup_vendor((dst_mac[0] << 16) | (dst_mac[1] << 8) |
			      dst_mac[2]));
	tprintf("%s%s%s", colorize_start(bold), 
		lookup_ether_type(ntohs(eth->h_proto)), colorize_end());

	pkt_set_proto(pkt, &eth_lay2, ntohs(eth->h_proto));
}

struct protocol ethernet_ops = {
	.key = 0,
	.print_full = ethernet,
	.print_less = ethernet_less,
};

#endif /* ETHERNET_H */
