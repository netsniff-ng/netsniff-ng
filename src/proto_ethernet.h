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

static inline void ethernet(uint8_t *packet, size_t len)
{
	uint8_t *src_mac, *dst_mac;
	struct ethhdr *eth = (struct ethhdr *) packet;

	if (len < sizeof(struct ethhdr))
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
}

static inline void ethernet_hex_all(uint8_t *packet, size_t len)
{
	tprintf("   ");
	__hex(packet, len);
}

static unsigned long num = 0;
static inline void ethernet_cstyle_all(uint8_t *packet, size_t len)
{
	tprintf("$P%lu {\n   ", num++);
	__hex2(packet, len);
}

static inline void ethernet_less(uint8_t *packet, size_t len)
{
	uint8_t *src_mac, *dst_mac;
	struct ethhdr *eth = (struct ethhdr *) packet;

	if (len < sizeof(struct ethhdr))
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
}

static inline void ethernet_next(uint8_t *packet, size_t len,
				 struct hash_table **table,
				 unsigned int *key, size_t *off)
{
	struct ethhdr *eth = (struct ethhdr *) packet;

	if (len < sizeof(struct ethhdr))
		goto invalid;

	(*off) = sizeof(struct ethhdr);
	(*key) = ntohs(eth->h_proto);
	(*table) = &eth_lay2;

	return;
invalid:
	(*off) = 0;
	(*key) = 0;
	(*table) = NULL;
}

struct protocol ethernet_ops = {
	.key = 0,
	.offset = sizeof(struct ethhdr),
	.print_full = ethernet,
	.print_less = ethernet_less,
	.print_pay_ascii = empty,
	.print_pay_hex = empty,
	.print_pay_none = ethernet,
	.print_all_cstyle = ethernet_cstyle_all,
	.print_all_hex = ethernet_hex_all,
	.proto_next = ethernet_next,
};

#endif /* ETHERNET_H */
