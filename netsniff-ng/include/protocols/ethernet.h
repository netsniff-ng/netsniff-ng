/*
 * Copyright (C) 2009, 2010  Daniel Borkmann <daniel@netsniff-ng.org> and 
 *                           Emmanuel Roullit <emmanuel@netsniff-ng.org>
 *
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation; either version 2 of the License, or (at 
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License 
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
 */

#ifndef	__PROTO_ETHERNET_H__
#define __PROTO_ETHERNET_H__

#include <stdint.h>
#include <assert.h>

#include <netinet/if_ether.h>

#include "macros.h"
#include "hash.h"

static inline struct ethhdr *get_ethhdr(uint8_t ** pkt, uint32_t * pkt_len)
{
	struct ethhdr *header;
	assert(pkt);
	assert(*pkt);
	assert(*pkt_len > ETH_HLEN);

	header = (struct ethhdr *)*pkt;

	*pkt += ETH_HLEN;
	*pkt_len -= ETH_HLEN;

	return (header);
}

static inline uint16_t get_ethertype(const struct ethhdr *header)
{
	assert(header);
	return (ntohs(header->h_proto));
}

/*
 * print_ethhdr - Just plain dumb formatting
 * @eth:            ethernet header
 */
static inline void print_ethhdr(struct ethhdr *eth)
{
	uint8_t *src_mac = eth->h_source;
	uint8_t *dst_mac = eth->h_dest;

	assert(eth);

	info(" [ ");
	info("MAC (%.2x:%.2x:%.2x:%.2x:%.2x:%.2x => %.2x:%.2x:%.2x:%.2x:%.2x:%.2x), ", src_mac[0], src_mac[1],
	     src_mac[2], src_mac[3], src_mac[4], src_mac[5], dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4],
	     dst_mac[5]);
	info("Proto (0x%.4x, %s)", ntohs(eth->h_proto), ether_types_find(eth->h_proto));
	info(" ] \n");

	info(" [ ");
	info("Vendor (%s => %s)", ieee_vendors_find(src_mac), ieee_vendors_find(dst_mac));
	info(" ] \n");
}

/*
 * print_ethhdr_less - Just plain dumb formatting
 * @eth:              ethernet header
 */
static inline void print_ethhdr_less(struct ethhdr *eth)
{
	uint8_t *src_mac = eth->h_source;
	uint8_t *dst_mac = eth->h_dest;

	assert(eth);

	info("0x%.4x, %.2x:%.2x:%.2x:%.2x:%.2x:%.2x => %.2x:%.2x:%.2x:%.2x:%.2x:%.2x, %s => %s, ",
	     ntohs(eth->h_proto),
	     src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],
	     dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5],
	     ieee_vendors_find(src_mac), ieee_vendors_find(dst_mac));
}

#endif				/* __PROTO_ETHERNET_H__ */
