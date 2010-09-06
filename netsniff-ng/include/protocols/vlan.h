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

#ifndef	__PROTO_VLAN_H__
#define __PROTO_VLAN_H__

#include <stdint.h>
#include <assert.h>

#include "macros.h"

#define VLAN_HLEN 4
#define ETH_P_8021QinQ	0x8200
#define VLAN_VID_MASK   0xfff

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

static inline struct vlan_hdr *get_vlanhdr(uint8_t ** pkt, uint32_t * pkt_len)
{
	struct vlan_hdr *vlan_header;
	assert(pkt);
	assert(*pkt);
	assert(*pkt_len > VLAN_HLEN);

	vlan_header = (struct vlan_hdr *)*pkt;
	pkt += VLAN_HLEN;
	pkt_len -= VLAN_HLEN;

	return (vlan_header);
}

static inline uint16_t get_vlan_tag(const struct vlan_hdr *header)
{
	assert(header);
	return (header->h_vlan_TCI & VLAN_VID_MASK);
}

static inline uint16_t get_vlan_encap_proto(const struct vlan_hdr *header)
{
	assert(header);
	return (header->h_vlan_encapsulated_proto);

}

/* XXX: Todo!! */

/*
 * print_vlan - Just plain dumb formatting
 * @header:            Vlan header
 */
static inline void print_vlanhdr(const struct vlan_hdr *header)
{
	info(" [ VLAN tag : %u ]", get_vlan_tag(header));
	info("\n");
}

/*
 * print_vlan_less - Just plain dumb formatting
 * @header:            Vlan header
 */
static inline void print_vlanhdr_less(const struct vlan_hdr *header)
{
	info("VLAN %u, ", get_vlan_tag(header));
}

#endif				/* __PROTO_VLAN_H__ */
