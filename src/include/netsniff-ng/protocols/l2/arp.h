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

#ifndef	__PROTO_ARP_H__
#define __PROTO_ARP_H__

#include <stdint.h>
#include <assert.h>

#include <netinet/in.h>
//#include <linux/if_arp.h>

static inline struct arphdr *get_arphdr(uint8_t ** pkt, uint32_t * pkt_len)
{
	struct arphdr *arp_header;

	assert(pkt);
	assert(*pkt);
	assert(*pkt_len > sizeof(*arp_header));

	arp_header = (struct arphdr *)*pkt;

	*pkt += sizeof(*arp_header);
	*pkt_len -= sizeof(*arp_header);

	return (arp_header);
}

#endif				/* __PROTO_ARP_H__ */
