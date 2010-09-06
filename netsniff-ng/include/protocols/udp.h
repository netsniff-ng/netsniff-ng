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

#ifndef	__PROTO_UDP_H__
#define	__PROTO_UDP_H__

#include <stdint.h>
#include <assert.h>

#include <linux/udp.h>

#include "macros.h"
#include "hash.h"

static inline struct udphdr *get_udphdr(uint8_t ** pkt, uint32_t * pkt_len)
{
	struct udphdr *udp_header = NULL;

	assert(pkt);
	assert(*pkt);
	assert(*pkt_len >= sizeof(*udp_header));

	udp_header = (struct udphdr *)*pkt;

	*pkt += sizeof(*udp_header);
	*pkt_len -= sizeof(*udp_header);

	return (udp_header);
}

/*
 * dump_udphdr_all - Just plain dumb formatting
 * @udp:            udp header
 */
void print_udphdr(struct udphdr *udp)
{
	char *tmp1, *tmp2;
	char *port_desc = NULL;

	assert(udp);

	uint16_t udps = ntohs(udp->source);
	uint16_t udpd = ntohs(udp->dest);

	/* XXX: Is there a better way to determine? */
	if (udps < udpd && udps < 1024) {
		port_desc = (char *)ports_udp_find(udp->source);
	} else if (udpd < udps && udpd < 1024) {
		port_desc = (char *)ports_udp_find(udp->dest);
	} else {
		tmp1 = (char *)ports_udp_find(udp->source);
		tmp2 = (char *)ports_udp_find(udp->dest);

		if (tmp1 && !tmp2) {
			port_desc = tmp1;
		} else if (!tmp1 && tmp2) {
			port_desc = tmp2;
		} else if (tmp1 && tmp2) {
			if (udps < udpd)
				port_desc = tmp1;
			else
				port_desc = tmp2;
		}
	}

	if (!port_desc)
		port_desc = "Unknown";

	info(" [ UDP ");

	info("Port (%u => %u, %s%s%s), ", udps, udpd, colorize_start(bold), port_desc, colorize_end());
	info("Len (%u), ", ntohs(udp->len));
	info("Chsum (0x%x)", ntohs(udp->check));

	info(" ] \n");
}

/*
 * dump_udphdr_all - Just plain dumb formatting
 * @udp:            udp header
 */
void print_udphdr_less(struct udphdr *udp)
{
	char *tmp1, *tmp2;
	char *port_desc = NULL;

	assert(udp);

	uint16_t udps = ntohs(udp->source);
	uint16_t udpd = ntohs(udp->dest);

	/* XXX: Is there a better way to determine? */
	if (udps < udpd && udps < 1024) {
		port_desc = (char *)ports_udp_find(udp->source);
	} else if (udpd < udps && udpd < 1024) {
		port_desc = (char *)ports_udp_find(udp->dest);
	} else {
		tmp1 = (char *)ports_udp_find(udp->source);
		tmp2 = (char *)ports_udp_find(udp->dest);

		if (tmp1 && !tmp2) {
			port_desc = tmp1;
		} else if (!tmp1 && tmp2) {
			port_desc = tmp2;
		} else if (tmp1 && tmp2) {
			if (udps < udpd)
				port_desc = tmp1;
			else
				port_desc = tmp2;
		}
	}

	if (!port_desc)
		port_desc = "U";

	info("UDP, ");
	info("%s%s%s, %u => %u\n", colorize_start(bold), port_desc, colorize_end(), udps, udpd);
}

#endif				/* __PROTO_UDP_H__ */
