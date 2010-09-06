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

#ifndef	__PROTO_ICMP_H__
#define __PROTO_ICMP_H__

#include <stdint.h>
#include <assert.h>

#include <netinet/in.h>
#include <linux/icmp.h>

#include "macros.h"
#include "protocols/csum.h"

static inline struct icmphdr *get_icmphdr(uint8_t ** pkt, uint32_t * pkt_len)
{
	struct icmphdr *icmp_header;

	assert(pkt);
	assert(*pkt);
	assert(*pkt_len > sizeof(*icmp_header));

	icmp_header = (struct icmphdr *)*pkt;

	*pkt += sizeof(*icmp_header);
	*pkt_len -= sizeof(*icmp_header);

	return (icmp_header);
}

/*
 * print_icmphdr - Just plain dumb formatting
 * @ip:           icmp header
 */
 /* XXX: print codes and the whole rest */
void print_icmphdr(struct icmphdr *icmp)
{
	assert(icmp);

	//uint16_t csum = calc_csum(icmp, sizeof(*icmp), 0);

	info(" [ ICMP ");
	info("Type (%u), ", icmp->type);
	info("Code (%u), ", icmp->code);
	info("Chsum (0x%x)",
	     ntohs(icmp->checksum) /* TODO:, csum ? colorize_full_str(red, black, "bogus (!)") : "ok"Ü */ );

	//if (csum) {
	//      info(" should be %x", csum_expected(icmp->checksum, csum));
	//}

	info(" ] \n");
}

/*
 * print_icmphdr_less - Just plain dumb formatting
 * @ip:                icmp header
 */
void print_icmphdr_less(struct icmphdr *icmp)
{
	assert(icmp);

	info("ICMP, ");
	info("Type %u, ", icmp->type);
	info("Code %u\n", icmp->code);
}

#endif				/* __PROTO_ICMP_H__ */
