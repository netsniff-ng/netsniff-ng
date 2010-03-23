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

#ifndef	__PRINT_IP_H__
#define	__PRINT_IP_H__

#include <stdint.h>
#include <assert.h>

#include <netsniff-ng/macros.h>
#include <netsniff-ng/protocols/l3/ip.h>

/*
 * print_iphdr - Just plain dumb formatting
 * @ip:            ip header
 */

void print_iphdr(struct iphdr *ip)
{
	/* XXX Version check */
	assert(ip);
	char src_ip[INET_ADDRSTRLEN] = { 0 };
	char dst_ip[INET_ADDRSTRLEN] = { 0 };
	uint16_t csum = calc_csum(ip, ip->ihl * 4, 0);
	uint16_t printable_frag_off;

	inet_ntop(AF_INET, &ip->saddr, src_ip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &ip->daddr, dst_ip, INET_ADDRSTRLEN);
	printable_frag_off = ntohs(ip->frag_off);

	info(" [ IPv4 ");
	info("Addr (%s => %s), ", src_ip, dst_ip);
	info("Proto (%u), ", ip->protocol);
	info("TTL (%u), \n", ip->ttl);
	info("   TOS (%u), ", ip->tos);
	info("Ver (%u), ", ip->version);
	info("IHL (%u), ", ntohs(ip->ihl));
	info("Tlen (%u), ", ntohs(ip->tot_len));
	info("ID (%u), \n", ntohs(ip->id));
	info("   Res: %u NoFrag: %u MoreFrag: %u offset (%u), ", FRAG_OFF_RESERVED_FLAG(printable_frag_off) ? 1 : 0,
	     FRAG_OFF_NO_FRAGMENT_FLAG(printable_frag_off) ? 1 : 0,
	     FRAG_OFF_MORE_FRAGMENT_FLAG(printable_frag_off) ? 1 : 0, FRAG_OFF_FRAGMENT_OFFSET(printable_frag_off));
	info("Chsum (0x%x) is %s", ntohs(ip->check), csum ? colorize_full_str(red, black, "bogus (!)") : "ok");

	if (csum) {
		info(" should be %x", csum_expected(ip->check, csum));
	}

	info(" ] \n");
}

#endif				/* __PRINT_IP_H__ */
