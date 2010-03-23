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

#ifndef	__PRINT_IPV6_H__
#define __PRINT_IPV6_H__

#include <stdint.h>
#include <assert.h>

#include <netsniff-ng/macros.h>
#include <netsniff-ng/protocols/l3/ipv6.h>

/*
 * print_ipv6hdr - Just plain dumb formatting
 * @ip:            ip header
 */
/* TODO To improve */
void print_ipv6hdr(struct ipv6hdr *ip)
{
	assert(ip);
	char src_ip[INET6_ADDRSTRLEN] = { 0 };
	char dst_ip[INET6_ADDRSTRLEN] = { 0 };

	if ((ip->version & 0x0110) == 0x0110) {
		info("Version is %u\n", ip->version);
		return;
	}

	inet_ntop(AF_INET6, &ip->saddr, src_ip, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &ip->daddr, dst_ip, INET6_ADDRSTRLEN);

	info(" [ IPv6 ");
	info("Addr (%s => %s), ", src_ip, dst_ip);
	info("Payload len (%u), ", ntohs(ip->payload_len));
	info("Next header (%u), ", ip->nexthdr);
	info("Hop limit (%u), ", ip->hop_limit);

	info(" ] \n");
}

#endif				/* __PRINT_IPV6_H__ */
