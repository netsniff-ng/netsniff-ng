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

#ifndef	__PROTO_IP_H__
#define __PROTO_IP_H__

#include <stdint.h>
#include <assert.h>

#include <netinet/in.h>
#include <linux/ip.h>

#include "macros.h"
#include "protocols/csum.h"

#define	FRAG_OFF_RESERVED_FLAG(x)      ((x) & 0x8000)
#define	FRAG_OFF_NO_FRAGMENT_FLAG(x)   ((x) & 0x4000)
#define	FRAG_OFF_MORE_FRAGMENT_FLAG(x) ((x) & 0x2000)
#define	FRAG_OFF_FRAGMENT_OFFSET(x)    ((x) & 0x1fff)

static inline struct iphdr *get_iphdr(uint8_t ** pkt, uint32_t * pkt_len)
{
	struct iphdr *ip_header;

	assert(pkt);
	assert(*pkt);
	assert(*pkt_len > sizeof(*ip_header));

	ip_header = (struct iphdr *)*pkt;

	*pkt += sizeof(*ip_header);
	*pkt_len -= sizeof(*ip_header);

	return (ip_header);
}

static inline uint16_t get_l4_type_from_ipv4(const struct iphdr *header)
{
	assert(header);
	return (header->protocol);
}

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

/*
 * print_iphdr_less - Just plain dumb formatting
 * @ip:              ip header
 */
void print_iphdr_less(struct iphdr *ip)
{
	/* XXX Version check */
	assert(ip);

	char src_ip[INET_ADDRSTRLEN] = { 0 };
	char dst_ip[INET_ADDRSTRLEN] = { 0 };

	uint16_t csum = calc_csum(ip, ip->ihl * 4, 0);

	inet_ntop(AF_INET, &ip->saddr, src_ip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &ip->daddr, dst_ip, INET_ADDRSTRLEN);

	info("%s => %s, ", src_ip, dst_ip);
	info("Chsum (0x%x) is %s", ntohs(ip->check), csum ? colorize_full_str(red, black, "bogus (!)") : "ok, ");
	if (csum) {
		info(" should be %x, ", csum_expected(ip->check, csum));
	}
}

#endif				/* __PROTO_IP_H__ */
