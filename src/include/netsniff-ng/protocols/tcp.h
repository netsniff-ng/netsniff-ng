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

#ifndef	__PROTO_TCP_H__
#define	__PROTO_TCP_H__

#include <stdint.h>
#include <assert.h>

#include <linux/tcp.h>

#include <netsniff-ng/macros.h>

static inline struct tcphdr *get_tcphdr(uint8_t ** pkt, uint32_t * pkt_len)
{
	struct tcphdr *tcp_header = NULL;

	assert(pkt);
	assert(*pkt);
	assert(*pkt_len >= sizeof(*tcp_header));

	tcp_header = (struct tcphdr *)*pkt;

	*pkt += sizeof(*tcp_header);
	*pkt_len -= sizeof(*tcp_header);

	return (tcp_header);
}

/*
 * dump_tcphdr_all - Just plain dumb formatting
 * @tcp:            tcp header
 */
static void inline print_tcphdr(struct tcphdr *tcp)
{
	assert(tcp);

	info(" [ TCP ");

	info("Port (%u => %u), ", ntohs(tcp->source), ntohs(tcp->dest));
	info("SN (0x%x), ", ntohs(tcp->seq));
	info("AN (0x%x), ", ntohs(tcp->ack_seq));
	info("Data off (%d), \n", ntohs(tcp->doff));
	info("   Res 1 (%d), ", ntohs(tcp->res1));

	info("Flags (");

	if (tcp->urg == 1) {
		info("URG ");
	}
	if (tcp->ack == 1) {
		info("ACK ");
	}
	if (tcp->psh == 1) {
		info("PSH ");
	}
	if (tcp->rst == 1) {
		info("RST ");
	}
	if (tcp->syn == 1) {
		info("SYN ");
	}
	if (tcp->fin == 1) {
		info("FIN ");
	}
	if (tcp->ece == 1) {
		info("ECE ");
	}
	if (tcp->cwr == 1) {
		info("CWR ");
	}

	info("), ");

	info("Window (%d), ", ntohs(tcp->window));
	info("Hdrsum (0x%x), \n", ntohs(tcp->check));
	info("   Urg ptr (%u)", ntohs(tcp->urg_ptr));

	info(" ] \n");

	/* TODO check csum */
}

#endif				/* __PROTO_TCP_H__ */
