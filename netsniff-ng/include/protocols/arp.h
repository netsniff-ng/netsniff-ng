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

#include "macros.h"

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

/*
 * print_arphdr - Just plain dumb formatting
 * @arp:         arp header
 */
void print_arphdr(struct arphdr *arp)
{
	char *opcode = NULL;

	assert(arp);

	switch (ntohs(arp->ar_op)) {
	case ARPOP_REQUEST:
		opcode = "ARP request";
		break;
	case ARPOP_REPLY:
		opcode = "ARP reply";
		break;
	case ARPOP_RREQUEST:
		opcode = "RARP request";
		break;
	case ARPOP_RREPLY:
		opcode = "RARP reply";
		break;
	case ARPOP_InREQUEST:
		opcode = "InARP request";
		break;
	case ARPOP_InREPLY:
		opcode = "InARP reply";
		break;
	case ARPOP_NAK:
		opcode = "(ATM)ARP NAK";
		break;
	default:
		opcode = "Unknown";
		break;
	};

	info(" [ ARP ");
	info("Format HA (%u), ", ntohs(arp->ar_hrd));
	info("Format Proto (%u), ", ntohs(arp->ar_pro));
	info("HA Len (%u), \n", ntohs(arp->ar_hln));
	info("   Proto Len (%u), ", ntohs(arp->ar_pln));
	info("Opcode (%u => %s)", ntohs(arp->ar_op), opcode);

	info(" ] \n");
}

/*
 * print_arphdr_less - Just plain dumb formatting
 * @arp:              arp header
 */
void print_arphdr_less(struct arphdr *arp)
{
	char *opcode = NULL;

	assert(arp);

	switch (ntohs(arp->ar_op)) {
	case ARPOP_REQUEST:
		opcode = "ARP request";
		break;
	case ARPOP_REPLY:
		opcode = "ARP reply";
		break;
	case ARPOP_RREQUEST:
		opcode = "RARP request";
		break;
	case ARPOP_RREPLY:
		opcode = "RARP reply";
		break;
	case ARPOP_InREQUEST:
		opcode = "InARP request";
		break;
	case ARPOP_InREPLY:
		opcode = "InARP reply";
		break;
	case ARPOP_NAK:
		opcode = "(ATM)ARP NAK";
		break;
	default:
		opcode = "Unknown";
		break;
	};

	info("Op %u, %s%s%s", ntohs(arp->ar_op), colorize_start(bold), opcode, colorize_end());
}

#endif				/* __PROTO_ARP_H__ */
