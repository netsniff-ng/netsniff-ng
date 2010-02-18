/* XXX: Coding Style - use the tool indent with the following (Linux kernel
 *                     code indents)
 *
 * indent -nbad -bap -nbc -bbo -hnl -br -brs -c33 -cd33 -ncdb -ce -ci4   \
 *        -cli0 -d0 -di1 -nfc1 -i8 -ip0 -l120 -lp -npcs -nprs -npsl -sai \
 *        -saf -saw -ncs -nsc -sob -nfca -cp33 -ss -ts8 -il1
 *
 *
 * netsniff-ng
 *
 * High performance network sniffer for packet inspection
 *
 * Copyright (C) 2009, 2010  Daniel Borkmann <danborkmann@googlemail.com> and 
 *                           Emmanuel Roullit <emmanuel.roullit@googlemail.com>
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
 *
 * Note: Your kernel has to be compiled with CONFIG_PACKET_MMAP=y option in 
 *       order to use this.
 */

#ifndef	__PRINT_ARP_H__
#define	__PRINT_ARP_H__

#include <stdint.h>
#include <assert.h>

#include <netsniff-ng/macros.h>
#include <netsniff-ng/protocols/l2/arp.h>

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

#endif				/* __PRINT_ARP_H__ */
