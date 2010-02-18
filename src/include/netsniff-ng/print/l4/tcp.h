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

#ifndef	__PRINT_TCP_H__
#define	__PRINT_TCP_H__

#include <stdint.h>
#include <assert.h>

#include <netsniff-ng/macros.h>
#include <netsniff-ng/protocols/l4/tcp.h>

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

#endif				/* __PRINT_TCP_H__ */
