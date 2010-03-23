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

#ifndef	__PRINT_UDP_H__
#define	__PRINT_UDP_H__

#include <stdint.h>
#include <assert.h>

#include <netsniff-ng/macros.h>
#include <netsniff-ng/protocols/l4/udp.h>

/*
 * dump_udphdr_all - Just plain dumb formatting
 * @udp:            udp header
 */
void print_udphdr(struct udphdr *udp)
{
	info(" [ UDP ");

	info("Port (%u => %u), ", ntohs(udp->source), ntohs(udp->dest));
	info("Len (%u), ", ntohs(udp->len));
	info("Chsum (0x%x)", ntohs(udp->check));

	info(" ] \n");
}

#endif				/* __PRINT_UDP_H__ */
