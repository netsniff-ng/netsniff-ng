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

#ifndef	__PRINT_ETHERNET_H__
#define	__PRINT_ETHERNET_H__

#include <stdint.h>
#include <assert.h>

#include <netsniff-ng/macros.h>
#include <netsniff-ng/protocols/l2/ethernet.h>

/*
 * print_ethhdr - Just plain dumb formatting
 * @eth:            ethernet header
 */
static inline void print_ethhdr(struct ethhdr *eth)
{
	uint8_t *src_mac = eth->h_source;
	uint8_t *dst_mac = eth->h_dest;

	assert(eth);

	info(" [ ");

	info("MAC (%.2x:%.2x:%.2x:%.2x:%.2x:%.2x => %.2x:%.2x:%.2x:%.2x:%.2x:%.2x), ", src_mac[0], src_mac[1],
	     src_mac[2], src_mac[3], src_mac[4], src_mac[5], dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4],
	     dst_mac[5]);

	info("Proto (0x%.4x)", ntohs(eth->h_proto));

	info(" ] \n");
}

#endif	/* __PRINT_ETHERNET_H__ */
